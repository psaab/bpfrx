# #2090 — `checkVIPReadinessForConfig` carrier-aware readiness (sibling of #2070)

**Status:** v2 — both hostile reviewers PLAN-NEEDS-MINOR (no BLOCKER/MAJOR/KILL);
all minors folded. Ready to implement.

## Issue framing

The #2070 fix (PR #2087, merged at `ffb94a006`) made the HA
interface-monitor read **operational carrier state** (`IFLA_OPERSTATE`)
instead of the administrative `IFF_UP` flag. It did this by adding a
`linkAttrsUp(attrs)` helper that returns:

- `OperUp` → up
- `OperUnknown` → fall back to the `IFF_UP` admin flag (virtual devices
  that report no carrier state)
- anything else (`OperDown`, `OperLowerLayerDown`, …) → down

That helper exists as a **private copy in three packages** — the #2070
PR duplicated it rather than exporting one:

- `pkg/vrrp/track.go:219` (the canonical original)
- `pkg/routing/monitor.go:83` (added by #2087)
- `pkg/cluster/monitor.go:501` (added by #2087)

A **sibling of the same bug class** was left un-fixed in a different HA
path: `checkVIPReadinessForConfig` in `pkg/daemon/daemon_ha_vip.go:80-81`
still uses the buggy disjunction:

```go
up := link.Attrs().OperState == netlink.OperUp ||
    link.Attrs().Flags&net.FlagUp != 0
```

This is the **takeover-readiness gate** for `no-reth-vrrp` /
`private-rg-election` mode. Real call chain:
`takeoverReadinessForRG` → `checkNoRethTakeoverReadiness` →
`checkVIPReadiness` → `checkVIPReadinessForConfig`
(`daemon_ha_vip.go:39/35/23/68`). Its docstring promises "operationally
UP," but with the OR a carrier-down VIP interface (admin-up, cable
pulled — `OperState=OperDown`, `IFF_UP` still set) is reported "up." A
node can be judged ready to take over VIPs on an interface whose cable
is unplugged. This is exactly the #2070 hazard, surfacing in the
no-reth-vrrp HA mode.

Two more **cosmetic** instances of the same OR exist (display-only, not
failover-class):

- `pkg/cluster/reth.go:158-159` (`RethController.FormatStatus`,
  `show chassis cluster`-style RETH status text).
- `pkg/grpcapi/server_cluster.go:47-48` (`RethInfo.Status` for the
  gRPC `show chassis cluster status` reth list — the de-Morgan'd form
  `OperState != OperUp && Flags&FlagUp == 0 -> "Down"`, same bug class).

Both are folded in this PR (plan reviewer B flagged that folding one
reth-status display while leaving its exact twin is inconsistent; both
are trivial reuses of the exported helper since both already import
`pkg/cluster`).

## Honest scope/value framing

This is a one-predicate correctness fix on an HA takeover gate, plus a
cosmetic display fix and a non-tautological unit test. The "win" is
correctness, not performance: a carrier-down VIP interface in
no-reth-vrrp mode is currently judged ready to host VIPs, which can let
a node with an unplugged uplink win/keep VIP ownership — a black-hole
risk. The change is a few lines plus a helper-export; no hot path, no
data-structure change, no allocation impact.

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* (Here there is no perf gain at all
— the justification is purely correctness/safety, so the relevant
PLAN-KILL trigger would instead be "the change is wrong" or "the
duplication/export choice is architecturally worse than the
alternative.")

## What's already shipped / partially batched

- #2070 / PR #2087 (`898806180`, merged in `ffb94a006`) fixed the
  interface-monitor demotion path in `pkg/routing/monitor.go` and
  `pkg/cluster/monitor.go`, plus README updates in both packages. It
  **deliberately scoped to the interface-monitor path** and left this
  VIP-readiness sibling for a follow-up — that follow-up is #2090.
- The canonical predicate is `pkg/vrrp.linkAttrsUp` (#2070-era), the
  read used by VRRP `track-interface` detection.

## Concrete design

### Reuse decision (the central design question)

The issue text says: *"reuse the existing exported helper if one is now
public, or factor a shared one — do NOT duplicate the predicate."*

Reality check: **no exported helper exists.** #2070 chose per-package
private duplication. There are now three identical private `linkAttrsUp`
funcs. Adding a fourth private copy in `pkg/daemon` would be the
path-of-least-resistance and would match #2070's own pattern, but it
directly contradicts the issue's "do NOT duplicate" instruction and
grows the copy count to four.

**Chosen approach: export the `pkg/cluster` copy once and reuse it.**

- `pkg/daemon/daemon_ha_vip.go` already imports `pkg/cluster` (line 15).
- Rename `pkg/cluster.linkAttrsUp` → **`cluster.LinkAttrsUp`** (exported)
  and update its two in-package callers (`monitor.go:267`, `:452`).
- `pkg/cluster/reth.go:158-159` (cosmetic site, same package) calls
  `LinkAttrsUp(link.Attrs())` directly — no import needed.
- `pkg/grpcapi/server_cluster.go:47-48` (cosmetic site) calls
  `cluster.LinkAttrsUp(link.Attrs())` — `pkg/grpcapi` already imports
  `pkg/cluster` (uses `cluster.RethInfo`) and `net` (stays used by
  `net.ParseIP`/`net.ParseCIDR`/`net.IP`), so zero new imports.
- `pkg/daemon/daemon_ha_vip.go:80-81` calls
  `cluster.LinkAttrsUp(link.Attrs())`.

**Why `pkg/cluster` is the correct export owner (not `pkg/vrrp`).**
Both reviewers probed the export target. The dependency direction is
`vrrp → cluster` (`pkg/vrrp` imports `pkg/cluster` for
`cluster.SendGratuitousARPBurst`; `pkg/cluster` imports only `config` +
`dataplane`). So **`pkg/cluster` is the lower layer** and is the right
home for a shared link-state predicate — exporting from the lowest
sensible layer maximizes reuse without inverting dependencies or
risking an import cycle. Exporting from `pkg/vrrp` (the canonical
*original*) would be worse: it is the higher layer, and the two new
cosmetic consumers (`pkg/cluster/reth.go`, `pkg/grpcapi`) would then
need to depend on `vrrp` (and `pkg/cluster` importing `pkg/vrrp` would
create a cycle). It would also touch the just-merged #2070 `vrrp` file.
"daemon already imports it" does not discriminate (daemon imports both
cluster and vrrp); the discriminators are the layering direction + the
free in-package cosmetic fold + minimal blast radius onto just-merged
code. `pkg/cluster` wins on all three.

This removes the daemon-site duplication entirely (the daemon reuses an
exported helper), fixes the cosmetic site by reusing the same helper in
its own package, and adds zero new copies. Net copy count after:

- `cluster.LinkAttrsUp` (now exported, used by cluster/monitor.go,
  cluster/reth.go, daemon/daemon_ha_vip.go)
- `routing.linkAttrsUp` (unchanged — out of scope, just-merged #2070)
- `vrrp.linkAttrsUp` (unchanged — canonical original, out of scope)

So 3 copies → still 3 copies, but the **new** consumer (daemon) does not
add a copy, and the cosmetic site is de-duplicated within its package.

**Rejected alternative A — add a 4th private copy in pkg/daemon.**
Simplest diff, matches #2070 pattern, but violates the issue's explicit
"do NOT duplicate" and worsens the copy sprawl. Rejected.

**Rejected alternative B — create a new shared `pkg/netutil`
(or similar) and migrate all four packages.** Cleanest end-state (one
true copy), but it touches `pkg/vrrp` and `pkg/routing` which both just
merged via #2070, materially widening blast radius on an HA-critical
path for a follow-up bug fix. Higher regression risk than the value
justifies. Deferred to "out of scope" as a possible future cleanup.

### The actual fix

`pkg/daemon/daemon_ha_vip.go:80-81`, replace:

```go
up := link.Attrs().OperState == netlink.OperUp ||
    link.Attrs().Flags&net.FlagUp != 0
if !up {
```

with:

```go
up := cluster.LinkAttrsUp(link.Attrs())
if !up {
```

(`net` import in daemon_ha_vip.go stays — it is used elsewhere in the
file: `net.FlagUp` is removed here but `net.IP`, `net.ParseCIDR`,
`net.IPNet`, `net.HardwareAddr` etc. are used throughout. Will verify
with `goimports`/build that no import becomes unused.)

`pkg/cluster/monitor.go`: rename func + two call sites:

```go
func LinkAttrsUp(attrs *netlink.LinkAttrs) bool { ... }   // was linkAttrsUp
...
up := LinkAttrsUp(link.Attrs())   // monitor.go:267
up := LinkAttrsUp(link.Attrs())   // monitor.go:452
```

`pkg/cluster/reth.go:158-163`, replace:

```go
if link.Attrs().OperState == netlink.OperUp ||
    link.Attrs().Flags&net.FlagUp != 0 {
    status = "up"
} else {
    status = "down"
}
```

with:

```go
if LinkAttrsUp(link.Attrs()) {
    status = "up"
} else {
    status = "down"
}
```

(`net` import in reth.go stays — used by `net.HardwareAddr` /
`net.IP` in the MAC helpers above. Verify with build.)

`pkg/grpcapi/server_cluster.go:47-48`, replace:

```go
if err != nil || (link.Attrs().OperState != netlink.OperUp &&
    link.Attrs().Flags&net.FlagUp == 0) {
    status = "Down"
}
```

with:

```go
if err != nil || !cluster.LinkAttrsUp(link.Attrs()) {
    status = "Down"
}
```

(`net` import stays — `net.ParseIP`/`net.ParseCIDR`/`net.IP` used
elsewhere. `cluster` already imported for `cluster.RethInfo`.)

### Docstring + README update

- Update the `checkVIPReadiness` / `checkVIPReadinessForConfig`
  docstrings to state explicitly that readiness now means **operational
  carrier UP** (not admin IFF_UP), mirroring #2070.
- Update the exported `LinkAttrsUp` godoc to note it is the shared
  carrier-state read for the cluster package, the daemon VIP-readiness
  gate, and the reth-status display.
- **`pkg/cluster/README.md:96-103`** names `linkAttrsUp` by name and
  enumerates its callers (doc-contract per CLAUDE.md). Update it for the
  exported name `LinkAttrsUp` and the new consumers (daemon
  VIP-readiness gate, reth-status displays in `reth.go` + `grpcapi`).

## Public API preservation

- `checkVIPReadiness(rgID int) (bool, []string)` — unchanged signature.
- `checkVIPReadinessForConfig(cfg, rgID, linkByName) (bool, []string)` —
  unchanged signature; only the per-interface up/down decision changes.
- `checkNoRethTakeoverReadiness`, `takeoverReadinessForRG` — unchanged.
- `RethController.FormatStatus() string` — unchanged signature; only the
  displayed up/down string changes for carrier-down-but-admin-up links.
- **New exported symbol:** `cluster.LinkAttrsUp(*netlink.LinkAttrs) bool`
  (was private `linkAttrsUp`). Additive; no existing caller breaks
  (rename of the private symbol is internal to pkg/cluster, the
  exported name is new surface).

## Hidden invariants the change must preserve

1. **OperUnknown fallback — load-bearing for VLAN sub-interfaces, not
   just exotic virtual devices.** Reviewer A grounded that
   `vrrp.RethVIPsForRG` (the map this gate iterates) does NOT return the
   `reth0` device — it resolves to the **physical member** via
   `RethToPhysical()`+`LinuxIfName`, and for VLAN-tagged reths it returns
   **VLAN sub-interface names** (`<member>.50`, `<member>.80` —
   `vrrp/vrrp.go:223-227`). On the loss cluster reth0 IS VLAN-tagged
   (reth0.50/reth0.80). Linux 802.1Q VLAN devices frequently report
   `OperUnknown` (no independent carrier; OPERSTATE follows the parent
   only when LowerLayerDown propagates). So the `OperUnknown → IFF_UP`
   fallback is genuinely load-bearing for the common case, and
   `LinkAttrsUp` preserves it exactly. The existing test
   `TestCheckVIPReadiness_InterfaceUpViaFlags` currently uses
   `OperDown + FlagUp` — that case is precisely the bug, so that test
   MUST flip to expect NOT-ready, and a NEW `OperUnknown + FlagUp` test
   must assert ready (to lock the VLAN-sub-interface fallback).
2. **No-VIP / wrong-RG short-circuits.** `len(vipMap)==0 → ready`,
   interface-not-found → reason+continue. Unchanged — only the up
   decision inside the loop changes.
3. **Reason strings.** "vip interface %s down" / "not found" preserved
   for downstream readiness-reason display.
4. **Cosmetic site semantics.** `FormatStatus` and the grpcapi
   `RethInfo.Status` string sets ("up"/"down"/"missing" and "Up"/"Down"
   respectively) are unchanged; only which links map to up vs down for
   the carrier-down-admin-up edge changes (now correctly down).
5. **No behavioral change for OperUp links** (the common healthy case):
   both old OR and new helper return up. Only the
   `OperDown/LowerLayerDown + IFF_UP` edge flips.
6. **Locking.** `RethController.FormatStatus` already holds `rc.mu`;
   `LinkAttrsUp` is a pure function over a passed-in attrs struct —
   no new locking, no netlink call inside the helper.
7. **The gate is promotion-only — it never demotes a primary, so the
   absence of dampening on this path is benign.** (Reviewer B
   investigated the dampening asymmetry as the most likely defect and
   resolved it as benign.) `checkVIPReadinessForConfig` feeds
   `takeoverReadinessForRG` → RG readiness → the cluster election. Every
   readiness-gated transition in `pkg/cluster/election.go` is
   `electLocalPrimary` guarded by `rg.State != StatePrimary`
   (election.go:109/118/140/152/163/173). So a carrier flap on a reth
   member, even though this gate is undampened (re-evaluated every 2s in
   `reconcileRGStateLoop`, unlike the dampened interface-monitor path),
   only flips a *secondary*'s promotion-eligibility — it cannot demote
   an already-primary node, and VIP-add/GARP is driven by `state ==
   Primary` in `applyDirectVIPOwnership`, not by the readiness boolean.
   Net effect: no VIP add/remove churn, no GARP storm; the fix correctly
   prevents *promoting* a node onto a dead-carrier link (the black hole)
   without any flap side-effect. This change does NOT alter
   carrier-down-primary handling (a separate, larger design question
   not in scope and not regressed here).

## Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | LOW | One predicate narrows from OR to carrier-aware. Healthy (OperUp) and virtual (OperUnknown) links unchanged. Only the carrier-down-admin-up edge flips — which is the bug. |
| Lifetime / borrow (Go: nil/import) | LOW | Pure function; passed-in `*netlink.LinkAttrs`. Risk is only an unused `net` import after removing `net.FlagUp` — caught at build. |
| Performance regression | NONE | Slow-path readiness gate + display path; one function call. |
| Architectural mismatch (#961 / #946 Phase 2 dead-end) | LOW | Not a new architecture — reuses the #2070 predicate. The only architectural decision is duplicate-vs-export; export chosen to honor the issue and minimize copies. |

## Test plan

This is a **Go-only** change (no Rust/dataplane touch), so the cargo /
CoS-smoke matrix in the triple-review skill template does not apply.
Gates:

- `go build ./...` clean (catch unused-import regressions).
- `go vet ./pkg/daemon/... ./pkg/cluster/...`.
- **New + updated pkg/daemon unit tests** (seam-injected link attrs via
  the existing `mockLinkByName` + `testLink`), non-tautological:
  - `admin-up + carrier-down (OperDown, FlagUp)` → **NOT ready**
    (this is the regression case; it FAILS against pre-fix code — the
    pre-fix OR returns ready).
  - `admin-up + carrier-up (OperUp, FlagUp)` → ready.
  - `admin-down (OperDown, no FlagUp)` → NOT ready.
  - `OperUnknown + FlagUp` (virtual device fallback) → ready.
  - `OperUnknown + no FlagUp` → NOT ready.
  - `OperLowerLayerDown + FlagUp` (peer link down) → NOT ready.
  - Repurpose/replace the existing
    `TestCheckVIPReadiness_InterfaceUpViaFlags` (which asserts the
    buggy behavior) — it must now assert NOT-ready for OperDown+FlagUp,
    and a separate test covers the OperUnknown fallback that the old
    test name was conflating.
  - Keep `mockLinkByName`/`testLink` usable for explicit-attrs cases
    (the existing `newTestLink` only sets OperUp/OperDown without
    Flags; add explicit-attrs construction where needed, as the
    existing `TestCheckVIPReadiness_InterfaceUpViaFlags` already does).
- `go test ./pkg/daemon/... ./pkg/cluster/... ./pkg/routing/...
  ./pkg/grpcapi/...` pass (grpcapi added — third cosmetic site lives
  there; `reth_test.go:95/108` FormatStatus tests confirm the fold).
- 5× flake check on the most-affected named daemon test.
- `go test ./...` (full Go suite, 30+ packages) pass.

### Lab-gap note (must appear in the PR body)

This is **failover-class**, but the `no-reth-vrrp` /
`private-rg-election` path that `checkVIPReadinessForConfig` gates is
**NOT exercised by `make test-failover`** (which uses RETH VRRP), and
the loss userspace cluster carries **no no-reth-vrrp config**. So the
carrier-loss takeover scenario for this specific gate **cannot be
smoke-tested in the lab.** Compensated by the seam-injected unit tests
above (admin-up+carrier-down → NOT ready proves the fix; the test fails
pre-fix). The cosmetic `reth.go` change is display-only. The
RETH-VRRP failover path is unaffected by this change, so a
`make test-failover` run would only prove non-regression of an
unrelated path; it will be noted as not-run-because-not-applicable
unless reviewers insist.

## Out of scope (explicitly)

- Migrating `pkg/vrrp` and `pkg/routing` to the exported
  `cluster.LinkAttrsUp` (or a new `pkg/netutil`) — would widen blast
  radius onto the just-merged #2070 paths. Possible future cleanup; not
  this PR.
- `pkg/daemon/daemon_run.go:986` (SNMP `ifOperStatus`) and the
  `pkg/cli/cli_show_interfaces.go` / `pkg/grpcapi` display reads — those
  are SNMP/display reporters with their own semantics (SNMP maps
  OperUnknown→up by design), not readiness gates. Not in scope.
- Any change to the readiness-reason string format or the
  `takeoverReadinessForRG` composition.

## Resolved by plan review (round 1 — both reviewers PLAN-NEEDS-MINOR)

Two independent hostile Claude reviewers verified every claim against
source. No BLOCKER/MAJOR/KILL. Resolutions folded into v2:

- **Export target (OQ1):** `pkg/cluster` is the correct owner — it is
  the lower layer (`vrrp → cluster`), so exporting there avoids a cycle
  and minimizes blast radius onto just-merged #2070 code. Justification
  rewritten to lead with the dependency direction (above).
- **Dampening asymmetry (the suspected BLOCKER):** RESOLVED benign — the
  gate is promotion-only and never demotes a primary
  (election.go:109/118/140/…); invariant #7 added.
- **Third display sibling:** `grpcapi/server_cluster.go:47-48` found and
  FOLDED (was inconsistent to fix reth.go's twin but not this one).
- **VLAN-sub-interface OperUnknown:** the gate queries VLAN sub-interface
  names (`vrrp/vrrp.go:223-227`), which commonly report OperUnknown — the
  fallback is load-bearing; invariant #1 strengthened, test added.
- **README doc-contract:** `pkg/cluster/README.md:96-103` names
  `linkAttrsUp` — added to scope.
- **FormatStatus tests:** `reth_test.go:95/108` both run with
  `nlHandle: nil` → the "unknown" branch, never asserting "up"/"down";
  cosmetic fold verified safe.
- **Import hygiene:** verified `net` stays used in all three edited files
  (daemon_ha_vip.go, reth.go, grpcapi/server_cluster.go).
- **Non-tautology:** pre-fix OR returns ready for `OperDown+FlagUp`; the
  new "NOT ready" assertion genuinely fails pre-fix.

## Open questions for adversarial review (round 1, now answered above)

1. **Export vs 4th private copy vs new shared package.** Is exporting
   `cluster.LinkAttrsUp` and having `pkg/daemon` depend on `pkg/cluster`
   for it the right call, given #2070 chose per-package duplication? Is
   there a layering concern with `pkg/daemon` reaching into `pkg/cluster`
   for a link-state predicate (daemon already imports cluster, so no new
   dependency edge — but is it the *right* package to own the exported
   helper, vs `pkg/vrrp` which holds the canonical original)? Would a
   reviewer prefer exporting `vrrp.LinkAttrsUp` instead (daemon also
   already imports vrrp)? PLAN-KILL if the export target is wrong enough
   to matter.
2. **OperUnknown fallback on real VIP interfaces.** On the loss cluster
   the RETH members are mlx5 VFs (real carrier → OperUp/OperDown). But
   could a legitimately-up VIP interface ever report `OperUnknown`
   (e.g. an IPVLAN/veth-backed reth in some deployment) such that the
   narrowing would wrongly judge it down? The helper keeps the
   OperUnknown→IFF_UP fallback, so this should be safe — confirm the
   reasoning holds for every interface type that can carry a reth VIP.
3. **Does narrowing this gate introduce a NEW black-hole / split-brain
   risk?** Before: carrier-down node judged ready (can take VIPs on a
   dead link → black hole). After: carrier-down node judged NOT ready
   (won't take VIPs). Is there any scenario where "not ready due to
   carrier-down" is *worse* — e.g. both nodes carrier-down transiently
   at boot, so neither takes VIPs? (Note: before the fix, both would
   have wrongly taken them — arguably also bad. Is no-VIP safer than
   black-hole-VIP here?)
4. **Test non-tautology.** Confirm the `admin-up+carrier-down → NOT
   ready` test genuinely fails against the current pre-fix code (it
   must: the pre-fix OR returns ready for OperDown+FlagUp). And confirm
   removing/repurposing `TestCheckVIPReadiness_InterfaceUpViaFlags`
   doesn't drop coverage of the OperUnknown fallback (a new test must
   pick that up).
5. **Cosmetic fold safety.** Is folding `reth.go:158-159` into the same
   change safe, or does `show chassis cluster` consumers / any test
   assert the OLD "up if admin-up" string? Check for golden-output
   tests on FormatStatus. PLAN-KILL the cosmetic fold (not the whole
   plan) if it has hidden coupling.
6. **Lab-gap honesty.** Is the "cannot smoke-test no-reth-vrrp in the
   lab" claim accurate, or is there a config/path that *could* exercise
   it (e.g. standing up a no-reth-vrrp config on the standalone VM)? If
   a reasonable lab exercise exists, reviewers should say so.
