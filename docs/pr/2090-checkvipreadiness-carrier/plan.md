# #2090 — `checkVIPReadinessForConfig` carrier-aware readiness (sibling of #2070)

**Status:** DRAFT v1 — pending adversarial plan review

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

A second, **cosmetic** instance of the same OR lives at
`pkg/cluster/reth.go:158-159` (`RethController.FormatStatus`,
display-only — `show chassis cluster`-style RETH status text). Not
failover-class; fold in opportunistically if clean.

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
- `pkg/cluster/reth.go:158-159` (the cosmetic site, same package) calls
  `LinkAttrsUp(link.Attrs())` directly — no import needed.
- `pkg/daemon/daemon_ha_vip.go:80-81` calls
  `cluster.LinkAttrsUp(link.Attrs())`.

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

### Docstring update

Update the `checkVIPReadiness` / `checkVIPReadinessForConfig` docstrings
to state explicitly that readiness now means **operational carrier UP**
(not admin IFF_UP), mirroring #2070, and update the exported
`LinkAttrsUp` godoc to note it is the shared carrier-state read for the
cluster package and the daemon VIP-readiness gate.

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

1. **OperUnknown fallback.** Virtual devices (the loss cluster's reth
   members are mlx5 VFs with real carrier; but veth/IPVLAN report
   OperUnknown) must still be judged up when admin-up. `LinkAttrsUp`
   preserves this exactly (`OperUnknown → IFF_UP`). The existing test
   `TestCheckVIPReadiness_InterfaceUpViaFlags` currently uses
   `OperDown + FlagUp` — that case is precisely the bug, so that test
   MUST flip to expect NOT-ready, and a NEW OperUnknown+FlagUp test
   must assert ready (to lock the fallback).
2. **No-VIP / wrong-RG short-circuits.** `len(vipMap)==0 → ready`,
   interface-not-found → reason+continue. Unchanged — only the up
   decision inside the loop changes.
3. **Reason strings.** "vip interface %s down" / "not found" preserved
   for downstream readiness-reason display.
4. **Cosmetic site semantics.** `FormatStatus` "up"/"down"/"missing"
   string set unchanged; only which links map to "up" vs "down" for the
   carrier-down-admin-up edge changes (now correctly "down").
5. **No behavioral change for OperUp links** (the common healthy case):
   both old OR and new helper return up. Only the
   `OperDown/LowerLayerDown + IFF_UP` edge flips.
6. **Locking.** `RethController.FormatStatus` already holds `rc.mu`;
   `LinkAttrsUp` is a pure function over a passed-in attrs struct —
   no new locking, no netlink call inside the helper.

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
- `go test ./pkg/daemon/... ./pkg/cluster/... ./pkg/routing/...` pass.
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

## Open questions for adversarial review (each invitable to PLAN-KILL)

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
