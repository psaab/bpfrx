# #1706 — Fix four latent routing-correctness defects in pkg/routing

Status: v2 — PLAN-READY (Codex PLAN-NEEDS-MAJOR on silent truncation
addressed by adding commit-time warnings; AGY PLAN-READY all four;
defect 1 reframed as robustness cleanup per both reviewers)

## Adversarial plan review outcome (round 1, commit d90bc3523)

- **Codex** (isolated session): Defect 2 PLAN-READY; Defect 1 PLAN-KILL
  *as a correctness defect* (benign in prod via ensureIndex name
  re-resolution) — demote to optional robustness cleanup; Defect 3/4
  math+placement correct but PLAN-NEEDS-MAJOR because the apply-time cap
  silently truncates an over-limit config that still commits cleanly —
  wants commit-time rejection OR explicit acceptance of the Junos
  divergence.
- **AGY**: all four PLAN-READY. Confirmed defect-1 benign-but-fix-worthy
  (ensureIndex patches only Index, not other LinkAttrs; reassignment
  cleaner than relying on the library fallback; `existingTun.Fds` nil →
  closeTuntapFiles safe no-op). Confirmed defect-2 panic 100% real.
  Confirmed defect-4 boundary math exact (50th table → 33098/33099;
  51st rejected). All four config paths reachable.

### Resolution applied in v2

- **Defect 1**: KEEP the fix but reframe as a robustness/clarity cleanup,
  not a production correctness bug (honest framing per both reviewers).
- **Defect 3/4 (Codex NEEDS-MAJOR)**: add commit-time warnings in
  `config.ValidateConfig` that fire when the raw config exceeds the
  programmable window (>100 next-table routes; >50 rib-group-leaking
  instances). These are CONSERVATIVE UPPER BOUNDS computed from the same
  inputs the applier consumes (global+inet6 static routes with NextTable
  set; instances referencing a non-empty interface-routes rib-group),
  so they never miss a real truncation, and they do NOT replicate the
  applier's exact dedup/skip logic (avoiding validator/applier drift).
  The apply-time hard cap stays as defense-in-depth against the
  permanent rule leak. This is a fifth commit.

## Issue framing

#1705 (the #1698 routing.go per-domain split) review surfaced four
latent correctness defects. All four are verbatim-identical to the
pre-split `routing.go` on master — #1698/#1705 were behavior-preserving
motion and deliberately left them unchanged. #1706 is the focused
follow-up that fixes them. They are cohesive (one package, surfaced
together) and ship as ONE PR, four logical-increment commits.

This is a correctness bug-fix, not a refactor or a perf change. PLAN-KILL
of an individual defect is acceptable if it turns out not to be real;
each has been verified end-to-end against the worktree source below.

## Defect verification (read end-to-end against the worktree)

### Defect 1 — TUN anchor reuse operates on a fresh ifindex-less link
`tunnelManager.Apply`, `pkg/routing/tunnel.go:110-168`.

When `tc.AnchorOnly` and the anchor already exists as a TUN, the code:
```go
anchor := &netlink.Tuntap{ LinkAttrs: netlink.LinkAttrs{Name: tc.Name}, ... } // :111
if err := t.ops.LinkAdd(anchor); err != nil {                                 // :118
    if existing, lookupErr := t.ops.LinkByName(tc.Name); lookupErr == nil {   // :122
        if _, isTun := existing.(*netlink.Tuntap); isTun {
            goto anchorReady                                                   // :126
        }
        ...
    }
}
anchorReady:
closeTuntapFiles(anchor.Fds)              // :143  uses fresh `anchor`
if err := t.ops.LinkSetUp(anchor); ...    // :144  uses fresh `anchor` (no ifindex)
    ... t.ops.AddrAdd(anchor, addr) ...    // :155  uses fresh `anchor`
```
On the reuse path `existing` (which HAS an ifindex from the kernel) is
discarded; `LinkSetUp`/`AddrAdd` run against the freshly-constructed
`anchor` whose `LinkAttrs.Index == 0`. With the real netlink handle,
`LinkSetUp`/`AddrAdd` resolve by ifindex when set, falling back to name
only when index==0 — but the anchor was never populated from the kernel,
so its attrs (flags, etc.) are stale and the operation targets a
zero-index link. The retry/replace arm (`:131`) correctly re-adds into
`anchor`, so only the `goto anchorReady` reuse arm is wrong.

SEVERITY CAVEAT (verified against vishvananda/netlink v1.3.1):
`Handle.LinkSetUp` (link_linux.go:391) and `Handle.addrHandle`
(addr_linux.go:83, reached by AddrAdd) BOTH call `h.ensureIndex(base)`,
which, when `base.Index == 0`, re-resolves the index via
`LinkByName(base.Name)` (link_linux.go:77-83). The fresh `anchor` DOES
carry `LinkAttrs{Name: tc.Name}`, so in production the index is
re-resolved by name before the op fires — the operation targets the
correct kernel link despite the zero index. Therefore defect 1 is
**largely benign in production today**: it relies on the netlink
library's implicit name re-resolution rather than being outright broken.

The fix is still warranted as a correctness/robustness improvement:
(a) it removes the dependency on an undocumented library fallback;
(b) the fresh anchor carries stale/default LinkAttrs (flags, etc.) that
ensureIndex does NOT refresh — only Index is patched — so any future op
reading other attrs off `anchor` would be wrong; (c) it matches the
replace arm which already operates on a properly-populated link.

If reviewers judge the benign-in-production reality means the churn
isn't justified, PLAN-KILL of defect 1 is acceptable and the PR ships
the other three.

Fix: on the reuse arm, assign the existing link before the goto:
```go
if existingTun, isTun := existing.(*netlink.Tuntap); isTun {
    slog.Info("tunnel anchor already exists as TUN, reusing", "name", tc.Name)
    anchor = existingTun
    goto anchorReady
}
```
`anchor` is `*netlink.Tuntap`, `existing` is `netlink.Link`; the type
assert already in the branch yields the concrete `*netlink.Tuntap`.
`closeTuntapFiles(anchor.Fds)` then runs against the reused link whose
`Fds` is nil (kernel-fetched link carries no fds) — harmless no-op.

### Defect 2 — xfrm double LinkByName + LinkSetUp(nil) panic risk
`xfrmManager.Apply`, `pkg/routing/xfrm.go:44-60`.
```go
if _, err := x.ops.LinkByName(ifName); err == nil {  // :44 first lookup, link discarded
    link, _ := x.ops.LinkByName(ifName)               // :45 second lookup, error ignored
    x.ops.LinkSetUp(link)                             // :46 link may be nil
    ...
}
```
If the second `LinkByName` transiently fails (EINVAL/EBUSY/etc.), `link`
is nil and `LinkSetUp(nil)` is called. With the real netlink handle this
dereferences `link.Attrs()` on a nil interface value → panic. This exact
double-call was preserved byte-identical in #1705 (pure motion).

CONFIRMED real (nil-deref panic on a transient second-lookup failure).

Fix: reuse the link from the FIRST lookup and handle its error:
```go
if link, err := x.ops.LinkByName(ifName); err == nil {
    if upErr := x.ops.LinkSetUp(link); upErr != nil {
        slog.Warn("failed to bring up existing xfrmi", "name", ifName, "err", upErr)
    }
    slog.Debug("xfrmi already exists", "name", ifName, "if_id", ifID)
    ... track ...
    continue
}
```
Single lookup, no second call, no nil passed to LinkSetUp.

### Defect 3 — next-table ip-rule priority can escape the cleared range
`nextTableManager.Apply` + `clear`, `pkg/routing/rules.go:50-121`.

`prio` starts at `nextTableRulePriority` (100), `prio++` once per
programmed route (`:99`). `clear()` only deletes
`[nextTableRulePriority, nextTableRulePriority+100)` = `[100,200)`
(`:112`). So the 101st next-table route programs prio 200, which lands
OUTSIDE the cleared window and leaks permanently across re-applies.

CONFIRMED real. The PBR manager already models the right fix
(`rules.go:326-329`): cap with a warning and stop.

Fix: cap inside the loop, mirroring PBR's pattern. Guard BEFORE the
RuleAdd (so we never program an out-of-range rule):
```go
if prio >= nextTableRulePriority+100 {
    slog.Warn("next-table rule limit reached; ignoring further next-table routes",
        "limit", 100, "destination", sr.Destination)
    break
}
```
Placed after the per-route skip/validation checks, immediately before
`rule := netlink.NewRule()` so only admit-able routes count against the
cap (matches PBR semantics where `prio++` only fires on a real add).

### Defect 4 — rib-group ip-rule priority can escape the cleared range
`ribGroupManager.Apply` + `clear`, `pkg/routing/rules.go:143-255`.

`prio` starts at `ribGroupRulePriority` (33000); each leaked source
table consumes TWO priorities (v4 `:214` then v6 `:230`). `clear()`
deletes `[33000,33100)` (`:244`). So the 51st leaking table programs
33100/33101 — outside the window — and leaks permanently.

CONFIRMED real.

Fix: cap before programming each table's pair. Because a table uses two
slots, stop when the NEXT pair would not fit (i.e. require room for both
v4 and v6 within the window):
```go
if prio+1 >= ribGroupRulePriority+100 {
    slog.Warn("rib-group rule limit reached; ignoring further leaking tables",
        "limit", 100, "instance", inst.Name, "table", sourceTable)
    break
}
```
Placed after `leakedTables[sourceTable] = true` is decided — actually
BEFORE marking the table leaked, so a capped table isn't recorded as
done (it was never programmed). Concretely: place the guard immediately
after the `if leakedTables[sourceTable] { continue }` skip and before
`leakedTables[sourceTable] = true`, so the v4+v6 pair is admitted
atomically or not at all. `prio+1 >= 33100` means the v6 slot (`prio+1`)
would be the 100th-or-beyond offset → reject the whole pair.

## Hidden invariants the change must preserve

- **Defect 1**: side-effect order (closeTuntapFiles → LinkSetUp →
  AddrAdd → VRF bind → track) is unchanged; only the link object the
  ops act on changes from fresh→existing on the reuse arm. The create
  and replace arms are untouched. `closeTuntapFiles(anchor.Fds)` stays
  correct: a kernel-fetched `*netlink.Tuntap` has nil `Fds`.
- **Defect 2**: tracking dedupe loop (`:48-58`) and `continue` are
  preserved; only the lookup count drops 2→1 and the error is handled.
  Debug log message preserved. `slog.Warn` on bring-up failure is new
  but matches the create path's `:82-85` style (non-fatal).
- **Defect 3/4**: the cap is a hard upper bound matching the clear()
  window so every programmed rule is guaranteed inside the cleared
  range — that is exactly the invariant clear() assumes. No behavior
  change below the cap; identical rules for ≤100 next-table routes /
  ≤50 leaking tables. Mirrors the already-shipped PBR cap (1000 window).
- **Logging**: all new logs are `slog.Warn` for the cap (rare,
  one-time at config-apply) and `slog.Warn` for the xfrm bring-up
  failure — no per-packet/per-tick logging. Compliant with CLAUDE.md.

## HA assessment

rib-group / next-table leak into kernel ip-rule state, NOT into HA
session-sync or VRRP state. The managers are driven by `applyConfig`
(control-plane commit path), not by the failover hot path. No RG-owned
session table, no VRRP priority, no fabric-redirect state is touched.
Conclusion: `make test-failover` is NOT required for this change. A
light route-correctness smoke (routes/VRFs/tunnels still program +
v4/v6 connectivity) on loss:xpf-userspace-fw0 is the appropriate gate.

## Test plan

New unit tests (all hermetic, fake ops — no netlink):

- **Defect 3 cap** (`fakeRuleOps`): feed 101 next-table routes to one
  table; assert (a) ≤100 rules programmed, (b) every programmed
  priority is `< nextTableRulePriority+100`, so a subsequent clear()
  removes ALL of them (re-apply leaves count stable, no leak).
- **Defect 4 cap** (`fakeRuleOps`): feed 51 leaking instances; assert
  ≤100 rules total and every priority `< ribGroupRulePriority+100`;
  re-apply leaves no residue.
- **Boundary** for both: exactly-at-limit (100 routes / 50 tables)
  programs the full set with NO warning/break; one-over triggers the
  cap. Assert the highest programmed prio is the last in-range slot.
- **Defect 1 reuse** (new `fakeLinkOps` for linkOps): seed an existing
  `*netlink.Tuntap` with a non-zero ifindex; make LinkAdd return
  EEXIST; assert LinkSetUp/AddrAdd are invoked against the SEEDED link
  (non-zero index), not a fresh zero-index one.
- **Defect 2 single-lookup** (`fakeLinkOps`): existing xfrmi present;
  assert LinkByName called exactly ONCE on the already-exists path and
  LinkSetUp receives the non-nil seeded link; add a transient-second-
  lookup variant to prove no nil is ever passed (with the fix there is
  no second lookup to fail).

Gates:
- `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./pkg/routing/...`
  then `./...` (full Go suite). Pre-existing pkg/dataplane/userspace
  sandbox unix-socket failures are known artifacts — reproduce on clean
  master and prove pre-existing, do not be blocked.
- `make audit-check` (regen only if a pkg/routing file crosses a
  threshold — unlikely; these are small edits).
- Light route-correctness smoke on loss:xpf-userspace-fw0 (deploy +
  verify routes/VRFs/tunnels program + v4+v6 connectivity through fw).
  NOT the full CoS iperf matrix.

## Out of scope

- The PBR manager's existing 1000-window cap is already correct — no
  change. Only documenting it as the model.
- Any restructuring of the #1698 domain split. Pure correctness fixes.
- Promoting next-table/rib-group windows to larger ranges — the cap is
  the minimal correct fix; widening the window is a separate decision.

## Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Defect 1**: does the real netlink handle resolve `LinkSetUp`/
   `AddrAdd` by name when `LinkAttrs.Index==0`, making the bug benign?
   (My read: no — netlink ops key on ifindex; a zero-index fresh
   Tuntap targets ifindex 0. But if the library re-resolves by name
   internally on these calls, defect 1 may be cosmetic → PLAN-KILL it.)
2. **Defect 2**: is `LinkSetUp(nil)` actually a panic, or does the
   netlink library nil-check and return an error? If it returns an
   error gracefully, the "panic" framing is wrong though the double
   lookup is still wasteful — assess whether the fix is still warranted.
3. **Defect 3/4 cap placement**: is `break` (stop programming further)
   the right Junos-faithful behavior vs. logging-and-continuing-without-
   add? Junos would reject at commit; we cap at apply. Is silent-drop
   past the cap acceptable, or must commit-time validation reject it?
4. **Defect 4 boundary math**: is `prio+1 >= base+100` the correct
   guard for a two-slot consumer, or off-by-one (should it be
   `prio+1 > base+99`, i.e. `prio+2 > base+100`)? Verify the last
   admitted table uses slots 98+99 and the 51st (slots 100+101) is
   rejected.
5. **Defect 1 `closeTuntapFiles(anchor.Fds)`**: after reassigning
   `anchor = existingTun`, is `existingTun.Fds` guaranteed nil/empty
   (kernel-fetched link), so the close is a safe no-op? If a fetched
   Tuntap could carry live fds, the reassignment could double-close —
   verify.
6. Are any of these four actually NOT reachable in production (dead
   config path)? If a defect's trigger config can't be expressed in
   Junos syntax this firewall accepts, PLAN-KILL that defect.
