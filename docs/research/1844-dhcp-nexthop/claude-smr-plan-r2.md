# Claude SMR plan-review — #1844 round 2

Reviewed plan v2 (`plan.md` @ cbe5a001b). Re-verified every round-1
fold against the code and hostile-checked the folds for NEW holes.

## Verdict: PLAN-READY

## Fold verification

- **Fire sites (r1-1, convergent):** §4.3 now names commitLease
  (gateway delta) + finishClient (unconditional, post-unlock) and
  cites Codex's cancel-mid-exchange counterexample; the
  `removeLeaseAndNotify` design is gone. Matches
  `pkg/dhcp/dhcp.go:251` (defer) and `:274-305` (cleanup owner). The
  Renew sequence (cancel → finishClient fire → Start → commitLease
  fire) coalesces in the engine debounce — no new hazard.
- **Constructor-arg hook (AGY r1-2):** §4.3 + §6 specify the third
  `dhcp.New` parameter and the nil-guarded closure; single in-tree
  caller (`daemon_dhcp.go:119`). No setter, no published-pointer race.
- **Publish/bump contract (Codex r1-2):** verified safe in ALL
  orderings against `manager.go:806-870`: `lastSnapshotHash` is
  updated ONLY after a successful `requestLocked`
  (`manager.go:863-866`), so a failed publish cannot poison the
  duplicate-skip and a retry is never falsely reported as skipped.
  The remaining nil-without-publish early returns (no published
  snapshot yet — overlay cached for the next full apply; helper proc
  absent) correctly map to `published=false`: with no helper/snapshot
  there are no cached flow routes to invalidate, and the next full
  apply carries the overlay AND its own invalidation. One textual
  clarification folded into §4.3 in this round (the contract must say
  `published=false` covers those early returns too, so an implementer
  does not "fix" them to true).
- **Spelling/normalization, mgmt rejection, type fix, RFC 2131 note,
  UnresolvedRoutes, gauge purity, bounded-blocking wording:** all
  present in §4.1/§4.2/§4.3/§4.5/§7; consistent with
  `types_interfaces.go:44` (`InterfaceUnit`), `daemon_flow.go:31-33`
  (mgmt exclusion precedent).

## New-hole hunt (negative results)

- Bump-skip vs. full apply interleaving: a full apply that changes
  routes goes through its own snapshot publish + (existing) apply-path
  invalidation; the actuator's skip decision is keyed on the SAME
  `lastSnapshotHash` bookkeeping under `m.mu` — no window where the
  actuator skips against a hash the helper never acked.
- finishClient fires while Reconcile holds nothing (`stops` are
  processed after `m.mu.Unlock` in Reconcile; the fire itself is in
  the client goroutine post-unlock) — lock order holds.
- Constructor change: `dhcp.New` callers = `daemon_dhcp.go:119` +
  package tests; mechanical.

No remaining findings. PLAN-READY.
