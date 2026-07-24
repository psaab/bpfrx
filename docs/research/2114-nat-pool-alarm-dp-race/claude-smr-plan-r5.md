# Claude SMR — HOSTILE plan review r5 — #2114 residual

Reviewer: Claude (kimi-k3, in-conversation SMR pass).
Plan under review: `docs/research/2114-nat-pool-alarm-dp-race/plan.md` v5 @
`ee5f54484`. External r5 inputs: Codex NEEDS-REVISION (2 MAJOR, 4 MINOR;
fold ledger 3 FOLDED, 3 PARTIAL); AGY **PLAN-READY** (0 MAJOR, 1 MINOR
prose note on the link-(iv) wording).

**VERDICT: NEEDS-REVISION** (1 BLOCKER, 2 MAJOR, 3 MINOR). Codex's r5 M1 is
the single most consequential catch of this review cycle: the RACE-3 audit
exposed a PRE-EXISTING startup-ordering defect (a nil-deref panic path that
exists on master TODAY) that the atomic cell cannot fix. I verified all of
it against source. AGY's PLAN-READY missed it; my r4 SMR missed it (I
traced the `d.dp` chain but not the apply tail's manager dependencies) —
owning both.

## BLOCKER

### B1. The recovered confirm timer can run the apply path against UNINITIALIZED daemon state (Codex r5 M1 — verified; requires a startup-readiness gate)
Verified end-to-end:
1. The rollback executor is registered before startup phases
   (`daemon_run.go:129-136`); `Store.Load` re-arms the timer with an
   arbitrarily short remaining window (`store_persist.go:251`); it can fire
   as soon as `Store.Load` releases `s.mu` — BEFORE phase-2 `initManagers`.
2. A NON-first rollback runs the full `applyConfigLocked`
   (`daemon_apply_commit.go:697`), whose tail UNCONDITIONALLY calls
   `d.vrrpMgr.UpdateInstances` (`daemon_apply_tail.go:49`) — but
   `d.vrrpMgr` is constructed at `daemon_run_bringup.go:219`. Timer fires
   early ⇒ nil-pointer dereference ⇒ daemon panic on boot. This exists on
   master today, independent of `d.dp`.
3. The first-commit branch has the bootstrap-armed interleaving: boot reads
   `d.inBootstrap()` at `daemon_run_bringup.go:490`; the timer's
   `enterBootstrapMode` (`bootstrap.go:322` Store(true)) + `Teardown`
   (`bootstrap.go:472`) can land between the :490 check and the :494
   `d.dp.Start(d.daemonCtx)` — bootstrap mode with the dataplane ARMED.
The atomic cell fixes neither — this is a DISPATCH-ORDERING defect, not a
memory-model one. v6 adds a companion work item (small, in-scope per issue
requirement #4's "don't ship another per-monitor patch"):

**Startup-readiness gate for the rollback executor.** New
`d.startupReady chan struct{}` (closed at the END of the startup phases —
after the boot apply, before PHASE 6). `executeConfirmedRollback` FIRST
waits on `startupReady` (select with `d.daemonCtx.Done()` — a shutdown
during startup abandons the dispatch; the persisted confirm record is
handled by the next boot's expired-window path at `store_persist.go:225`),
ONLY THEN takes `d.applySem` and proceeds. Gate-BEFORE-applySem is
mandatory: the boot apply holds applySem, so gating while holding it would
deadlock startup. Effects: the nil-deref dies (all managers exist before
dispatch), the bootstrap-armed interleaving dies (the rollback runs only
after the boot settled bootstrap-vs-normal), and the timer-vs-boot-writer
`d.dp` race is eliminated by ORDER, not just by the cell (the cell remains
the issue-required uniform mechanism + defense for RACE-1/RACE-2/future
writers). Store-internal fallback (`performAutoRollback`) is untouched —
it is store-state-only, no daemon managers.

Test changes: the v5 `TestDataplaneCell_ConfirmTimerVsBootPublication`
pivots — (a) gate test: with `startupReady` open, a fired
`executeConfirmedRollback` must BLOCK (assert no rollback side effects);
close it, assert the rollback proceeds; (b) the two-sided-gate cell test
keeps a post-startup shape (concurrent applySem-holding reader vs
`setDataplane` churn — revert-guard); (c) an ordering test driving the REAL
recovered-timer path (stubbed store record) against a real startup
sequence asserting dispatch lands only after `startupReady`.

## MAJOR

### M1. RACE-3 reachability must extend to the WHOLE apply pipeline — and collapses back once the gate lands (Codex r5 M2, verified)
A non-first rollback traverses `daemon_apply_interfaces.go:42`,
`daemon_apply_tail.go:491`, `daemon_apply_routing.go:367`, the scheduler,
ipmon, policy-invalidate — every APPLY-class row, not just the two v5
annotated. v6 states in the §5.4 preamble: every APPLY row is additionally
timer-path-reachable PRE-gate; POST-gate all timer dispatch is ordered
after startup, so the rows collapse to plain APPLY-serialized, with the
cell as uniform defense. The RACE-3 annotation stays on
`bootstrap.go:472,473` and the `daemon_apply_dataplane.go` rows as the
canonical documentation of the pre-gate defect the gate closes.

### M2. Prose contradictions + citation corrections (Codex r5 MINOR 2, verified)
- `plan.md:71` "the ONLY pre-publication reader chain" contradicts RACE-3's
  timer chain — reword to scope it (cluster-side chains; the timer chain is
  documented separately).
- `plan.md:387` "everything else is uniformity-only" must exempt the
  RACE-3-annotated rows.
- Citations: executor registration `daemon_run.go:136`; timer re-arm
  `store_persist.go:251`; executor invocation `store_commit.go:819`; chain
  A promotion call `daemon_ha.go:311` (`:310` is the condition).

## MINOR

### m1. Stream `:67` is mixed standalone/HA and RACE-2-reachable (Codex r5 MINOR 1, verified)
Standalone launcher `daemon_run.go:365-369`: if `d.dp` is cleared before
the `:122` provider assertion fails, the fallback calls
`syncUserspaceSessionDeltas` (`:125`), which reads `d.dp` at `:67` BEFORE
checking `d.cluster == nil` at `:68`. Row corrected to
capture-once/mixed/RACE-2.

### m2. Legacy confirm records (Codex r5 MINOR 3 + AGY r5 MINOR 1 — same neighborhood, fold both)
`store_persist.go:149` accepts persisted confirm records without the modern
GuardedHash generation binding and applies no topology preflight. Scope the
four-link exclusion's premise to current-version guards, and note the
containment argument that survives legacy records: a never-committed marker
and a committed cluster config cannot coexist in one store, so
`enterBootstrapMode` (prevCfg==nil) with a live cluster runtime stays
unreachable even for legacy records; a legacy first-commit CLUSTER record
implies the cluster config WAS committed (pre-#5840 code allowed it),
making the node ever-committed ⇒ prevCfg != nil ⇒ the non-first rollback
path, not `enterBootstrapMode`.

### m3. Stale-citation sweep (Codex r5 MINOR 4, verified)
Add `pkg/daemon/cluster_identity_preflight_6192_test.go:27` and
`docs/ha-no-hitless-restart.md:85,130` (copied stale `daemon_run.go:1868`
cites).

## Disposition required for v6

1. Add the startup-readiness gate companion work item (B1) with the
   gate-before-applySem design, abandonment-on-shutdown rule, and the
   pivoted test trio.
2. Extend RACE-3 reachability to the whole apply pipeline with the
   pre/post-gate semantics stated (M1).
3. Prose/citation fixes (M2); stream `:67` row (m1); legacy-record scoping
   prose (m2); two more sweep entries (m3).
4. New open question for r6: keep the readiness gate IN this PR (my
   recommendation — small, required for a coherent RACE-3 story, and
   leaving a known boot-panic would fail issue requirement #4's spirit) vs
   split to a follow-up issue.
