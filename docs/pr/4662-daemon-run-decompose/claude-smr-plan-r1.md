# Claude SMR — #4662 Increment 1 plan review (round 1)

**Verdict: PLAN-READY-WITH-MINOR** (safe to implement; two minor refinements).

Reviewed plan v1 (daddcfe4e) against the actual source
(pkg/daemon/daemon_run.go 1700-1858, hostile).

## Confirmed safe
1. **Local completeness.** The teardown region references exactly three
   function-scoped locals: `stop()` (1710), `wg` (1711 `wg.Wait()`), and
   `runErr` (1858 return). Every other identifier is a `d.*` field/method
   (teardownSNMP, stopFlowExporter, feeds, rpm, stopArchiveTimer, eventEngine,
   ipmon, stopAndDiscardNATPoolAlarm, frr, lldpMgr, store, dp, ra, isNoRethVRRP,
   directRemoveVIPs, vrrpMgr, cluster, sessionSync, stopSyncReadyTimer,
   restoreStep0TunablesOnShutdown, applyCancel) or declared WITHIN the region
   (`cfg`/`haMode`/`hitless` at 1770-1774, `shutdownCtx`/`cancel` at 1781).
   Signature `runShutdownSequence(wg *sync.WaitGroup, stop func(), runErr error)
   error` is complete and correct.
2. **`cfg` is region-local, not the outer config.** Line 1770 re-reads
   `d.store.ActiveConfig()` fresh; the extraction does NOT need the outer `cfg`
   loaded at Run() top. Clean cut.
3. **Defer analysis correct.** The only defer in the region is `defer cancel()`
   at 1782, and `shutdownCtx` is consumed only in the loop at 1783-1796 (done
   before 1858). Firing at helper-return vs Run-return is unobservable —
   behaviorally equivalent, as the plan states.
4. **wg by pointer necessary.** A value param would fail `go vet`
   (copying sync.WaitGroup) and `Wait()` a copy — the plan's `*sync.WaitGroup`
   is the only correct form. Background goroutines capture the same `wg` via
   closure; `&wg` aliases it.
5. **Double-stop idempotent.** Explicit `stop()` (1710) + Run's `defer stop()`
   is a documented-idempotent signal-context stop; unchanged by the extraction.

## Minor refinements (address at implement time)
- **M1 — region start.** The true teardown boundary is ~1700 (the
  `if d.applyCancel != nil { d.applyCancel() }` block at 1705-1707 + its
  comment), not 1709. Include it so the extracted method owns the COMPLETE
  teardown. Does not change the param list (`d.applyCancel` is a field). The
  implementer must confirm the main-block/wait code ends exactly before this
  comment and nothing between the wait and 1705 is left behind.
- **M2 — drop the structural test.** §5's "assert the method is called + returns
  runErr" test is low-signal. This is pure code motion; the gate is `go build`
  (proves it compiles + types line up) + the existing 30+ daemon test suite
  (proves behavior) + one `make test-failover` (proves the moved HA/VRRP/sync
  shutdown ordering still fails over). Ship Increment 1 with NO new test — the
  true-pure-code-motion posture — per project refactor discipline. (Answers Open
  Question #6: yes, no new test.)

## Scope
157-line tail extract is the right Increment 1: it is the ONLY defer-clean,
low-local-coupling phase. Deferring Phases 1-6 is correct — they thread
cfg/activeCfg/userspaceDP/er/eventBuf/wg and interleave the stop/applyCancel
defer declarations, so they need a phase-context design decision (a later
/triple-review). Do NOT bundle; each increment is independently provable.

## Not a KILL
The maintainability win (a reviewable teardown method vs an un-reviewable 1691-
line function) is real and the change is genuinely zero-behavior pure motion.
No architectural premise to fail.
