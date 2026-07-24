# Codex hostile plan-review — round 9 (plan v9 @ `27c968b45`)

Reviewer: Codex (companion task `task-mryjc32b-vc6cwg`, session
`019f92b9-8718-7663-bfcc-f125a96b436d`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications recorded in plan v10.

---

Fold verification

1. PARTIAL — The gate → startupOK → applySem → stopping order is correct for post-publication acquirers, but teardown can begin before publication and a pre-publication executor can outlast the five-second drain; pkg/daemon/daemon_run.go:741-756, pkg/daemon/daemon_run_shutdown.go:50-60, pkg/daemon/daemon_apply_commit.go:693-698.

2. FOLDED — The guard follows stale-hash rejection and expired recovery, while reusing the FirstCommit persistence, removal-debt, candidate-reset, and journal tail; pkg/configstore/store_persist.go:159-165,171-228. The sacrificed window and #4577-preserving revert are honestly documented.

3. PARTIAL — The recurrence chain is real: rollback clears everCommitted, leaves d.cluster alive, and runtime-keyed preflight admits another FirstCommit record; pkg/configstore/store_commit.go:867-908, pkg/daemon/bootstrap.go:321-478, pkg/daemon/daemon_apply_commit.go:551-570. The proposed permanent predicate is unsound, as detailed below.

4. FOLDED — Run-scoped defer d.finishStartup(false), guarded by sync.Once, safely releases waiters with startupOK=false during phase panic/unwind; docs/research/2114-nat-pool-alarm-dp-race/plan.md:335-342,392-398 and pkg/daemon/daemon_run.go:794-805.

5. FOLDED — The exhaustive set is complete: rollback_resync_test.go:31,81; bootstrap_rollback_test.go:24,74; rollback_serialize_test.go:71,150,201,247; startup_signal_5807_test.go:118,157.

6. FOLDED — The deletion inventory covers the assertion, base methods, userspace wrapper, userspaceStatusProbe, dead status helper, and retained cached-status path; pkg/daemon/daemon_forwarding_status.go:10,20-53,55-76,85-116. pkg/configstore is now listed.

7. FOLDED — The corrected semaphore rationale matches pkg/daemon/daemon_apply.go:50-51. HTTP already starts at pkg/daemon/daemon_run.go:586-589, while gRPC construction completes synchronously before startGRPCServer returns at pkg/daemon/daemon_run_servers.go:109-123,231-240.

New findings

MAJOR — stopping is published after signal-driven teardown has already begun. Run observes the already-cancelled context before entering runShutdownSequence at pkg/daemon/daemon_run.go:741-756, while gRPC and HTTP immediately start shutdown from that same context at pkg/grpcapi/server.go:486-493 and pkg/api/listener.go:64-93. During PHASE 5, servers can therefore begin shutting down before the planned finishStartup(true); that publish can release a timer which acquires applySem and observes stopping=false before PHASE 6 reaches runShutdownSequence. Its apply includes reconcileWebManagement at pkg/daemon/daemon_apply.go:208-211, so this is apply-versus-server-teardown, not ordinary request concurrency. Publication must precede service-context cancellation, or the executor must also reject the already-cancelled shutdown context under applySem.

MAJOR — The bounded drain does not cover an executor admitted immediately before stopping publication. Shutdown abandons its Acquire after five seconds and proceeds at pkg/daemon/daemon_run_shutdown.go:10-15,50-60,95-230. Confirmed rollback deliberately runs non-cancellable work through context.Background() at pkg/daemon/daemon_apply_commit.go:693-698; even its FirstCommit branch performs unbounded FRR/dataplane teardown at pkg/daemon/bootstrap.go:463-475. Thus an executor can read stopping=false, exceed five seconds, and continue against manager/dataplane teardown. The absolute invariant must either gain a real join/fence or be weakened to admit this overlap.

MAJOR — Work H predicates on raw s.active rather than effective compiled topology: docs/research/2114-nat-pool-alarm-dp-race/plan.md:483-499. Runtime cluster construction uses compiled ActiveConfig().Chassis.Cluster at pkg/configstore/store_format.go:55-60 and pkg/daemon/daemon_run_bringup.go:161-164. Compilation prunes inactive nodes and expands apply-groups at pkg/config/compiler.go:2257-2268; node-selected cluster content is demonstrated at pkg/config/parser_ast_test.go:4340-4376. A raw scan either misses inherited cluster configuration or falsely counts dormant/inactive templates. Load already has authoritative s.compiled before recovery at pkg/configstore/store_persist.go:79-113. Require s.compiled != nil && s.compiled.Chassis.Cluster != nil plus active-group and dormant/inactive negative tests.

MINOR — The shutdown-fence test manually stores d.stopping rather than driving production publication; docs/research/2114-nat-pool-alarm-dp-race/plan.md:973-980. It stays green if runShutdownSequence omits or misorders the Store. Add an actual-path ordering test following pkg/daemon/daemon_shutdown_wiring_5523_test.go:113-129.

MINOR — Recovery documentation still promises exactly two outcomes and unconditional re-arm for every future-deadline record at pkg/configstore/store_persist.go:127-135 and pkg/configstore/README.md:432-449. Work H creates a third outcome, but the docs inventory at plan.md:767-794 schedules neither update.

MINOR — stopping and startupDoneOnce are monotonic, but the single-use lifecycle is unstated. Run is exported without a one-shot guard at pkg/daemon/daemon_run.go:62-63, although production calls it once at cmd/xpfd/main.go:490-507. Document or enforce single-use; resetting stopping alone would leave the prior startup outcome published.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v10)

All 3 MAJOR + 3 MINOR code-verified before folding:

- M1 (fence published too late) VERIFIED — PHASE 6 at `daemon_run.go:
  741-752`, PHASE 7 `runShutdownSequence` at :755; gRPC `<-ctx.Done()` →
  `stopGRPCServer` (`server.go:489-491`); HTTP listener selects
  `rootCtx.Done()` (`api/listener.go:64-72`); apply touches
  `reconcileWebManagement` (`daemon_apply.go:208`). Folded as the DOUBLE
  guard: `d.stopping.Load() || d.runCtx.Err() != nil` under applySem
  (`runCtx` = Run's signal ctx stored at Run entry; `d.daemonCtx` never
  cancels per #5807). `runShutdownSequence` still publishes `stopping`
  for the interactive-exit (non-ctx) path.
- M2 (drain doesn't cover in-flight) VERIFIED —
  `applyCloseoutDrainTimeout = 5 * time.Second`
  (`daemon_run_shutdown.go:15`); timeout path proceeds with a warn
  (:54-58). Folded as invariant 11's HONEST BOUND: entry ordered
  absolutely; in-flight overlap beyond the drain is pre-existing on
  master (master has NO executor shutdown guard), admitted, not
  worsened; cancellable-apply declared out of scope.
- M3 (raw-scan predicate) VERIFIED — `ActiveConfig()` returns
  `s.compiled` (`store_format.go:55-60`); compiler prunes `inactive:`
  first + expands apply-groups (`config/compiler.go:2257-2268`);
  `s.compiled` set at `store_persist.go:111` before recovery at :113
  (compile-failed path returns at :108, never reaches recovery). Guard
  predicate now `rec.FirstCommit && s.compiled != nil &&
  s.compiled.Chassis.Cluster != nil`; tests (vi) apply-groups-positive
  and (vii) inactive-negative added.
- m1 (actual-path fence test) VERIFIED — 5523 wiring pattern exists
  (`daemon_shutdown_wiring_5523_test.go:113-129`); folded as test (d)
  leg 3.
- m2 (two-outcomes docs) VERIFIED — `store_persist.go:127-135` "Two
  outcomes:" comment; folded into §5.5 with
  `pkg/configstore/README.md:417-449`.
- m3 (single-use lifecycle) VERIFIED — Run called once
  (`cmd/xpfd/main.go:490-507`); folded as a document-only contract
  comment on the monotonic fields.

Verdict recorded: **NEEDS-REVISION (3 MAJOR, 3 MINOR)**.
