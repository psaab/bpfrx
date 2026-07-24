# Codex hostile plan-review — round 8 (plan v8 @ `9c2bc5bbd`)

Reviewer: Codex (companion task `task-mryhteof-3r6csp`, session
`019f9292-9b88-7513-b7ff-c9ea0c3a9e46`; dispatched from the worktree,
read-only). Verbatim output below; fold adjudications noted inline by the
orchestrator are recorded in plan v9.

---

Fold/verification notes

1. BROKEN — Both returned failure legs can publish false from the common `err != nil` path at pkg/daemon/daemon_run.go:823-832, but a panic at the phase call at :799 bypasses that handling, and a signal during Phase 5 reaches the planned true publication before immediately entering shutdown. Gate-before-applySem is correct, although boot holds applySem only during `applyConfig` at pkg/daemon/daemon_apply.go:49-56, called from pkg/daemon/daemon_run_bringup.go:518-520—not "across startup."

2. BROKEN — The H guard must run after stale-hash rejection and after the expired branch returns: pkg/configstore/store_persist.go:149-165 and :171-228. Running it earlier preserves an already-expired unconfirmed config, directly contradicting :172-174. Even after correct placement, keep-active/drop-record silently confirms an unexpired configuration.

3. BROKEN — A clean current-version bootstrap cannot create the record because file import performs a real commit at pkg/daemon/daemon_apply_commit.go:17-60 and cluster topology admission keys on `d.cluster != nil` at :551-570. A current binary can nevertheless produce a new nonempty-hash FirstCommit+cluster record after accepting a future legacy record; the complete recurrence is detailed below.

4. BROKEN — The two-sided sampler barrier is valid: `ReadSelfStat` precedes the dataplane access at pkg/fwdstatus/sampler.go:93-125, and Start's prime is synchronous at :61-67. The fixture migration is incomplete: pkg/daemon/bootstrap_rollback_test.go:74 and pkg/daemon/rollback_resync_test.go:81 are omitted, as are direct failure-helper fixtures at pkg/daemon/startup_signal_5807_test.go:118,157 if false publication lives in that helper.

5. BROKEN — The narrowing itself is structurally sound, and daemon production has only the caller at pkg/daemon/daemon_run.go:595; gRPC and CLI retain independent Build adapters at pkg/grpcapi/server_show_forwarding.go:65-73 and pkg/cli/cli_show_chassis.go:103-111. The deletion inventory omits the assertion, userspace wrapper, and old probe at pkg/daemon/daemon_forwarding_status.go:10,55-87.

6. VERIFIED — The five production writes are exactly pkg/daemon/daemon_run_bringup.go:448,464,469,497 and pkg/daemon/daemon_run_naming.go:234; the 5-writer/129-reader audit is consistent. The existing canary really requires a field named `dp` at pkg/dataplane/retirement_boundary_canary_test.go:3314-3349, and its renderer lacks generic `ast.IndexExpr` support at :3352-3364, so the proposed redesign is necessary and correctly scoped.

Findings

MAJOR — Work G has no shutdown admission fence. The assertion at docs/research/2114-nat-pool-alarm-dp-race/plan.md:335-337 that Phase-5 signal handling is "applySem-ordered" is false. A signal can be pending when `finishStartup(true)` releases the rollback waiter; Run then immediately reaches shutdown through pkg/daemon/daemon_run.go:749-756. Shutdown merely acquires and releases applySem once at pkg/daemon/daemon_run_shutdown.go:50-53. If shutdown wins that acquisition, the timer can acquire it immediately afterward and execute a non-cancellable rollback at pkg/daemon/daemon_apply_commit.go:629-631,693-698 while shutdown tears down managers and the dataplane at pkg/daemon/daemon_run_shutdown.go:95-230. The timer runs on its own goroutine and is not joined by `wg.Wait`, as shown by pkg/configstore/store_commit.go:803-820. G needs a permanent stopping/admission fence checked by the executor under applySem, with shutdown publishing that fence before draining; a one-shot drain is not exclusion against later acquirers.

MAJOR — Work H reverses the persisted-confirm safety contract. Current recovery explicitly says an expired unconfirmed config "must NOT stand" and rolls it back at pkg/configstore/store_persist.go:171-228. Therefore the guard must, at minimum, be after that return so expired FirstCommit+cluster records retain existing safe behavior. But the proposed future-window behavior at docs/research/2114-nat-pool-alarm-dp-race/plan.md:364-371 is still invalid: keeping active and deleting `confirm.json` converts an unconfirmed config into a permanent confirmed config, exactly the failure #4577 prevents at pkg/configstore/store_persist.go:117-135 and pkg/configstore/README.md:417-449. The recovery design must instead roll back safely during Load, fail closed, or repair the eventual cluster-runtime teardown; placement alone cannot make keep-active/drop-record correct. The test plan at plan.md:374-379 also lacks the mandatory already-expired negative case.

MAJOR — "Pre-topology-guard artifact" is not a correct production boundary. Current recovery can re-arm a future legacy FirstCommit record at pkg/configstore/store_persist.go:231-253, after which boot constructs `d.cluster` from the active clustered configuration at pkg/daemon/daemon_run_bringup.go:161-203. When the timer expires, `PromoteRollback` restores nil compiled state and clears `everCommitted` at pkg/configstore/store_commit.go:867-908, while `enterBootstrapMode` leaves `d.cluster` alive because its teardown list contains networkd, FRR, and dataplane only at pkg/daemon/bootstrap.go:321-375,407-478. A subsequent cluster commit-confirmed then passes the current runtime-keyed preflight at pkg/daemon/daemon_apply_commit.go:551-570, snapshots a nil previous compiled config at pkg/configstore/store_commit.go:475-524, and writes a new FirstCommit record with a current nonempty GuardedHash at :539-548. Work H must be specified as a permanent invariant with a current-version recurrence test, not a legacy-only cleanup.

MINOR — The "every startup-exit path" promise is not panic-safe. A panic from `p.run` at pkg/daemon/daemon_run.go:799 bypasses the explicit error handling at :823-832, while the plan specifies only branch-local false publication at plan.md:328-334. There is no startup-internal `os.Exit`; the process-level exit occurs after Run returns at cmd/xpfd/main.go:367-369, so that case cannot leak a live waiter. A Run-scoped `defer d.finishStartup(false)` is needed for recovered panics and other unwinds; `sync.Once` makes it harmless after successful publication.

MINOR — Fixture migration is incomplete and would cause hangs or panics. The plan lists six executor fixtures at plan.md:338-342, but the exact executor search also finds Daemon literals at pkg/daemon/bootstrap_rollback_test.go:74 and pkg/daemon/rollback_resync_test.go:81. If false publication is placed inside `runStartupOrAbort` as specified, the nil-gate Daemons at pkg/daemon/startup_signal_5807_test.go:118,157 will call `close(nil)` through `finishStartup`. All four must initialize the startup outcome deliberately.

MINOR — The change/deletion inventory is internally incomplete. Collapsing the daemon adapter requires replacing or deleting `var _ fwdstatus.DataPlaneAccessor` and removing `forwardingStatusDaemonUserspaceDataPlane` plus `userspaceStatusProbe` at pkg/daemon/daemon_forwarding_status.go:10,55-87; plan.md:398-423 does not enumerate them. Additionally, plan.md:483 says no other package is touched even though Work H necessarily changes pkg/configstore/store_persist.go:136-255.

MINOR — Two Work G rationale statements are factually wrong. Boot does not hold applySem "across startup" as claimed at plan.md:309-312; it holds it only around the Phase-4 apply. Gate-first remains mandatory because an early timer could otherwise acquire the semaphore before Phase 4 and block boot. Also, the end-of-Phase-5 point is not "exactly equivalent to a remote commit arriving at first server contact" as claimed at plan.md:321-327: HTTP is already started at pkg/daemon/daemon_run.go:586-589, and its Start returns with listeners live at pkg/api/listener.go:108-138 before gRPC construction at daemon_run.go:598-600. The endpoint remains conservative for the timer, but the stated equivalence is false.

NEEDS-REVISION

---

## Orchestrator fold adjudication (into v9)

All 3 MAJOR + 4 MINOR verified against worktree code before folding:

- M1 (shutdown fence) VERIFIED — `daemon_run_shutdown.go:50-53`
  acquires+releases applySem once; teardown proceeds after. Folded as the
  `stopping` fence (published pre-drain, re-checked under applySem).
- M2 (H reverses #4577) VERIFIED — subsumes Claude SMR M1 (placement).
  Work item H redesigned: revert-at-Load semantics, guard after the
  expired branch, expired-branch revert body reused.
- M3 (recurrence) VERIFIED — `store_commit.go:901-907` FirstCommit leg
  clears everCommitted; `enterBootstrapMode` leaves `d.cluster` alive;
  runtime-keyed preflight then admits a cluster commit-confirmed whose
  firstCommit=true record carries a current GuardedHash. Guard restated
  as a PERMANENT invariant + recurrence test (v).
- m1 (panic defer) VERIFIED — folded.
- m2 (fixtures) VERIFIED — :74/:81 hang; :118/:157 `close(nil)` panic.
  Folded (all four).
- m3 (deletion inventory + §5.1) VERIFIED — folded (`var _` :10, wrapper
  :52-75, `userspaceStatusProbe` :83-87; §5.1 package list corrected).
- m4 (rationale corrections) VERIFIED — `daemon_apply.go:50-51` holds
  applySem only around the apply; `daemon_run.go:586-589` HTTP serves
  before gRPC construction. Folded (corrected rationale + claim).

Verdict recorded: **NEEDS-REVISION (3 MAJOR, 4 MINOR)**.
