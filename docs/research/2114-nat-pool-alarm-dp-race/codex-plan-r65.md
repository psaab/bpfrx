# Codex hostile plan-review — round 65 (plan v65 @ 36b8f6cfb)

Task: task-msajv43z-7rp75s (session 019fbe06-c3d8-7393-a47e-1c539b2c80be).
Verdict: NEEDS-REVISION (3 MAJOR, 1 MINOR; fold verification 2 FOLDED / 2 NOT-FOLDED). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification 1: NOT-FOLDED — The bounded scheduler reacquisition has no duration or expiry disposition (docs/research/2114-nat-pool-alarm-dp-race/plan.md:7233-7238); startup abort still skips the only claimed join because the drain remains under `applyCancel != nil` (pkg/daemon/daemon_run_shutdown.go:35-60; pkg/daemon/daemon_run.go:174-197), and closing admission cannot join a phase-four callback already reserved or running (pkg/daemon/daemon_run_bringup.go:493-520). §9 has only timeout-inside-an-already-entered-call and generic guard-to-mutation prose, not the required timeout/preemption-between-check-and-call regression (plan.md:8760-8768,8773-8782).

Fold verification 2: PARTIAL — The intended mechanics are correctly pinned: Teardown-specific reset before `stopLocked`’s early return and generation comparison after `applySem` acquisition (plan.md:7163-7179; pkg/dataplane/userspace/process.go:210-216). Production callers are helper restart/cleanup at process.go:29,32,133, manager_compile.go:248, and process_status.go:68; terminal `Close` at manager.go:471-475; and `Teardown` at manager.go:478-482, reusable from pkg/daemon/bootstrap.go:470-475 and terminal from pkg/daemon/daemon_run_shutdown.go:226-229. The promised Teardown→reset→B-registration→A-rejection regression is absent from §9 (plan.md:8773-8798).

Fold verification 3: FOLDED — The H2 runbook carries the queued-empty predicate (plan.md:5628-5637), §5.1 inventories the per-attempt QUEUED set beside token/pending (plan.md:7097-7102), and both formal acceptance copies include it (plan.md:8600-8606,8656-8662).

Fold verification 4: FOLDED — The plan now correctly states 18s, up to 6s more from defers, and the pre-existing unbounded wait (plan.md:7213-7222), matching pkg/daemon/daemon_run.go:98-112 and pkg/daemon/daemon_run_shutdown.go:62-64.

New findings:

MAJOR — The proposed callback “join” is not a join. The plan reserves before detached launch (plan.md:7196-7205), while production launches with `go m.OnXSKBound()` (pkg/dataplane/userspace/maps_sync.go:451-456). The goroutine can remain unscheduled while shutdown acquires/releases `applySem`, then start afterward; therefore one semaphore drain cannot “wait for every in-flight callback” as claimed (plan.md:7227-7232). The daemon-scope tracker is never actually waited, and the supposedly “CONCRETELY-NAMED” close/join mechanism remains unnamed and absent from the §5.1 daemon/shutdown inventory (plan.md:6607-6622,6975-6980,7211-7224).

MAJOR — The scheduler timeout has no safe terminal state. Its bound is unspecified and a fresh timeout would add another sequential wait despite the prohibition at plan.md:7213-7222. Current state is protected by `applySem`, the acquire error is ignored, and release is unconditional (pkg/daemon/daemon_scheduler.go:170-183; pkg/daemon/daemon.go:342-346). Returning on expiry leaves the scheduler live before dataplane teardown; proceeding mutates without ownership; and cancellation cannot unblock an update already acquiring with intentionally uncancelled `d.daemonCtx`, leaving `schedulerWg.Wait()` unbounded (pkg/daemon/daemon_scheduler.go:192-203; pkg/scheduler/scheduler.go:103-116,207-217).

MAJOR — Shutdown-entry coverage excludes zeroize’s callback-relevant pre-signal interval. Steady signals and CLI-shell exit converge at pkg/daemon/daemon_run.go:735-756; startup abort enters at daemon_run.go:174-176,827-830; reboot/halt/power-off eventually enter through systemd (pkg/grpcapi/server_diag_system_action.go:56-67,148-168; pkg/cli/cli_request_system.go:23-61). But successful zeroize releases `applySem` with `resetting` latched before stopping xpfd (pkg/daemon/daemon_apply_reset.go:59-89; pkg/grpcapi/server_diag_system_action.go:69-86,186-205; pkg/cli/cli_request_system.go:174-198), while H2’s “FULL” callback fence checks only `runCtx.Err()` or `stopping` (plan.md:7181-7189,7250-7253). A queued callback can therefore acquire after the wipe and mutate netlink from the retained pre-wipe configuration.

MINOR — The reset-scope caller taxonomy is false as written: `Manager.Close` is a third, terminal category, and `Teardown` itself has both reusable and terminal callers (pkg/dataplane/userspace/manager.go:471-482; pkg/daemon/bootstrap.go:470-475; pkg/daemon/daemon_run_shutdown.go:222-229). This does not invalidate Teardown-only re-arm reset, but the inventory must state the terminal assumption.

Structure confirmation: §4.7 still cleanly defines PR-1 as the A1/accessor core and the follow-up as G+H+H2 together (plan.md:6558-6593).

NEEDS-REVISION

Codex session ID: 019fbe06-c3d8-7393-a47e-1c539b2c80be
Resume in Codex: codex resume 019fbe06-c3d8-7393-a47e-1c539b2c80be
