# AGY adversarial plan-review — round 67 (plan v67 @ ebeaaf607)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY (4/4 folds FOLDED; 2 fresh attacks FAILED — its attack-1 reading, that the critical section covers check+registration with the syscall outside the lock, was adopted into v68). Structure confirmed. Raw output follows verbatim.

---

(A) Fold verification:
1. FOLDED — `plan.md:3007-3014,7351-7362`, `pkg/daemon/daemon_ha_fabric.go:23-93,102-148`: The reservation retires via a `defer` on every callback exit path (completion, abandon, panic, error); a callback past the 5 s bound has at most ONE in-flight netlink call before its next mutation check hits the 3-term fence and abandons; a never-returning call dies with process exit at `TimeoutStopSec=20`.
2. FOLDED — `plan.md:3015-3020,7298-7302,8923-8926`: The fence check and mutation entry form one critical section under the debt-ledger lock (check-then-enter atomically); the netlink syscall executes outside the lock, and §9 (`plan.md:8923`) tests that no call starts after gate closure.
3. FOLDED — `plan.md:3021-3033,7380-7398`, `pkg/daemon/daemon_scheduler.go:192-217`, `pkg/daemon/daemon_run.go:89-100`, `pkg/dataplane/manager.go:471-482`: (i) `publishPolicyScheduleState` (`daemon_scheduler.go:192-217`) is the scheduler's dataplane mutation entry point and gains the 3-term fence check; (ii) terminal latch `schedulerAbandoned` prevents `stopPolicySchedulerLoop` re-entry from `daemon_run.go:99`; (iii) teardown wait behind `Manager.Close()` mutex `m.mu` is bounded by one in-flight snapshot IPC's control request deadline (<=5 s), well within `TimeoutStopSec=20`.
4. FOLDED — `plan.md:3034-3036,7412,8932`: Full fence references consistently use the 3-term form (`stopping || runCtx.Err() != nil || resetting`), and §9 (`plan.md:8932`) explicitly includes the `ZEROIZE CALLBACK` leg.

(B) Fresh attacks:
- Check-then-enter critical section & netlink call under lock: FAILED — The netlink syscall executes outside the debt-ledger lock after a short microsecond check-then-enter registration, so a hung netlink call does not hold the ledger lock and cannot stall the mint.
- Terminal latch vs legitimate later stop call: FAILED — `Daemon.Run()` execution is single-invocation per process, daemon shutdown is strictly terminal (`daemon_run_shutdown.go:25`), and no non-exiting path re-invokes `stopPolicySchedulerLoop()`.

(C) New findings:
None.

(D) Structure confirmation:
The §4.7 two-unit delivery structure (PR-1 core accessor core vs follow-up G+H+H2 unit) stands with r28 (A) dissent recorded (`plan.md:13-17,9491-9500`).

(E) Verdict line:
PLAN-READY
