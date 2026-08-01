# Codex hostile plan-review — round 67 (plan v67 @ ebeaaf607)

Task: task-msamifjq-0d7v82 (session 019fbe4a-a333-70e2-a624-877cab49ad9a).
Verdict: NEEDS-REVISION (4 MAJOR, 3 MINOR; fold verification 4 PARTIAL). Structure confirmed. Raw companion output follows verbatim.

---

Fold verification:
1. PARTIAL — The defer itself is correct: plan.md:7346-7361 covers completion, abandon, error, and panic unwinding; the current callback has no os.Exit/log.Fatal path and executes synchronous netlink calls sequentially (pkg/daemon/daemon_apply_interfaces.go:100-109; pkg/daemon/daemon_ha_fabric.go:23-148), so the one-active-call bound is honest. However, TimeoutStopSec is not universal: Run explicitly supports returning to an embedded caller (pkg/daemon/daemon_run.go:89-99), where a never-returning call survives and its reservation never retires.

2. NOT-FOLDED — The critical section at plan.md:7293-7303 is incompatible with the shutdown sequence at plan.md:7346-7364. Because the netlink calls are synchronous and non-contextual (pkg/daemon/daemon_ha_fabric.go:23-148), holding the ledger through “entry” means holding it until return; releasing it earlier restores the preemption gap.

3. PARTIAL — The scheduler path is correctly identified: NewPrimed installs publishPolicyScheduleState and Scheduler.evaluate invokes it synchronously (pkg/daemon/daemon_scheduler.go:53-55; pkg/scheduler/scheduler.go:207-217). The proposed latch also mechanically suppresses Run’s second stop call, but the fence remains non-atomic, the latch does not prohibit later starts, process exit is not universal, and the m.mu wait is not bounded within 20 seconds (plan.md:7380-7398).

4. PARTIAL — The normative fence is now three-term and §9 has the zeroize leg (plan.md:7411-7413,8932-8936), but STALE-CALLBACK still calls runCtx.Err() OR stopping the “FULL fence,” omitting resetting (plan.md:8950-8953).

New findings:

MAJOR 1 — The ledger becomes an unbounded netlink-call lock. Registration, completion, and mint supersession all require this explicitly short-held lock (plan.md:6964-6976), and shutdown must acquire it before closing admission (plan.md:7346-7348). Holding it through a possibly never-returning call prevents gate closure, the five-second join, mint progress, and other ledger users; unlocking before the invocation recreates r66 M2. Consequently §9’s preemption seam cannot both pause between check and call and allow shutdown to close the gate (plan.md:8922-8926).

MAJOR 2 — The scheduler’s three-term fence has the same check/call race. publishPolicyScheduleState checks state and then makes two separate dataplane calls (pkg/daemon/daemon_scheduler.go:205-215,220-241); the userspace seed releases m.mu before UpdatePolicyScheduleState reacquires it (pkg/dataplane/userspace/manager_compile.go:153-160,447-453). A callback preempted after the proposed fence can therefore start either mutation after shutdown’s timeout, contradicting plan.md:7383-7395’s claim that the fence prevents new mutations.

MAJOR 3 — The abandoned-stop latch is neither safely owned nor start-terminal. Existing schedulerCancel, schedulerWg, and schedulerStopped are applySem-guarded (pkg/daemon/daemon.go:334-346), so a timed-out stop cannot safely modify that state. The plan only makes later stop calls no-ops (plan.md:7387-7389); it does not require startPolicySchedulerLoopLocked to observe the latch. An already-admitted apply can resume after ApplyConfig and start another scheduler generation (pkg/daemon/daemon_apply_dataplane.go:133-165; pkg/daemon/daemon_scheduler.go:140-157). The deferred stop is also legitimate cleanup once contention clears, especially for the explicitly supported embedded/early-error Run paths (pkg/daemon/daemon_run.go:89-100,815-832), where no process exit destroys the stranded state.

MAJOR 4 — The m.mu wait is not bounded by one control-request deadline or by TimeoutStopSec=20. UpdatePolicyScheduleState holds m.mu across rebuild work, optional preliminary IPC, and apply_snapshot (pkg/dataplane/userspace/manager_compile.go:450-564); JSON marshaling occurs before any socket deadline (pkg/dataplane/userspace/process_control.go:106-142). The snapshot deadline alone can reach approximately 67 seconds (pkg/dataplane/userspace/process_control.go:33-56,92-103), versus the service’s 20-second stop limit (test/incus/xpfd.service:11). plan.md:7393-7395 therefore describes neither the complete lock-hold bound nor an orderly-teardown disposition.

MINOR 1 — v67 explicitly claims all two-term “FULL” references were corrected (plan.md:3034-3036), but the live formal acceptance copy remains two-term at plan.md:8950-8953.

MINOR 2 — §5.1 omits both new lifecycle mechanisms. Its daemon.go inventory names stopping and other H2 state but not the daemon-owned admission flag/reserved set or scheduler abandoned-stop latch and synchronization changes (plan.md:6691-6708 versus plan.md:7334-7349,7387-7389). The §9 shutdown tests likewise cover fabric callbacks but no timeout→latch→late-start/defer/embedded-return scheduler regression (plan.md:8922-8945).

MINOR 3 — The post-reactivation predicate labeled “COMPLETE” omits IsConfirmPending and IsDirty (plan.md:8818-8828), although both are mandatory in the initial formal predicate (plan.md:8786-8789). Event-options mutates the candidate before invoking commitFn (pkg/eventengine/engine.go:899-930,948), so the abbreviated rerun can false-green.

Structure confirmation: §4.7 stands—PR-1 remains the synchronized d.dp core and G+H+H2 remain together in the follow-up (plan.md:6644-6679); §9’s JOIN-COHERENCE leg remains intact (plan.md:8838-8887).

NEEDS-REVISION

Codex session ID: 019fbe4a-a333-70e2-a624-877cab49ad9a
Resume in Codex: codex resume 019fbe4a-a333-70e2-a624-877cab49ad9a
