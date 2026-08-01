# AGY adversarial plan-review — round 65 (plan v65 @ 36b8f6cfb)

Direct agy print-mode invocation from the trusted workspace with --add-dir at a 12m timeout (see reviewer-ids.md infra notes). Verdict: PLAN-READY (4/4 folds FOLDED; 2 fresh attacks FAILED; no new findings). Structure confirmed. Raw output follows verbatim (file:/// link markup as emitted).

---

**(A) Fold verification:**
1. FOLDED — [daemon_scheduler.go:170-183](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_scheduler.go#L170-L183) (bounded context on reacquisition), [daemon_run_shutdown.go:25-35](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go#L25-L35) (unconditional admission-gate close at `runShutdownSequence` entry covering startup abort at [daemon_run.go:174-176](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L174-L176) & [daemon_run_bringup.go:493-520](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go#L493-L520)), and [plan.md:7244-7246,8765-8768](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7244-L7246) (§9 preemption-between-check-and-call leg).
2. FOLDED — [manager.go:471-483](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/manager.go#L471-L483) (reset/generation bump scoped to `Close`/`Teardown`), [process.go:18-33,133,197-216](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/dataplane/userspace/process.go#L18-L33) (helper-restart callers `ensureProcessLocked`, `requestLocked` ping failure, and `process_status.go:68` bypass reset/generation bump and hit early return), and [plan.md:7179-7180](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7179-L7180) (§9 `Teardown→reset→B-registration→A-generation-rejection` regression).
3. FOLDED — [plan.md:7100-7103,2945-2946](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L7100-L7103) (rendering inventory explicitly includes per-attempt `QUEUED` set beside token and pending set).
4. FOLDED — [plan.md:2946-2950,7219-7220](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md#L2946-L2950) (corrected 18s budget total + up to 6s `Run` defers at [daemon_run.go:100-112](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go#L100-L112) + unbounded `wg.Wait` at [daemon_run_shutdown.go:62-64](file:///home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_shutdown.go#L62-L64)).

**(B) Fresh attacks:**
- Bounded context on scheduler-loop reacquisition: FAILED — if `Acquire` times out in `stopPolicySchedulerLoop`, `schedulerCancel()` still terminates the scheduler goroutine while `d.dp` teardown occurs later in Phase 7.
- Unconditional gate close at every shutdown entry: FAILED — all four shutdown paths (signal-driven, startup-abort at `daemon_run.go:175`, CLI-exit, API-triggered) route through `runShutdownSequence`, where the gate close is executed as the very first statement before any drain or teardown.

**(C) New findings:**
None.

**(D) Structure confirmation:**
Confirmed: §4.7 two-unit delivery structure stands (r28 (A) dissent recorded).

**(E) Verdict line:**
PLAN-READY
