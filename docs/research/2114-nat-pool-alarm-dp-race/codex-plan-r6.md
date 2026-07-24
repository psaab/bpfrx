The successful-startup gate concept is sound, but v6 is not implementation-ready. Two residual design defects remain.

### MAJOR

1. **R5 M1 — PARTIAL. Startup success is ordered correctly; startup failure is not.**

   On a successful startup, G addresses all three reported defects:

   - **(a) `vrrpMgr` nil-deref:** the manager is constructed at [daemon_run_bringup.go:218](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:218), before the proposed close, so the unconditional call at [daemon_apply_tail.go:50](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_tail.go:50) cannot precede construction.
   - **(b) Bootstrap-arm interleaving:** delaying dispatch until after the boot `inBootstrap()`/`Start()` decision at [daemon_run_bringup.go:490](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:490) prevents `enterBootstrapMode` from landing between the check and `Start`.
   - **(c) Timer versus boot `d.dp` writer:** channel close/receive supplies the missing happens-before edge after the writes at [daemon_run_bringup.go:448](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:448). Waiting before `applySem`, as required by [plan.md:280-289](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:280), also avoids deadlocking the boot apply at [daemon_run_bringup.go:518](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:518).

   The failure leg is defective:

   - `d.daemonCtx` is deliberately the raw parent, while signals cancel a separate derived context at [daemon_run.go:64-87](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:64). Production passes `context.Background()` at [cmd/xpfd/main.go:504](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/cmd/xpfd/main.go:504).
   - Signal aborts and ordinary phase errors return before the proposed close through [daemon_run.go:147-178](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:147) and [daemon_run.go:794-832](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:794). Therefore neither select arm in [plan.md:284-289](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:284) fires.
   - An already-fired timer goroutine at [store_commit.go:803-823](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:803) then blocks indefinitely. Process exit masks this for normal `xpfd`, but it is not acceptable for early-return or embedded `Run` users, which this code explicitly supports. A signal during Phase 5 presents the inverse problem: the raw context remains live and the plan may publish “ready” despite shutdown already being requested.

   G needs one initialized, exactly-once startup outcome covering every pre-ready return: `ready` or `aborted`. Aborted must wake the executor without dispatching; simply closing `startupReady` on failure would incorrectly authorize rollback against partial initialization.

   No second production caller of `executeConfirmedRollback` exists beyond registration at [daemon_run.go:130-136](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:130). The boot apply deliberately bypasses the gate, and Phase-5 background/API paths can run before an end-of-phase close, but by then the required managers and boot dataplane decision are settled. The gRPC launch at [daemon_run.go:586-599](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:586) is therefore safe: even if a timeout fires before the just-following close, it waits, and the close orders the startup writes. A cleaner linearization point would be after the last late manager initialization at [daemon_run.go:435-511](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run.go:435), before exposing HTTP/gRPC.

   The pivoted tests do not pin the gate:

   - Test (a) only asserts absence of side effects at [plan.md:668-673](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:668). An incorrect implementation that acquires `applySem` and then waits passes. It must prove the semaphore remains independently acquirable while gated. Cancelling the raw `daemonCtx` also does not exercise production signal behavior.
   - Test (b) pins the atomic cell, not gate placement.
   - Test (c) supplies no deterministic post-`Load`/pre-manager barrier, and `NoDataplane` skips the boot writer/arm path at [daemon_run_bringup.go:414-523](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:414). Its claimed pre-gate failure is scheduler-dependent and cannot pin defects (b) or (c).

2. **R5 MINOR 3 — NOT-FOLDED; the concrete counterexample elevates this to MAJOR.**

   The coexistence proof at [plan.md:138-147](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:138) is false. It conflates the newly active cluster config’s committed marker with the previous rollback target:

   - First `CommitConfirmed` marks the new active config committed/ever-committed at [store_commit.go:455-461](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:455), while independently retaining a nil previous compiled config and persisting `FirstCommit=true` at [store_commit.go:475-524](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:475).
   - Recovery accepts an empty legacy `GuardedHash` at [store_persist.go:149-159](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:149) and reconstructs `confirmPrevCfg=nil` solely from `FirstCommit` at [store_persist.go:237-247](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_persist.go:237).
   - The active cluster config constructs `d.cluster` at [daemon_run_bringup.go:161-165](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_run_bringup.go:161), after which timeout promotion returns nil and enters bootstrap at [daemon_apply_commit.go:645-671](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:645). `enterBootstrapMode` does not stop the cluster runtime at [bootstrap.go:321-478](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap.go:321).

   Thus a pre-topology-guard first confirmed standalone→cluster record can boot a live cluster and later enter bootstrap. Matching hash-bearing records from the GuardedHash/preflight rollout interval have the same problem. The plan must either define safe cross-upgrade behavior or classify and handle live-cluster/bootstrap coexistence, with a regression test.

### MINOR

1. **R5 M2 — PARTIAL.**

   The new preamble correctly recognizes that rollback calls the full apply at [daemon_apply_commit.go:697](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:697), reaching interfaces, routing and tail. But §5.4 calls itself an “exact classification snapshot,” while rows [plan.md:495-500](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:495) still say only `serialized`; the adjacent dataplane and bootstrap rows explicitly show pre-gate RACE-3. The global prose and row-level exposure cells disagree. Add explicit pre-gate/post-gate columns or mark each timer-reachable row consistently.

2. **R5 MINOR 1 — FOLDED.**

   The `:67` row now correctly says capture-once, mixed standalone/HA, and RACE-2 only for the standalone use at [plan.md:475](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:475). That matches the capture before the cluster check at [daemon_ha_userspace_stream.go:67-68](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_ha_userspace_stream.go:67).

3. **R5 MINOR 2 — FOLDED.**

   The RACE-1 scope wording and requested citations are now accurate: executor registration `daemon_run.go:136`, timer rearm `store_persist.go:251`, dispatch branch/call `store_commit.go:819-820`, and blackhole promotion `daemon_ha.go:311`.

   Fresh citation nits remain: [plan.md:110](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:110) should cite `daemon_apply_tail.go:50`; Teardown is `bootstrap.go:473`, not `:472`; and [plan.md:299](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:299) mislabels `store_commit.go:819` as the fallback—`performAutoRollback` is called at `:822`.

4. **R5 MINOR 4 — FOLDED.**

   The additions at [cluster_identity_preflight_6192_test.go:27](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/cluster_identity_preflight_6192_test.go:27) and [ha-no-hitless-restart.md:85](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/ha-no-hitless-restart.md:85), [ha-no-hitless-restart.md:130](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/ha-no-hitless-restart.md:130) complete the actionable source/docs sweep. Remaining historical log text does not require rewriting.

5. **Fresh gate-specification gaps.**

   The plan declares but never initializes `startupReady`; the production constructor at [daemon.go:1086-1108](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon.go:1086) must create the outcome before executor registration. Existing direct executor fixtures such as [rollback_resync_test.go:31](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/rollback_resync_test.go:31) and [bootstrap_rollback_test.go:24](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/bootstrap_rollback_test.go:24) otherwise hang or panic on nil `daemonCtx`.

   The implementation scope must also update the “acquires `applySem` FIRST” contracts at [store_commit.go:327-334](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/configstore/store_commit.go:327) and [daemon_apply_commit.go:611-628](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/pkg/daemon/daemon_apply_commit.go:611). Finally, [plan.md:592-599](/home/ps/git/kimi-xpf/.claude/worktrees/2114-research-nat-pool-alarm-dp-race/docs/research/2114-nat-pool-alarm-dp-race/plan.md:592) still says “no lifecycle redesign” and omits startup-outcome, semaphore-deadlock and timer-retention risks.

For open question 6: keep G in this PR, after redesign. It repairs a more severe defect on the exact RACE-3 path and is required for honest regression coverage. For reviewability it can be a separate prerequisite commit in the same PR/stack, but deferring it to a later follow-up would knowingly ship the discovered boot-panic/bootstrap-interleaving path.

VERDICT: NEEDS-REVISION

Codex session ID: 019f924e-71ad-7943-8734-c1997e6c4780
Resume in Codex: codex resume 019f924e-71ad-7943-8734-c1997e6c4780
