VERDICT: PLAN NO

### Q1 (shared capability commit): SOUND
* **File:Line Evidence**: [plan.md:4016-4036](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4016-L4036), [plan.md:4056-4085](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4056-L4085) (referencing `pkg/cluster/sync_conn.go:118-194`, `pkg/cluster/sync_conn_read.go:38, :205`, `pkg/cluster/sync_auth.go:289`)
* **Trace & Analysis**:
  * **Reversal Safety**: The plan specifies that the entire `CONFIRM` declaration exchange, owner calculation, and `CAPABILITY_DECISION(class)` publication/ACK complete *before* slot installation ([pkg/cluster/sync_conn.go:118, :130](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L118-L130)), session dispatch, or cold-prime ([pkg/cluster/sync_conn.go:138-194](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn.go#L138-L194)). Neither node dispatches sessions or starts cold-prime until the decision is ACK'd, ensuring node B cannot have started processing prior to reversing to the published decision.
  * **Owner Death Mid-Decision**: If the setup owner dies before `CAPABILITY_DECISION` is committed and ACK'd, neither side installs the class. The decision phase times out with no committed decision, triggering a connection close and a retry with bounded backoff ([plan.md:4075-4076](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4075-L4076)).

---

### Q2 (versioned readiness): UNSOUND
* **File:Line Evidence**: [plan.md:4086-4114](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4086-L4114) (referencing `pkg/cluster/sync_conn_read.go:241, :246`, `pkg/cluster/sync.go:407`, `pkg/daemon/daemon_ha_sync.go:40-47, :90`, `pkg/cluster/sync_state.go:13`)
* **Trace & Analysis**:
  * **Lock Domain Split**: Line 4093 specifies that repair obligations and cold-prime state live under the `SessionSync` mutex domain ([pkg/cluster/sync.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go)). Line 4098 specifies that readiness state lives under a separate mutex, `Manager.m.mu` ([pkg/daemon/sync_state.go:13](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/sync_state.go#L13)).
  * **Racy CAS Evaluation**: When `OnBulkSyncReceived` or the readiness timer evaluates "AND no repair obligation is armed" before performing its CAS, the obligation check (under `SessionSync.mu`) and the readiness CAS (under `Manager.m.mu`) are split across two separate lock domains. A delayed callback G1 can observe no repair obligation under `SessionSync.mu`, drop `SessionSync.mu`, and then acquire `Manager.m.mu`. Meanwhile, a new activation G2 can acquire `SessionSync.mu`, arm the repair obligation, update the generation in `SessionSync`, and set `ready=false`. G1's CAS can then proceed under `Manager.m.mu` and overwrite readiness to `ready=true` over G2's armed repair obligation.

---

### Q3 (convergence sweep): UNSOUND
* **File:Line Evidence**: [plan.md:469-750](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L469-L750), [plan.md:3925-4114](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3925-L4114)
* **Trace & Analysis**:
  * While §5.2's dataplane demote gate closes blind RST/FIN demotion DoS and Part B's holder-lifetime machinery ([plan.md:5448-5460](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5448-L5460)) addresses SNAT mid-flow swap and tuple release/reissue (#6522), the dual-lock domain split identified in Q2 ([plan.md:4093-4114](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4093-L4114)) leaves reachable harm.
  * Specifically, an async delayed bulk callback can race across the two mutexes (`SessionSync.mu` vs `Manager.m.mu`) during activation and restore `ready=true` prematurely while a repair obligation is armed. This introduces HA state desynchronization and availability regressions during failover/takeover transitions.

---

### NEW Traces Folded Open by v9.9.54.4

1. **Dual-Lock Domain Race on Versioned Readiness CAS**
   * **Code Lines**: [plan.md:4093-4114](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4093-L4114) (`pkg/daemon/sync_state.go:13`, `pkg/cluster/sync.go:407`, `pkg/daemon/daemon_ha_sync.go:40-47, :90`, `pkg/cluster/sync_conn_read.go:246`)
   * **Trace**: The activation transaction arms outbound repair obligations under the `SessionSync` mutex ([pkg/cluster/sync.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go)), but readiness writers execute CAS against `Manager.m.mu` ([pkg/daemon/sync_state.go:13](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/daemon/sync_state.go#L13)). Because checking repair obligations and CASing readiness spans two mutexes, a delayed `OnBulkSyncReceived` callback G1 can inspect `SessionSync` obligations before activation G2 arms them, then acquire `Manager.m.mu` after G2 updates `SessionSync` state, allowing G1 to CAS `ready=true` over G2's armed repair.

2. **Partial Frame Discard Stream Alignment Risk**
   * **Code Lines**: [plan.md:4077-4082](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4077-L4082) (`pkg/cluster/sync_auth.go:289`, `pkg/cluster/sync_conn_read.go:38`)
   * **Trace**: If the `CAPABILITY_DECISION` confirmation exchange times out with a partially received frame consumed by `sync_auth.go:289`, discarding the partial frame and attempting to re-align the framing boundary for `sync_conn_read.go:38` without tearing down the underlying TCP connection risks TCP stream desynchronization if framing header bytes were already consumed from the socket buffer.
AGY EXIT: 0
