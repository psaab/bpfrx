VERDICT: PLAN NO


### Q1 (construction invisibility)
* **r71 T1 Folded**: **YES** ([plan.md:L5020-5029](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5020-L5029), [plan.md:L7199-7201](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7199-L7201)).
* **Assessment**: **UNSOUND**
* **Evidence**: [plan.md:L5006-5011](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5006-L5011)
* **Analysis**: The text specifies that every domain's state stages in a staging key namespace no canonical lookup can match. Consequently, when a second packet for the *same* 5-tuple arrives while the first admission is staged, canonical lookup finds nothing in canonical space. The second admission proceeds concurrently, leading to double-allocation of NAT tuples ([allocator.rs:1617](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1978)) or key collisions upon atomic publication. If same-tuple admissions were to serialize on a tuple intent record, that record would either be visible to packet lookups (breaking construction-level invisibility) or invisible (failing to serialize).

---

### Q2 (split-carriage causal rules)
* **r71 T2 Folded**: **YES** ([plan.md:L5525](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5525), [plan.md:L7203-7208](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7203-L7208)).
* **Assessment**: **UNSOUND**
* **Evidence**: [plan.md:L5531-5539](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5531-L5539), [plan.md:L5677](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5677), [plan.md:L5685](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5685)
* **Analysis**: The summary fence is defined to be strictly `LIVENESS-BOUND`, dropping automatically when authority heartbeats cease (>5×200ms). During a network fabric flap, heartbeat loss causes the retired peer to immediately drop its summary fence while the sync channel carrying `RETIREMENT_NOTICE` is also disconnected. The retired node becomes election-eligible ([election.go:172](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5598)) and claims mastership during the flap. Furthermore, no operator escape or majority/minority partition semantics are defined for a summary fence stuck during fabric loss (operator clear is stated only for `CommitUncertain` and permanent loss).

---

### Q3 (one grammar + class-conditional markers + sequences)
* **r71 T3 Folded**: **YES** ([plan.md:L6160-6169](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6160-L6169), [plan.md:L7209-7215](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7209-L7215)).
* **Assessment**: **UNSOUND**
* **Evidence**: [plan.md:L5586-5588](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5586-L5588), [plan.md:L4029-4032](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4029-L4032), [plan.md:L7433](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7433)
* **Analysis**: Limiting heartbeats to at most two pending summaries per target while queuing further retirements at the authority fails to specify:
  1. Queue drain / supersession policy: whether a newer retirement replaces older queued items or if they are sent FIFO.
  2. Queue durability across authority process restarts.
  3. Unscoped sequence scopes in decision-phase entry rules ([plan.md:L4029](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4029), [plan.md:L4032](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4032)) and generic sequence definitions ([plan.md:L7433](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7433)).

---

### NEW Traces Opened by v9.9.54.26 Folds

1. **Staging Key Namespace Double-Allocation Trace** ([plan.md:L5006-5011](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5006-L5011), `poll_descriptor/mod.rs:2449`, `allocator.rs:1617`):
   Staging all domain state in a staging namespace invisible to canonical lookup prevents packet processing from detecting in-flight admissions for the same tuple. Concurrent packets for the same tuple initiate parallel NAT port allocations, resulting in NAT tuple double-allocation or publication key conflicts.

2. **Liveness-Bound Summary Fence Drop Split-Brain Trace** ([plan.md:L5531-5539](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5531-L5539), `heartbeat_manager.go:306`, `election.go:172`):
   Making the summary fence drop automatically upon heartbeat loss causes a retired peer in a fabric flap scenario (1s heartbeat loss) to clear its fence before receiving `RETIREMENT_NOTICE`. The retired peer re-enters election eligibility while the authority still considers it retired, leading to split-brain mastership.

3. **Pending Summary Queue Volatility and Starvation Trace** ([plan.md:L5586-5588](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5586-L5588), `heartbeat.go:48`, `sync_conn_write.go:36`):
   Capping heartbeat summaries at 2 and queuing extra retirements in-memory without persistence or supersession rules causes multi-RG rapid retirements to stall behind older queued items, while an authority restart wipes unpersisted queued summaries, leaving target nodes unfenced.

4. **Restart Mandatory Redo of Installed Receipts Race Trace** ([plan.md:L5030-5038](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5030-L5038), `shared_ops.rs:907`, `manager.go:372`):
   Mandating restart recovery to redo the visibility flip for every durable `INSTALLED` receipt creates a race condition when table maps are recreated empty at startup (`manager.go:372`), failing or corrupting state if shadow slots do not exist prior to the re-executed flip.
