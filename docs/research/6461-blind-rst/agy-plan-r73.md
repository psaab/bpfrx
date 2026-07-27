VERDICT: PLAN NO


### Q1: UNSOUND
- **Evidence**: [plan.md:5044-5077](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5044-L5077), [plan.md:5102-5115](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5102-L5115), [plan.md:7337-7348](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7337-L7348).
- **Flaws**:
  1. **Missing Load/Store Memory Barrier on XDP**: Lines 5066-5077 specify two non-transactional loads (`value.generation <= published`) but omit the mandatory memory barrier / load-store fence (`smp_wmb`/`smp_rmb` or acquire-release semantics) required on weakly ordered architectures to guarantee published cell updates land after value writes.
  2. **Phantom Co-holder Window**: Allocator co-holder counts are updated at mint/RETAIN ([plan.md:5048-5050](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5048-L5050)). A process crash after incrementing a co-holder count but before writing a durable `INSTALLED` receipt leaves no receipt for restart rehydration ([plan.md:5102-5115](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5102-L5115)); however, on a live node without restart, an uninstalled/rolled-back candidate whose rollback handler fails or crashes mid-flight leaves a phantom holder increment pinning the NAT tuple indefinitely.

---

### Q2: UNSOUND
- **Evidence**: [plan.md:5608-5633](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5608-L5633), [plan.md:5651-5662](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5651-L5662), [plan.md:5714-5727](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5714-L5727).
- **Flaws**:
  1. **Fresh-Box Successor Mass Release**: Rule (c) ([plan.md:5623-5628](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5623-L5628)) dictates that any fence absent from a successor's published fence snapshot is released. A restarted/fresh-box successor starting with an empty local fence snapshot will transmit an empty snapshot, causing all receivers to immediately release ALL active cluster fences.
  2. **Receiver-Ahead Epoch Window**: Authority expansion expands `ALL` against the authority's local RG set ([plan.md:5652-5660](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5652-L5660)). If a receiver is ahead in epoch (holding extra RGs), the excess RGs are not in the transmitted list and remain unfenced on the receiver, breaking the invariant that a retirement for `ALL` fences all local RGs on the target node.

---

### Q3: UNSOUND
- **Evidence**: [plan.md:5683-5695](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5683-L5695), [plan.md:5742-5750](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5742-L5750), [plan.md:7357-7363](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7357-L7363).
- **Flaws**:
  1. **Pending NOTICE Incarnation Mismatch**: Pending NOTICEs target specific, random process incarnations ([plan.md:5705-5708](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5705-L5708)). Because incarnation IDs are exact-match unordered u64s ([plan.md:5744-5748](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5744-L5748)), a NOTICE queued for $I_1$ that becomes active under a subsequent incarnation $I_2$ will fail the equality check and remain stranded/unapplied.
  2. **Operator Automation Deception**: Queued retirements remain PRE-COMMIT ([plan.md:5686](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5686)). Without explicit CLI/telemetry status reporting and alarms for staged vs. committed queue state, automated operator scripts running staged migrations ($N$ before $N+1$) observe early execution and proceed before ownership PONR is established.

---

### NEW Traces Folded Open in v9.9.54.27

1. **Trace T73-1: BPF Read Race on Weakly-Ordered CPUs without Store/Load Barriers**
   - **Mechanism**: [plan.md:5066-5077](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5066-L5077)
   - **Sequence**: On ARM64 XDP, CPU 0 writes shadow/canonical values then advances `published_generation` cell without `smp_wmb()`. CPU 1 reads `published_generation` then value payload without `smp_rmb()`. Out-of-order memory visibility allows CPU 1 to observe the updated `published_generation` before the value payload store completes, matching uninitialized or stale BPF map memory.

2. **Trace T73-2: Empty Successor Snapshot Failsafe Vacuum**
   - **Mechanism**: [plan.md:5623-5628](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5623-L5628)
   - **Sequence**: Authority process crashes and restarts on a new host/process incarnation. The successor initializes with an empty local fence table and broadcasts its fence snapshot. Per rule (c), every peer interprets absence from the snapshot as explicit release by authority, instantly lifting all active fences across the cluster.
