VERDICT: PLAN NO


---

### Q1 (PREPARING contract)
**UNSOUND**
* **Evidence:** [plan.md:5481-5504](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5481-L5504), [plan.md:8449-8457](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8449-L8457)
* **Rationale:** The plan specifies that a dead/stalled owner's `PREPARING` is reclaimed by any worker via a CAS of `PREPARING → EXPIRED`, followed by candidate-conditional cleaning of the dead candidate's shadow space across multiple maps (`bpf_map/mod.rs:48`, `poll_descriptor/mod.rs:2578`, `session_import.rs:169`). However, the plan fails to state an intermediate `CLEANING(reclaimer_id)` state (or `EXPIRED → CLEANING → free` transition). While a reclaiming worker W4 is executing multi-map deletions for an `EXPIRED` reservation, a third worker W3 observing `EXPIRED` can issue a new `PREPARING` CAS on the same root record and begin staging into shadow slots currently being cleared by W4, corrupting W3's new staging.

---

### Q2 (root ABI + mint authority)
**SOUND**
* **Evidence:** [plan.md:4101-4120](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4101-L4120), [plan.md:5562-5584](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5562-L5584), [plan.md:8458-8471](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8458-L8471)
* **Rationale:**
  1. **Odd-writer recovery scope:** [plan.md:5583](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5583) explicitly bounds the odd-state window to the root record write duration (~100ns, "sub-microsecond"), not multi-millisecond shadow staging. Dependents stage invisibly in shadow space before the atomic flip on the root record (`bpf_map/mod.rs:48`).
  2. **Mint authority & Liveness:** The RG0-primary node is the sole mint authority ([plan.md:4101-4104](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4101-L4104)). Standalone nodes act as self-authoritative RG0-primary. During peer-down / ISSU / partition, non-primary nodes queue new RG mints with operator visibility (`show` + alarm/log alerts, `group_state.go:20`). Incarnation mismatches on convergence are resolved via quiesced remove/re-add transactions ([plan.md:4109-4115](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4109-L4115)).

---

### Q3 (required_version + permit + floor)
**UNSOUND**
* **Evidence:** [plan.md:4220-4249](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4220-L4249), [plan.md:6330-6352](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6330-L6352), [plan.md:6449-6475](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6449-L6475), [plan.md:8472-8491](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8472-L8491)
* **Rationale:**
  1. **Partition convergence ordering:** While the floor state `contiguous_high_water` is monotone and merged via `FLOOR_SYNC` (frame 45, [plan.md:6344-6346](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6344-L6346)), the plan does not enforce an explicit wire/processing message ordering requiring `FLOOR_SYNC` to be processed BEFORE un-drained delayed journal `Active` records upon reconnect (`sync_conn_read.go:96`). If a delayed `Active(R10)` frame arrives and processes before `FLOOR_SYNC` updates Node B's local floor, `Active(R10)` evaluates against Node B's stale local floor and is accepted, erroneously re-fencing R10.
  2. **Permit revocation handling:** The helper-owned per-RG permit is taken at packet entry and held through upsert ([plan.md:6450-6452](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6450-L6452)). If a drain deadline expires and revokes held permits ([plan.md:6474](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6474)), a packet suspended in slow-path processing (`inspect.rs:1455`, `slow_path.rs:213`) that resumes post-revocation lacks an atomic permit re-validation check before calling `install.rs:179`, risking illegal upsert into a newly elected generation.

---

### NEW TRACES FOLDED OPEN BY v9.9.54.33

1. **Third-Worker PREPARING Race During EXPIRED Reclaim Cleanup**
   * **Code lines:** [plan.md:5489-5492](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5489-L5492), [plan.md:8452-8455](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8452-L8455) (`bpf_map/mod.rs:48`, `poll_descriptor/mod.rs:2578`, `session_import.rs:169`)
   * **Trace:** Worker W4 observes W2's expired lease and CASes `PREPARING → EXPIRED`. W4 starts deleting W2's shadow entries across maps. Because no `CLEANING` state exists, W3 CASes `EXPIRED → PREPARING` and begins writing new candidate shadow entries into slots W4 is actively deleting.

2. **Unordered FLOOR_SYNC vs Delayed Active Journal Frame Processing on Convergence**
   * **Code lines:** [plan.md:6344-6352](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6344-L6352), [plan.md:8489-8491](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8489-L8491) (`sync_conn_read.go:96`, `sync_conn_gen.go:398`)
   * **Trace:** Node A clears R10 and advances its high-water line during a partition. Upon convergence, Node A sends `FLOOR_SYNC` (frame 45) alongside delayed pre-partition `Active(R10)` journal entries. If Node B receives or processes `Active(R10)` prior to applying `FLOOR_SYNC`, `Active(R10)` is checked against Node B's pre-convergence floor line and accepted.

3. **Un-revalidated Slow-Path Packet Resumption After Permit Revocation**
   * **Code lines:** [plan.md:6450-6460](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6450-L6460), [plan.md:8479-8483](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L8479-L8483) (`session/lookup.rs:105`, `session/install.rs:179`, `inspect.rs:1455`, `slow_path.rs:213`)
   * **Trace:** Packet P acquires a helper per-RG permit and enters slow-path reassembly/delivery. The HA drain times out, revoking all held permits and advancing election. When P resumes, it executes its upsert (`install.rs:179`) without checking if its held permit was revoked, polluting the state table of the new generation.
