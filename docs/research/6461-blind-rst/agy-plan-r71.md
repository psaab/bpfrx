VERDICT: PLAN NO


### Q1 (Commit Cell + Split Carriage)
* **Status**: **UNSOUND**
* **File:Line Evidence**: [docs/research/6461-blind-rst/plan.md:4956-4984](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4956-L4984), [docs/research/6461-blind-rst/plan.md:5451-5468](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5451-L5468), [docs/research/6461-blind-rst/plan.md:7016-7033](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7016-L7033).
* **Evaluation**:
  1. *r70 Q1/Q2 Folded*: Yes, folded at lines 7016–7033.
  2. *Lookup-Mask Coverage Attack*: The plan asserts that "EVERY lookup masks with" the commit cell ([plan.md:4974](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4974)), but fails to audit or specify how lockless and BPF lookup paths (such as `materialize_shared_session_hit` at [session_glue/mod.rs:1092](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/session_glue/mod.rs#L1092), reverse-alias lookups, NAT64 forward-wire, and flow-cache seed) enforce the commit-cell mask without memory-ordering race windows against hidden writes.
  3. *Two-Channel Ordering Attack*: The plan specifies `INCOMPLETE-EXTENSION` handling when a heartbeat summary arrives before per-RG detail ([plan.md:5464-5466](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5464-L5466)), but specifies **no** buffering or immediate-application ordering rule for when frame 41 `RETIREMENT_NOTICE` on the TCP sync channel arrives *before* the heartbeat summary on UDP. Immediate application without summary context leaves the fence state incomplete.

---

### Q2 (Marker Layouts + Handshake Sequences)
* **Status**: **UNSOUND**
* **File:Line Evidence**: [docs/research/6461-blind-rst/plan.md:5837-5840](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5837-L5840), [docs/research/6461-blind-rst/plan.md:5974-5988](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5974-L5988), [docs/research/6461-blind-rst/plan.md:6018-6027](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md:6018-6027), [docs/research/6461-blind-rst/plan.md:7034-7039](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7034-L7039), [docs/research/6461-blind-rst/plan.md:7097-7099](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7097-L7099).
* **Evaluation**:
  1. *v0 Receiver Frame-Length Tolerance Attack*: `BulkEnd` is expanded to 24 bytes carrying the canonical repair-ID pair ([plan.md:6025](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6025)). While the legacy `bulk_epoch u64` is preserved at offset 0, the plan omits specifying whether a legacy v0 receiver (expecting an 8-byte payload at `sync_bulk.go:183`, `sync_conn_read.go:205`) accepts trailing payload bytes or rejects the 24-byte frame due to payload-length mismatch.
  2. *v1-Proof AUTH_PROOF Input & Golden Vectors Attack*: `AUTH_PROOF_v2` is fully specified with exact byte formulas and normative golden vectors ([plan.md:5837](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5837), [plan.md:7097-7099](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7097-L7099)). However, `v1-proof` `AUTH_PROOF` is only described as "nonce-only proof" ([plan.md:5810](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5810), [plan.md:5981](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5981)) without stating the exact byte input formula or providing normative golden vectors for v1.

---

### Q3 (Receipt Re-ACK + Class Scoping)
* **Status**: **UNSOUND**
* **File:Line Evidence**: [docs/research/6461-blind-rst/plan.md:5241-5248](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5241-L5248), [docs/research/6461-blind-rst/plan.md:6115-6126](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6115-L6126), [docs/research/6461-blind-rst/plan.md:7041-7045](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7041-L7045), [docs/research/6461-blind-rst/plan.md:7057-7068](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L7057-L7068).
* **Evaluation**:
  1. *r70 Q3 + T2 Folded*: Yes, folded at lines 7041–7045, 7057–7068.
  2. *Post-Restart Empty Receipt Map Attack*: `plan.md` notes that node restart recreates receipt maps empty (`manager.go:372, :386`, [plan.md:5244](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5244)). While failover transfer receipts receive explicit two-stage write-ahead persistence ([plan.md:5247-5270](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5247-L5270)), completed-repair receipts for session repair remain in-memory only ([plan.md:6117](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6117)). Line 6122 states that an un-matched `JOURNAL_END` post-restart is discarded, but `plan.md` leaves open whether the completed-repair receipt should be persisted write-ahead or if a post-restart drop of `JOURNAL_ACK` forces an uncoordinated re-repair loop.

---

### NEW Traces Folded Open by v9.9.54.25

1. **Unwind Failure Orphan in Hidden Write Rollback**
   * **Location**: [plan.md:4981-4984](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4981-L4984), `poll_descriptor/mod.rs:2578, :2591`, `bpf_map/mod.rs:82`
   * **Trace**: Worker W0 writes hidden BPF alias rows for publish points 1..K-1. At publish point K, a BPF map insertion error occurs. W0 triggers pre-publication rollback to unwind points 1..K-1. If the BPF map deletion for point $i < K$ fails during the unwind sequence, W0 leaves a hidden entry in the BPF map. Because the ticket remains in `STAGED` state and never transitions to `INSTALLED`, worker-liveness rollback eventually cleans up userspace staged structures, but the orphaned BPF map entry is never reclaimed, causing silent BPF map leak and key collisions for future session allocations.

2. **Sync TCP Stall / UDP Summary Election Deadlock**
   * **Location**: [plan.md:5464-5466](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5464-L5466), `heartbeat_manager.go:306`, `election.go:172`
   * **Trace**: Node A issues a heartbeat with a 33-byte summary specifying `EXPLICIT` fence for RG 1. Node B receives the heartbeat UDP frame and enters `INCOMPLETE-EXTENSION` state for RG 1, fencing RG 1 election. If the TCP sync connection stalls or drops before frame 41 `RETIREMENT_NOTICE` arrives, Node B remains in `INCOMPLETE-EXTENSION` state indefinitely while heartbeat UDP traffic continues. RG 1 remains permanently fenced, preventing failover promotion even if Node A crashes.

3. **Stream Desynchronization on Downgraded 37-Byte BulkStart**
   * **Location**: [plan.md:6018-6024](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6018-L6024), `sync_conn_read.go:71-94`, `sync_conn_read.go:183`
   * **Trace**: A v1-capable peer sends a 37-byte `BulkStart` frame containing `declared_count_present` at offset 32. On a connection downgraded to legacy v0 rules, the receiver reads only 8 bytes (`bulk_epoch u64`) at `sync_conn_read.go:183`. The remaining 29 unread payload bytes linger in the TCP stream buffer, causing the framing loop (`sync_conn_read.go:71-94`) to parse payload bytes as the next frame's header, corrupting the connection stream and triggering immediate connection reset.
