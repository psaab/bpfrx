VERDICT: PLAN NO

### Q1 (Discharge Terminology): SOUND
- **Evidence**: [plan.md:L1460-L1485](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1460-L1485), [plan.md:L1708-L1715](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1708-L1715), [plan.md:L1978-L1993](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1978-L1993), [plan.md:L3906-L3924](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3906-L3924), [plan.md:L4340-L4346](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4340-L4346).
- **Evaluation**: All discharge clauses are direction-explicit. Receiver inbound-repair obligation and readiness clear ONLY upon applying `JOURNAL_END(repair_id, journal_epoch, terminal_seqno)` ([plan.md:L1474](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1474), [plan.md:L1978](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1978)). Sender outbound-bulk obligation and cold-prime latch clear ONLY upon receiving `JOURNAL_ACK` containing the matching immutable triple ([plan.md:L1482](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1482), [plan.md:L3919](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3919)). Bare `BulkAck(u64)` and negotiated `BulkEnd` explicitly never clear either obligation ([plan.md:L1985](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1985), [plan.md:L3907](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3907)). Line 1991 explicitly rules out "clean replacement bulk on its own", and line 4344 notes that `JOURNAL_ACK` supersedes all generic ACK-epoch discharge clauses.

### Q2 (Incarnation State Machine): SOUND
- **Evidence**: [plan.md:L1391-L1411](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1391-L1411).
- **Evaluation**: 
  - **Trace (`n1` stalls, `n2` completes, `n1` resumes)**: `n2`'s completion revokes `n1`'s handlers/lanes under `s.mu`, retires `n1`, and promotes `n2`. When `n1` resumes, its mutation recheck of `(node_id, incarnation, lane_token)` fails because `n1` is `retired` ("retired never readopted", [plan.md:L1408](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1408)).
  - **Drain vs connection death**: Lane revocation under `s.mu` marks state flags in memory synchronously; a natural connection death also closes the socket/lane under `s.mu`. Promotion does not wait for blocking network I/O, so it does not hang.
  - **High-water for `n3`**: Reset-generation high-water is maintained "PER INCARNATION" ([plan.md:L1409](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1409)), giving `n3` an independent high-water namespace.

### Q3 (Hello Transcript): UNSOUND
- **Evidence**: [plan.md:L1381-L1390](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1381-L1390), [plan.md:L3887-L3898](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3887-L3898).
- **Evaluation**: The plan states that the capability tuple gains `(node_id, process_incarnation)` and is authenticated within the `AUTH_PROOF` wrapper, but fails to specify the wire-level canonicalization (field ordering, integer byte-order/endianness, length prefixes, or domain separation string). Without a deterministic wire representation specification, two independent implementations or cross-architecture builds risk computing mismatched digests for identical logical hello messages, causing authentication drops on the reset lane.

### Q4 (Convergence Sweep): UNSOUND
- **Evidence**: [plan.md:L423-L1540](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L423-L1540), [plan.md:L3880-L3960](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3880-L3960).
- **Evaluation**: While §5.2 and §5.8 successfully eliminate blind RST/FIN demote DoS, SNAT mid-flow swaps, HA state desynchronization, and live session tuple reuse, the overall stack remains **UNSOUND** due to the hello transcript canonicalization under-specification (identified in Q3), which introduces an availability risk during HA connection setup.

---

### NEW Traces Folded Open by v9.9.41

1. **Hello Transcript Canonicalization / Wire Encoding Under-Specification**
   - **File:Line**: [plan.md:L1381-L1390](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1381-L1390), [plan.md:L3887-L3898](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3887-L3898) (`sync_auth.go:314`, `sync_auth.go:321`)
   - **Trace**: The hello transcript includes `(node_id, process_incarnation, capabilities, nonces)` signed inside `AUTH_PROOF`, but `plan.md` does not specify binary encoding, endianness, or field serialization order. Heterogeneous nodes or compiler versions can construct different byte layouts before hashing, causing `AUTH_PROOF` verification failures during reset-lane handshakes and preventing peer resync.

2. ** Goroutine I/O Block vs Synchronous Incarnation Promotion Lock Deadlock**
   - **File:Line**: [plan.md:L1392-L1410](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1392-L1410) (`sync_conn.go:388`, `sync_admission.go:66`)
   - **Trace**: Incarnation promotion requires `n2` to drain/revoke `n1`'s handlers/lanes under `s.mu`. If `n1`'s read/write goroutines in `sync_conn_read.go` are blocked on socket network I/O outside `s.mu` and `n2`'s drain synchronously awaits goroutine completion without forcibly closing `n1`'s socket first, `s.mu` will remain held, deadlocking the session registry and halting HA promotion.
AGY EXIT: 0
