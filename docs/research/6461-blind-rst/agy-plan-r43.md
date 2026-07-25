VERDICT: PLAN YES

### Q1: Reset Handshake
**Verdict:** SOUND  
**Evidence:** [docs/research/6461-blind-rst/plan.md:1313-1337](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1313-L1337), [1346-1350](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1346-L1350)  
- **Lost `RESET_GEN`:** Handshake rides the next connection setup (`plan.md:1327-1332`). Inbound repair obligations are durable and escalate with exponential backoff (`plan.md:1346-1350`).
- **Delayed `RESET_ACK`:** Node B reopens admission only after receiving `RESET_ACK(g)` or upon silence-timeout backstop (`plan.md:1323-1325`). Node A has already quiesced dialers, rejected inbound, and recorded both slots empty before ACKing (`plan.md:1320-1323`), preventing stale slot occupation.
- **Simultaneous `RESET_GEN`:** Both barriers are independent (A's barrier governs B$\to$A repair, B's governs A$\to$B repair), generations are node-scoped, and no tie-breaking is required (`plan.md:1333-1337`).

---

### Q2: Slot Membership Token
**Verdict:** SOUND  
**Evidence:** [docs/research/6461-blind-rst/plan.md:1425-1445](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1425-L1445)  
- **Revoked mid-handler:** Presented tokens are checked for validity and repair-era authorization atomically at publication time (both in Go and Rust), discarding paused handlers at publication (`plan.md:1438-1442`).
- **ABA protection:** Minting uses a per-node monotonic `u64` counter, guaranteeing tokens are never reused after revocation (`plan.md:1443-1445`).

---

### Q3: Single Counter + Row Version CAS
**Verdict:** SOUND  
**Evidence:** [docs/research/6461-blind-rst/plan.md:1967-2005](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1967-L2005)  
- **Row version scope:** Row versions are per-entry on `SyncedSessionEntry` (`plan.md:1980-1985`), preventing false serialization of unrelated conversions across the coordinator.
- **Lock ordering & CAS domain:** The cell swap is count-preserving across variants (`plan.md:1996-1997`). The canonical version/CAS executes *after* releasing the allocator lock (`plan.md:1997-1999`), obeying the strict no-nesting rule. On CAS failure, the cell state is swapped back via `Converted(old_state)` undo (`plan.md:2000-2005`).

---

### NEW Traces Folded Open by v9.9.31

1. **Legacy Peer Silence Teardown Trace** ([plan.md:1304-1312](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1304-L1312)): Unconditional silence teardown disconnects quiet legacy peers that do not acknowledge heartbeats ([pkg/cluster/sync_test.go:4721](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_test.go#L4721)). Closed by capability-scoping absolute silence teardowns to negotiated pairs only.
2. **Finite Local Barrier Endpoint Race Trace** ([plan.md:1313-1326](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1313-L1326)): A finite node-local barrier cannot prove the remote peer observed both slots empty (a late retry accepted and immediately closed just before barrier end can occupy a slot until timeout). Closed by negotiating `RESET_GEN`/`RESET_ACK` handshakes.
3. **Peer-Global Monotone Counter Stream Ambiguity Trace** ([plan.md:1425-1445](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1425-L1445)): A peer-global monotone counter cannot differentiate a pinned repair stream from a subsequent non-repair connection. Closed by minting opaque, per-fabric slot-membership tokens.
4. **Post-Cut Journal Readiness Discharge Race Trace** ([plan.md:1532-1548](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1532-L1548), [1655-1660](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1655-L1660)): Clearing readiness on a clean `BulkEnd` lets post-cut deltas delayed on another fabric land after readiness clears. Closed by requiring explicit `JOURNAL-END` marker validation carrying repair ID and terminal sequence.
5. **Asymmetric Peer Capacity Rebuild Loop Trace** ([plan.md:1582-1593](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1582-L1593)): Assuming a full table always fits on receiver nodes fails for asymmetric peers, creating an infinite rollback/retry loop during shadow rebuilds. Closed by negotiating capacity during handshake and reporting a defined degraded state.
6. **Two-Counter Duality Cell Double-Release Trace** ([plan.md:1967-1978](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1967-L1978)): Treating `DirectHold` and `GroupHold` as separate counters allows pre-conversion direct tokens to outlive Arc finalizers or double-release credits. Closed by collapsing hold types to reference flavors over a single per-credit cell counter.
7. **Worker-Local Install Epoch Canonical Disconnect Trace** ([plan.md:1980-1996](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1980-L1996)): Using worker-local `install_epoch` for canonical conversion rechecks fails because `SyncedSessionEntry` lacks worker epoch visibility. Closed by adding per-entry canonical row versions and CAS domain commits.
AGY EXIT: 0

--- Q4/Q5 half ---
VERDICT: PLAN YES

### Q4 (Capacity + Quiesced Rebuild): SOUND
- **Quiesce Serialization**: The rebuild quiesce and migration gate quiesce serialize on the coordinator's single-threaded lifecycle, eliminating cross-quiesce deadlock (`docs/research/6461-blind-rst/plan.md:1612-1615`).
- **Tuple Collision / Merge Precedence**: Precedence is locally-authoritative-WINS. The shadow store carries only peer-owned state; locally-authoritative entries admitted after shadow creation are preserved, and any shadow row aliasing the NAT tuple is discarded by the incarnation/identity fence (`docs/research/6461-blind-rst/plan.md:1607-1611`).
- **Capacity Handshake**: Asymmetric pairs negotiate capacity at handshake and report a defined operator-visible degraded state rather than entering an infinite retry loop (`docs/research/6461-blind-rst/plan.md:1582-1592`).

### Q5 (JOURNAL-END + Arm-Then-Recheck): SOUND
- **ACK Loss & Retry Semantics**: Marker validation at the receiver is idempotent. If the receiver's ACK is lost, the sender's persisted outbound obligation re-drives the repair; the receiver detects the duplicate repair ID, re-ACKs, and avoids re-mutating (`docs/research/6461-blind-rst/plan.md:1539-1544`).
- **Mid-Stage-2 Re-import**: Quarantine state and retry queue entries are incarnation-scoped (`SessionIdentity`). A SAME-identity re-import cancels the active quarantine, while a DIFFERENT-identity import creates a new family epoch without interfering with stage 2 cleanup of the old identity (`docs/research/6461-blind-rst/plan.md:2283-2288`).
- **Terminal Sequence & Ordering**: Inbound repair obligations clear strictly at `JOURNAL-END` validating exact repair ID and terminal sequence (`docs/research/6461-blind-rst/plan.md:1533-1537`, `1654-1658`); quarantine flags arm before holder count reads (`docs/research/6461-blind-rst/plan.md:2279-2282`).

### NEW TRACES
None. All traces identified across prior iterations are closed by explicit mechanisms in v9.9.31 and v9.9.32.
AGY EXIT: 0
