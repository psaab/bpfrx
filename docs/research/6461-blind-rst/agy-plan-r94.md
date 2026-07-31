# AGY hostile plan-review — round 94 (v10.11.0)

Reviewer: AGY (direct binary). Verdict: UNSOUND — four editorial stragglers naming retracted shapes as live (§5.8 reservation-condition fragment; §11 Q1's active-rule list; §11 Q3(a)'s verification prompt; §3 site-row-3 reference). All substance verified SOUND: master's retained-lookup parity confirmed (session_glue/mod.rs:1178-1261), the close-aware gate end-to-end walk shows zero FIN/RST-driven state mutation, the in-place overdue adopt closes the pin without split-brain, and all four stress tests (cold-neighbor spray, single-packet flow, second-packet-during-buffer, close-after-purge) pass. Stragglers folded in v10.11.1.

## Verbatim review

UNSOUND

### Review Summary

A consistency sweep of [`docs/research/6461-blind-rst/plan.md`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md) (v10.11.0) against the codebase at [`userspace-dp/src/afxdp/session_glue/mod.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1178-L1261) confirms that the core architectural mechanics—specifically master's retained-lookup dispatch, the close-aware purge gate, and the in-place overdue adopt—are sound. However, the document contains residual text fragments that describe the retracted v10.4.1 same-dispatch re-entry and the retracted v10.10.0 reservation-success condition as live design in sections 3, 5.8, and 11.

---

### Verification Checklist Analysis

#### (a) Master Retained-Lookup Dispatch & Parity Claim
- **Code Trace:** In [`session_glue/mod.rs:1178-1261`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/mod.rs#L1178-L1261), when `keep_transient` is true, master executes `purge_translated_synced_hit(...)` and sets `resolved = hit.lookup.clone()`. It returns `Some(ResolvedFlowSessionDecision)` with `created: false, install_failed: false`.
- **Behavior:** Master dispatches packet 1 on the retained lookup without installing, deriving, allocating, publishing, or seeding. Packet 2 arrives after `sessions.delete(key)` has executed, yielding a clean miss (`sessions.lookup(...) -> None`). Packet 2 performs the genuine clean miss derivation, allocation, install, publication, Open, and seed.
- **Parity Confirmation:** The document's v10.11.0 claim that retracting the v10.4.1 re-entry to master-verbatim matches master's exact 2-packet behavior is verified.

#### (b) Close-Aware Gate End-to-End Walk (No Re-entry)
1. **Resolve Phase:** A FIN/RST packet matching a peer-synced translated entry causes `should_keep_synced_hit_transient` to return `false` (purge skipped). The packet resolves as `ExistingResolved` backed by the shared entry.
2. **Demote Validation:** [`close_seq_plausible`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L942) evaluates the segment against the forward entry's anchor. Because peer-synced provenance carries no trusted anchor (`trusted == 0`), the validator returns `false` (REFUSE-DEMOTE). No `closing`/`reset` flags are set, `last_seen_ns` is untouched, no wheel re-queue occurs, and no Close delta is emitted.
3. **MissingNeighbor Arm:** The packet reaches the arm head as `ExistingResolved` and buffers with stored decision $P_1$ (no NAT derivation/allocation, no install, no publication).
4. **Transmission:** Upon ARP/ND resolution, the buffered packet transmits $P_1$.
5. **State Mutation:** Zero FIN/RST-driven state mutation occurs on peer-synced provenance.

#### (c) In-Place Overdue Adopt
- When [`materialize_shared_session_hit`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1241) (site 2c) encounters an overdue probation entry $K$ ($D \le \text{now\_ns}$), adopting $S_2$'s decision and metadata in-place while preserving $K$'s `last_seen_ns`/`expires_after_ns` verbatim and skipping wheel re-queue closes the split-brain (local entry and packet forwarding both use $S_2$) and prevents a 1-packet-per-tick spray from re-queueing $K$ ahead of GC.

#### (d) End-State Stress Testing
- **Close spray at cold neighbor:** All close packets retain shared backing, refuse demote, buffer at MissingNeighbor with $P_1$, and transmit on resolution without state mutation.
- **Single-packet flow:** Bare closes hit `#4400` `strict_syn_check_drops_new_flow` on clean miss and drop. Peer-synced hits retain shared backing, refuse demote, buffer/deliver with $P_1$, and emit no Close delta.
- **Second packet while first is buffered:** Non-close packet 2 purges shared backing, dispatches on retained decision $P_1$, and leaves the local session table entry deleted. Packet 3 (clean miss) installs fresh decision $P_2$. Packet 1 transmits buffered decision $P_1$ upon ARP resolution (master parity).
- **Close arriving after non-close purged:** Packet 1 (non-close) purges shared backing. Packet 2 (bare close) finds a clean miss (`sessions.lookup(...) -> None`) and drops at `#4400`.

---

### Findings & Document Inconsistencies

1. [`plan.md:L1557-1559`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1557-L1559): **Unexcised v10.10.0 reservation-success condition in §5.8.**
   - *Trace:* Section 5.8 states: `; retention requires the row's synced reservation to have SUCCEEDED — reservation-failed rows take master's flag-agnostic purge even for closes, v10.10.0)`.
   - *Issue:* This contradicts the v10.11.0 fold established in §5.6 ([`plan.md:L1431`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1431)), §7 ([`plan.md:L1865`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1865)), §9 ([`plan.md:L2077`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2077)), and §11 ([`plan.md:L2457`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2457)), which retracted the reservation-success requirement in favor of unconditional close-aware retention.

2. [`plan.md:L2423`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2423): **Stale reference to `ResolvedWithoutLocalBacking` re-entry as live design in §11 Question 1.**
   - *Trace:* Section 11 Question 1 lists `the ResolvedWithoutLocalBacking cold/miss re-entry` as an active Part-B rule.
   - *Issue:* This contradicts the header ([`plan.md:L3-8`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L3-L8)), §5.2 ([`plan.md:L694`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L694)), §5.8 ([`plan.md:L1586`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1586)), and §9 ([`plan.md:L2138`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2138)), which state that RWoLB re-entry was retracted to master-verbatim in v10.11.0.

3. [`plan.md:L2441-2448`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L2441-L2448): **Stale verification prompt in §11 Question 3(a).**
   - *Trace:* Question 3(a) asks reviewers to verify whether `ResolvedWithoutLocalBacking re-enters the cold/miss pipeline from the packet (as if the resolve had returned None)... safe under full re-entry?`.
   - *Issue:* This prompts review of the retracted v10.4.1 same-dispatch re-entry mechanism instead of asking for verification of the v10.11.0 master-verbatim retained-lookup dispatch.

4. [`plan.md:L427`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L427): **Editorial straggler in §3 Table Row 3.**
   - *Trace:* Section 3 site row 3 states `when the tuple carries peer-synced provenance (ResolvedWithoutLocalBacking re-entry or ReplacedSyncedLocal displacement)`.
   - *Issue:* Because RWoLB re-entry was retracted to master-verbatim in v10.11.0, citing it as a live `re-entry` in §3 is an editorial inconsistency.
