VERDICT: PLAN NO


### Question Evaluations

#### Q1 (Two-Phase Journal + 32-Byte Record): UNSOUND
- **File:Line Evidence**: [docs/research/6461-blind-rst/plan.md:4922-4945](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4922-L4945), [docs/research/6461-blind-rst/plan.md:4005-4018](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4005-L4018), [docs/research/6461-blind-rst/plan.md:6840-6847](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6840-L6847).
- **Flaws**:
  1. *Atomicity vs Multi-Point Publish*: The plan specifies that `STAGED` transitions to `INSTALLED` "ONLY after canonical publication" at `poll_descriptor/mod.rs:2578, :2591`. However, shared-map publish (`:2578`) and sibling worker publish (`:2591`) are separate, non-atomic publish steps. If an error occurs between `:2578` and `:2591`, treating the failure as pre-publication (rolling back `STAGED`) leaves a published ghost entry in the shared map at `:2578`; treating it as post-publication leaves a half-published `INSTALLED` record missing from sibling workers.
  2. *Byte-Identity Enforcement*: The claim that frame-32 payload IS the transcript capability record byte-for-byte relies on "golden vectors cover the wire encoding" (`:4016-4018`). Golden vectors are test assertions, not a unified, single-encoder compile-time invariant, allowing separate wire serializers and transcript hashers to drift without compiler enforcement.

#### Q2 (Counted Scope + DIRTY Carry): UNSOUND
- **File:Line Evidence**: [docs/research/6461-blind-rst/plan.md:5383-5409](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5383-L5409), [docs/research/6461-blind-rst/plan.md:4952-4966](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4952-L4966), [docs/research/6461-blind-rst/plan.md:1957-1981](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1957-L1981), [docs/research/6461-blind-rst/plan.md:6848-6858](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6848-L6858).
- **Flaws**:
  1. *ALL-Sentinel vs. Per-Element Clearance*: The plan specifies `count=0` as the `ALL` sentinel (`:5384`). When a clearance ACK arrives for a specific subset (e.g., `{2}` at `:5407`), if the pending fence is stored as the `count=0` sentinel, a set-subtraction clearance cannot carve out `{2}` without expanding `count=0` into explicit RG elements at mark time or maintaining an explicit exception set, neither of which is specified.
  2. *Authoritative-Absence Proof*: For a `DIRTY` ticket bound to `(ticket generation, SessionIdentity)` where public tuple P has been reissued to E3 (`:1976-1981`), evaluating identity absence alone (`:4964`, `:1957-1960`) clears E1's `DIRTY` ticket without checking whether tuple P is currently owned by E3. If E1 was live on a partitioned segment, clearing the ticket based on identity absence fails to detect the tuple ownership conflict.

#### Q3 (Canonical Repair-ID): UNSOUND
- **File:Line Evidence**: [docs/research/6461-blind-rst/plan.md:4036-4050](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4036-L4050), [docs/research/6461-blind-rst/plan.md:5969-5979](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5969-L5979), [docs/research/6461-blind-rst/plan.md:6858-6862](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6858-L6862).
- **Flaw**:
  1. *Receipt Dedup Key Mismatch*: The plan defines `repair_id` as the 16-byte pair `(sender_incarnation u64, request_seqno u64)` (`:4043`). However, the completed-repair receipt is explicitly keyed by the 32-byte 4-field tuple `(repair_id, journal_epoch, terminal_seqno)` (`:5969-5970`). A retransmitted `JOURNAL_END` carrying the same `repair_id` but an updated/different `journal_epoch` or `terminal_seqno` fails the 4-field receipt key lookup. Under `:5976-5978`, unmatched terminal frames with no active obligation are discarded without re-emitting `JOURNAL_ACK`, causing sender retransmission timeouts.

---

### New Traces Folded Open by v9.9.54.24

1. **Pre-Publication Rollback / Shared-Map Ghost Trace**
   - **Locations**: [docs/research/6461-blind-rst/plan.md:4910-4945](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4910-L4945); `poll_descriptor/mod.rs:2449, :2578, :2591`
   - **Trace**: Minting a `STAGED` record at ticket creation precedes multi-point dataplane publication. If local forward installation (`:2449`) succeeds but subsequent shared-map (`:2578`) or sibling worker (`:2591`) publication fails, rolling back the `STAGED` record frees the NAT allocation while leaving partially published forward/shared entries exposed.

2. **Decision-ACK Serialization Edge vs. Class Latching Trace**
   - **Locations**: [docs/research/6461-blind-rst/plan.md:4473-4480](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4473-L4480), [docs/research/6461-blind-rst/plan.md:6792-6798](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L6792-L6798)
   - **Trace**: In v9.9.54.24, v2 latches `TENTATIVE` at exchange and `COMMITTED` only when `CAPABILITY_DECISION_ACK` completes serialization on the setup stream. If connection loss occurs after the responder enqueues the ACK but before physical wire serialization completes, the responder revokes the tentative v2 class while the initiator (having received/processed the ACK) considers v2 committed, producing a version mismatch across reconnects.

3. **Receipt Key Lookup Discard Loop Trace**
   - **Locations**: [docs/research/6461-blind-rst/plan.md:4047-4050](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L4047-L4050), [docs/research/6461-blind-rst/plan.md:5969-5979](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L5969-L5979)
   - **Trace**: Retransmitted `JOURNAL_END` frames with matching `repair_id` but modified `journal_epoch` or `terminal_seqno` fail the 4-field receipt key lookup (`(repair_id, journal_epoch, terminal_seqno)`). Because unmatched terminal frames are discarded, `JOURNAL_ACK` is never returned, wedging the peer in an un-ACKed retransmission loop.
