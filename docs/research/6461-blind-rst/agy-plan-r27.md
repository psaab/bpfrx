### Verdict: PLAN YES

Verification of the three newest additions in plan v9.9.11 §5.2:

1. **`requires_identity_enforcement` Frame Tag** ([sync.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync.go#L467), [sync_conn_write.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go#L114-L268)):
   - `sendCh` (`chan []byte`) and `deleteJournal` (`[][]byte`) currently store opaque `[]byte` raw wire frames.
   - Wire messages encode `msgType` at byte offset `msg[4]` ([sync_protocol.go](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_protocol.go#L79-L91)). Tagging queued/journaled entries by checking `msg[4]` or wrapping them in a struct `(msg []byte, requiresIdentity bool)` is fully consistent with current serialization and allows per-write/per-replay connection capability enforcement.

2. **Final-Outcome Family Cleanup (`installed_count == 0`)** ([install.rs](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L295-L322)):
   - In a mixed-outcome fanout (W0 installs E1 and retains its hold, W1 rejects): W1's rejection now only decrements `pending_count`.
   - At terminal transition (`pending_count == 0`), final-outcome cleanup runs ONLY if `installed_count == 0`. Because W0 installed E1 (`installed_count >= 1`), cleanup skips, preserving W0's live entry and the shared family.

3. **Allocator Migration by Collision-Domain Compatibility** ([source.rs](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L829-L873), [allocator.rs](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1617)):
   - `PortAllocator` instances maintain independent occupancy state. Allocator B can reserve a tuple currently held by allocator A using `reserve_flow` / `reserve_address_only`.
   - Reserving the tuple into allocator B *before* releasing allocator A's hold ensures the tuple is continuously held, completely eliminating the [source.rs:829](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/source.rs#L829) / [allocator.rs:1617](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L1617) race condition where a concurrent `allocate_translation` could grab the unreserved tuple.
