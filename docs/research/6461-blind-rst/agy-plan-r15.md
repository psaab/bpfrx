### Verdict
**PLAN YES** (0 findings)

---

### Verification of v9.4 / v9.5 Additions

1. **Commit-Time NAT Check (Atomic Verify-and-Retain & Refcount Machinery)**
   - **Implementability**: Fully implementable against [`nat/allocator.rs`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L810-L1840). Allocation state is governed by `self.shared.live` (`Mutex<PortAllocatorLiveState>`), containing `live_by_flow: HashMap<SourceNatFlowKey, LiveAllocation>`. Adding a `holders: u32` refcount to `LiveAllocation` allows an atomic `verify_and_retain(&flow, translated)` method under `shared.live.lock()` to verify `existing.translated == decision.translated` and increment `holders` in a single critical section.
   - **Commit Paths**: No commit path acquires/removes instead of retaining. All shared-decision consumers (`materialize_shared_session_hit`, `install_reverse_session_from_forward_match`, ICMP embed paths, `keep_transient`, and prewarm/replication upserts) execute atomic verify-and-retain at commit under the allocator lock and set `nat_hold: true` on installed entries. Reaps decrement `holders` under the lock; port freeing occurs only when `holders == 0`.

2. **30s Batched Push, Probation, & Monotone Horizon**
   - **Family-Clock Stamping**: Refused (closing-flagged) materializations explicitly skip updating the family liveness clock (`last_touch_ns`). Stamping requires a committed non-close packet or event.
   - **Horizon Shortening**: Refused materializations set `probation: bool = true` on the 20s opening-window entry. The 30s batched push explicitly skips entries where `probation == true` until a committed non-close packet clears the flag. Additionally, updates to `expires_after_ns` on the canonical family record enforce a monotone max (`max(stored, pushed)`), guaranteeing the timeout horizon is non-decreasing.
   - **Remaining Leak Paths**: None. All paths from a refused materialize to family-clock stamping or horizon shortening are eliminated.
