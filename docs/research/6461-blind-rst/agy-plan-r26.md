Verdict: PLAN YES

### Findings & Verification

1. **Delete Suppression Capability Bit ([sync_auth.go:314-370](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go#L314-L370))**:
   - **Verification**: In [performSyncHandshake](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_auth.go#L314-L370), `hello = append(hello, syncAuthVersion, 1)` transmits byte 1 as a flag byte (`keyed`).
   - **Fit**: A capability bit (e.g. `capEnforceIncIdDeletes = 1 << 1`) fits cleanly into byte 1 or as an extended payload field. Unnegotiated legacy peers send raw frames or `keyed=0`, enabling new nodes to suppress Close, invalidation, and conditional deletes toward them.

2. **Helper-Authoritative Atomic Snapshot ([session_manager.rs:12-18](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs#L12-L18))**:
   - **Verification**: [SessionManager](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs#L12-L18) maintains separate `Arc<Mutex<FastMap>>` locks for `synced`, `nat`, and `forward_wire`. No helper-side atomic read path producing rows+aliases in one lock span exists today.
   - **Lock Alignment**: It must be added. Adding it is consistent with [SessionManager](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs#L12-L18) by acquiring locks in canonical hierarchy order (`synced` → `nat` → `forward_wire` → indexes) within a single helper method.

3. **Coordinator-Global Seqno & Cursor Safety ([session_manager.rs:12](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/session_manager.rs#L12))**:
   - **Verification**: Shared maps have independent mutexes. Using an `AtomicU64` for a coordinator-global seqno is safe **only if** `fetch_add` occurs **inside** the map's insertion lock.
   - **Cursor Risk**: If `AtomicU64::fetch_add` is called outside the map lock, out-of-order lock acquisition allows seq 101 to be inserted before seq 100. A cursor scan advancing to seq 101 will permanently skip the late-inserted seq 100 entry in subsequent `seqno > cursor` scans. Allocating the seqno inside the insertion lock span guarantees monotonic cursor safety.
