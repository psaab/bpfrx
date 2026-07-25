### Plan v9.8 Verification Verdict

**VERDICT: PLAN YES** (0 findings)

---

### Verification Analysis

#### 1. Escrow Boundary & Ordering Validation
* **Teardown & Snapshot Ordering:** In [`teardown.rs:80`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs#L80), `coord.stop_inner(false)` is invoked **before** [`PreservedReconcileState`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs#L92) is constructed. Workers stop and join first, guaranteeing that the teardown snapshot ([`teardown.rs:56`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs#L56)) runs entirely **quiesced**.
* **Replay Ack & Escrow Release:** In [`coordinator/mod.rs:761`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/coordinator/mod.rs#L761) (`replay_synced_sessions`), queued commands produce per-command install acknowledgements. Replicas verify and increment their refcount upon install. The escrow keeper token holds the underlying allocation refcount elevated until replay outcomes are fully processed, preventing any premature allocation release window.

#### 2. Helper-Owned External Mutations
* **Go Side Deletions:** Audited Go dataplane and cluster packages (`pkg/dataplane/`, `pkg/cluster/`).
* Go-side `DeleteWithCompanionsV4/V6` calls occur exclusively for non-close operations (e.g., [`DeleteReasonClusterStale`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_gen.go#L503) or Go conntrack GC/admin clear).
* None of these paths perform direct session-map close deletions that bypass the fenced helper transaction, preventing stale E1 decision exploitation.

#### 3. Per-Worker Side Map & Token Lifecycle
* **PortAllocator Sharing:** In [`nat/allocator.rs:742-746`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L742-L746), `PortAllocator` wraps `shared: Arc<PortAllocatorShared>`.
* `NatHoldToken` stored in the per-worker side map retains an `Arc<PortAllocator>`. Even if a worker thread panics, stack unwinding executes RAII `Drop` for the side map, correctly decrementing allocation refcounts on the thread-safe `PortAllocatorShared` inner state. Allocation live state safely outlives any panicking worker frame without leaking or premature freeing.
