VERDICT: PLAN YES

---

### Q1 (barrier pinning)
**Verdict:** **SOUND**
* **File:Line Evidence:** [`docs/research/6461-blind-rst/plan.md:1208-1237`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1208-L1237)
* **Analysis:** B's refusal release is **time-based** ("sized to the SLOW detector (≥ 2-missed-ack bound + RTT margin)", lines 1230-1231), NOT state-based on waiting for incoming bulk state. If both nodes enter the barrier and raise obligations in the same window, both nodes suppress outbound dials and refuse inbound dials during their respective time-based barrier windows. Because the release is driven by timer expiration rather than waiting for the peer's bulk sync, both barriers expire deterministically. Once the timers expire, outbound dial suppression ends, dial retries succeed, and neither node deadlocks waiting for the other's bulk.

---

### Q2 (sendLoop quiesce-and-join)
**Verdict:** **SOUND**
* **File:Line Evidence:** [`pkg/cluster/sync_conn_write.go:268-302`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go#L268-L302), [`docs/research/6461-blind-rst/plan.md:1293-1306`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1293-L1306)
* **Analysis:** In `pkg/cluster/sync_conn_write.go:268-302`, `sendOne` retries writing an already-dequeued frame over `getActiveConn()` and checks `<-ctx.Done()` on every iteration (line 272). Joining `sendLoop` closes/cancels `ctx`, which breaks `sendOne` out of its retry loop immediately even during a fabric flap (`conn == nil` or write error), preventing the join from hanging. Because incremental emission is paused, the pre-cutoff queue is flushed/discarded, and the snapshot (the state cutoff) is taken *after* `sendLoop` joins, any un-sent frame's state is subsumed by the snapshot. No pre-cutoff frame can land post-`BulkEnd`.

---

### Q3 (pending-release edge)
**Verdict:** **SOUND**
* **File:Line Evidence:** [`userspace-dp/src/nat/allocator.rs:999-1018,:1318`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/nat/allocator.rs#L999-L1018), [`docs/research/6461-blind-rst/plan.md:1648-1678`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1648-L1678)
* **Analysis:** All reservation checks and ticket cancellations/claims execute inside the allocator's critical section (`shared.live` mutex). If a `PendingRelease(g, ticket)` has already committed and freed `P` at `allocator.rs:1318`, a subsequent `NoChange` exact-reservation check for `(K,P)` evaluates `P`'s occupancy under the lock. If a third flow claimed `P` in the interim (`allocator.rs:1007-1018`), the reservation check detects `P` occupied and rejects the claim/import (`allocator.rs:1682, :1688`), preventing reverse-NAT port aliasing. If `P` is un-claimed, `(K,P)` is reserved with a genuinely new allocation generation.

---

### Q4 (registry retirement + conversion race)
**Verdict:** **SOUND**
* **File:Line Evidence:** [`userspace-dp/src/session/install.rs:542`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/session/install.rs#L542), [`userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:29`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs#L29), [`docs/research/6461-blind-rst/plan.md:1603-1634`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1603-L1634)
* **Analysis:** 
1. The executing worker rehydrates a strong reference (`GroupHold` / `Arc` clone) from the durable coordinator registry via `AllocationRef` prior to command execution. Even if the registry retires the entry during execution, the worker retains its strong `Arc` clone, ensuring the allocation is not freed under live command execution.
2. The `DirectHold` $\rightarrow$ `GroupHold` conversion is evaluated atomically under the allocator critical section using the receipt $\times$ variant transition matrix (`plan.md:1625-1630`). If a demoted entry is re-promoted locally (`install.rs:542`) before a peer replacement (`upsert_synced.rs:29`) lands, the peer replacement evaluates the incumbent's `DirectHold` tag and `SessionIdentity` under the lock: `NoChange` converts the direct hold to a `GroupHold` without uncredited minting, while an identity mismatch triggers identity-conditional replacement (`Replaced(old_state)` dual-holding ownership until commit).

---

### NEW Traces Folded Open in v9.9.25

1. **Barrier Inbound/Outbound Pinning Race**
   * **Location:** [`docs/research/6461-blind-rst/plan.md:1215-1237`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1215-L1237)
   * **Trace:** During reconnect, node B refusing inbound dials via a passive "never-answer" silence wedges node A's connection-timeout accounting and backoff detection. Furthermore, if node B initiates its own outbound dial during its barrier, it creates an un-cleared slot on B, causing node A's subsequent reconnect install to compute `wasDisconnected == false` and skip cold-prime bulk sync.
   * **Fold Fix:** Node B's barrier refusal is explicitly pinned: (i) on accept, B sends an **immediate-close** to avoid wedging A's dialer retry loop; (ii) B **suppresses its own outbound dial** for the barrier duration so no slot is occupied on either node, guaranteeing A's post-barrier install computes both-empty and triggers cold-prime bulk sync.

2. **SendLoop Retry-Path Post-BulkEnd Leakage**
   * **Location:** [`docs/research/6461-blind-rst/plan.md:1296-1306`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/docs/research/6461-blind-rst/plan.md#L1296-L1306), [`pkg/cluster/sync_conn_write.go:268-302`](file:///home/ps/git/kimi-xpf/.claude/worktrees/6461-research-blind-rst/pkg/cluster/sync_conn_write.go#L268-L302)
   * **Trace:** Pausing the `sendCh` queue before taking a repair snapshot fails to stop a frame that has already been dequeued into `sendLoop`'s inner `sendOne` retry loop (`sync_conn_write.go:268`). If a fabric flap occurs during the cutoff, `sendOne` continues retrying that pre-cutoff frame and writes it *after* `BulkEnd` completes on the active connection, corrupting recency.
   * **Fold Fix:** The repair cutoff requires a **QUIESCE-AND-JOIN** of `sendLoop`. The cutoff cancels `sendOne` via `ctx.Done()`, joins the thread, flushes the pre-cutoff queue, and takes the snapshot before driving the bulk and resuming incremental writes.
AGY EXIT: 0
