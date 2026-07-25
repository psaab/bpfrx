**Verdict**: **PLAN YES**

### (1) Two-Phase Stop Verification (`teardown.rs` & `worker/loop_body`)
* **Quiesce-without-destruct**: Does **not** exist today. `tear_down` (`teardown.rs:80`) calls `stop_inner(false)` which immediately signals `stop=true` and joins/destructs worker threads (`worker_manager.rs:146`). A non-destructive quiesce state (workers halt new packet commits while remaining alive) must be added.
* **Unconsumed Command Queue Tokens**: If unconsumed commands in worker command queues carry hold tokens at quiesce, workers must drain pending command queues during phase (1) quiesce (or handoff must extract queue tokens) into side-maps before phase (2) handoff. Otherwise, worker thread join/destruction would trigger RAII `Drop` on unconsumed queue items, releasing holds prematurely instead of transferring them to escrow.

### (2) Keeper Accounting & Deadline-Conversion Attack Analysis
* **Attack Trace**: Worker $W_{\text{slow}}$ stalls $\rightarrow$ replay deadline converts $W_{\text{slow}}$'s pending command for allocation $A$ to `Rejected` $\rightarrow$ pending count hits 0 $\rightarrow$ escrow keeper releases $\rightarrow$ allocation $A$ refcount drops to 0 and frees $\rightarrow$ port $P$ is reused by allocation $B$. $W_{\text{slow}}$ wakes up later and attempts `verify-and-retain`.
* **Outcome**: **Fails cleanly**. Under the allocator lock, $W_{\text{slow}}$'s atomic `verify-and-retain` checks if the live allocation matches decision $A$. Because the live allocation is now $B$ (or unallocated), $B \neq A$, verification fails inside the critical section, `verify-and-retain` returns an error, and $W_{\text{slow}}$ aborts installation without incrementing refcounts or re-creating a hold on reused port $P$.
