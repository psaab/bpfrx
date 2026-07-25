**Verdict: PLAN YES**

### 1. Helper-Authoritative Conditional Selection & Predicate Staleness
- **Policy-Correct Behavior**: Policy-driven deletions (e.g., policy invalidation) evaluate whether *live sessions* violate updated rules, whereas state-driven cleanups (e.g., Close/RST deltas) target a specific historical session instance ($E_1$). 
- **Atomic Helper Selection**: Evaluating the predicate helper-side under the canonical lock tests the live alias ($E_2$) atomically. If $E_2$ matches the invalidated policy, selecting and deleting $E_2$ is correct because the updated policy no longer permits $E_2$. If $E_2$ does not match the predicate, evaluation returns false and $E_2$ is preserved.
- **Incarnation Fencing**: The helper emits peer delete deltas carrying the selected `(origin_process_nonce, flow_incarnation_id)`, ensuring peer standby nodes apply deletions only if their stored incarnation matches what was actually selected.

### 2. CLAIM Rule & Execution Window Boundedness
- **Bounded Execution Window**: Workers claim pending replay commands immediately prior to executing them on their non-blocking event loop (`loop_body/mod.rs`). In-memory execution (verify-and-retain and side-map insertion) completes in microseconds, emitting `Installed` or `Rejected` to decrement the keeper's pending count.
- **Worker Death Conversion**: If a worker panics or stalls, supervisor watchdog detection (`supervisor.rs:80, :98`) and RAII side-map unwind convert claimed-but-uncompleted commands into rejections and release escrow refcounts.
- **No Keeper Deadlock**: A command cannot remain claimed forever; healthy workers complete execution in bounded time, while unresponsive workers trigger supervisor death cleanup.
