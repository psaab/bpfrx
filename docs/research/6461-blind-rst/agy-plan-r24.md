**Verdict: PLAN YES**

### 1. Dual-Active Mixed-Version Delete Immunity Trace
* **E2 Survival:** **Yes**, E2 survives. When the old node emits a gen-based invalidation delete for $E_1$ (tuple $T$), the new node checks the local entry under key $T$. Because $E_2$ is locally authoritative (`locally-born` or `SharedPromote`), the new v9.9.8 immunity rule suppresses the gen-based delete on the new node, preserving $E_2$.
* **$E_1$ Standby Cleanup:** **Yes**, cleaned up correctly without harming $E_2$. Before $E_2$ is re-seeded, $E_1$'s standby copy is non-locally-authoritative (`SyncImport`), so gen-based deletes apply. When $E_2$ is re-seeded locally, $E_2$ replaces $E_1$'s standby entry at `install.rs:139`/`322`. Since $E_1$ standby and $E_2$ cannot coexist at the same table key, once $E_2$ is installed it is protected by local-authority immunity.

### 2. Escrow Lifetime & Dataplane Restoration Trace
* **Restoration Path:** On config rejection, the coordinator aborts reconcile and restores the previous known-good dataplane.
* **Replay Execution:** Bring-up of the restored dataplane (`coordinator/reconcile/bringup.rs:421`) runs the session snapshot replay. Restored workers execute `verify-and-retain` during replay, consuming the escrowed NAT allocations and transferring holds to the restored dataplane.
* **Coverage:** Every non-fatal reconcile abandonment brings up a restored dataplane that completes replay consumption. (Full helper process crashes lose state by design and are out of scope).
