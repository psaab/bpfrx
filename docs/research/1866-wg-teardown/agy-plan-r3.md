I will list the current permission grants to see what directories I can already access.
I will request read permission for `/home/ps/git/bpfrx` to view the plan and the source code files.
I will view the content of the plan file.
I will view the `userspace-dp/src/server/handlers/snapshot.rs` file to study the snapshot handling logic and confirm the sequence.
I will view the `userspace-dp/src/afxdp/coordinator/mod.rs` file to see how WG control threads are managed and the desired set is constructed.
I will list the files in the coordinator directory to see what modules we have.
I will view `wg_control.rs` to see the WireGuard control loop implementation and its exit conditions.
I will search for `refresh_status` to locate its definition and calls in the codebase.
I will view the `userspace-dp/src/server/helpers.rs` file to see the logic in `refresh_status`.
I will search for `should_run_afxdp` to find its definition and usages.
I will view `helpers.rs` around line 321 to see the `should_run_afxdp` implementation.
I will search for the definition of the `reconcile` function in the coordinator.
I will search for `fn reconcile` in the coordinator directory.
I will view `coordinator/reconcile/mod.rs` around line 64 to understand what coordinator reconcile does.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs` to see how snapshot state is applied to the coordinator.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` to see what happens during worker/thread bringup in a full reconcile.
I will view the end of `bringup.rs` to see where `spawn_wg_control_threads` is invoked.
I will view lines 800-1600 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see if there are any other WG control functions or periodic routines.
I will search for `wg_engines` to find where the WG engines are populated and where the populate gates are defined.
I will view the `userspace-dp/src/afxdp/forwarding_build/wg.rs` file to see the validation and hydration gates used during engine population.
I will search for the definition of the function that builds the forwarding state.
I will view `userspace-dp/src/afxdp/forwarding_build/mod.rs` around line 112 to see how `tunnel_endpoints` are processed.
I will view the `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` file to see how endpoint configuration rows are parsed.
I will search for `Mutex` or `ServerState` in `userspace-dp/src/server/handlers` to verify the single-mutex lifecycle guard invariant.
I will view `userspace-dp/src/server/handlers/mod.rs` to see how requests are handled and how the `ServerState` mutex is acquired.
# #1866 WireGuard Teardown adversarial Review (Round 3)

We have verified the Plan v3 ([docs/research/1866-wg-teardown/plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md)) against the userspace-dp source code. Below is the confirmation analysis.

---

### Analysis of the v2 vs v3 Defer-Workers Race

In **v2**, during a `defer_workers == true` window:
1. `userspace-dp/src/server/handlers/snapshot.rs:109-115` skips worker reconciliation and does not update `self.forwarding` in the coordinator.
2. Change 2b prunes `wg0` from `wg_control_threads` since it's absent from the newly applied snapshot.
3. However, `refresh_status` is executed. The liveness sweep in v2 constructed the desired set from the stale `self.forwarding` (which still listed `wg0`). Because the entry was missing from `wg_control_threads`, the sweep immediately recreated the entry and respawned/re-bound the thread.

In **v3**, the fix is:
> "the periodic sweep is tombstone-only — it never creates entries for ids absent from the map; entry creation happens exclusively at apply-time where forwarding and snapshot are coherent" (plan.md:11-14)

---

### Section 11 Confirmation Questions

#### 1. F7 Fix Completeness
*With the tombstone-only sweep, is there ANY remaining sequence (defer windows, stop/rebind handlers, rapid add/remove/add) where a thread is created against a desired set that does not reflect the latest applied snapshot?*

**No.**
* **Defer Windows (`same_plan == false` + `defer_workers == true`)**: The coordinator's `self.forwarding` remains stale because `reconcile` is bypassed. Change 2b (`prune_wg_control_threads_for_snapshot`) stops, joins, and removes the entry for the pruned tunnel from `wg_control_threads` (plan.md:282). The periodic liveness sweep `reconcile_wg_control_liveness` (plan.md:237) is **tombstone-only**: it only processes entries already existing in the map. Since the entry has been deleted by Change 2b, the sweep ignores it.
* **Defer Windows (`same_plan == true` + `defer_workers == true`)**: The `else` branch of `same_plan` in `userspace-dp/src/server/handlers/snapshot.rs:95` immediately calls `refresh_runtime_snapshot`, which updates `self.forwarding` and calls `spawn_wg_control_threads()` under the same lock transaction. Therefore, the forwarding state is never stale in the `same_plan` case.
* **Stop/Rebind Handlers**: If the daemon stops, `reconcile_status_bindings` calls `state.afxdp.stop()`, which executes `stop_inner` (`userspace-dp/src/afxdp/coordinator/mod.rs:206`), stopping, joining, and clearing the entire `wg_control_threads` map. When disarmed (`should_run_afxdp(&state.status)` is false), the sweep is gated and does not execute.
* **Rapid Add/Remove/Add**: If `wg0` is added, removed (deferred), and re-added (deferred), the `wg_control_threads` entry is removed on the first deletion and stays empty (not recreated by the tombstone-only sweep) until the next non-deferred apply runs a full `reconcile`, updating `self.forwarding` and spawning it coherently.
* **Mutex Serialization**: All handler paths and status checks run under the server state mutex (`userspace-dp/src/server/handlers/mod.rs:83`), ensuring no two control actions can execute concurrently.

---

#### 2. Tombstone Identity Semantics
*Pass-2 removes a tombstone whose recorded `engine_ptr` differs from the current engine (identity changed), resetting its backoff so the fresh identity spawns immediately. Any abuse path (e.g. identity-flapping config) where this defeats the backoff in a way that matters?*

**No.** 
* Resetting the backoff when the identity changes is correct and intended. When the operator pushes a configuration change (such as updating keys or switching ports to fix a bind issue), they expect the engine to be spawned immediately without waiting for a 3-second backoff.
* The backoff is designed to prevent tight-loop CPU/sys-log flooding when retrying the *same* failing configuration (e.g., EADDRINUSE on port bind) during periodic liveness ticks.
* An identity change requires an explicit configuration apply request from the Go control plane over the Unix domain socket (`userspace-dp/src/server/handlers/mod.rs:86`), which is not generated autonomously by the helper itself. Thus, it cannot trigger a high-frequency retry loop.

---

#### 3. Anything Else Blocking PLAN-READY
There are **no remaining blockers**.
* **Hydration gates matched**: The Change 2b prune check mirrors the populate gates in `userspace-dp/src/afxdp/forwarding_build/tunnels.rs:62-79` exactly:
```rust
            if endpoint.wg_listen_port == 0 {
                continue;
            }
            if decode_wg_key_hex(&endpoint.wg_local_privkey_hex, &mut wg_local_privkey).is_err() {
                continue;
            }
            if decode_wg_key_hex(&endpoint.wg_peer_pubkey_hex, &mut wg_peer_pubkey).is_err() {
                continue;
            }
```
* Unparsable `wg_endpoint` (hydrates to `None` for responder-only) and bad allowed-ips (filtered per-cidr in `tunnels.rs:71-76` but keeps the row) do not disqualify the endpoint, avoiding over-pruning.
* The design respects all invariants (single-mutex state mutations, bind/TUN work in aux thread, stop-gate, and tombstone-only liveness checks).

PLAN-READY
