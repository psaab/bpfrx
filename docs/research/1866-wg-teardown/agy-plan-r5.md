I will start by viewing the plan file at `/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md` to understand the v5 proposal, the three questions in section 11, and the current implementation direction.
I will view the files in the codebase to find concrete evidence and perform the code review. I'll read the coordinator's WG spawn implementation starting at line 480 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see what parameters are captured by `wg_control_loop` and how threads are currently managed.
I will view the `wg_identity_unchanged` implementation in `userspace-dp/src/afxdp/forwarding_build/wg.rs` to verify how engine reuse matches the plan.
I will view the rest of `userspace-dp/src/afxdp/forwarding_build/wg.rs` to see where `wg_identity_unchanged` is called.
I will view the `wg_control_loop` signature and structure in `userspace-dp/src/afxdp/coordinator/wg_control.rs`.
I will search for the definition of `TunnelEndpoint` in the codebase to see what properties it contains.
I will view the `TunnelEndpoint` struct definition to see all of its fields and make sure we don't miss any spawn-parameters.
I will find and view `bind_wg_socket` in `userspace-dp/src/afxdp/coordinator/wg_control.rs`.
I will view lines 250 to 300 of `userspace-dp/src/afxdp/coordinator/wg_control.rs` to see the complete `bind_wg_socket` logic.
I will search for `wg_control_threads` in `mod.rs` to verify its current definition.
I will view lines 240 to 270 of `userspace-dp/src/afxdp/coordinator/mod.rs` to see how `stop_inner` shuts down the threads.
I will search for `socket_is_v6` in the codebase to see how it is used.
I will search for `socket_is_v6` in the Go codebase.
I will list all permissions to see what actions I can perform.
I will run `git status` and check the git branches in the `/home/ps/git/bpfrx/.claude/worktrees/1866-research` worktree to confirm the git history and branches.
I will check the git log on the current branch to see the commit history and check if we are at commit 3b7aeaabf as described in the user prompt.
I will view `refresh_runtime_snapshot` and surrounding code in `userspace-dp/src/afxdp/coordinator/mod.rs` to verify that `self.forwarding` holds the prior engine while the new forwarding state (with the new engine) is constructed.
I will view lines 650 to 710 in `userspace-dp/src/afxdp/coordinator/mod.rs` to find the exact code where `self.forwarding` is populated.
I will search for `handlers/snapshot.rs` or the server's snapshot handler file in the codebase.
I will view `userspace-dp/src/server/handlers/snapshot.rs` lines 95 to 130 to see the exact context of the `defer_workers` branch.
I will search for `reconcile_status_bindings` in the codebase to understand its behavior.
I will view `reconcile_status_bindings` in `userspace-dp/src/server/helpers.rs` to see what it does.
I will view lines 60 to 95 of `userspace-dp/src/server/handlers/snapshot.rs` to understand how snapshot same-plan matches are processed.
I will view the `reconcile` implementation in `userspace-dp/src/afxdp/coordinator/mod.rs` to verify how it updates the forwarding state.
I will view lines 400 to 480 of `userspace-dp/src/afxdp/coordinator/mod.rs` to find the `reconcile` method definition.
I will search for the definition of the `reconcile` method in `userspace-dp/src/afxdp/coordinator/mod.rs`.
I will search for `reconcile` in `userspace-dp/src/afxdp/coordinator/mod.rs` without `fn` to see the match.
I will search for `impl Coordinator` in `userspace-dp/src/afxdp/coordinator/mod.rs`.
I will view lines 69 to 150 of `userspace-dp/src/afxdp/coordinator/mod.rs`.
I will search for `reconcile` files in the coordinator directory to find the implementation of `reconcile`.
I will list the contents of the `reconcile` subdirectory to locate the `reconcile` method definition.
I will view the `reconcile/mod.rs` file to see the entry point for coordinator reconciliation.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs` to see what is torn down during reconciliation.
I will grep for `spawn_wg_control_threads` in the `reconcile` directory to see where it is invoked during worker bring-up.
I will search for `Mutex<ServerState>` or lock patterns in the server handlers to ensure that all handlers (including snapshot applies and status polls) serialize on a single mutex lock.
I will view `userspace-dp/src/server/handlers/mod.rs` to verify the single-mutex lifecycle invariant.
I will view the rest of the handler function in `userspace-dp/src/server/handlers/mod.rs` to confirm the scope of the lock.
I will view `refresh_status` in `userspace-dp/src/server/helpers.rs` to verify that the liveness sweep is called synchronously inside `refresh_status`.
I will view lines 61 to 100 of `userspace-dp/src/server/helpers.rs` to locate the liveness sweep call site.
I will view lines 101 to 140 of `userspace-dp/src/server/helpers.rs` to locate the liveness sweep.
I will view lines 141 to 180 of `userspace-dp/src/server/helpers.rs`.
I will view lines 181 to 220 of `userspace-dp/src/server/helpers.rs`.
I will search for all occurrences of `refresh_status` in the Rust codebase to make sure it is only called under the serialized control mutex.
### Final Plan Review (Round 5) for Issue #1866

Below is the adversarial analysis of the **v5 research plan** for the WireGuard tunnel teardown. This review is read-only, pressure-testing the design, attachment semantics, and concurrency models against the codebase.

---

### 1. Verification of the v5 Fix
The v5 plan introduces several key structural fields to [WgControlEntry](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md#L239-L262):
```markdown
239: struct WgControlEntry {
240:     /// Live (or finished-but-unswept) thread. None = tombstone: no
241:     /// thread, entry retained for backoff continuity + identity.
242:     handle: Option<LocalTunnelSourceHandle>,
...
250:     engine_ptr: usize,
...
257:     spawned_ifindex: i32,
258:     spawned_tunnel_name: String,
```
This addresses the residual gaps by making both the apply-time stale check and the liveness sweep checks aware of the **TUN attachment** (the interface's Linux name and its `ifindex`).

---

### 2. Answers to Section 11 Questions

#### Question 1: Attachment Semantics
> **(1) Attachment semantics**: the stale condition now keys on `(engine_ptr, spawned_ifindex, spawned_tunnel_name)` and the coherence tuple adds `interface/linux_name/ifindex`. Sound and complete — or is there a remaining spawn-parameter (anything else captured by the `wg_control_loop` closure: listen_port and peer endpoint are already in the crypto-identity tuple) whose divergence escapes both checks?

**Analysis:**
The capture of parameters for the supervisor thread occurs at [userspace-dp/src/afxdp/coordinator/mod.rs:537-564](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs#L537-L564):
*   `thread_tunnel_name` (Linux name) is resolved via `logical_ifindex` and is validated against `spawned_tunnel_name`.
*   `listen_port` and `peer_endpoint` are compared directly as part of the crypto-identity validation tuple.
*   `engine` (`Arc<WgEngine>`) contains the cryptographic keys, allowed IPs, and persistent keepalive configured in [userspace-dp/src/afxdp/forwarding_build/wg.rs:85-94](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L85-L94). Since any configuration change there triggers a rebuild of the engine Arc in `populate_wg_engines`, `engine_ptr` is guaranteed to differ. 
*   `tunnel_endpoint_id` (the key) is structurally mapped to the map keys.
*   Other non-WireGuard `TunnelEndpoint` fields (e.g., `redundancy_group`, `source`, `destination`, `key`, `ttl`, `transport_table`) do not affect the initialization or runtime parameters of the `WgEngine` control loop.

`socket_is_v6` is a runtime dynamic variable resolved *internally* within the thread by calling `bind_wg_socket` and does not need to be captured or checked at spawn time.

**Verdict:** The check is **sound and complete**; no spawn-parameter can diverge and escape detection.

---

#### Question 2: Remaining Incoherent-Spawn Sequence
> **(2) Remaining incoherent-spawn sequence**: any sequence left where a thread runs parameters the latest accepted snapshot does not describe?

**Analysis:**
Let's analyze the paths to spawn or maintain a control thread:
1.  **Apply-time (`spawn_wg_control_threads`):** This is executed during a snapshot apply. The newly constructed `self.forwarding` state is structurally aligned with the snapshot being applied. Stale threads are stopped and joined before any spawns occur.
2.  **Periodic Sweep (`reconcile_wg_control_liveness`):** This sweep runs inside `refresh_status`, which is called inside the request handlers.
    *   As shown in [userspace-dp/src/server/handlers/mod.rs:82-168](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/mod.rs#L82-L168), all request handling and status refreshes run inside a single critical section guarded by `state.lock()`.
    *   The sweep is constrained to only respawn existing **tombstones** where the target endpoint ID's identity and attachment parameters match the stored snapshot (`state.snapshot`) and the current forwarding state. If there is a defer window (where `state.snapshot` contains a new key/identity/attachment, but `self.forwarding` hasn't been reconciled to it), the sweep detects the mismatch and skips the respawn.
    *   Under a `defer_workers = true` apply, **Change 2b** (invoked at [userspace-dp/src/server/handlers/snapshot.rs:109-115](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs#L109-L115)) prunes deleted endpoints immediately, and does not spawn new ones, leaving any remaining unchanged tunnels running on the old configuration (which matches the still-active worker configuration).

**Verdict:** There is **no path** for an incoherent spawn.

---

#### Question 3: Anything Else
> **(3) Anything else** that blocks PLAN-READY?

**Analysis:**
No other issues are present:
*   The TAI64N high-water propagation invariant is preserved.
*   Port releases are handled cleanly.
*   Observability has been solved via Go-side and Rust-side dual-boundary logging (Change 3).
*   The 3s backoff prevents CPU starvation on persistent bind failures.

---

### Conclusion
The v5 plan closes the final gaps with robust attachment tracking and snapshot coherence checks.

PLAN-READY
