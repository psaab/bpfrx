I am going to check the current permission grants to see what access we already have.
I will request read permission on `/home/ps/git/bpfrx` to view source code files and the research plan.
I will view the plan.md file in the research directory to read the proposed plan.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around `stop_inner` (line 206) to see how WireGuard control threads are stopped, joined, and cleared.
I will view lines 470 to 570 in `userspace-dp/src/afxdp/coordinator/mod.rs` to understand the `spawn_wg_control_threads` logic and how `self.wg_control_threads` is managed.
I will view lines 571 to 600 in `userspace-dp/src/afxdp/coordinator/mod.rs` to see the end of the `spawn_wg_control_threads` function.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` around `refresh_runtime_snapshot` (lines 710 to 800) to see how it invokes `spawn_wg_control_threads`.
I will view `userspace-dp/src/afxdp/coordinator/refresh_bindings.rs` to see what `refresh_bindings` does and where it is called.
I will use grep to search for references to `refresh_bindings` to identify all its call sites.
I will view `userspace-dp/src/server/helpers.rs` around line 17 to check the context of the `refresh_bindings` call.
I will search for `refresh_status` call sites using grep to see what triggers it.
I will view `userspace-dp/src/server/lifecycle.rs` around line 248 to see the main tick/poll loop of the daemon.
I will search for `Status` or status polling in the Go code to understand how and when `refresh_bindings` is invoked from Go.
I will view the Go userspace tunnel implementation file to verify the Go-side interfaces, snapshot generation, and how WG interfaces are managed.
I will view the `userspace-dp/src/afxdp/forwarding_build/wg.rs` file to see how WG engines are built and how they are associated with IDs.
I will search for `tunnel_endpoints` to see how it is defined and populated from the Go snapshot.
I will view `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` to confirm how `TunnelEndpointSnapshot` values are loaded and how `id` is mapped on the Rust side.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` to see how the control loop handles errors and exits.
I will view `userspace-dp/src/server/handlers/snapshot.rs` to see what is executed under the state lock when applying snapshots and getting status.
I will grep for `Status` methods in `pkg/dataplane/userspace` to understand how the Go side interacts with the userspace dataplane's status endpoint.
I will use a corrected regex to search for the Status function in `pkg/dataplane/userspace`.
I will perform a simpler literal query for `Status(` to avoid regex parsing issues.
I will view the `Status` method in `pkg/dataplane/userspace/manager.go` around line 1748 to see how Go queries status.
I will search for `NewSampler` in the `pkg` directory to find the status polling interval.
I will view `pkg/fwdstatus/sampler.go` to find the default polling loop frequency.
I will search for the definition of `SampleInterval` to confirm its value.
I will search for `handle_stream` in the Rust server code to see how requests are handled and if they are single-threaded or concurrent.
I will view `userspace-dp/src/server/handlers/mod.rs` around line 44 to see how streams/requests are processed and if any locks are held.
I will view lines 111-150 of `userspace-dp/src/server/handlers/mod.rs` to see where `refresh_status` is called for `status` requests.
I will view the end of `userspace-dp/src/server/handlers/mod.rs` to see where `refresh_status` is called for the "status" request.
I will view the main loop of `wg_control_loop` in `userspace-dp/src/afxdp/coordinator/wg_control.rs` to analyze its exit latency and blocking points.
I will view lines 301 to 400 of `userspace-dp/src/afxdp/coordinator/wg_control.rs` to analyze `dispatch_inbound` and see if it has any blocking operations.
I will search for `open_tun` definition in the codebase.
I will search for `open_tun` in `userspace-dp/src/` to see where it is imported from.
I will view `open_tun` in `userspace-dp/src/slowpath.rs` to see what syscalls or blocking operations it performs.
I will view the `reconcile` module around line 120 to see the context of `refresh_bindings` there.
I will search for the definition of `reconcile_status_bindings` using grep.
I will view `reconcile_status_bindings` in `userspace-dp/src/server/helpers.rs` starting at line 381 to see if it reconciles the WG control threads.
I will search for all call sites of `spawn_wg_control_threads` to see when and how WG control threads are started.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` around line 446 to verify how WG control threads are spawned on bringup.
I will view `pkg/routing/tunnel.go` to understand how Go handles the WireGuard TUN creation and deletion, and if there are any conditions under which an interface deletion is ignored or skipped.
I will run a command to list branches and inspect the commit log to see the state of `research/1866-wg-teardown` and `engineer/1736-wg-interop`.
I will check if there are any local or remote branches relating to #1736/1868 or #1865.
I will run `git diff origin/master..engineer/1736-wg-interop` to see what changes PR #1868 makes, particularly to `wg_control.rs`.
I will view the `wg_control.rs` file on the `engineer/1736-wg-interop` branch around `wg_control_loop` to see how the socket is bound and used.
I will search for any commits in the repository history that reference #1865 to see what telemetry is queued.
I will search for `buildTunnelEndpointSnapshots` in the Go codebase using grep.
I will view `pkg/dataplane/userspace/builder.go` around line 42 to see how the ConfigSnapshot is constructed and where `interfaces` comes from.
I will grep for `ApplyConfig` in the `pkg` directory to see where it is called and how the apply sequence is ordered.
I will view `ApplyConfig` in `pkg/dataplane/userspace/manager.go` to see the sequence of applying config snapshots and managing kernel resources.
I will search for the definition of the `Compile` method in `pkg/dataplane/userspace/manager.go`.
I will view the `Compile` method in `pkg/dataplane/userspace/manager.go` from line 535 to 585 to see how the snapshot is sent to the Rust helper.
I will view lines 586 to 650 of `pkg/dataplane/userspace/manager.go` to see the rest of `Compile`.
I will view lines 651 to 700 of `pkg/dataplane/userspace/manager.go` to see the remainder of `Compile`.
I will view lines 700 to 750 of `pkg/dataplane/userspace/manager.go` to inspect the `UpdatePolicyScheduleState` method.
# Hostile Adversarial Plan Review

This is a **REVIEW-ONLY** pass for **xpf issue #1866**. No files have been written or modified.

---

## 1. Verification of Plan Defect 1 (D1)

The plan asserts in D1 that a control thread exiting early leaves its map entry in `wg_control_threads`, permanently blocking respawns under an unchanged identity. This is **VERIFIED** by the source code:

1. **Early Exit Site**: In [wg_control.rs:L93-102](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/wg_control.rs#L93-L102), if the UDP socket binding fails (e.g. `EADDRINUSE`), the loop returns immediately:
   ```rust
       let socket = match bind_wg_socket(listen_port) {
           Ok(sock) => sock,
           Err(err) => {
               record_local_tunnel_exception(
                   &recent_exceptions,
                   &tunnel_name,
                   format!("wg_bind_listen_port:{listen_port}:{err}"),
               );
               return;
           }
       };
   ```
2. **Permanent Blocking in Coordinator**: The exited thread's handle remains registered in `self.wg_control_threads` at [mod.rs:L568](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs#L568). When a new snapshot is applied with the same configuration identity, the engine `Arc` is reused. 
   - The stale filter at [mod.rs:L509-L514](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs#L509-L514) compares the pointers:
     ```rust
             .filter(|(id, (_, engine_ptr))| desired.get(id) != Some(engine_ptr))
     ```
     Since the engine pointer matches, the ID is not marked stale and the thread is not stopped/joined.
   - The spawn loop at [mod.rs:L530-L532](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs#L530-L532) then skips spawning:
     ```rust
                 if self.wg_control_threads.contains_key(&id) {
                     continue;
                 }
     ```
   The dead control thread is never cleaned up, and no fresh thread is ever spawned. D1 is correct.

---

## 2. Attack on the 1/s `refresh_bindings` Liveness-Sweep Design

### Attack A: Broken Backoff State Leak (Fatal Defect)
In Change 1 and 2, the plan cleans up finished threads by removing them from `self.wg_control_threads`:
```rust
for id in finished {
    if let Some(mut t) = self.wg_control_threads.remove(&id) { ... }
}
```
**The flaw**: Once the entry is removed from the map, its `last_spawn_attempt_ns` timestamp is dropped and forgotten. In the subsequent spawn loop, `self.wg_control_threads.contains_key(&id)` will return `false`, completely bypassing the 3-second backoff logic.
- **Consequence**: Under persistent `EADDRINUSE`, the coordinator will attempt a fresh `thread::spawn` on **every single status poll** (1/s tick) and **every single status command/FIB bump** query, causing a tight thread/FD recreation loop and CPU/lock contention.
- **Fix**: The coordinator map must retain the entry as a tombstone (e.g. setting `handle` to `Option<LocalTunnelSourceHandle>` and clearing it to `None` on exit), preserving `last_spawn_attempt_ns` to gate the next retry.

### Attack B: Mutex Contention via Synchronous Spawning
Calling `thread::spawn` (via `spawn_supervised_aux`) within `refresh_bindings` runs synchronously under the `state` mutex lock (held in [handlers/mod.rs:L83](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/mod.rs#L83)). Under OS scheduler latency or resource exhaustion, a blocking `clone()` call inside the Linux kernel to allocate the thread stack can take several milliseconds, stalling all other control-socket messages (like CLI queries or metrics pulls).

---

## 3. Sharper Diagnosis of the Residual Unknown (§4c)

The plan notes that the delete-commit leaving the thread running could not be reproduced in-process. There is a sharper, structural explanation for this bug:

### Finding: The Defer-Workers Reconciliation Gap
When a configuration changes the binding plan (meaning `same_plan` is `false`), and `defer_workers` is `true` (e.g., waiting for `RETH` interface MAC resolution), the snapshot handler in [snapshot.rs:L109-L115](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs#L109-L115) skips the worker bring-up phase:
```rust
        if defer_workers {
            eprintln!(
                "CTRL_REQ: apply_snapshot defer_workers=true — skipping worker spawn (RETH MAC pending)"
            );
        } else {
            reconcile_status_bindings(guard);
        }
```
Because `reconcile_status_bindings` is skipped, the coordinator's internal `self.forwarding` state is **never updated** with the new snapshot. If Go subsequently aborts the commit due to a timeout (e.g. `RETH` MAC resolution fails) and never sends the follow-up snapshot, the helper retains the old `forwarding` state containing the `wg0` endpoint. Thus, the coordinator never triggers `spawn_wg_control_threads` to stop the thread.

---

## 4. Answers to open questions in Section 11

1. **Tick placement**: Riding `refresh_bindings` is acceptable only if the backoff tracking is corrected (see Attack A). The check itself is a cheap atomic read on the join handle. Without fixing the map removal bug, this placement will leak thread spawning onto route updates (FIB bumps) and status checks.
2. **Residual-unknown stance**: Hardening and logging are the right lean because D1 is verified and severe. However, the plan must also address the **Defer-Workers Reconciliation Gap** (Finding 2) which is the likely cause.
3. **Retry-forever on EADDRINUSE**: Retry-forever with a 3-second backoff is correct and standard for routing engines. A hard cap would leave the tunnel permanently dead if the port was temporarily grabbed by a kernel process.
4. **`is_finished()` sufficiency**: `is_finished()` is sufficient. The control loop in [wg_control.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/wg_control.rs) is non-blocking on all sockets and TUN fds, and strictly bounds loops to `WG_RX_BURST = 64` before re-evaluating `stop.load()`. No locks are held indefinitely, so the thread will exit within a 1.5ms window of receiving the stop signal.
5. **Map-entry semantics for spawn-failure**: Immediate cleanup is racy. A tombstone mechanism (`Option<LocalTunnelSourceHandle> = None`) inside the map entry is the clean shape to preserve backoff timestamps without losing state.
6. **Sequencing vs #1868**: The refactoring in #1868 returns `(socket, socket_is_v6)` from `bind_wg_socket` and updates helper signatures. The factored helper `spawn_one_wg_control_thread` must capture and thread `socket_is_v6` into the spawned closure. Landing after #1868 is mandatory.

---

## 5. Peer/PR Interactions & Hidden Risks

### Finding 3: Alphabetical ID Instability (Cascade Handshake Reset)
In [tunnels.go:L42, L114](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/pkg/dataplane/userspace/tunnels.go#L42), the Go side assigns sequential integer IDs to endpoints after sorting interfaces alphabetically:
```go
	var nextID uint16 = 1
...
		nextID++
```
If `wg0` is deleted, the ID of `wg1` shifts from 2 to 1. In `populate_wg_engines`, the comparison in [wg.rs:L56-L65](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/wg.rs#L56-L65) is performed against ID 1 of the prior state (which was `wg0`). Because the identities differ, the reuse check returns `false`, causing **every subsequent WireGuard engine's session to be destroyed and rebuilt**, triggering handshake storms and transient packet drops on unrelated tunnels.

---

### Verdict: PLAN-NEEDS-CHANGES

### Findings
1. **Broken Backoff State Leak**: Removing the `WgControlThread` handle from the map on early exit drops the backoff timestamp. Under persistent bind failures, this causes a thread-spawn storm (1/s or faster).
2. **Defer-Workers Reconciliation Gap**: If `defer_workers` is true on plan changes, the helper skips coordinator snapshot updates, leaking the old control thread.
3. **Alphabetical ID Instability**: Interface list sorting and sequential integer assignment cause tunnel IDs to shift when unrelated interfaces are added/removed, resetting active WG transport sessions.
