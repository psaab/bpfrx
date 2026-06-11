I will view the plan file at `/home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md` to begin our adversarial review.
I will run a grep search to locate key WireGuard control and coordinator files in the repository.
I will view the `agy-plan-r1.md` file to review the details of the round 1 findings.
I will view the snapshot handler code in `userspace-dp/src/server/handlers/snapshot.rs` to verify the defer-workers behavior and how the proposed Change 2b fits in.
I will view `userspace-dp/src/server/helpers.rs` to understand what happens during `reconcile_status_bindings` and `refresh_status`.
I will view `userspace-dp/src/afxdp/coordinator/mod.rs` to understand the `Coordinator` struct, the methods `refresh_runtime_snapshot`, `spawn_wg_control_threads`, and how `wg_control_threads` is managed.
I will use a grep search to find the implementation of the `reconcile` method in the coordinator.
I will view the `reconcile` method implementation in `userspace-dp/src/afxdp/coordinator/reconcile/mod.rs` starting at line 64.
I will view `userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs` around line 440 to see how worker bring-up triggers WireGuard control thread spawning.
I will view `userspace-dp/src/afxdp/coordinator/wg_control.rs` to inspect the WG control thread implementation.
I will grep search for `populate_wg_engines` to see its exact logic and how it interacts with WG control thread lifecycle gates.
I will view `userspace-dp/src/afxdp/forwarding_build/wg.rs` around line 37 to see how WG engines are built and how they are validated.
I will search for `tunnel_endpoints` population in the codebase to see how it is parsed and built from `ConfigSnapshot`.
I will view `userspace-dp/src/afxdp/forwarding_build/tunnels.rs` to see how endpoints are populated.
I will search for `wg_engines` usage in the worker frame processing or datapath code to see how workers depend on the engines.
I will search for `.stop()` calls on the afxdp coordinator to see what triggers a stop.
I will view `userspace-dp/src/server/handlers/stop_workers.rs` to see how it stops the coordinator and workers.
I will view `userspace-dp/src/server/handlers/rebind.rs` to see its stop/restart interaction.
I will search for the status tick or background loop in the server to see if it acquires the lock.
I will view `userspace-dp/src/server/lifecycle.rs` around line 219 to see how the background tick is structured.
I will view lines 100 to 189 in `userspace-dp/src/server/lifecycle.rs` to see the background thread structure.
I will view `userspace-dp/src/server/handlers/mod.rs` around line 100 to see how control requests are dispatched.
I will view the beginning of `userspace-dp/src/server/handlers/mod.rs` to see what requests set `suppress_status`.
I will run `git log -n 5` inside the worktree directory to see the commit history and check if #1868 is present.
I will grep for `bind_wg_socket` on the current branch to see if the IPv6/v4 socket binding signatures have been updated.
# AGY Adversarial Review (Round 2)

This is a HOSTILE adversarial plan review (REVIEW-ONLY — no files are written or modified) of the v2 research plan for xpf issue #1866.

---

## 1. Verification of Round 1 Resolutions in v2

We have verified that each of the three Round 1 findings from `agy-plan-r1.md` is addressed in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md):

### Finding 1: Backoff State Leak → Spawn Storm
* **Resolution**: Map value is redesigned as a tombstone-capable entry containing `last_spawn_attempt_ns: u64` and `thread: Option<(LocalTunnelSourceHandle, usize)>`. The entry is kept when the thread finishes, retaining the backoff timestamp.
* **v2 Quote (Lines 171–173, 191–192)**:
  > `"the entry is removed ONLY when the endpoint leaves the desired set — a finished thread leaves a tombstone that preserves the backoff stamp"`
  > `"join (instant: thread done), set thread = None, keep the entry + stamp"`

### Finding 2: Defer-Workers Reconciliation Gap (Defect D4)
* **Resolution**: A new narrower coordinator pruning method is introduced to propagate removals even when worker bring-up is deferred.
* **v2 Quote (Lines 239–247)**:
  > `"Change 2b (fixes D4) — removal propagation on the defer-workers path"`
  > `"In handlers/snapshot.rs, the NOT-same-plan + defer_workers branch (currently: store snapshot, log, skip reconcile) additionally calls a NARROW coordinator method: guard.afxdp.prune_wg_control_threads_for_snapshot(&snapshot);"`

### Finding 3: Tunnel-Endpoint ID Instability
* **Resolution**: The sequential ID reassignment issue under alphabetical interface changes is recorded as a follow-up defect to be tracked separately.
* **v2 Quote (Lines 385–391)**:
  > `"- Tunnel-endpoint ID instability (AGY 3): buildTunnelEndpointSnapshots assigns sequential ids over alphabetically-sorted interfaces... Pre-existing, multi-tunnel-scope defect — file a follow-up issue at /engineer time (name-keyed or stable-id allocation); not fixed here."`

---

## 2. Attack on the New Surface

### (a) Change 2b Safety on the Defer Branch
* **Analysis**: Change 2b runs `prune_wg_control_threads_for_snapshot(&snapshot)` in [snapshot.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs#L109-L115) when `defer_workers` is `true`. It acts as a prune-only, no-spawn, no-forwarding mutation step.
* **Sufficient?** Yes. When an interface is removed, the physical socket bind and the `wgN` TUN handle should be released immediately. Even if the workers continue to run under the prior `ForwardingState` (since `self.forwarding` hasn't updated yet), egressing packets to a removed tunnel will naturally drop/blackhole, which is safe.
* **Right desired-set gates?** Yes. Pruning on absent ID OR non-hydratable endpoint (e.g. ifindex <= 0, listen_port == 0, key decoding failures) mirrors the populate gates in [tunnels.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/forwarding_build/tunnels.rs#L16-L80). It ensures that if an endpoint can no longer run under the new config, its UDP/TUN resources are freed immediately, avoiding EADDRINUSE on subsequent applies.

### (b) Tombstone Growth/Leak Under Endpoint Flapping
* **Analysis**: When an endpoint is flapping in and out of the configuration:
  - When in the config and failing, it leaves a tombstone entry in `wg_control_threads`.
  - When removed from the config, the entry is completely removed in Pass 2 (Stale prune) of `spawn_wg_control_threads` or via Change 2b.
* **Growth Risk**: None. Because the map `wg_control_threads` is keyed by the endpoint ID (`u16`), there is at most one entry per ID. The map size is strictly bounded by the number of configured WG endpoints, meaning there is zero leak or unbounded growth path.

### (c) Three-Pass Ordering in Change 1 (Join-Before-Bind)
* **Analysis**: In `spawn_wg_control_threads`:
  - Pass 1 (Finished sweep) joins finished threads and sets `thread = None`.
  - Pass 2 (Stale prune) stops and joins stale threads (engine changed / ID removed) and removes their entries.
  - Pass 3 (Spawn pass) spawns new threads for missing/tombstone entries.
* **Violation Window**: None. Because the entire operation runs within a single call to `spawn_wg_control_threads` while holding the `ServerState` mutex guard (`Arc<Mutex<ServerState>>`), the execution is fully serialized. Every old thread is guaranteed to be joined (and its UDP socket closed) before Pass 3 attempts to bind a new socket for that ID.

### (d) Stop-Gate Interaction
* **Analysis**: Can a respawn slip between `stop()` and the next `refresh_status()`?
  - `stop()` is called in handlers like [stop_workers.rs](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/stop_workers.rs#L15) and [rebind.rs](file:///home/ps/git/bpfrx/userspace-dp/src/server/handlers/rebind.rs#L17) under the `ServerState` lock.
  - `refresh_status()` is called at the end of these handlers while still holding the lock.
  - Since the lock is held across the entire sequence, no concurrent status polls or other requests can interleave to trigger a racy respawn.
  - If `should_run_afxdp` is true, the WG control threads will be restarted by `refresh_status()` at the end of `stop_workers` or `rebind`. This is correct because forwarding remains armed.
  - If `should_run_afxdp` is false, the stop-gate prevents `reconcile_wg_control_liveness()` from running, keeping threads stopped.

---

## 3. Answers to Section 11 Questions

1. **Tick placement**: No latency or reentrancy hazard exists. `JoinHandle::is_finished()` is a non-blocking atomic check. Joins only occur on threads already known to have finished, making them instantaneous. The O(#wg endpoints) execution is extremely lightweight, and serialization under the `ServerState` lock prevents reentrancy.
2. **Residual-unknown stance**: Harden+instrument is highly sufficient. The known gaps (D1 and D4) are fully closed, and the new transition logs at both Go and Rust boundaries will immediately isolate the source of any stale snapshot republishes.
3. **Tombstone lifecycle**: The tombstone lifecycle is safe. The map is bounded by the current configured WG endpoints, and stale entries/tombstones are swept when endpoints leave the desired set.
4. **Change 2b gates**: Mirroring the populate gates (mode/id/ifindex/port/keys) is correct. If an endpoint becomes un-hydratable in the new config, we must release its port/TUN immediately rather than running a thread with stale configuration.
5. **Backoff constant**: 3 seconds is optimal. It prevents CPU spinning/log floods under misconfiguration while remaining fast enough to recover within seconds once a port collision is resolved.
6. **Sequencing vs #1868**: Confirmed. Since the coordinator only spawns the aux thread and does not call `bind_wg_socket` on the control-socket thread, it only needs to spawn the thread. The updated `(UdpSocket, bool)` binding logic runs entirely within `wg_control_loop` in the spawned thread.

---

## Verdict

PLAN-READY

---
### Summary of Work
I reviewed [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/docs/research/1866-wg-teardown/plan.md) (v2) and analyzed the related code structures in [snapshot.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/handlers/snapshot.rs), [helpers.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/server/helpers.rs), and [mod.rs](file:///home/ps/git/bpfrx/.claude/worktrees/1866-research/userspace-dp/src/afxdp/coordinator/mod.rs). I verified the resolutions of the Round 1 findings, pressure-tested the new Change 2b defer branch safety, validated the tombstone flapping lifecycle, confirmed the join-before-bind sequencing, checked the stop-gate/lock interactions, and answered all Section 11 questions. The plan is correct and safe to proceed.
