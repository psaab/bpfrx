# #1881 Implementation Review — AGY Hostile Code Review (Round 1)

Scope: Hostile adversarial code review (round 1) of the `engineer/1881-gre-frozen` changes against Plan V3 (`docs/research/1881-gre-frozen-state/plan.md`).

Verdict: **MERGE-READY**

---

## 1. Plan v3 Verification

### D.1 State via ArcSwap & Single-Load-Per-Iteration
- **Single-Load at Loop Head**: Inside `local_tunnel_source_loop` (`userspace-dp/src/afxdp/tunnel.rs:188`), `ha_runtime` is loaded once from `ha_state` via `let ha_runtime = ha_state.load();` at the outer loop head.
- **Pass Down Signature**: `build_local_origin_tunnel_tx_request` (`userspace-dp/src/afxdp/tunnel.rs:286-292`) now accepts `ha_runtime: &BTreeMap<i32, HAGroupRuntime>` instead of the `ha_state` `Arc<ArcSwap<...>>` reference.
- **Zero Double-Load**: In `build_local_origin_tunnel_tx_request`, both `enforce_ha_resolution_snapshot` (`tunnel.rs:302`) and `synthesized_synced_reverse_entry` (`tunnel.rs:357`) consume the loaded snapshot directly. No intermediate loads on `ha_state` remain.

### D.1b Rotation Gate
- **Gating**: Inside the loop, `endpoint_attachment_valid` is called to re-evaluate the attachment ONLY in the `load_arc_if_changed` branch (`tunnel.rs:172-182`):
  ```rust
  if let Some(new_forwarding) = super::worker::load_arc_if_changed(&forwarding, &shared_forwarding) {
      forwarding = new_forwarding;
      endpoint_attached = endpoint_attachment_valid(
          &forwarding,
          tunnel_endpoint_id,
          spawned_logical_ifindex,
          &tunnel_name,
      );
  }
  ```
- **Parked Thread behavior**: When `endpoint_attached` is false, the thread parks:
  - It still drains deliveries via `drain_local_tunnel_deliveries` (`tunnel.rs:189-198`), which performs writes to the TUN to prevent queue backup.
  - It still reads the TUN fd (`tunnel.rs:199`).
  - If a packet is read, it hits `if !endpoint_attached` (`tunnel.rs:207-214`) and `continue`s, dropping the outgoing packet safely without executing `build_local_origin_tunnel_tx_request`.

### D.2 Three-Pass Reconcile (GRE Flavor)
- **Pass 1 (Finished Sweep)**: `sweep_finished_local_tunnel_sources` (`userspace-dp/src/afxdp/coordinator/mod.rs:637-666`) joins finished threads, clearing `handle` and `delivery_tx` to tombstone the entry.
- **Pass 2 (Stale Prune)**: `reconcile_local_tunnel_sources` (`coordinator/mod.rs:567-590`) identifies stale entries (mode flips, removals, attachment drift).
- **Unpublish-Before-Join**: 
  - `publish_local_tunnel_deliveries_excluding(&stale_ids)` is stored as Store #1 (`coordinator/mod.rs:591-597`). It excludes stale IDs as well as any swept tombstones and failed spawns (which have `handle == None`).
  - This ensures workers see the updated delivery map *before* the coordinator blocks on joining stale threads (`stop_remove_local_tunnel_entry` at `coordinator/mod.rs:598-600`), bounding control-socket join latency under busy producers.
- **Pass 3 (Spawn)**:
  - **Spawn Gate**: Spawning runs only when `!self.workers.handles.is_empty()` (`coordinator/mod.rs:605`), preventing freezing of empty binding captures during deferred snap apply windows.
  - **Backoff Reuse**: Tombstone backoffs use `WG_SPAWN_BACKOFF_NS` (`coordinator/mod.rs:619`).
  - **Fresh Channel**: A new sync channel is generated per attempt (`coordinator/mod.rs:748`), ensuring failed spawns do not leak stale channels.
  - **Store #2**: Final publication of live handles is executed at `coordinator/mod.rs:630`.

### D.3 Call Sites & stop_inner
- **Bringup**: Reconciles tunnel sources (`coordinator/reconcile/bringup.rs:445`) after workers have spawned.
- **Refresh Snapshot**: Reconciles/stops tunnel sources after `ha.forwarding.store()` (`coordinator/mod.rs:1501-1527`), ensuring new threads see the updated state.
- **Defer Prune**: Defer-workers apply branch propagates prunes immediately (`server/handlers/snapshot.rs:124`), allowing timely release of TUN reader fds.
- **Liveness**: Integrates liveness self-heal (`server/helpers.rs:29`).
- **Stop Inner**: Binds joins and clears all entries (`coordinator/mod.rs:376-390`).

### POST-PLAN Addition: EINVAL Downgrade on Write
- **Predicate**: `local_tunnel_write_error_is_fatal` (`tunnel.rs:30-39`) removes `EINVAL` from the fatal error set for writes only.
- **Security & Operational Assessment**: 
  - On Linux, write `EINVAL` is a per-packet input validation error (such as a malformed inner packet payload format/slicing). It does not indicate fd/link death.
  - Fd-level errors (`EBADF`, `EBADFD`, `ENODEV`, `ENXIO`) remain fatal on both reads and writes.
  - Reads keep `EINVAL` as fatal, ensuring structural channel issues are captured.
  - Downgrading it on write prevents a single malformed packet from permanently killing the local-origin thread or creating a rapid respawn-loop. This downgrade is sound and correct.

---

## 2. Adversarial Hunt for Missed Items

### Single-Threaded Access Assumptions
All mutations to `self.tunnel_sources` (reconcile, liveness sweep, and disarmed/snapshot prunes) are executed while holding the `ServerState` mutex lock (`state: Arc<Mutex<ServerState>>`) inside `handle_stream` or startup/shutdown. Hence, single-threaded coordinator assumptions are fully correct.

### Control-Socket Join Latency
The loop reads non-blocking fds, sleeps at most 50ms on read error, and checks `stop` on every iteration and inside `drain_local_tunnel_deliveries`. Join latency is bounded to <=50ms, causing zero control-socket protocol bottlenecks.

### Delivery-Map Publication Races
Workers load `local_tunnel_deliveries` into an `Arc` snapshot. A lookup returning `None` or a send returning `Disconnected` (e.g., if loaded before Store #1 but sent after the channel closed) is gracefully handled in `slow_path.rs:183-196` without panic or block.

### Verification of the 20 New Tests
The test suite pins all critical requirements:
- `gre1881_refresh_creates_entry_and_publishes_delivery` & `local_origin_tunnel_tx_request_follows_supplied_state_destination` verify the core staleness fix (which fails on master because master does not reconcile/refresh GRE sources).
- `gre1881_attachment_change_restarts_thread` & `gre1881_mode_flip_to_wireguard_prunes_gre_entry` verify attachment drift and mode flip restarts.
- `drain_local_tunnel_deliveries_observes_stop_under_busy_producer` pins bounded stop latency.
- `local_tunnel_write_error_einval_is_not_fatal` pins error split.

---

## 3. Verdict

**MERGE-READY**
No issues or omissions were identified. The implementation matches Plan V3 exactly, compiles cleanly, and passes all Go/Rust tests.
