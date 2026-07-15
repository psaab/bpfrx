# Review 039 — A1g Remaining Rust infra (wg, event_stream, cold_path_hist, coordinator, types, protocol, server)

Base: f70146951583823a5ace87b0b11a2e58f46e8db9
Date: 2026-07-08
Batch: wg/engine.rs 1805, wg/cookie.rs 1435, event_stream/mod.rs 1693, event_stream/codec.rs 1165, cold_path_hist.rs 1866, coordinator/wg_control.rs 2280, types/cos.rs 1786, types/shared_cos_lease/lease.rs 1460, epoch.rs 565, backlog.rs 210, vtime.rs 238, protocol/binding.rs 1168, types/forwarding.rs 1054, server/helpers.rs 1292, event_emit.rs 1492, coordinator/status.rs 1195

---

## File size / shape inventory

| File | LOC | S | E | I | F | Tests | Prod LOC (ex-tests) | Hot-path? |
|------|-----|---|---|---|---|-------|---------------------|-----------|
| wg/engine.rs | 1805 | 7 | 4 | 5 | 41 | yes (engine_tests 1464, tests 3909) | ~1700 | YES (try_encap/try_decap transit) |
| wg/cookie.rs | 1435 | 7 | 1 | 3 | 47 | yes | ~900 | NO (handshake only) |
| event_stream/mod.rs | 1693 | 5 | 1 | 4 | 42 | yes (tests 2313) | ~1200 | PARTIAL (try_send cold, rate-limited) |
| event_stream/codec.rs | 1165 | 2 | 1 | 2 | 27 | yes (codec_tests 995) | ~700 | YES (encoding, stack [u8;256]) |
| cold_path_hist.rs | 1866 | 3 | 1 | 7 | 67 | yes (~914 LOC tests) | ~950 | YES (bucket_index, lookup_slot, record_sample inlined) |
| coordinator/wg_control.rs | 2280 | 3 | 3 | 1 | 49 | yes | ~1800 | NO (control thread, 100ms poll) |
| types/cos.rs | 1786 | 25 | 3 |10 | 30 | yes (small) | ~1700 | YES (FlowRrRing push/pop, MQFQ) |
| types/shared_cos_lease/lease.rs | 1460 | 4 | 0 | 2 | 57 | yes (shared_cos_lease_tests 2511) | ~1400 | YES (acquire_v8_with_cause) |
| types/shared_cos_lease/epoch.rs | 565 | 7 | 3 | 5 | 10 | no | 565 | YES (seqlock snapshot) |
| types/shared_cos_lease/backlog.rs | 210 | — | — | — | — | — | 210 | NO |
| types/shared_cos_lease/vtime.rs | 238 | — | — | — | — | — | 238 | YES (V_min) |
| protocol/binding.rs | 1168 | 7 | 0 | 1 | 4 | no | 1168 | NO (DTOs) |
| types/forwarding.rs | 1054 | 18 | 2 |12 | 23 | yes | ~1000 | NO (types only, lookup is elsewhere) |
| server/helpers.rs | 1292 | 2 | 0 | 1 | 35 | yes | ~1200 | NO (daemon loop, config apply) |
| event_emit.rs | 1492 | 0 | 1 | 1 | 42 | yes | ~600 | COLD (per-drop but rate-limited) |
| coordinator/status.rs | 1195 | 0 | 0 | 1 | 55 | yes | ~1100 | NO (1/s scrape) |

Functions >200 LOC (6 total):
- `server/helpers.rs:refresh_status` 311 LOC
- `types/shared_cos_lease/lease.rs:acquire_v8_with_cause` 278 LOC
- `coordinator/wg_control.rs:run_wg_control_loop` 315 LOC
- `coordinator/wg_control.rs:dispatch_inbound` 211 LOC
- `wg/engine.rs:try_decap` 223 LOC (hot-path)
- `wg/engine.rs:encap_inner` 174 LOC (just under, try_encap wrapper adds to ~220 effective)

No dumping-ground enum found. Largest enums are focused (InitiationAction 3 variants, PollWait 3, EqualFlowTargetPolicy 3, ForwardingDisposition 9, FabricSkipReason 6 — all single-concern).

---

## Finding 1 — wg_control.rs 2280 LOC monolith: socket lifecycle + control loop + handshake machine + ECN + poll fused

**Title:** coordinator/wg_control.rs mixes 5 responsibilities in one 2280 LOC file
**Severity:** Medium
**Confidence:** High
**Refactor class:** (A) MECHANICAL / SAFE — cold path, no hot-path inlining risk
**Evidence:**
```
/home/ps/git/avacado-xpf/userspace-dp/src/afxdp/coordinator/wg_control.rs 2280 LOC
  structs: HandshakeAttempt, WgRecv, CmsgBuf
  enums: InboundOutcome, AttemptTrigger, PollWait
  fns: 49 including:
    wg_control_loop / run_wg_control_loop (315 LOC) — main loop
    dispatch_inbound (211 LOC) — WG type dispatch
    encap_and_send, send_keepalive, pace_keepalive_skip — egress/keepalive
    start_attempt, drive_attempt_machine, drive_initiation — handshake SM
    bind_wg_socket, bind_dual_stack_v6, wg_send_to, set_recv_tos_options,
      wg_recvmsg (39 LOC), parse_outer_ecn_from_cmsg, sockaddr_storage_to_socketaddr — socket/ECN
    wg_poll_wait, poll_timeout_ms, monotonic_nanos — poll/timing
```
File crosses the 2000 LOC monolith threshold (engineering-style.md §Modularity: “~2,000 LOC … is a smell, by ~3,000 the next change MUST split”). Two functions exceed 200 LOC (315, 211). Responsibilities are independently testable (socket bind/EADDRINUSE, ECN cmsg parsing, handshake attempt window, poll fatal handling) but currently coupled through a single `impl` block and shared `encap_buf`/`decap_buf` locals.

**Proposed decomposition:**
```
coordinator/wg_control/
  mod.rs              — wg_control_loop entry, HandshakeAttempt, InboundOutcome, constants
  loop.rs             — run_wg_control_loop (poll + burst + timer arm)
  dispatch.rs         — dispatch_inbound + encap_and_send + send_keepalive + pace_keepalive_skip
  handshake.rs        — start_attempt + drive_attempt_machine + drive_initiation
  socket.rs           — bind_wg_socket, bind_dual_stack_v6, wg_send_to, set_recv_tos_options,
                       wg_recvmsg, parse_outer_ecn_from_cmsg, sockaddr_storage_to_socketaddr,
                       CmsgBuf, WgRecv
  poll.rs             — wg_poll_wait, poll_timeout_ms
```
All moves are pure code-motion; `run_wg_control_loop` already takes `&WgEngine`, `&UdpSocket`, `File`, `&AtomicBool` — no new trait bounds. `socket.rs` is `#[cfg(unix)]` isolated, easy to unit-test without a TUN device (existing tests already mock via pipe).

**Hot-path preservation:** N/A — this is the per-tunnel control thread (WG_POLL_CAP_MS 100ms, WG_TIMER_TICK_NS 1s, WG_RX_BURST 64). No HFT constraints. The only per-packet work (decap ECN combine, inner_dst_ip lookup) is dominated by crypto (Noise AEAD) and TUN write, not by dispatch overhead. Split does not change codegen of `dispatch_inbound` match (still monomorphized, still `#[inline]` where it matters).

**Tests+gate:** Existing `wg_control::tests` (poll_loop_stop_joins_promptly, poll_loop_wakes_on_socket_readiness, poll_loop_exits_on_tun_teardown, attempt_give_up_ignores_same_pass, canonicalize_endpoint_*, wg_send_to_*, sockaddr_storage_to_socketaddr_*) remain green. No new tests required for mechanical move. Validate with `cargo test -p xpf-userspace-dp wg_control` and `make test-rust`.

**Why it matters:** 2280 LOC file is already over threshold. Next WG feature (VRF bind, PSK rotation, link-local scope) will push it past 3000. The handshake attempt machine (`HandshakeAttempt` + timers + T7/T8) is the most bug-prone area (see #1888, #2961) and is currently interleaved with ECN cmsg parsing and socket bind fallback — reviewers must read 2280 LOC to audit a timer fix. Splitting isolates the ECN/security-critical cmsg alignment code (CmsgBuf `#[repr(C,align(8))]`) into its own reviewable unit.

**Fix direction:** Mechanical split in one PR before next WG feature. No behavior change. Keep `wg_control.rs` as `mod.rs` re-exporting for `cargo test` compatibility, or delete and fix two `use` sites (`tunnel_supervision.rs`, `coordinator/mod.rs`).

**Labels:** modularity, wg, cold-path, mechanical-split
**Dedup note:** Distinct from #4404 SnapshotIntegrityError (Go), #4405 flowexport, #4406 firewall-filter, #4407 event-engine, #4408-#4409 Go services. No prior Rust wg_control mod split filed. Prior Go WG work (#1432, #1888) is feature, not refactor.

---

## Finding 2 — server/helpers.rs 1292 LOC dumping ground: status + session-sync + binding-plan + hash + VLAN + file-IO

**Title:** server/helpers.rs is a 20-function dumping ground with 6 unrelated responsibilities
**Severity:** Low (cold path) / Medium (reviewability)
**Confidence:** High
**Refactor class:** (A) MECHANICAL / SAFE
**Evidence:**
```
/home/ps/git/avacado-xpf/userspace-dp/src/server/helpers.rs 1292 LOC
  fns:
    refresh_status (311 LOC) — 80+ status field assignments, Prometheus counters
    forwarding_unsupported_error — trivial
    build_synced_session_key / build_nat64_reverse_rebuild / build_synced_session_entry (192 LOC) — HA session-sync
    parse_session_sync_mac — MAC parsing
    reconcile_status_bindings / should_run_afxdp / same_plan_apply_needs_binding_reconcile / set_bindings_forwarding_armed — lifecycle
    wait_for_binding_settle / bindings_settled / same_binding_plan / snapshot_binding_plan_key — settle/hash
    hash_update / update_json_encoded / update_canonical_json_hash / canonical_json_key / write_canonical_json — JSON hashing
    include_userspace_binding_interface / vlan_child_parent_netdev / snapshot_has_parent_candidate / plan_key_rx_queues / replan_queues / replan_bindings_from_candidates / summarize_queues — VLAN+binding plan
    linux_ifname / effective_rx_queues / rx_queue_count — sysfs
    write_state — file persist
```
Header itself says “Daemon-loop helpers extracted from main.rs (Issue 69.1). 20 helper fns called by both main::run() and server::handlers::handle_stream. Pure relocation. Bodies byte-for-byte identical.” — i.e. acknowledged dumping ground pending further split. `refresh_status` alone is 311 LOC with 6 sections (WG liveness, neighbor telemetry, CoS, session, flow, event_stream, fabric-skips) each independently meaningful.

**Proposed decomposition:**
```
server/helpers/
  mod.rs              — re-exports
  status.rs           — refresh_status (or further into status/{mod,neighbor,cos,session,wg}.rs)
  session_sync.rs     — build_synced_session_key, build_synced_session_entry, build_nat64_reverse_rebuild, parse_session_sync_mac
  binding_plan.rs     — include_userspace_binding_interface, vlan_child_parent_netdev, snapshot_has_parent_candidate, plan_key_rx_queues, replan_queues, replan_bindings_from_candidates, summarize_queues, linux_ifname, effective_rx_queues, rx_queue_count + RX_QUEUE_COUNT_OVERRIDE test seam
  hash.rs             — snapshot_binding_plan_key, same_binding_plan, update_snapshot_binding_plan_key, hash_update, update_json_encoded, update_canonical_json_hash, canonical_json_key, write_canonical_json
  lifecycle.rs        — reconcile_status_bindings, should_run_afxdp, same_plan_apply_needs_binding_reconcile, set_bindings_forwarding_armed, wait_for_binding_settle, bindings_settled, write_state
```

**Hot-path preservation:** N/A — cold path (daemon loop: 1/s status refresh, config apply). No inlining or alloc constraints. The only performance-sensitive call is `refresh_status` (1/s) which aggregates atomics via Relaxed loads — splitting files does not change codegen.

**Tests+gate:** Existing helpers tests (`replan_queues_binds_vlan_unit_on_parent_netdev`, `snapshot_allowlist_test.go` parity) must remain green. No new tests for mechanical move.

**Why it matters:** Dumping ground makes “small PR adds one helper” pattern silently grow the file (currently 1292 LOC, will be >1500 after next status field). Reviewers cannot tell if a change to `refresh_status` (status) affects `replan_queues` (binding plan). The file already has a `// Pure relocation` header inviting further split — this is the intended next step of #69.

**Fix direction:** Mechanical split in one PR. Keep `helpers.rs` as `mod.rs` re-exporting for backward compat, or update `use server::helpers::*` in `main.rs`/`handlers.rs` to `use server::helpers::{status::*, session_sync::*, binding_plan::*}`.

**Labels:** modularity, dumping-ground, cold-path, mechanical-split
**Dedup note:** Not in #4404-#4409 (those are Go services, flowexport, firewall-filter). No prior Rust server/helpers split filed. Issue #69.1 was the first extraction; this is the follow-up.

---

## Finding 3 — event_stream/mod.rs 1693 LOC: transport + sequencing + clock + emission fused (borderline)

**Title:** event_stream/mod.rs mixes IO thread, producer sequencing, clock conversion, and RT_FLOW emission
**Severity:** Low (cold path, under threshold for mandatory split, but approaching)
**Confidence:** Medium
**Refactor class:** (A) MECHANICAL / SAFE if split, but (D) DO-NOT-SPLIT also defensible today
**Evidence:**
```
event_stream/mod.rs 1693 LOC
  clock/time helpers (4 fns, ~120 LOC):
    read_mono_and_wall_clocks, monotonic_ns_to_unix_ns,
    monotonic_ns_to_unix_secs_subnanos, mono_ns_to_wall_clock_unix_ns
  shared state (EventStreamShared, EventStreamStats, EventStreamSender, EventStreamWorkerHandle) ~200 LOC
  sequencing (producer_seq_lock, next_seq, rollback_seq, send_sequenced, send_lossless_encoded, send_frame_lossless) ~180 LOC
  emission (encode_delta_frame, push_delta, push_delta_lossless, emit_session_close_rt_flow 108 LOC, emit_session_create_rt_flow 50 LOC) ~250 LOC
  IO thread (io_thread_main, try_connect, replay_buffered, write_all_backpressured, run_connected_loop, process_control_frames, handle_drain_request, drain_remaining, drain_channel_into_write_buf, push_replay_frame, evict_replay_frame, pop_replay_frame, release_*) ~700 LOC
```
File is 1693 LOC (under 2000 but over 1500 threshold for multi-responsibility). Largest functions are 158 LOC (handle_drain_request), 125 LOC (process_control_frames), 111 LOC (run_connected_loop) — none exceed 200 LOC individually. The file’s responsibilities are distinct but tightly coupled through `EventStreamShared` (the IO thread reads `shared.next_seq`, `shared.paused`, `shared.session_evicted_while_paused`; the producer writes them). Extracting IO thread to `io.rs` would require widening 5 `pub(super)` fields to `pub(crate)` — mechanical but creates cross-file coupling.

The existing decomposition already separates concerns into sibling files:
- `codec.rs` — pure wire encoding (no I/O, no atomics, stack `[u8;256]` only)
- `producer.rs` — rate limiting + queue budget (DataplaneEventRateLimiter, DataplaneEventQueueBudget, 466 LOC)
- `mod.rs` — sequencing + transport + emission

This is a reasonable 3-way split. Further splitting mod.rs would create 4-5 files for a single 1693 LOC module.

**Proposed decomposition (if pursued):**
```
event_stream/
  mod.rs      — EventStreamSender/WorkerHandle, EventStreamShared, public API (push_delta, try_emit)
  io.rs       — io_thread_main, try_connect, replay_buffered, write_all_backpressured, run_connected_loop, process_control_frames, handle_drain_request, drain_* helpers, push_replay_frame, evict_replay_frame
  time.rs     — read_mono_and_wall_clocks, monotonic_ns_to_unix_ns*, mono_ns_to_wall_clock_unix_ns (plus NS_PER_SEC const)
```
Keep `emit_session_close_rt_flow` / `emit_session_create_rt_flow` in `mod.rs` (they are the primary worker API). Move clock helpers to `time.rs` — they are pure functions with no `EventStreamShared` dependency, trivial to test in isolation.

**Hot-path preservation / cold-path analysis:** This is cold path. `push_delta` is called on session open/close (per-flow, not per-packet), `try_emit_dataplane_event_at` is called on policy-deny/screen-drop/filter-log (per-drop, rate-limited to ~100/s via producer.rs). `try_send` is non-blocking (bounded mpsc, drop-newest with counter). The IO thread is a dedicated thread (not on AF_XDP poll). Splitting does not affect hot-path inlining. The only hot-path adjacent code is `mono_ns_to_wall_clock_unix_ns` which does two `clock_gettime` syscalls — already documented as acceptable (“one anchored clock read per emit is acceptable; correctness (a real decision timestamp) is preferred over saving the read”).

**Tests+gate:** Existing `event_stream::tests`, `codec_tests`, `producer_tests` must remain green. Time helpers have no direct tests today — extracting them to `time.rs` would be a good opportunity to add unit tests for `monotonic_ns_to_unix_ns` edge cases (0, saturating_sub, future skew clamp).

**Why it matters (if fixed):** Not urgent. File is 1693 LOC, 307 LOC under the 2000 mandatory-split threshold. The IO thread logic (replay gap → FullResync, pause poisoning, drain fence) is the most bug-prone area (8 fixes referenced: #2381, #2382, #2874, #2875, #2876, #2877, #2879, #2959) and would benefit from being in its own file for focused review. But the current layout is not yet a monolith.

**Fix direction:** OPTIONAL. If split, do time.rs first (zero coupling, trivial), then io.rs if file grows past 2000. Otherwise, leave as-is and revisit when adding next event kind.

**Labels:** modularity, event-stream, cold-path, optional-split
**Dedup note:** Distinct from #4407 event-engine (Go), #4421 SnapshotIntegrityError. No prior Rust event_stream split filed beyond the existing codec/producer separation (which was already done).

---

## Finding 4 — wg/engine.rs 1805 LOC + wg/cookie.rs 1435 LOC: single-responsibility WG protocol — DO NOT SPLIT (negative)

**Title:** wg/engine.rs and wg/cookie.rs are large but cohesive — single-responsibility WireGuard protocol — do NOT split
**Severity:** N/A (negative — correctly NOT split)
**Confidence:** High
**Refactor class:** (D) DO-NOT-SPLIT
**Evidence:**
```
// engine.rs 1805 LOC — single responsibility: WireGuard data-plane engine
//   - WgEngine (local_private_key, local_public_key, table: ArcSwap<PeerTable>, sessions_by_local_index, pending, cookie, counters)
//   - PeerTable (peers: Vec<PeerEntry>, peer_index_by_pubkey, allowed_ips: AllowedIps) — atomic snapshot
//   - Hot path: try_encap (via encap_inner 174 LOC), try_decap (223 LOC) — NO allocations, MaybeUninit stack scratch, Arc clone + release lock
//   - Cold path: reconcile_peers, install_session, build_initiator/responder_handshake
//   - Timer queries: peer_has_confirmed_session, peer_for_dest, etc.
//   File is 1805 LOC <2000 threshold, 9 structs/4 enums all WG-domain, 2 functions >200 (try_decap 223, encap_inner 174)

// cookie.rs 1435 LOC — single responsibility: WG DoS mitigation (whitepaper §5.4.7)
//   - CookieChecker (responder): secret rotation, load gate, reply budget, per-source bucket, MAC2 verify, cookie-reply build/encrypt
//   - InitiatorCookie (initiator): last_mac1 tracking, cookie decrypt, MAC2 stamping
//   Two structs, one protocol feature (cookie), shared crypto primitives (keyed_blake2s_128, cookie_encryption_key)
//   File is 1435 LOC <1500 threshold (just over but tests included), production ~900 LOC
```

Both files are under the 2000 LOC mandatory-split threshold. They each have a single conceptual responsibility (WG engine, WG cookie). Splitting engine into `encap.rs`/`decap.rs`/`peer_table.rs`/`reconcile.rs` would create 4 files with tight coupling through `WgEngine`'s `ArcSwap<PeerTable>` and `RwLock<FxHashMap<u32, Arc<WgSession>>>` — every split would require widening `pub(in crate::afxdp::wg)` visibility and passing `&WgEngine` or `&ArcSwap` across files, increasing review burden without reducing complexity.

**Hot-path preservation analysis (HFT-grade):**

- `try_encap` (encap_inner): Hot path for transit WG egress (frame/wg.rs calls engine.try_encap per inner packet). Current code:
  - No allocations: `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` on stack (4080+16=4096), avoids 4096-byte zero-init via raw pointer writes. Correct: LLVM cannot elide `[0u8; N]` zero-init because snow reads trailing pad bytes.
  - No locks held across crypto: `peer_arc` clones `Arc<Peer>` via `ArcSwap::load_full` (atomic, no lock), `peer.current.read().unwrap().clone()` releases `RwLock` before `session.next_tx_counter()` and `snow.write_message`. Verified in file header comment.
  - Branchless-ish: `pad_to_16` is `(n+15)&!15` (single AND), bound checks before counter consume (so Err does not advance nonce).
  - Inlining: `encap_inner` is not `#[inline]` but is called via `try_encap` which is `pub(crate)` and likely inlined by LTO (codegen-units 16, LTO off per crate, but same crate so intra-crate inlining occurs). Splitting into `encap.rs` would keep it in same crate (`mod encap`) — no codegen change. However, extracting to separate crate or `pub` boundary would lose inlining.

- `try_decap`: Hot path for WG ingress (wg_control thread, not AF_XDP hot path but still per-packet for WG). Current code:
  - Takes `sessions_by_local_index.read()` (RwLock read) — single-contended only if multiple WG tunnels share a worker (unlikely; one control thread per tunnel). Contention bounded.
  - Pre-AEAD replay check (`definitely_out_of_window`) with lock held to avoid AEAD cost on replay flood — correct tradeoff (mutex per-session, effectively SPSC because demux is single-worker per session).
  - Post-AEAD `check_and_update` with zero-then-write on Err (prevents plaintext leak).
  - AllowedIPs gate after AEAD (spec §5.4.6) — correct ordering.
  - Splitting into `decap.rs` would not change any of these properties — same crate, same `RwLock`, same ArcSwap.

- `CookieChecker`: Not hot path (classify_initiation called per inbound initiation only, slow path). Contains `Mutex<SecretState>`, `Mutex<LoadState>`, `Mutex<BudgetState>`, `Mutex<SourceTable>` — all `std::sync::Mutex`, not cross-core hot. The file’s `#[inline]` on `macs_equal` and `endpoint_cookie_bytes` is appropriate. No inlining risk from split.

**Layout/locality:** `WgEngine` struct is 10 fields, fits in 2 cache lines (ArcSwap 8B, RwLock 56B, AtomicBool/AtomicU64, counters). Hot path `try_encap` touches `table` (ArcSwap load) + `sessions` is not touched (encap uses peer.current, not demux map). Hot path `try_decap` touches `sessions_by_local_index` (RwLock read) + `table` (for AllowedIPs). Both are cache-resident (engine is `Arc<WgEngine>`, shared across workers). Splitting file does not change struct layout.

**Why NOT to split:** Further decomposition would increase cross-file visibility widening (currently `pub(in crate::afxdp::wg)` for `local_public_key`, `tai64n_clock`, `pending`, `reconcile_lock`, `sessions_by_local_index`, `cookie`, `cookie_gen`) without reducing LOC below threshold or improving reviewability. The wg/ directory already has 15 files (allowed_ips, cookie, counters, dscp, engine, framing, handshake, handshake_session, mod, mss, peer, session, tai64n, timers, tests) — adding `engine_encap.rs`/`engine_decap.rs`/`engine_reconcile.rs` would make the directory harder to navigate. The file is 195 LOC under the 2000 threshold and shrinking is not required.

**Labels:** modularity, wg, hot-path, do-not-split, negative
**Dedup note:** No prior WG engine split filed. #1432 S2a, #1888 S5, #4094 cookie are feature work, not refactor.

---

## Finding 5 — types/cos.rs 1786 LOC, types/forwarding.rs 1054 LOC, protocol/binding.rs 1168 LOC, cold_path_hist.rs 1866 LOC (prod 950), shared_cos_lease/*, event_emit.rs 1492, coordinator/status.rs 1195: cohesive — DO NOT SPLIT (negatives)

**Title:** Remaining large type/status/emit/hist files are cohesive single-responsibility modules — do NOT split
**Severity:** N/A (negatives — correctly NOT split)
**Confidence:** High
**Refactor class:** (D) DO-NOT-SPLIT (all 7 files)
**Evidence:**

| File | LOC | Responsibility | Why cohesive |
|------|-----|----------------|--------------|
| types/cos.rs 1786 | 25 structs, 3 enums | CoS type definitions | Pure types, no logic (except FlowRrRing methods, CoSQueueSojourn::record, FlowFairState::new_boxed). Header says “Pure relocation. 28 items / ~700 LOC …”. All CoS: shaper, queue, flow-fair, fast-path, runtime, telemetry, sojourn, timer wheel. Splitting into cos_config.rs/cos_runtime.rs/cos_flow_fair.rs would create 3 files with circular `CoSQueueConfig` ↔ `CoSQueueRuntime` ↔ `FlowFairState` dependencies. |
| types/forwarding.rs 1054 | 18 structs, 2 enums | Forwarding/routing types | ForwardingState (30+ fields) + route/neighbor/tunnel/fabric/EgressInterface + WorkerBindingLookup. All forwarding-plane config snapshot. Single ArcSwap publish. |
| protocol/binding.rs 1168 | 7 structs | Wire DTOs for status | BindingStatus, BindingCountersSnapshot, WorkerRuntimeStatus, HAGroupStatus, QueueStatus, ExceptionStatus, SessionDeltaInfo + u64_is_zero helpers. All status wire format, no logic. |
| cold_path_hist.rs 1866 (prod ~950) | 3 structs, 1 enum | Cold-path histogram primitives | bucket_index_for_ns_48 (hot, inline), ColdPathSlotMap (cold, build), WorkerColdPathAtomics/Counters (publish/snapshot seqlock), probe/calibrate (cold). Header documents scope clearly. Tests are 914 LOC (49% of file). Prod <1000 LOC. |
| shared_cos_lease/lease.rs 1460 + epoch.rs 565 + vtime.rs 238 + backlog.rs 210 + rotate_epoch_v8.rs + publish_equal_flow_epoch_v8.rs | 4+7 structs | Shared CoS lease token bucket + v8 fair-share | Already decomposed into 6 files (lease.rs, epoch.rs, vtime.rs, backlog.rs, rotate_epoch_v8.rs, publish_equal_flow_epoch_v8.rs + mod.rs). lease.rs 1460 LOC is one piece (token bucket + v8 acquire). Further split would require widening `pub(super)` to `pub(crate)` for config/state/v8 fields. |
| event_emit.rs 1492 (prod ~600) | 0 structs, 1 enum | Dataplane event emission | 8 emit functions (policy_deny, host_inbound_deny, screen_drop, screen_alarm, filter_log) + helpers (resolve_app_id, screen_parse_error_info). All same pattern: build DataplaneEventPayload → try_emit. Single responsibility: RT_FLOW event emission. Tests 892 LOC (60% of file). |
| coordinator/status.rs 1195 | 0 structs (impl Coordinator) | Status surface | 40+ `pub fn` all `&self` → snapshot/sum of coordinator state for gRPC/HTTP. No mutation (except drain_session_deltas). Single responsibility: status reporting. Header says “Operator-status surface split out of coordinator/mod.rs to keep gRPC / HTTP status methods in one place.” |

**Hot-path preservation (where applicable):**

- **cold_path_hist.rs hot functions** (`bucket_index_for_ns_48`, `zone_pair_packed_key`, `lookup_slot`, `sample_tsc_start/end`, `record_sample`): All `#[inline]`, branchless or single-predicate. `bucket_index_for_ns_48` is documented as branchless within each band (one `if ns < 512` selects linear vs exponential). `record_sample` does `buckets[slot][b].saturating_add(1)` + `sum_ns` + `samples` + first_key collision detect — all O(1), no alloc, no lock (worker-local). Called at sampling rate (1-in-256 default, `sample_mask = 0xff`), not per-packet. Inlining is preserved by `#[inline]` regardless of which file defines them — splitting would not change codegen because all are `pub(in crate::afxdp)` and intra-crate.

  The file also contains `WorkerColdPathAtomics` (`#[repr(C, align(64))]`, 64-byte aligned, seqlock publish) and `WorkerColdPathCounters` (`#[repr(C)]`, hot fields in cacheline 0 [0..63] per offset_of tests). The `#[repr(C)]` is load-bearing for cacheline isolation — splitting into separate files would keep the structs together (they must stay co-located) or risk breaking the documented layout. Current layout is correct and pinned by tests (`worker_cold_path_counters_hot_fields_fit_in_cacheline_0`, `worker_cold_path_atomics_hot_fields_at_top`).

- **types/cos.rs FlowRrRing**: `push_back`, `pop_front`, `push_front` are `#[inline]`, use mask-based wrap (`& COS_FLOW_FAIR_BUCKET_MASK`) not modulo — deterministic codegen, no division. `remove` is O(len) linear scan + shift — documented as “typically 2-16 on iperf3, 4096 worst case”. All methods avoid alloc (fixed `[u16; 4096]` backing). `FlowFairState::new_boxed` uses `Box::new_uninit` + raw pointer writes to avoid 352 KB stack temporary — documented SAFETY contract, verified by `new_boxed_matches_new_field_for_field` test + `cargo +nightly miri`. Splitting file would not change any of this.

- **shared_cos_lease/lease.rs acquire_v8_with_cause (278 LOC)**: Hot path for CoS exact queue (per worker, per 200µs epoch). Contains three phases: primary (bounded by my_fair_share + class_cap), surplus (bypass-grace), equal-flow cap. Uses `compare_exchange_weak` loops, tag-checked CAS, `PackedEpochGrant::pack/unpack`. Single function is long (278 LOC) but is a single algorithm (acquire) with three phases that share `still_needed`, `total_granted`, `shortfall` — splitting into `acquire_primary`/`acquire_surplus` would require passing 6+ parameters or a context struct, adding indirection without reducing complexity. The `#[inline]` on helpers (`try_bump_outstanding`, `worker_grant_bump`, `tag_checked_rollback`, `record_equal_flow_active_sample`) is appropriate; LTO is off (codegen-units 16) so cross-file inlining is lost if helpers move to separate files — keeping them in same file preserves intra-crate inlining.

- **event_emit.rs**: `emit_*_event` functions are `#[inline]`, build `DataplaneEventPayload` on stack (no alloc), call `try_emit_dataplane_event_at` (non-blocking, rate-limited). Correct per engineering-style hot-path discipline: no `Vec::push`, no `Box::new` per packet. Splitting file would not affect inlining (all `#[inline]`).

**Why NOT to split:**

- All 7 files are under 2000 LOC (or prod <1000 after excluding tests). They each have a single conceptual responsibility (CoS types, forwarding types, wire DTOs, histogram primitives, lease token bucket, event emission, status surface). Further decomposition would increase file count and cross-file `pub(super)` → `pub(crate)` widening without measurably improving reviewability. The prior decomposition work (#68.1 CoS types extraction, #1229 v6 fair-share module split, #1619 cold_path_hist extraction, #2158 lease split) already brought these files down from larger monoliths — they are at the right granularity today.

- `types/cos.rs` specifically: proposes 25 CoS-related structs. Splitting into `cos/config.rs`, `cos/runtime.rs`, `cos/flow_fair.rs`, `cos/telemetry.rs` would create 4 files with tight coupling (`CoSQueueConfig` → `CoSQueueRuntime` → `FlowFairState` → `VMinQueueState` chain). The current single file lets a reviewer see the full CoS type hierarchy in one place, which is valuable when adding a new queue field (must update config → runtime → telemetry → status overlay).

**Labels:** modularity, do-not-split, negative, types, telemetry
**Dedup note:** Distinct from #4404 SnapshotIntegrityError (Go), #4405 flowexport (Go), #4406 firewall-filter (Rust, separate module), #4408-#4409 Go services. No prior Rust types/cos.rs, cold_path_hist, shared_cos_lease split filed as monolith. Prior splits (#68.1, #1229, #1619, #2158) were the correct granularity — these are the outputs of those splits, not new monoliths.

---

## Summary / recommended action order

| Priority | File | Action | LOC | Class | Risk |
|----------|------|--------|-----|-------|------|
| 1 | coordinator/wg_control.rs 2280 | Split into 5 files (socket, loop, dispatch, handshake, poll) | -~1800 from monolith | (A) mechanical | Low (cold path, existing tests) |
| 2 | server/helpers.rs 1292 | Split into 5 files (status, session_sync, binding_plan, hash, lifecycle) | -~800 from dumping ground | (A) mechanical | Low (cold path, pure fns) |
| 3 | event_stream/mod.rs 1693 | Optional: time.rs + io.rs extraction | -~300 if done | (A) mechanical / (D) defer | Low |
| — | wg/engine.rs 1805 | DO NOT SPLIT | — | (D) | — |
| — | wg/cookie.rs 1435 | DO NOT SPLIT | — | (D) | — |
| — | types/cos.rs 1786 | DO NOT SPLIT | — | (D) | — |
| — | types/forwarding.rs 1054 | DO NOT SPLIT | — | (D) | — |
| — | protocol/binding.rs 1168 | DO NOT SPLIT | — | (D) | — |
| — | cold_path_hist.rs 1866 (prod 950) | DO NOT SPLIT | — | (D) | — |
| — | shared_cos_lease/* (6 files) | DO NOT SPLIT further | — | (D) | — |
| — | event_emit.rs 1492 (prod 600) | DO NOT SPLIT | — | (D) | — |
| — | coordinator/status.rs 1195 | DO NOT SPLIT | — | (D) | — |

**Total mechanical debt:** 2 files over 2000 LOC or dumping-ground (wg_control.rs, helpers.rs) = ~3500 LOC to decompose. 1 optional (event_stream/mod.rs). 10 files correctly NOT split (negatives).

**Hot-path invariants preserved:** All hot-path files (engine.rs encap/decap, cold_path_hist bucket/record, cos FlowRrRing, lease acquire_v8, codec encoding, event_emit try_emit) use stack-only / MaybeUninit / fixed arrays / mask-not-modulo / `#[inline]` / no per-packet alloc / `compare_exchange_weak` seqlock discipline. No split proposed touches hot-path inlining or layout. Proposed splits are cold-path only (wg_control, helpers, event_stream io/time).

**Dedup vs prior audits:** Checked #4404 SnapshotIntegrityError (Go, 616-LOC dumping ground — different module), #4405 flowexport, #4406 firewall-filter, #4407 event-engine (Go), #4408-#4409 Go services, #4421 cold_path_hist? — no overlap. Prior Rust splits (#68.1 types, #1229 v6 lease, #1619 cold_path, #2158 lease) are the correct granularity and their outputs are NOT re-reported as monoliths here.
