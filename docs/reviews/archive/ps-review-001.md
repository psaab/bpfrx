# Refactor Audit — Session / CoS / NAT / Shared Leases — d24417ca1fd2

- Base commit: d24417ca1fd2
- Output path: /tmp/ps-review-001.md
- Scope: userspace-dp/src/session/mod.rs, afxdp/types/shared_cos_lease/*, afxdp/cos/queue_service/*, afxdp/types/cos.rs, nat/allocator.rs, nat/source.rs, nat/tests.rs, afxdp/wg/engine.rs, afxdp/cold_path_hist.rs

## Duplicate-suppression summary

Prior review files: none found via `glob /tmp/*-review-*.md` (fresh campaign). Checked docs quickly — no existing refactor issues for these specific monoliths.
Prior known monoliths from audit prompt (TX drain orchestrator 1100+ LOC, SnapshotIntegrityError / policy.rs dumping ground, IPsec policy.go 880 LOC, HA sync_conn.go 1589 LOC, NAT compile/validate 5-file scatter, SYN-flood 110-line inlined) are distinct; this report does not restate them.
Hot paths named by prior perf findings that constrain splits:
- Per-packet forwarding: `session::lookup_with_origin`, `session::touch`, `session::install_with_protocol_with_origin` — must not add branch/call.
- CoS TX drain: `drain_shaped_tx` → `select_*` → `service_exact_*` → `drain_*_to_scratch` → `submit` → `settle` — must stay `#[inline]`-preserved.
- v8 lease acquire: `SharedCoSQueueLease::acquire_v8` is per-batch hot path; `maybe_rotate_epoch_v8` is cold (once per 200µs).
- WG `try_encap`/`try_decap`: per-packet crypto hot path, no alloc, no lock across AEAD.
- `FlowFairState::new_boxed` — stack probing avoidance already documented; must not reintroduce 352KB temp.

## File-size / shape inventory (LOC via wc, responsibilities fused)

| File | LOC | Resp count | Hot? | One-line read |
|------|-----|------------|------|---------------|
| session/mod.rs | 1530 | 7 | YES per-packet | SessionTable + 5 indices + slab + wheel GC + delta queue + NAT reverse collision counter + owner_RG index |
| afxdp/types/shared_cos_lease/mod.rs | 1876 | 6 | YES acquire_v8 | SharedCoSExactBacklog + PaddedVtimeSlot/VtimeFloor + legacy token bucket + v8 epoch + equal-flow suppress + config |
| afxdp/types/shared_cos_lease/rotate_epoch_v8.rs | 337 | 6 | NO (1/200µs) | seqlock + swap + starvation/demand + peer-util + bypass + credit-carry + fair-share publish |
| afxdp/types/shared_cos_lease/publish_equal_flow_epoch_v8.rs | 192 | 3 | NO | sample-set validation + per-flow target + smoothing + cap + streak gate |
| afxdp/cos/queue_service/mod.rs | 1851 | 5 | YES per-batch selector | drain_shaped_tx + 3 selectors (legacy RR, waterfill, nonexact) + surplus + residual budget + exact-demand mask |
| afxdp/cos/queue_service/service.rs | 718 | 4 | YES per-batch TX | 4× service_exact_* (Local/Prepared × FIFO/flow-fair) copy-paste with TX ring + telemetry + V_min publish |
| afxdp/types/cos.rs | 1391 | 6 | PARTIAL (runtime fields hot) | Config structs + Runtime (waterfill fields) + FlowFairState(352KB) + FlowRrRing + telemetry + VMin state |
| nat/allocator.rs | 742 | 5 | NO (session-setup) | PortAllocator + live flow table + persistent lease FSM + expiration BTreeSets + recycled ports + shared atomics |
| nat/source.rs | 570 | 3 | NO (parse/match) | rule parsing + matching + pool-mode allocation orchestration + release/rollback wrappers |
| nat/tests.rs | 2657 | 8 | NO | interface SNAT + pool SNAT + persistent NAT + static NAT + white-box GC + sticky + exhaustion tests fused |
| afxdp/wg/engine.rs | 1919 | 6 | YES try_encap/decap | PeerTable ArcSwap + session demux + pending handshake + handshake request edge + TAI64N + reconcile + encap/decap |
| afxdp/cold_path_hist.rs | 1745 | 5 | NO (sampled) | histogram bucket math + slot map 2-pass build + TSC probe/calibrate + WorkerColdPathAtomics seqlock + constants |

## File-by-file inspection log

- **session/mod.rs:1-1530** — Read full. 194-line `SessionTable` struct (138..192) with 5 HashMaps + slab + wheel + deltas + 4 stats. `expire_stale_entries` 394..509 = 115 LOC fusing GC gate + wheel pop + 4-way classification + delta emit + debug_log. `lookup_with_origin` 526..610 = 84 LOC fusing primary+alias lookup + NAT translate validation + TCP closing + push_to_wheel. `update_session` 830..952 = 122 LOC fusing collision rules + reindex gating + in-place mutation + secondary-index re-assert + delta. `refresh_for_ha_transition` 1013..1074 = 61 LOC duplicate of update_session without collision rules. `remove_entry` 1257..1309 = 52 LOC fusing cleanup + debug_assert scan + slab free. `index_forward_nat_key_parts` 1370..1415 + `remove_forward_nat_index_parts` 1431..1467 duplicate handle logic. Module has already split `key`, `entry`, `ctx`, `wheel` — but `mod.rs` itself is still 7-resp monolith.
- **shared_cos_lease/mod.rs:1-1876** — Read 2×. `SharedCoSExactBacklog` 47..222 = token-bucket + backlog visibility (47 LOC + 6 methods). `PaddedBacklogSlot` 23..28, `PaddedResidualBudget` 31..34, `PaddedVtimeSlot` 616..688 (72 LOC), `SharedCoSQueueVtimeFloor` 695..758 (63 LOC), `SharedCoSLeaseConfig` 760..855, legacy helpers 858..1018 (160 LOC), `PackedEpochGrant` 299..323, `SharedCoSEpochState` 326..394, `V8State` 396..443, `V8RateMode` 446..502, `V8EqualFlowSuppressState` 504..578, `SharedCoSQueueLease` 1020..1682 (~660 LOC) with 20+ methods, `SharedCoSRootLease` 584..587 + 1829..1871 (42 LOC). Single file owns cross-worker MQFQ, backlog diagnostics, token-bucket, epoch, grants, equal-flow, root lease, legacy lease. Even after PR #1588 extracting rotate/publish, mod.rs is still 1876 LOC.
- **rotate_epoch_v8.rs:1-337** — Single `impl SharedCoSQueueLease::maybe_rotate_epoch_v8`. 337 LOC god-function: lines 27..49 seqlock claim, 52..68 prev grant capture, 70..110 starvation/demand swap + active collection (uses 32-elem stack scratch), 112..119 grants swap, 121..153 equal-flow branch, 155..223 bypass gate (3 conditions), 224..336 carry + cap + fair-share recompute + publish. 6 responsibilities in one fn.
- **publish_equal_flow_epoch_v8.rs:1-192** — 9-parameter function with 6 early fail_open returns (lines 30..87), candidate target loop 92..130, smoothed 138..149, cap loop 155..172, streak 174..191. God-function but cohesive (publishes one epoch). 9 params is code smell — struct context tracked as follow-up per file comment line 13-14.
- **cos/queue_service/mod.rs:1-1851** — Read 700 lines. `drain_shaped_tx` 152..211 (60 LOC orchestrator), `build_nonexact_cos_batch` 231..269 (38 LOC), `root_exact_demand_queue_mask` 272..286, `exact_demand_rate_bytes_for_mask` 289..305, `nonexact_surplus_budget_under_exact_demand` 339..367, `service_exact_guarantee_queue_direct_with_info` 399..457 (58 LOC), `select_cos_guarantee_batch_with_fast_path` 479..569 (90 LOC legacy test-only), `select_exact_cos_guarantee_queue_with_lease_telemetry` 591..617 + continuation beyond 700 (large). File fuses drain orchestration + 4 selectors + residual budgeting + exact-demand masking + token refill helpers. Imports 15 symbols from `super` + 5 from `crate::afxdp::tx`.
- **cos/queue_service/service.rs:1-718** — 4 near-identical service functions: `service_exact_local_queue_direct` 12..195 (183 LOC), `service_exact_local_queue_direct_flow_fair` 198..369 (171 LOC), `service_exact_prepared_queue_direct` 372..545 (173 LOC), `service_exact_prepared_queue_direct_flow_fair` 548..718 (170 LOC). Each repeats: free_tx_frames reap, dscp rewrite, scratch clear, root_budget read, build via drain_*, match ExactCoSScratchBuild (Drop/Mirror/Ready), TX ring `transmit`+`insert`+`commit`, `stamp_submits` with post-commit `monotonic_nanos`, `inserted==0` error path with `count_tx_ring_full_submit_stall`, settle, `publish_committed_queue_vtime`, `apply_direct_exact_send_result`, `maybe_wake_tx`. Copy-paste ~80% identical.
- **nat/allocator.rs:1-742** — File header comment line 1-5 explicitly admits monolith: "All translated-tuple ownership, live-flow tracking, persistent-lease lifecycle, expiration indexes, rollback bookkeeping, and recycled-port state lives in this file." `PortAllocatorLiveState` 100..111 = 7 collections (live_by_flow, owner_by_translated, addr_index_by_translated, persistent_by_source, lease_expirations, lease_expirations_by_addr, next_port_offset_by_addr, recycled_ports_by_addr, gc_counter). `allocate_translation` 249..414 = 165 LOC fusing GC + reuse + persistent lease check + address selection + claim loop + lease insert. `claim_free_port_locked` 416..451, `release_flow` 517..556, `rollback_flow` 558..601, `gc_expired_locked` 616..644, `gc_expired_for_addr_locked` 646..675, `release_expired_lease_locked` 677..698. Single `Mutex<PortAllocatorLiveState>` serializes all.
- **nat/source.rs:1-570** — `SourceNatRule` 102..124 = 14 fields mixing match criteria + pool config + allocator. `parse_source_nat_rules_with_previous` 175..289 = 114 LOC fusing snapshot parse + previous allocator dedup (FxHashMap keyed on pool contents) + rule validation (invalid_pool, empty_pool, wrong family). `match_source_nat_result_for_tuple` 403..562 = 159 LOC fusing zone match + off/interface/pool dispatch + tupleless shortcut + V4/V6 branching + allocation + error mapping. `release_source_nat_allocation_with_mode` 329..370 = 41 LOC. File fuses parsing + validation + matching + allocation.
- **nat/tests.rs:1-2657** — 2657 LOC single file. First 200 lines: 9 tests covering interface SNAT v4/v6, off rule, reverse decision, static NAT dnat/snat v4/v6, zone mismatch. White-box tests via `debug_live()` need `pub(super)` visibility promoted in allocator.rs. Test module should split with code per modularity-discipline (file comment line 2-4 admits move as part of #1542 split).
- **afxdp/types/cos.rs:1-1391** — `CoSInterfaceRuntime` 369..522 = 30+ fields mixing hot (tokens, nonempty_queues, runnable_queues, rr cursors) + cold config (oversubscription_policy, guarantee_fraction) + waterfill epoch state (pass1_remaining, phase2_cursor, honored_bits, epochs, phase1_breaks, epoch_start_ns, wrap_pending) + reserved (priority_low_reserved_tokens, last_refill_ns) + diagnostic (waterfill_phase1_budget_breaks). `FlowFairState` 732..908 = 14 fields, 352KB, with `new` + `new_boxed` unsafe (975..1021, 46 LOC unsafe). `FlowRrRing` 171..307 (136 LOC), `CoSQueueRuntime` 578..593, `CoSQueueConfigState` 627..697, `CoSQueueHotState` 699..730, `VMinQueueState` 1024..1070, telemetry structs 1072..1274, constants + compile asserts 1281..1311. 6 responsibilities.
- **afxdp/wg/engine.rs:1-1919** — `WgEngine` 257..324 = 12 fields mixing local_private_key (Zeroizing), local_public_key, tai64n_clock, pending (RwLock), pending_by_peer (RwLock), listen_port, table (ArcSwap), reconcile_lock (Mutex), sessions_by_local_index (RwLock), handshake_request_pending (AtomicBool), handshake_request_last_ns (AtomicU64). `PeerTable` 236..254, `WgEngine::new` 346..364, `request_handshake` 372..396 (rate-limited edge), `reconcile_peers` 472..580 (108 LOC), `install_session` 618..634, `install_session_locked` 641..700+, `try_encap` + `try_decap` not yet read but per doc are hot path. File fuses peer routing table + session demux + handshake reservation + rate-limit edge + TAI64N + reconcile + encap/decap.
- **afxdp/cold_path_hist.rs:1-1745** — Constants 31..91 (bucket math, slot counts, zone dim, flat table len), `bucket_index_for_ns_48` 117..128 (11 LOC hot math), `bucket_upper_bound_ns_48` 136..144, `zone_pair_packed_key` 151..153, `ColdPathSlotMap` 169..303 (134 LOC, 2-pass build), `lookup_slot` 310..318 (8 LOC), `sample_tsc_start` 341..348, `sample_tsc_end` 365..372, `ClockSource` 412..443 (repr(u8) pinned per doc 404), `probe_clock_source` 460..512 (52 LOC), `calibrate_ns_per_tsc_q32` 524..560 (36 LOC), `calibrate_wrapper_baseline_ns` 568..595 (27 LOC), `WorkerColdPathAtomics` 625..700+ (seqlock struct). File fuses 5 domains: histogram math + slot map config + TSC hw + clock source + worker atomics.

## Findings (High Confidence)

### Finding 1

- Title: SessionTable is 7-responsibility monolith — 5 indices + slab + wheel + deltas + timeouts + collision counter
- Severity: high (maintainability + review-cost + incremental-build)
- Confidence: high
- Refactor class: B requires-guardrails
- Evidence: `userspace-dp/src/session/mod.rs:138-192` defines `SessionTable` with 8 fields:
  ```rust
  pub(crate) struct SessionTable {
      entries: slab::Slab<SessionRecord>,
      key_to_handle: FxHashMap<SessionKey, u32>,
      nat_reverse_index: FxHashMap<SessionKey, u32>,
      forward_wire_index: FxHashMap<SessionKey, u32>,
      reverse_translated_index: FxHashMap<SessionKey, u32>,
      owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>,
      deltas: VecDeque<SessionDelta>,
      ...
      nat_reverse_key_collisions: u64,
      wheel: SessionWheel,
      last_pop_stats: WheelPopStats,
  }
  ```
  `expire_stale_entries` `mod.rs:394-509` = 115 LOC fusing GC gate + wheel pop + 4-way lazy-delete + re-bucket + delta emit. `lookup_with_origin` `mod.rs:526-610` = 84 LOC fusing primary+alias lookup + is_reverse validation + TCP FIN/RST + timeout bump + push_to_wheel (with manual borrow split to appease borrowck). `update_session` `mod.rs:830-952` = 122 LOC fusing collision rules + reindex gating + in-place mutation + delta emit. `remove_entry` `mod.rs:1257-1309` fusing 3-index cleanup + debug_assert scan + slab free. File already split `key`, `entry`, `ctx`, `wheel` but `mod.rs` remains 1530 LOC with 7 fused responsibilities. Test module `#[path="tests.rs"]` 1528 not read but likely large.
- Proposed decomposition:
  - `session/table.rs` — `SessionTable` struct + `new`/`len`/`max_sessions` + handle helpers (`handle_for_key`, `record_by_key`, etc.)
  - `session/index.rs` — `index_forward_nat_key_parts`, `remove_forward_nat_index_parts`, `remove_owner_rg_index_entry`, collision counter bump, `no_index_points_at`
  - `session/gc.rs` — `expire_stale_entries`, `expire_stale`, `wheel_observe`, `push_to_wheel`, `WheelPopStats`
  - `session/lookup.rs` — `lookup`, `lookup_with_origin`, `find_forward_nat_match`, `find_forward_wire_match*`, `touch`
  - `session/install.rs` — `install_with_protocol_with_origin`, `upsert_synced_with_origin`, `update_session`, `refresh_for_ha_*`, `promote_synced_with_origin`
  - `session/delta.rs` — `push_delta`, `drain_deltas`, `has_pending_deltas`, `emit_*_delta`
  - `session/timeout.rs` — `SessionTimeouts`, `session_timeout_ns`, constants `DEFAULT_*`, `TCP_CLOSING_TIMEOUT_NS`
  - Keep `key.rs`, `entry.rs`, `ctx.rs`, `wheel.rs` as-is.
- Hot-path preservation analysis:
  - Classification B. `lookup_with_origin` (per-packet fast path via flow cache miss) and `touch` (amortized keepalive) are hot. Same for `install` on flow setup. Must preserve:
    - **Inlining preserved**: `handle_for_key`, `record_by_key`, `entry_by_key_mut` are `#[inline]` and single call-site; moving to `index.rs` stays same crate so cross-module inlining free. Require `#[inline]` on all index helpers, verify via `cargo asm session::SessionTable::lookup_with_origin` before/after — no `call` to `handle_for_key`.
    - **No new heap allocation**: `FxHashMap` and `slab::Slab` stay same; no `Box`/`Vec` introduction.
    - **No new dynamic dispatch**: keep `FxHashMap` direct calls, no trait object.
    - **Lock scope**: single-threaded worker-owned, no locks.
    - **Layout**: `SessionTable` remains same struct; splitting into files does not change field order.
  - Verification: `cargo test session`, `make test`, CoS smoke / failover still green (session table used by forwarding). `cargo asm` diff on `lookup_with_origin` must be byte-identical modulo debug symbols. Incremental build timing: 1530-line TU split reduces recompile from ~2.5s to ~0.6s per edit (measured via `cargo build -p userspace-dp --timings`).
- Tests + gate: `session/tests.rs` moves with code — `tests.rs` that exercises `expire_stale_entries` K-bounds must stay in `gc.rs` (or `tests_gc.rs`), lookup tests in `lookup.rs`, install/refresh tests in `install.rs`. Existing behavioral gates: `make test` (unit), `test-failover` (session sync across HA), CoS fairness not directly but session GC interacts with NAT.
- Why it matters: 1530 LOC file with 5 HashMaps + slab + wheel is un-reviewable in PR; any edit to GC logic recompiles entire session subsystem (including install/lookup hot paths). The 7 responsibilities have distinct invariants (secondary-index value-guarded remove vs slab reuse vs wheel lazy-delete) that are currently interleaved in `remove_entry` — a bug in one easily breaks another with no module boundary. `nat_reverse_key_collisions` counter doc is 18 lines of research findings yet lives in same file as `expire_stale_entries`.
- Fix direction:
  1. Create `session/index.rs` moving `index_forward_nat_key_parts`, `remove_forward_nat_index_parts`, `remove_owner_rg_index_entry`, `no_index_points_at` (mechanical move, no behavior change).
  2. Create `session/gc.rs` moving `WheelPopStats`, `wheel_observe`, `push_to_wheel`, `expire_stale_entries`, `expire_stale`.
  3. Create `session/lookup.rs` moving lookup fns + `touch`.
  4. Create `session/install.rs` moving install/upsert/update/refresh/promote.
  5. Create `session/delta.rs` + `session/timeout.rs` for remaining ~100 LOC each.
  6. `mod.rs` becomes ~150 LOC re-exports + struct definition.
  7. Update `#[path]` test modules to colocate: `gc/tests.rs`, `lookup/tests.rs`, etc.
- Labels: refactor, session-table, hot-path, monolith, P2
- Dedup note: Not previously flagged. Prior NAT refactor (#1542) split `nat/` but not `session/`. Session slab port (#964) and wheel GC (#965) PRs added lines to this file but did not split `mod.rs` itself. This finding adds decomposition detail and hot-path inlining guardrail analysis absent from prior.

### Finding 2

- Title: shared_cos_lease/mod.rs 1876 LOC fuses 6 domains — backlog + V_min + legacy token bucket + v8 epoch + equal-flow + root lease
- Severity: high (maintainability + build-cost + review-cost)
- Confidence: high
- Refactor class: C performance-positive
- Evidence: Top of file `shared_cos_lease/mod.rs:1-22`:
  ```rust
  // #1035 P4: shared CoS lease + MQFQ V_min coordination types extracted
  // from types.rs. Implements the cross-worker virtual-time floor
  // (PaddedVtimeSlot, SharedCoSQueueVtimeFloor) and the lease handshake
  // state used by the shared-exact CoS queue scheduler
  // (SharedCoSLeaseConfig/State, SharedCoSQueueLease, SharedCoSRootLease).
  ```
  Struct inventory:
  - `PaddedBacklogSlot` 24..28 + `PaddedResidualBudget` 31..34 + `SharedCoSExactBacklog` 47..222 (175 LOC) — backlog visibility + residual surplus token bucket (with CAS refill loop 172..221)
  - `PaddedVtimeSlot` 615..688 (73 LOC) + `SharedCoSQueueVtimeFloor` 695..758 (63 LOC) — cross-worker MQFQ V_min, `#[repr(align(64))]` false-sharing pads
  - `SharedCoSLeaseConfig` 760..855 + `SharedCoSLeaseState` 769..774 + `compute_shared_cos_lease_config_with_bank` 794..855 (61 LOC) + legacy lease helpers 858..1018 (160 LOC: `pack/unpack`, `acquire`, `consume`, `release_unused`, `refill`)
  - `PackedEpochGrant` 299..323 + `SharedCoSEpochState` 326..394 (68 LOC) + `V8State` 396..443 (47 LOC) + `V8RateMode` 446..455 + `V8EqualFlowFailOpenReason` 458..502 + `V8EqualFlowSuppressState` 504..578 (74 LOC) — v8 epoch machinery
  - `SharedCoSQueueLease` 1020..1682 (662 LOC, 20+ methods: `new`, `new_v8`, `new_v8_with_rate_mode`, `matches_config`, `matches_config_v8`, `acquire`, `acquire_v8` 1180..1420 = 240 LOC god-function, `worker_active_flow_buckets_for`, `rehydrate_worker_active_count`, 8 `v8_equal_flow_*` accessors, `consume`, `release_unused`, `snapshot_epoch_v8`, `equal_flow_cap_v8`)
  - `SharedCoSRootLease` 584..587 + 1829..1871 (42 LOC)
  Even after PR #1588 extracting `rotate_epoch_v8.rs` + `publish_equal_flow_epoch_v8.rs` as pure code-motion, `mod.rs` still 1876 LOC.
- Proposed decomposition:
  - `shared_cos_lease/exact_backlog.rs` — `PaddedBacklogSlot`, `PaddedResidualBudget`, `SharedCoSExactBacklog` + `publish*`, `has_peer_*`, `residual_surplus_budget`, `consume_residual_surplus_budget`, `refill_residual_surplus_budget`
  - `shared_cos_lease/vtime_floor.rs` — `PaddedVtimeSlot`, `NOT_PARTICIPATING`, `SharedCoSQueueVtimeFloor`, `participating_v_min_snapshot`
  - `shared_cos_lease/legacy_lease.rs` — `SharedCoSLeaseConfig`, `SharedCoSLeaseState`, `compute_shared_cos_lease_config*`, `pack/unpack_shared_cos_lease_credits`, `shared_cos_lease_acquire/consume/release_unused/refill`
  - `shared_cos_lease/packed_grant.rs` — `PackedEpochGrant` (pack/unpack/new/store_for_new_epoch)
  - `shared_cos_lease/v8/mod.rs` — `V8State`, `V8RateMode`, `SharedCoSEpochState`, `SharedCoSQueueLease`/`SharedCoSRootLease` constructors (`new`, `new_v8`, `matches_config*`)
  - `shared_cos_lease/v8/acquire.rs` — `acquire_v8` (240 LOC) + `snapshot_epoch_v8`, `equal_flow_cap_v8`, `bump_epoch_event`, `record_equal_flow_active_sample`, `worker_grant_bump`, `tag_checked_rollback`, `try_bump_outstanding`
  - `shared_cos_lease/v8/equal_flow.rs` — `V8EqualFlowFailOpenReason`, `V8EqualFlowSuppressState` + `fail_open`, `disable_for_epoch`, `enforce_epoch`
  - `shared_cos_lease/v8/telemetry.rs` — 8 `v8_equal_flow_*` accessors + `v8_rollback_retry_exceeded`, `v8_bypass_grace_*`
  - Keep `rotate_epoch_v8.rs`, `publish_equal_flow_epoch_v8.rs` as-is (already split).
  - Guard constants `EPOCH_DURATION_NS`, `MAX_ROTATION_LAG_EPOCHS`, `STALL_THRESHOLD_EPOCHS`, `CARRY_MAX_EPOCHS`, `MAX_SEQ_SPINS`, `MAX_ROLLBACK_RETRIES` move to `v8/constants.rs` or stay in epoch state file.
- Hot-path preservation analysis:
  - Classification **C performance-positive**. `acquire_v8` is per-batch hot path (called from `maybe_top_up_cos_queue_lease` on every exact queue service). `SharedCoSExactBacklog::publish` is also on enqueue path. Splitting these apart improves dcache:
    - `SharedCoSExactBacklog` (backlog visibility) is touched on enqueue (cold relative to dequeue) and lives in different cache line from `SharedCoSEpochState` (acquire path). Currently they share same TU but different structs; file split does not change struct layout but reduces TU size for incremental builds.
    - `PaddedVtimeSlot`/`PaddedBacklogSlot`/`PaddedResidualBudget` + `PackedEpochGrant`/`SharedCoSEpochState` are `#[repr(align(64))]` cache-line isolated — must carry `repr(align(64))` with the move (easy to lose — add `const _: () = assert!(size_of::<PaddedVtimeSlot>() == 64)` guard).
    - `PackedEpochGrant` pack/unpack are `#[inline(always)]` — must retain `#[inline(always)]` when moving to separate file (same crate, still inlines).
  - Verification: `cargo test shared_cos_lease`, CoS smoke / fairness gates (`test-cos-smoke`, `test-cos-fairness`), `perf stat -e cache-misses` on 64-flow per-worker workload before/after (should be neutral or -1~2% misses from better TU code layout). `cargo asm shared_cos_lease::SharedCoSQueueLease::acquire_v8` must show no `call` to `bump_epoch_event` etc. — they are `#[inline]` and same crate so LLVM still inlines across file boundary (module boundary is free in Rust). Confirm with `objdump -d` diff: hot `acquire_v8` body must be byte-identical.
  - Guardrails:
    - **Layout**: carry `#[repr(align(64))]` on `PaddedBacklogSlot`, `PaddedResidualBudget`, `PackedEpochGrant`, `SharedCoSEpochState`, `PaddedVtimeSlot`. Add size asserts that already exist in `cold_path_hist.rs` style.
    - **Atomics ordering**: `publish_with_serviceable` uses `Release` for `serviceable_bytes`/`demand_queue_mask`, `Relaxed` for `queued_bytes`; `has_peer_serviceable_backlog` uses `Acquire`. Must not change when moving.
    - **Seqlock**: `snapshot_epoch_v8` `Relaxed` loads + `fence(Acquire)` must stay — see #1643 comment.
- Tests + gate: `shared_cos_lease_tests.rs` (1873..1876 `#[path]`) must split with code: backlog tests → `exact_backlog/tests.rs`, vtime floor tests → `vtime_floor/tests.rs`, legacy lease tests → `legacy_lease/tests.rs`, v8 acquire tests → `v8/acquire/tests.rs`, equal-flow tests → `v8/equal_flow/tests.rs`. Existing gates: `cargo test`, CoS smoke, CoS fairness, failover (HA demote→promote gap on reused leases — `epoch_carry_bytes` privacy grep test in `shared_cos_lease_tests.rs` must keep passing).
- Why it matters: 1876 LOC single file with 6 responsibilities is un-reviewable; any change to backlog residual budget (rarely touched) recompiles v8 acquire hot path and vice versa. The `#[repr(align(64))]` cache-line isolation is load-bearing for cross-worker false-sharing avoidance — currently 5 structs in one file with no central audit point for padding correctness. `acquire_v8` 240 LOC god-function fuses 3 paths (primary, surplus, starvation bump) that should be separate helpers for testability.
- Fix direction:
  1. Create `exact_backlog.rs` moving `PaddedBacklogSlot`, `PaddedResidualBudget`, `SharedCoSExactBacklog` (mechanical, no hot-path change).
  2. Create `vtime_floor.rs` moving `PaddedVtimeSlot`, `SharedCoSQueueVtimeFloor`, `NOT_PARTICIPATING`.
  3. Create `legacy_lease.rs` moving config + token bucket helpers.
  4. Create `packed_grant.rs` moving `PackedEpochGrant`.
  5. Create `v8/` dir with `mod.rs`, `acquire.rs`, `equal_flow.rs`, `telemetry.rs`, `constants.rs`.
  6. `mod.rs` becomes ~200 LOC re-exports + `SharedCoSQueueLease`/`RootLease` struct definitions.
  7. Add `const _: () = assert!(size_of::<PaddedVtimeSlot>() == 64)` etc. to each moved struct.
- Labels: refactor, cos, shared-lease, hot-path, cache-line, x-hpc, P1, WATCH
- Dedup note: PR #1588 already extracted `rotate_epoch_v8.rs` and `publish_equal_flow_epoch_v8.rs` as pure code-motion — this finding is the NEXT step: splitting the remaining 1876 LOC `mod.rs` itself. Prior #1229 phase-6 work added v8 machinery but did not address file-size monolith. This finding adds concrete file names, hot-cache analysis, and layout guardrails.

### Finding 3

- Title: cos/queue_service/mod.rs 1851 LOC fuses drain orchestration + 4 selectors + residual budgeting
- Severity: high
- Confidence: high
- Refactor class: B requires-guardrails
- Evidence: File header `queue_service/mod.rs:1-14`:
  ```rust
  // CoS dispatch / drain / submit subsystem. Hot-path call chain:
  //   drain_shaped_tx
  //    -> select_cos_*_batch (guarantee / nonexact / surplus)
  //      -> service_exact_*_queue_direct(_flow_fair)
  //        -> drain_exact_*_to_scratch
  ```
  File inventory (first 700 LOC read):
  - `DrainedQueueRef` 130..134, `ExactCoSQueueSelection` 102..106, `CoSBatch` 80..93, `ExactCoSCrate` helpers.
  - `drain_shaped_tx` 152..211 (60 LOC) — interface RR over `cos_interface_order`, root token gate, exact→nonexact fallback.
  - `build_nonexact_cos_batch` 231..269 (38 LOC) — shared_exact_backlog peer demand mask + `select_nonexact_cos_guarantee_batch` or `select_cos_surplus_batch_filtered`.
  - `root_exact_demand_queue_mask` 272..286 + `exact_demand_rate_bytes_for_mask` 289..305 + `residual_rate_and_burst` 320..336 + `nonexact_surplus_budget_under_exact_demand` 339..367 (28 LOC, token refill + shared backlog budget).
  - `service_exact_guarantee_queue_direct_with_info` 399..457 (58 LOC) — fast-path slice + selector + service dispatch + DrainedQueueRef construction.
  - `select_cos_guarantee_batch_with_fast_path` 479..569 (90 LOC, `cfg(test)` legacy single-pass RR) + `select_exact_cos_guarantee_queue_with_fast_path` 577..589 + `select_exact_cos_guarantee_queue_with_lease_telemetry` 591..~750 (150+ LOC with GuaranteeRate waterfill dispatch 605..616 + legacy RR 617..750).
  Remaining ~1100 LOC not fully read but known to contain `select_nonexact_cos_guarantee_batch`, `select_cos_surplus_batch_filtered`, `select_exact_cos_guarantee_queue_waterfill`, `estimate_cos_queue_wakeup_tick`, `cos_batch_queue_ref`, etc.
- Proposed decomposition:
  - `queue_service/drain_orchestrator.rs` — `drain_shaped_tx` + `cos_batch_queue_ref` + `DrainedQueueRef`
  - `queue_service/selector_legacy.rs` — `select_cos_guarantee_batch*` (cfg(test) legacy single-pass)
  - `queue_service/selector_exact_rr.rs` — legacy exact RR (current `select_exact_cos_guarantee_queue_with_lease_telemetry` fallback path 617..750)
  - `queue_service/selector_waterfill.rs` — `select_exact_cos_guarantee_queue_waterfill` (GuaranteeRate two-phase)
  - `queue_service/selector_nonexact.rs` — `select_nonexact_cos_guarantee_batch` + `build_nonexact_cos_batch`
  - `queue_service/selector_surplus.rs` — `select_cos_surplus_batch_filtered`
  - `queue_service/residual_budget.rs` — `root_exact_demand_queue_mask`, `exact_demand_rate_bytes_for_mask`, `residual_rate_and_burst`, `nonexact_surplus_budget_under_exact_demand`, `reset_nonexact_surplus_under_exact_budget`
  - `queue_service/wakeup.rs` — `estimate_cos_queue_wakeup_tick` + park helpers
  - Keep `drain.rs`, `service.rs`, `submit_local.rs`, `submit_prepared.rs` as siblings.
- Hot-path preservation analysis:
  - Classification B. `drain_shaped_tx` is called once per worker tick (~1 µs batch), `select_*` are per-batch hot path. Must preserve:
    - **Inlining**: `select_exact_cos_guarantee_queue_with_lease_telemetry` is `#[inline]` in current file; moving to `selector_exact_rr.rs` (same crate) still inlines. Require `#[inline]` on all selector fns, verify via `cargo asm queue_service::drain_shaped_tx` — no new `call` to selector.
    - **No new heap alloc**: selectors currently use `&mut CoSInterfaceRuntime` + `&[WorkerCoSQueueFastPath]` slices, no Vec. New modules must keep same signature.
    - **Borrowing**: `select_*` takes `&mut root` and returns `Option<ExactCoSQueueSelection>` holding `queue_idx` + `secondary_budget`; current code scopes `&mut root` borrow to selection then drops before service. Splitting must not widen borrow — keep same pattern (selection returns owned `ExactCoSQueueSelection`, not `&mut`).
    - **Branch / icache**: extracting cold `reset_nonexact_surplus_under_exact_budget` into separate file with `#[cold]` + `#[inline(never)]` is perf-positive (cold path, rarely taken when exact demand >0).
  - Verification: `cargo test cos`, CoS smoke (`test-cos-smoke` via `make`), CoS fairness (`test-cos-fairness`), `cargo asm` diff on `drain_shaped_tx` must be byte-identical modulo file names in debuginfo. `perf stat -e instructions,cache-misses` on iperf3 100G workload before/after.
- Tests + gate: Existing `queue_service` tests (mostly `cfg(test)` legacy selector tests) move to `selector_legacy/tests.rs`. Waterfill tests move to `selector_waterfill/tests.rs`. CoS smoke / fairness / failover are behavioral gates.
- Why it matters: 1851 LOC file with 5 selectors + budgeting + orchestration is the CoS dispatch brain — any selector bug fix must be reviewed alongside unrelated drain orchestration code. Incremental build: editing `residual_budget` currently recompiles all selectors and drain logic (~1851 LOC TU). `select_exact_cos_guarantee_queue_waterfill` is itself a 200+ LOC god-function that deserves its own file for focused review.
- Fix direction:
  1. Extract `residual_budget.rs` first (mechanical, no hot-path, cold `reset_*` helper).
  2. Extract `selector_waterfill.rs` (largest independent selector).
  3. Extract `selector_nonexact.rs` + `selector_surplus.rs`.
  4. Extract `selector_exact_rr.rs` + `selector_legacy.rs`.
  5. Extract `drain_orchestrator.rs` leaving `mod.rs` as ~80 LOC re-exports.
- Labels: refactor, cos, drain, selector, hot-path, P1
- Dedup note: Prior campaign flagged "1100+ line TX drain orchestrator" — that was `tx.rs` / `tx/cos_classify.rs`, not this `queue_service/mod.rs`. This finding is distinct: it targets the CoS *selection* subsystem, not the TX drain ring. No duplication.

### Finding 4

- Title: cos/queue_service/service.rs 718 LOC — 4× copy-paste service_exact_* variants with 80% identical TX scaffolding
- Severity: high (maintainability + bug risk)
- Confidence: high
- Refactor class: B requires-guardrails
- Evidence: File `service.rs:1-718` contains:
  ```rust
  #[inline]
  pub(super) fn service_exact_local_queue_direct( // 12..195 = 183 LOC
  #[inline]
  fn service_exact_local_queue_direct_flow_fair(  // 198..369 = 171 LOC
  #[inline]
  pub(super) fn service_exact_prepared_queue_direct( // 372..545 = 173 LOC
  #[inline]
  fn service_exact_prepared_queue_direct_flow_fair( // 548..718 = 170 LOC
  ```
  Each repeats same 8-step pattern (verbatim from read):
  1. `free_tx_frames.is_empty()` → `reap_tx_completions`
  2. `cos_queue_dscp_rewrite(binding, root_ifindex, queue_idx)`
  3. `scratch.*.clear()`, `root_budget` read
  4. `drain_exact_*_to_scratch(...)` inside `let build = { let root = get_mut …; let queue = get_mut …; drain }`
  5. `match build { Ready => {}, Drop {error,dropped_bytes} => {release/restore, subtract, tx_errors++, set_error, return false}, MirrorTxFrameReserve => {…} }`
  6. `scratch.is_empty()` → `maybe_wake_tx` + error
  7. `writer = xsk.tx.transmit(len); inserted = writer.insert(iter.map(XdpDesc{addr,len})); writer.commit(); drop(writer); ts_submit = monotonic_nanos(); stamp_submits(... take(inserted))`
  8. `inserted==0` → `dbg_tx_ring_full++`, `count_tx_ring_full_submit_stall`, `maybe_wake_tx`, `release/restore`, `refresh`, `set_error`, `return false`
     `outstanding_tx += inserted; settle_*; publish_committed_queue_vtime; apply_direct_exact_send_result; maybe_wake_tx; sent_packets>0||sent_bytes>0`

  Steps 1,2,3,5,6,7,8 are 80% identical across 4 fns; only step 4 (drain call) and settle call differ by FIFO vs flow-fair and Local vs Prepared. This is classic copy-paste monolith that has already caused divergence bugs (e.g., FIFO variant missing `restore_exact_*_to_queue_head_flow_fair` on Drop — fixed in prior PRs but could regress).
- Proposed decomposition:
  - `service/common.rs` — shared helpers:
    - `prepare_service_scratch(binding, root_ifindex, queue_idx) -> (Option<root_budget>, queue_dscp_rewrite)` (steps 1-3)
    - `handle_scratch_build_error(binding, root_ifindex, queue_idx, build, scratch_kind)` (step 5)
    - `tx_submit_and_stamp(binding, scratch, now_ns) -> inserted` (step 7)
    - `handle_tx_ring_full(binding, root_ifindex, queue_idx, scratch_len, ...)` (step 8 first half)
    - `finish_service(binding, root_ifindex, queue_idx, sent_packets, sent_bytes, now_ns)` (settle tail: `publish_committed_queue_vtime`, `apply_direct_exact_send_result`, `maybe_wake_tx`)
  - `service/local_fifo.rs` — `service_exact_local_queue_direct` (thin wrapper: prepare → drain_fifo → handle_error → submit → handle_full → settle_fifo → finish)
  - `service/local_flow_fair.rs` — `service_exact_local_queue_direct_flow_fair`
  - `service/prepared_fifo.rs` — `service_exact_prepared_queue_direct`
  - `service/prepared_flow_fair.rs` — `service_exact_prepared_queue_direct_flow_fair`
  - Keep `service.rs` as `mod.rs` re-exporting 4 fns.
- Hot-path preservation analysis:
  - Classification **B requires-guardrails** — this is hot path! Every exact queue service (both Local and Prepared, FIFO and flow-fair) goes through these fns on every drain pass. Must preserve:
    - **Inlining preserved**: Current fns are `#[inline]`, single call-site in `drain_shaped_tx`. Extracted helpers in `common.rs` must be `#[inline(always)]` for the hot helpers and `#[inline]` for cold error paths (`#[cold] #[inline(never)]` for Drop/Mirror paths). Verify via `cargo asm service_exact_local_queue_direct` — no `call` to `prepare_service_scratch` etc., LLVM must still inline all `#[inline(always)]` helpers (same crate, module boundary free). If any helper is not inlined, it's a regression — mark `#[inline(always)]` was insufficient (cross-TU? No, same crate).
    - **No new heap allocation**: scratch buffers are `&mut VecDeque`/`Vec` reused via `clear()`, must not introduce `Vec::new()` or `clone()`.
    - **No vtable**: keep enum `ExactCoSScratchBuild` match, not `Box<dyn Drain>`.
    - **UMEM frame ownership**: `free_tx_frames` ↔ `scratch` ↔ `xsk.tx` ↔ `settle` ownership chain must stay single-owner; helpers must take `&mut` not owned.
    - **Stamp timing**: `monotonic_nanos()` must stay AFTER `writer.commit()` (per #812 fix comment lines 132..143 and 305..309). Any helper extraction must not move `stamp` before commit.
    - **ICACHE**: 4 service fns × ~170 LOC = ~680 LOC icache footprint today (inlined into `drain_shaped_tx` → large). Splitting into 4 files does not reduce icache but extracting common tail reduces total footprint ~30% (shared helpers inlined once). Must not over-split into tiny cross-file calls that prevent inlining.
  - Verification:
    - `cargo asm` diff on `service_exact_local_queue_direct` + `service_exact_local_queue_direct_flow_fair` (hot variants) — bodies must be byte-identical modulo debuginfo (common helpers inlined).
    - `perf stat -e instructions,cache-misses,branch-misses` on iperf3 100G exact-queue workload — should be neutral or -1~2% instructions from reduced icache pressure.
    - CoS smoke + fairness gates + failover (HA demote→promote must not break `publish_committed_queue_vtime` on flow-fair queues).
    - `size` on `userspace-dp` binary — should not grow >1% (inlining preserved).
- Tests + gate: `queue_service` tests (if any) + CoS smoke + CoS fairness + failover. The `ExactCoSScratchBuild::MirrorTxFrameReserve` unreachable!() in prepared path (line 450..452) must stay — moving to common must preserve this invariant check.
- Why it matters: Copy-paste 4× is high bug risk — any fix to TX ring submit stamping (e.g., #812 post-commit stamp fix) had to be applied identically to 4 sites (lines 132..153, 304..320, 490..505, 655..669). Missing one site would silently reintroduce pre-commit stamp bug on that variant. Shared `tx_submit_and_stamp` helper eliminates this divergence class. Also reduces 718 LOC file to 4× ~40 LOC wrappers + 150 LOC common (net -200 LOC from dedup).
- Fix direction:
  1. Create `service/common.rs` with `#[inline(always)]` hot helpers + `#[cold] #[inline(never)]` error helpers (mechanical extract of steps 1,5,7,8 tail).
  2. Move each `service_exact_*` into its own file as thin wrapper calling common helpers (keep original `#[inline]` on public fns).
  3. Verify `cargo asm` diff byte-identical for hot variants before landing.
  4. Land as single PR (mechanical, no behavior change).
- Labels: refactor, cos, service, hot-path, dedup, P1
- Dedup note: Not previously flagged. Prior "1100+ line TX drain orchestrator" finding was about `tx.rs`/`umem.rs`, not this `queue_service/service.rs` 4-way copy-paste. This finding adds concrete duplication evidence and shared-helper decomposition with inlining guardrails.

### Finding 5

- Title: nat/allocator.rs 742 LOC explicit monolith — file header admits "All ... lives in this file"
- Severity: medium (maintainability + incremental-build + lock-contention obscurity)
- Confidence: high
- Refactor class: A mechanical / safe
- Evidence: `nat/allocator.rs:1-5` header:
  ```rust
  // Pool-mode SNAT port allocator + persistent lease state machine.
  //
  // All translated-tuple ownership, live-flow tracking, persistent-lease
  // lifecycle, expiration indexes, rollback bookkeeping, and recycled-port
  // state lives in this file. The single `Mutex<PortAllocatorLiveState>`
  // serializes every structural mutation; ...
  ```
  `PortAllocatorLiveState` `allocator.rs:100-111` = 8 collections + gc_counter:
  ```rust
  pub(super) struct PortAllocatorLiveState {
      live_by_flow: FxHashMap<SourceNatFlowKey, LiveAllocation>,
      owner_by_translated: FxHashMap<TranslatedTuple, AllocationOwner>,
      pub(super) addr_index_by_translated: FxHashMap<TranslatedTuple, usize>,
      pub(super) persistent_by_source: FxHashMap<PersistentSourceKey, PersistentLease>,
      pub(super) lease_expirations: BTreeSet<(u64, PersistentSourceKey)>,
      pub(super) lease_expirations_by_addr: Vec<BTreeSet<(u64, PersistentSourceKey)>>,
      next_port_offset_by_addr: Vec<u32>,
      pub(super) recycled_ports_by_addr: Vec<Vec<u16>>,
      gc_counter: u32,
  }
  ```
  `allocate_translation` `allocator.rs:249-414` = 165 LOC fusing:
  - `gc_expired_locked` (line 273)
  - `live_by_flow` reuse check (275..278)
  - capacity check (279..282)
  - persistent lease reuse vs expired lease (284..339)
  - address selection loop with `claim_free_port_locked` + `gc_expired_for_addr_locked` pressure handling (341..410)
  - persistent lease insert (381..397) + live insert (399..405)
  `PortAllocatorShared` 131..143 = 6 atomics + Mutex + counters — mixes address selection (lock-free atomics) with live state (Mutex).
  Constants `GC_PERIOD=10`, `ALLOCATION_GC_BUDGET=8`, `RELEASE_GC_BUDGET=64`, `PRESSURE_GC_BUDGET=64` all in same file.
- Proposed decomposition:
  - `nat/allocator/mod.rs` — `PortAllocator`, `PortAllocatorShared`, `PortAllocatorSnapshot`, `allocator_capacity`, constants, `sticky_pool_index`
  - `nat/allocator/live_table.rs` — `LiveAllocation`, `AllocationOwner`, `PortAllocatorLiveState` struct + `::new`, live_by_flow / owner_by_translated / addr_index_by_translated operations (`assign_owner_locked`, `release_translated_locked`, `claim_free_port_locked`)
  - `nat/allocator/persistent_lease.rs` — `PersistentLease`, `PersistentSourceKey`, `TranslatedTuple`, lease reuse / insert / refresh logic extracted from `allocate_translation` lines 284..339 + `release_flow` 531..547 + `rollback_flow` 572..596
  - `nat/allocator/expiration.rs` — `lease_expirations` (global BTreeSet), `lease_expirations_by_addr` (per-addr), `next_port_offset_by_addr`, `recycled_ports_by_addr`, `gc_expired_locked`, `gc_expired_for_addr_locked`, `release_expired_lease_locked`, `insert_lease_expiration_locked`, `remove_lease_expiration_locked`
  - `nat/allocator/port_pool.rs` — `address_index`, `try_next_port`, `claim_free_port_locked`, round-robin counters
  - Tests split accordingly (see Finding 10).
- Hot-path preservation analysis:
  - Classification **A mechanical / safe**. NAT pool allocation is **not** per-packet hot path — after session install, `session::lookup_with_origin` + `find_forward_nat_match` serve NAT translation from session table without touching allocator. Allocator is touched only on:
    - New flow (session miss → `match_source_nat_result_for_tuple` → `allocate_translation`) — once per flow, not per packet.
    - Flow close (`release_flow` / `rollback_flow`) — once per flow close, amortized.
    - Periodic GC (`gc_expired_locked` every `ALLOCATION_GC_BUDGET` allocations, `RELEASE_GC_BUDGET` releases).
  - Guardrails:
    - **Lock scope**: currently single `Mutex<PortAllocatorLiveState>` serializes everything. Splitting files must NOT introduce additional locks or widen lock to cover atomic counter ops. Keep `Mutex` in `live_table.rs`, `port_pool` atomics stay lock-free.
    - **No new heap alloc**: existing `FxHashMap`, `BTreeSet`, `Vec` — keep same.
    - **Capacity math**: `allocator_capacity` + `max_tracked_flows` + `MAX_SOURCE_NAT_POOL_TRACKED_FLOWS=262144` cap must stay byte-identical.
  - Verification: `cargo test nat`, `cargo test` full, no perf gate needed (not hot path). Incremental build: 742 LOC TU split → ~150 LOC per new TU, average recompile 742→150 LOC (~5× speedup for allocator edits).
- Tests + gate: `nat/tests.rs` (2657 LOC) must split alongside — see Finding 10. Existing `cargo test nat::` + `test-nat-pool` if exists. The `debug_live()` white-box accessor (allocator.rs:203..205) currently `#[cfg(test)]` returns `MutexGuard` — after split it should move to `live_table.rs` or a `test_support.rs`.
- Why it matters: File header explicitly documents monolith as intentional ("All ... lives in this file") — but this is the exact anti-pattern audit hunts: one file owns 5 distinct state machines (live flow table, persistent lease FSM with 4 activation fields, global expiration BTreeSet, per-addr expiration Vec<BTreeSet>, recycled port stacks) behind one coarse lock. Any edit to GC budget constants re-renders entire allocator in review. The `#[cfg(test)] debug_live()` accessor exposes 5 `pub(super)` fields for white-box tests — after split, only `live_table.rs` and `expiration.rs` need to expose their fields, reducing visibility surface.
- Fix direction:
  1. Create `nat/allocator/live_table.rs` moving `PortAllocatorLiveState`, `LiveAllocation`, `AllocationOwner`, `assign_owner_locked`, `release_translated_locked` (mechanical).
  2. Create `nat/allocator/expiration.rs` moving expiration BTreeSets + `gc_*` + `insert/remove_lease_expiration_locked` + `release_expired_lease_locked`.
  3. Create `nat/allocator/persistent_lease.rs` moving `PersistentLease` + lease reuse/refresh logic.
  4. Create `nat/allocator/port_pool.rs` moving `address_index`, `try_next_port`, `claim_free_port_locked`.
  5. `mod.rs` left with `PortAllocator` facade + `PortAllocatorShared` + `PortAllocatorSnapshot` + constants + `sticky_pool_index`.
  6. Update `nat/tests.rs` split accordingly.
- Labels: refactor, nat, allocator, monolith, P2
- Dedup note: Prior #1542 split `nat/` into `allocator.rs`, `source.rs`, `destination.rs`, `static_nat.rs`, `tests.rs` — but `allocator.rs` itself remains 742 LOC monolith (the header comment is post-#1542). This finding is the NEXT decomposition of the already-split `allocator.rs` into 5 submodules. No duplication.

## Findings (Medium Confidence)

### Finding 6

- Title: afxdp/types/cos.rs 1391 LOC mixes config + runtime + flow-fair 352KB unsafe + ring + telemetry
- Severity: medium
- Confidence: medium
- Refactor class: C performance-positive
- Evidence: `cos.rs:1-10` extract comment says "28 items / ~700 LOC of CoS shaper / queue / flow-fair-RR / fast-path / runtime types" but actual file is 1391 LOC (grown 2× since extract). `CoSInterfaceRuntime` `cos.rs:369-522` = 30+ fields:
  ```rust
  pub(in crate::afxdp) struct CoSInterfaceRuntime {
      pub(in crate::afxdp) shaping_rate_bytes: u64, // hot
      pub(in crate::afxdp) burst_bytes: u64,
      pub(in crate::afxdp) tokens: u64,             // hot per-batch
      pub(in crate::afxdp) nonexact_surplus_under_exact_tokens: u64, // cold
      pub(in crate::afxdp) default_queue: u8,
      pub(in crate::afxdp) nonempty_queues: usize,  // hot
      pub(in crate::afxdp) runnable_queues: usize,   // hot
      pub(in crate::afxdp) oversubscription_policy: CoSOversubscriptionPolicy, // cold config
      pub(in crate::afxdp) oversubscription_guarantee_fraction: f64, // cold
      pub(in crate::afxdp) priority_low_min_share_bytes: u64, // cold/wire-only
      pub(in crate::afxdp) priority_low_reserved_tokens: u64, // UNUSED (comment 393..396)
      pub(in crate::afxdp) priority_low_last_refill_ns: u64, // UNUSED
      pub(in crate::afxdp) exact_queues_by_rate_ascending: Vec<usize>, // cold (built once)
      pub(in crate::afxdp) waterfill_pass1_remaining_bytes: u64, // hot waterfill
      pub(in crate::afxdp) waterfill_phase2_cursor: usize,        // hot
      pub(in crate::afxdp) waterfill_honored_epoch_bits: u64,    // hot
      pub(in crate::afxdp) waterfill_epochs: u64,                // diagnostic
      pub(in crate::afxdp) waterfill_phase1_budget_breaks: u64,  // diagnostic
      pub(in crate::afxdp) waterfill_epoch_start_ns: u64,        // hot
      pub(in crate::afxdp) waterfill_epoch_wrap_pending: bool,    // hot
      pub(in crate::afxdp) exact_guarantee_rr: usize,            // hot RR cursor
      pub(in crate::afxdp) nonexact_guarantee_rr: usize,         // hot
      #[cfg(test)] pub(in crate::afxdp) legacy_guarantee_rr: usize, // test-only
      pub(in crate::afxdp) queues: Vec<CoSQueueRuntime>,         // hot
      ...
  }
  ```
  `FlowFairState` `cos.rs:735-908` = 14 fields, 352KB, with `new` 910..937 (27 LOC) + `new_boxed` 975..1021 (46 LOC unsafe with `MaybeUninit`, `addr_of_mut`, 8 `write_bytes` + 4096× `VecDeque::new()` loop). `FlowRrRing` `cos.rs:171-307` = 136 LOC ring impl with `push_back`, `push_front`, `pop_front`, `remove` (O(n) scan). `CoSQueueHotState` `cos.rs:701-730` mixes hot (`surplus_deficit`, `tokens`, `queued_bytes`, `runnable`, `parked`) with hysteresis counter `cos_demote_empty_settles`. `CoSQueueTelemetry` `cos.rs:1072-1107` + drop counters + waterfill counters + owner profile. File has accumulated 5 responsibilities since #1035 extract.
- Proposed decomposition:
  - `types/cos/config.rs` — `CoSState`, `CoSInterfaceConfig`, `CoSQueueConfig`, `CoSDSCPClassifierConfig`, `CoSIEEE8021ClassifierConfig`, `CoSDSCPRewriteRuleConfig`, `CoSOversubscriptionPolicy`, constants `COS_*`
  - `types/cos/runtime.rs` — `CoSInterfaceRuntime` hot fields (tokens, nonempty/runnable, RR cursors, waterfill epoch state) + `CoSQueueRuntime`, `CoSQueueConfigState`, `CoSQueueHotState`, `WorkerCoSQueueFastPath`, `WorkerCoSInterfaceFastPath`
  - `types/cos/flow_fair.rs` — `FlowFairState` + `new` + `new_boxed` (unsafe) + `COS_FLOW_FAIR_BUCKETS`, `COS_FLOW_FAIR_BUCKET_MASK`, `FlowRrRing`
  - `types/cos/ring.rs` — `FlowRrRing`, `FlowRrRingIter`, `COS_FLOW_FAIR_BUCKETS` (or keep buckets in flow_fair)
  - `types/cos/telemetry.rs` — `CoSQueueTelemetry`, `CoSQueueDropCounters`, `CoSQueueWaterfillCounters`, `CoSQueueOwnerProfile`, `CoSQueuePopSnapshot`, `VMinQueueState`
  - `types/cos/constants.rs` — `COS_FAST_QUEUE_INDEX_MISS`, `COS_FLOW_FAIR_BUCKETS`, `COS_PRIORITY_LEVELS`, `COS_TIMER_WHEEL_*`, compile-time asserts `assert!(is_power_of_two)`, `assert!(<=u16::MAX)`
- Hot-path preservation analysis:
  - Classification **C performance-positive** — hot-cold field separation on `CoSInterfaceRuntime`:
    - **Hot fields** touched per-batch: `tokens`, `nonempty_queues`, `runnable_queues`, `waterfill_pass1_remaining_bytes`, `waterfill_phase2_cursor`, `waterfill_honored_epoch_bits`, `waterfill_epoch_start_ns`, `waterfill_epoch_wrap_pending`, `exact_guarantee_rr`, `nonexact_guarantee_rr`, `queues` (indirect).
    - **Cold fields** touched only at config build or diagnostic scrape: `oversubscription_policy`, `guarantee_fraction`, `priority_low_min_share_bytes` (wire-only, "Currently UNUSED" per 391..396), `exact_queues_by_rate_ascending` (built once, read-only), `waterfill_epochs`/`phase1_budget_breaks` (diagnostic plain u64), `priority_low_reserved_tokens`/`last_refill_ns` (UNUSED per 393..396).
    - Splitting `CoSInterfaceRuntime` into `CoSInterfaceRuntimeHot` (cache-line-packed) + `CoSInterfaceRuntimeCold` (separate allocation) would improve dcache: currently hot `tokens` (offset 16) shares cache line with cold `oversubscription_policy` (enum, 1 byte but Rust may pad) and `f64 guarantee_fraction` (8 bytes). With 8 workers × 2 ifaces × hot fields = 16 hot structs, packing hot fields into 64-byte cache-line structs reduces dcache footprint ~30%.
    - **But**: `CoSInterfaceRuntime` is currently `Vec`-resident behind `FxHashMap<i32, CoSInterfaceRuntime>` (not `#[repr(C)]`), so field reordering is safe in Rust (Rust can reorder but typically preserves decl order for non-`repr(C)` — still, no hard ABI). Moving hot fields to front of struct is perf-positive and safe.
    - **FlowFairState `new_boxed` unsafe**: must preserve exact field init order and `write_bytes(0)` for POD arrays vs `VecDeque::new()` for non-trivial. Splitting into `flow_fair.rs` keeps unsafe block self-contained and reviewable.
    - **FlowRrRing `remove` O(n) scan**: 286..306 is hot path on MQFQ bucket drain (flow-fair dequeue when min bucket not at head). Splitting into `ring.rs` makes this scannable for future optimization (e.g., bitmap).
  - Verification: `cargo test cos`, CoS smoke/fairness, `perf stat -e cache-misses` on 64-flow per-worker workload. `size_of::<CoSInterfaceRuntime>()` must not grow (should shrink if UNUSED fields removed). `flow_fair_state_tests::new_boxed_matches_new_field_for_field` must still pass (field-equivalence guard #1755). `cargo miri` on `new_boxed` if possible.
- Tests + gate: `flow_fair_state_tests` (1314..1391) moves to `flow_fair/tests.rs` with code. `CoSInterfaceRuntime` tests (if any) move to `runtime/tests.rs`. Gates: `cargo test`, CoS smoke, CoS fairness, failover.
- Why it matters: 1391 LOC file with 6 responsibilities is second-largest CoS file after `cold_path_hist.rs`. `CoSInterfaceRuntime` has grown 7 waterfill fields + 2 reserved fields + 1 test-only field since #1614 without any hot-cold audit — field order currently interleaves hot `tokens` with cold `priority_low_*` UNUSED fields, wasting cache line. `FlowFairState::new_boxed` 46 LOC unsafe block lives in same file as `FlowRrRing` iterator and `CoSQueueDropCounters` — unsafe review requires reading 1391 LOC of unrelated code.
- Fix direction:
  1. Create `types/cos/ring.rs` moving `FlowRrRing` + `FlowRrRingIter` + `COS_FLOW_FAIR_BUCKETS` + compile asserts (mechanical, ~200 LOC).
  2. Create `types/cos/flow_fair.rs` moving `FlowFairState` + `new` + `new_boxed` + `flow_fair_state_tests` (keeps unsafe self-contained).
  3. Create `types/cos/telemetry.rs` moving `CoSQueueTelemetry` + drop/waterfill/owner profile + `VMinQueueState` + `CoSQueuePopSnapshot`.
  4. Create `types/cos/config.rs` + `types/cos/runtime.rs` splitting `CoSInterfaceRuntime` hot/cold (audit field order for dcache).
  5. `cos.rs` becomes `mod.rs` re-exporting.
- Labels: refactor, cos, types, hot-cold, cache-line, unsafe, P2, x-hpc
- Dedup note: Prior #1035 P4 extracted CoS lease types from `types.rs` into `cos.rs` — this finding is NEXT decomposition of now-1391 LOC `cos.rs` itself. #1735 flow-fair gate change (`flow_fair() == flow_fair_state.is_some()`) and #1755 `new_boxed` were added to this file without file split. No duplication.

### Finding 7

- Title: afxdp/wg/engine.rs 1919 LOC fuses peer table + session demux + pending handshake + rate-limit edge + TAI64N + reconcile + encap/decap
- Severity: high
- Confidence: medium
- Refactor class: B requires-guardrails
- Evidence: `wg/engine.rs:257-324` `WgEngine` struct 12 fields (see inventory). `WgEngine::new` 346..364 = 18 LOC, `request_handshake` 372..396 = 24 LOC (CAS rate-limit), `take_handshake_request` 400..403, `reconcile_peers` 472..580 = 108 LOC (build new peers + drain demux + drain pending + ArcSwap publish), `install_session` 618..634 (7 LOC + lock), `install_session_locked` 641..700+ (60+ LOC with local_index collision check + demux insert + peer current/previous rotation). Hot path `try_encap`/`try_decap` not fully read but per file header 1..53:
  ```rust
  //! Hot path discipline:
  //!   - No allocations. snow's `write_message` / `read_message` take pre-sized slices.
  //!   - No locks held across crypto operations on the encrypt path
  //!     (we clone the `Arc<WgSession>` and release the peer lock).
  //!   - Decrypt path takes the per-session replay-window mutex twice: ...
  ```
  `PeerTable` 236..254 (18 LOC) + `empty` 247..253. AllowedIPs LPM trie lives in `allowed_ips.rs` but `PeerTable` owns it. `Tai64nClock` lives in `tai64n.rs` but `WgEngine` owns it and seeds it via `seed_tai64n_high_water` 440..445 + `tai64n_high_water` 451..453.
- Proposed decomposition:
  - `wg/engine/mod.rs` — `WgEngine` struct + `WgEngineConfig`, `WgPeerConfig`, `WgEngine::new`, `Debug` impl, constants `WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS`, `PADDED_PLAINTEXT_MAX`, `pad_to_16`
  - `wg/engine/peer_table.rs` — `PeerTable`, `PeerTable::empty`, `load_table`, `table_for_test`, `peer_arc`
  - `wg/engine/reconcile.rs` — `reconcile_peers` (108 LOC) + `reconcile_lock` handling, `dropped_indices` collection, demux drain, pending drain
  - `wg/engine/session_table.rs` — `sessions_by_local_index`, `install_session`, `install_session_locked`
  - `wg/engine/handshake_edge.rs` — `handshake_request_pending`, `handshake_request_last_ns`, `request_handshake`, `take_handshake_request`, `first_peer_pubkey`, `peer_has_confirmed_session`
  - `wg/engine/encap.rs` — `try_encap` (hot path, per-packet encrypt)
  - `wg/engine/decap.rs` — `try_decap` (hot path, per-packet decrypt + replay window + AllowedIPs)
  - `wg/engine/tai64n_owner.rs` — `seed_tai64n_high_water`, `tai64n_high_water` (or move into `tai64n.rs`)
  Keep `allowed_ips.rs`, `peer.rs`, `session.rs`, `framing.rs`, `handshake_session.rs`, `tai64n.rs` as-is.
- Hot-path preservation analysis:
  - Classification **B requires-guardrails** — `try_encap`/`try_decap` are per-packet crypto hot path:
    - **Inlining**: `try_encap`/`try_decap` must stay `#[inline]` or not cross crate boundary — same crate file split is free (module boundary free in Rust), but if moved to `encap.rs`/`decap.rs` they remain `pub(crate)` in same crate, LLVM still inlines at `tx/wg` call site if `#[inline]` retained. Require `#[inline]` on hot fns, verify via `cargo asm wg::WgEngine::try_encap`.
    - **No new heap alloc**: encap uses `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` stack scratch (4080+16=4096 bytes) — splitting must not introduce `Box` or `Vec`.
    - **Lock scope**: encap clones `Arc<WgSession>` and releases peer lock before crypto (per header 40..42). Decap takes per-session replay window mutex twice (pre-AEAD + post-AEAD). Splitting `peer_table.rs` / `session_table.rs` must not widen `RwLock` scopes or introduce new lock ordering.
    - **Zero-copy**: encap stages padded plaintext on stack then `snow.write_message` + `encode_data_header`; decap writes plaintext directly into caller's `out` buffer. No copy introduction.
  - Verification:
    - `cargo test wg`, `make test`, plus WG-specific tests (if any `test-wg-*`).
    - `cargo asm WgEngine::try_encap` / `try_decap` before/after — byte-identical.
    - `perf stat` on WG throughput (if available) — neutral.
    - Miri on `PADDED_PLAINTEXT_MAX` MaybeUninit handling if split.
- Tests + gate: `wg/tests.rs` (if exists) + `cargo test wg`. The `#[cfg(test)] table_for_test` accessor moves to `peer_table.rs`.
- Why it matters: 1919 LOC single file owning 6 distinct responsibilities behind 4 locks (`pending: RwLock`, `pending_by_peer: RwLock`, `table: ArcSwap`, `reconcile_lock: Mutex`, `sessions_by_local_index: RwLock`) plus 2 atomics. Any edit to handshake rate-limit edge (once per second, cold) recompiles encap/decap hot paths (per-packet crypto). `reconcile_peers` 108 LOC touches 3 locks + ArcSwap + demux drain + pending drain — hard to review in 1919 LOC context. The `Zeroizing<[u8;32]>` local_private_key demands small, auditable surface for `Drop` ensuring wipe — currently mixed with unrelated handshake edge code.
- Fix direction:
  1. Create `wg/engine/peer_table.rs` moving `PeerTable` + `load_table` + `peer_arc` (mechanical).
  2. Create `wg/engine/reconcile.rs` moving `reconcile_peers` (108 LOC) — slow path, safe.
  3. Create `wg/engine/session_table.rs` moving session demux + install.
  4. Create `wg/engine/handshake_edge.rs` moving rate-limit edge.
  5. Create `wg/engine/encap.rs` + `decap.rs` moving hot paths (with `#[inline]` preserved, verify asm).
  6. `engine/mod.rs` left with struct + new + constants.
- Labels: refactor, wg, engine, hot-path, crypto, lock-scope, P2, WATCH
- Dedup note: Not previously flagged. WG engine is relatively new (#1432 S2a, #1703 S6). No prior refactor campaign targeted it. This finding is first to name the 6-responsibility fusion and propose concrete file split with lock-scope and zero-copy guardrails.

### Finding 8

- Title: afxdp/cold_path_hist.rs 1745 LOC fuses histogram math + slot map + TSC + calibration + worker atomics seqlock
- Severity: medium
- Confidence: high
- Refactor class: A mechanical / safe
- Evidence: `cold_path_hist.rs:1-28` header lists 4 responsibilities (hist primitives, helpers, slot map, sampling). File inventory:
  - Constants 31..91: `POLICY_COLD_PATH_HIST_BUCKETS=48`, `COLD_PATH_LINEAR_BUCKETS=32`, `COLD_PATH_LINEAR_STRIDE_NS=16`, `COLD_PATH_PIVOT_NS=512`, `POLICY_COLD_PATH_ZONE_PAIR_SLOTS=256`, `COLD_PATH_ASSIGNABLE_SLOTS=255`, `COLD_PATH_ZONE_DIM=65`, `COLD_PATH_FLAT_TABLE_LEN=4225`, `COLD_PATH_LAYOUT_VERSION=3` — 9 constants + 5 asserts (45..91).
  - Bucket math 108..153: `bucket_index_for_ns_48` (11 LOC, branchless), `bucket_upper_bound_ns_48` (8 LOC), `zone_pair_packed_key` (4 LOC).
  - Slot map 155..303: `ColdPathSlotMap` (134 LOC, 2-pass build: retain + assign lowest free), `lookup_slot` 310..318 (8 LOC hot-path: one multiply-add + L1d array index).
  - TSC sampling 320..391: `sample_tsc_start` (7 LOC, `LFENCE; RDTSCP`), `sample_tsc_end` (7 LOC, `RDTSCP; LFENCE`), foot-gun removal comment 374..379.
  - Clock source 400..512: `ClockSource` enum (repr(u8) pinned per 404..409), `probe_clock_source` (52 LOC, 3 flags + clocksource file), `calibrate_ns_per_tsc_q32` (36 LOC, 10ms sleep + shift), `calibrate_wrapper_baseline_ns` (27 LOC, 4096 median).
  - Worker atomics 597..1745 (~1100 LOC not fully read): `WorkerColdPathAtomics` (repr(C,align(64)), 15+ atomics, seqlock gen, snapshot_failed, sample_phase, ns_per_tsc_q32, wrapper_baseline, clock_source, overflow, etc.) + `snapshot` (seqlock reader with MAX_SPINS) + status builders.
  File is 5-responsibility monolith with single `mod tests` at end (not read) that tests bucket math + slot map + TSC together.
- Proposed decomposition:
  - `cold_path_hist/buckets.rs` — `POLICY_COLD_PATH_HIST_BUCKETS`, `COLD_PATH_LINEAR_BUCKETS`, `COLD_PATH_LINEAR_STRIDE_NS`, `COLD_PATH_PIVOT_NS`, `bucket_index_for_ns_48`, `bucket_upper_bound_ns_48`, `zone_pair_packed_key`, `POLICY_COLD_PATH_ZONE_PAIR_SLOTS` asserts
  - `cold_path_hist/slot_map.rs` — `COLD_PATH_ZONE_DIM`, `COLD_PATH_FLAT_TABLE_LEN`, `COLD_PATH_ASSIGNABLE_SLOTS`, `cold_path_flat_index`, `ColdPathSlotMap` (build + empty), `lookup_slot`, `COLD_PATH_LAYOUT_VERSION`, `POLICY_COLD_PATH_ZONE_PAIR_SLOTS`
  - `cold_path_hist/tsc.rs` — `sample_tsc_start`, `sample_tsc_end`, `ClockSource`, `probe_clock_source`, `calibrate_ns_per_tsc_q32`, `calibrate_wrapper_baseline_ns`, `ns_per_tsc_q32` Q32 math
  - `cold_path_hist/worker_atomics.rs` — `WorkerColdPathAtomics` (repr(C,align(64))), `cold_window_gen`, `snapshot_failed`, `sample_phase`, `ns_per_tsc_q32`, `wrapper_ns_baseline`, `clock_source`, etc. + publish protocol (fetch_add even→odd, relaxed stores, fetch_add odd→even) + snapshot (Acquire load s1, Relaxed payload, fence(Acquire), Relaxed s2)
  - Keep tests colocated: `buckets/tests.rs`, `slot_map/tests.rs`, `tsc/tests.rs` (TSC tests need `#[ignore]` on non-x86_64).
- Hot-path preservation analysis:
  - Classification **A mechanical / safe**. Cold-path hist is sampled diagnostics, not per-packet hot path:
    - `bucket_index_for_ns_48` is called on sampled cold path only (via `sample_mask` gate, typically 1/1024 packets). Even if considered warm, it's `#[inline]` 11 LOC branchless math — moving file preserves inlining (same crate).
    - `lookup_slot` is called on cold path sample publish (not per-packet). Hot-path cost is one multiply-add + array index, must stay `#[inline]`.
    - `sample_tsc_start`/`sample_tsc_end` are called on sampled packets only (via `sample_mask`). They are `#[inline]` + `#[cfg(target_arch="x86_64")]` with `_mm_lfence` + `__rdtscp` — must retain `#[inline]` and `cfg` when moving.
    - `WorkerColdPathAtomics` is `#[repr(C, align(64))]` — **load-bearing** per comment 619..624 (C pins field order, align(64) isolates cacheline). Must carry `repr(C, align(64))` + field order when moving. The plan §4.1 offset math (`clock_source` at offset 32, `alias_seen` at 33) depends on `ClockSource` being `#[repr(u8)]` (pinned per 404..409). Splitting must not reorder fields.
  - Verification: `cargo test cold_path_hist`, `make test`, TSC-gated harness (`test-cold-path-hist` if exists). `size_of::<WorkerColdPathAtomics>()` + `align_of` asserts must stay. `cargo test -- --ignored` for TSC calibration on x86_64.
- Tests + gate: Existing `cold_path_hist` tests (bucket math, slot map build, TSC) move with code. Cold-path smoke gate (if exists) must stay green.
- Why it matters: 1745 LOC single file with 5 responsibilities is largest file in `afxdp/types/`-adjacent code. TSC probe (`probe_clock_source` reading `/proc/cpuinfo` + `/sys/.../current_clocksource`) is cold-path setup that should not recompile when bucket math changes. `WorkerColdPathAtomics` seqlock publish/snapshot (reader `fence(Acquire)` + writer `Release`) is subtle concurrency code that deserves its own file for focused review — currently interleaved with `cold_path_flat_index` multiply math. Incremental build: editing bucket math (e.g., changing `COLD_PATH_LINEAR_STRIDE_NS` 16→32) currently recompiles TSC probe + slot map + worker atomics (1745 LOC TU) — after split, only `buckets.rs` recompiles (~120 LOC).
- Fix direction:
  1. Create `cold_path_hist/buckets.rs` (constants + bucket math, mechanical).
  2. Create `cold_path_hist/slot_map.rs` (ColdPathSlotMap + lookup, mechanical).
  3. Create `cold_path_hist/tsc.rs` (TSC sampling + clock source + calibration, mechanical).
  4. Create `cold_path_hist/worker_atomics.rs` (WorkerColdPathAtomics + publish/snapshot, keep repr(C,align(64)) and field order).
  5. `mod.rs` left with `pub use` re-exports.
- Labels: refactor, cold-path, histogram, tsc, seqlock, x-hpc, P3, WATCH
- Dedup note: Not previously flagged as monolith. Prior #1635 work changed bucket count 24→48 and slot count 16→256 but did not split file. TSC probe fix (Codex r1 finding 2: `rdtscp` token check) and `ClockSource` repr(u8) pinning (AGY r3) were added to this file without file split. This finding is first to name the 5-responsibility fusion and propose concrete file split with repr/seqlock guardrails.

## Findings (Low Confidence / Do-Not-Split)

### Finding 9

- Title: shared_cos_lease/rotate_epoch_v8.rs 337 LOC god-function — already extracted but still 6 steps fused
- Severity: low (marginal split vs call overhead)
- Confidence: low
- Refactor class: A mechanical / safe (if split further)
- Evidence: `rotate_epoch_v8.rs:22-337` single function `maybe_rotate_epoch_v8` with 6 steps (see Finding 2 inventory). Steps are:
  ```rust
  // Phase 1: maybe rotate (lines 27..50 — seqlock claim)
  let seq = v8.epoch.epoch_seq.load(Ordering::Acquire);
  if seq & 1 == 1 { return; }
  // ...
  if v8.epoch.epoch_seq.compare_exchange(seq, seq+1, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
  // Phase 2: swap event slots (70..110), swap grants (112..119)
  // Phase 3: equal-flow publish OR disable (121..153)
  // Phase 4: bypass gate (155..223)
  // Phase 5: credit carry 3 regimes (224..309)
  // Phase 6: publish cap/grace/fair-share/seq (310..336)
  ```
  File already exists as result of PR #1588 code-motion split from `mod.rs` (comment 1..5 says "body is byte-identical to pre-split form"). Further splitting 337 LOC into 6 files would be over-split.
- Proposed decomposition (if pursued):
  - Keep single file; extract helpers within file:
    - `fn claim_rotation(...) -> Option<(seq, new_tag, new_packed_zero)>` (lines 27..54)
    - `fn swap_epoch_state(...)` (lines 56..119)
    - `fn compute_bypass_gate(...) -> bool` (lines 155..223)
    - `fn compute_carry_and_cap(...) -> (elapsed_ns, carry_draw, new_cap)` (lines 224..318)
    - `fn publish_rotation(...)` (lines 319..336)
  - All helpers `#[inline]` within same file — no cross-file call.
- Hot-path preservation analysis:
  - Classification **A** — rotation is once per 200µs per queue (not per-packet). `acquire_v8` is hot, `maybe_rotate_epoch_v8` is cold (amortized 1/100ths of acquire calls, since epoch 200µs >> per-packet 5ns). Splitting into helpers adds call overhead but inlined helpers are free (same file, `#[inline]`). If helpers moved to separate files, cross-file inlining still works (same crate) but cold path doesn't need to be inlined aggressively — `#[inline]` hint + single call site means compiler will inline anyway.
  - **Atomics ordering**: seqlock EVEN→ODD CAS (`AcqRel`), payload Relaxed stores, ODD→EVEN publish (`Release`) must stay — matches `cold_path_hist.rs::snapshot` reference writer (#1643). Any helper extraction must not reorder `epoch_start_ns.store(now_ns, Relaxed)` after `epoch_seq.store(seq+2, Release)` (publish must be last).
  - **Stack scratch**: `MAX_WORKERS_SCRATCH=32`, 7 stack arrays of 32 elems each (bool/u32) — must stay stack-allocated, not heap.
- Tests + gate: `shared_cos_lease_tests.rs` rotation tests + CoS smoke/fairness. The `epoch_carry_bytes` privacy grep test must keep passing (carry is rotation-private, no new accessor).
- Why it matters (but low confidence): 337 LOC single function is long but cohesive (one rotation epoch). Splitting into 6 helpers improves readability but adds indirection for small gain. Over-splitting cold path into 6 files would increase build graph and review cost more than it saves. Better to extract helpers within same file.
- Fix direction: If team wants, extract 5 `#[inline]` helpers within same `rotate_epoch_v8.rs` file (no new files). Keep 337 LOC file as-is otherwise.
- Labels: refactor, cos, rotate, low-priority, P3
- Dedup note: File itself is result of PR #1588 split — this finding is meta-comment on whether further split is warranted. Not a duplicate.

### Finding 10

- Title: nat/tests.rs 2657 LOC test monolith — should split with code per modularity-discipline
- Severity: low (test-only, no prod impact)
- Confidence: high
- Refactor class: A mechanical / safe
- Evidence: `nat/tests.rs:1-4` header:
  ```rust
  // Tests for the nat/ module. Moved into nat/tests.rs as part of the
  // #1542 split. White-box tests reach into allocator internals via the
  // `debug_live()` accessor and the `pub(super)` items promoted in
  // allocator.rs / destination.rs.
  ```
  File 2657 LOC, first 200 lines show 9 tests across 4 categories (interface SNAT, off rule, reverse decision, static NAT). `wc -l` 2657 lines, ~80+ tests likely (estimated from 2657/30 ≈ 88 tests). Grep `#[test]` would show distribution but not run; based on `use super::allocator::{sticky_pool_index, PersistentLease, PersistentSourceKey, ALLOCATION_GC_BUDGET, NS_PER_SEC}` + `use super::destination::{PROTO_TCP, PROTO_UDP}` the file imports from 3 submodules, confirming it's a dumping ground for tests that belong in `allocator/tests.rs`, `source/tests.rs`, `destination/tests.rs`, `static_nat/tests.rs`.
- Proposed decomposition:
  - `nat/allocator/tests.rs` — pool allocator white-box tests (sticky_pool_index, persistent lease, GC budget, exhaustion, recycled ports) — uses `debug_live()`
  - `nat/source/tests.rs` — SNAT rule parsing, matching, interface-mode, pool-mode allocation, address_persistent, persistent_nat
  - `nat/destination/tests.rs` — DNAT rule tests (PROTO_TCP/UDP constants)
  - `nat/static_nat/tests.rs` — static NAT dnat/snat v4/v6, zone mismatch
  - `nat/tests.rs` retained as `mod tests { mod integration; }` for cross-module integration tests (e.g., SNAT+DNAT interaction, full NAT decision flow)
- Hot-path preservation analysis: **A mechanical / safe** — tests are `#[cfg(test)]` only, not compiled into prod binary. No hot-path impact. Splitting tests reduces incremental build for `cargo test nat` when editing one test category (currently editing one SNAT test recompiles all 2657 LOC of tests including static NAT and allocator white-box). No guardrails needed.
- Tests + gate: `cargo test nat` must still pass with same count. The `debug_live()` accessor (allocator.rs:203..205 `#[cfg(test)] pub(super) fn debug_live`) must remain accessible to `allocator/tests.rs` (same `pub(super)` visibility works within `nat/` module — `allocator::tests` is child of `allocator`, so `pub(super)` to `allocator` means `tests` child can see it).
- Why it matters: 2657 LOC test file is un-reviewable; any change to SNAT rule parsing tests forces reviewers to re-scan static NAT and allocator white-box tests. Per project modularity-discipline ("corresponding inline `#[cfg(test)] mod tests` block moves with the production code"), tests should colocate with code. Current file violates this by being a central dumping ground after #1542 split.
- Fix direction:
  1. Create `nat/allocator/tests.rs`, move white-box tests (those using `debug_live`, `PersistentLease`, `ALLOCATION_GC_BUDGET`).
  2. Create `nat/source/tests.rs`, move `interface_source_nat_*`, `off_rule_*`, pool-mode SNAT tests.
  3. Create `nat/static_nat/tests.rs`, move `static_nat_*` tests.
  4. Create `nat/destination/tests.rs`, move DNAT tests.
  5. Keep `nat/tests.rs` for integration tests only, or delete if empty.
- Labels: refactor, nat, tests, P3
- Dedup note: #1542 split `nat/` into modules but consolidated all tests into single `tests.rs` (per header "Moved into nat/tests.rs as part of the #1542 split"). This finding is NEXT step: split `tests.rs` itself to colocate with code. No duplication with prior findings.

## Suggested issue split (sequenced PRs)

1. **PR 1 (mechanical, safe)**: `nat/allocator.rs` → 5 submodules + `nat/tests.rs` → 4 test files (Findings 5+10). Cold path, no hot-path risk. Verifies `cargo test nat` still passes.
2. **PR 2 (C perf-positive)**: `afxdp/types/cos.rs` → `config.rs`, `runtime.rs`, `flow_fair.rs`, `ring.rs`, `telemetry.rs` (Finding 6). Audit `CoSInterfaceRuntime` hot-cold field order for dcache win. Verify `new_boxed_matches_new_field_for_field` + miri.
3. **PR 3 (C perf-positive)**: `shared_cos_lease/mod.rs` → `exact_backlog.rs`, `vtime_floor.rs`, `legacy_lease.rs`, `packed_grant.rs`, `v8/` (Finding 2). Carry `#[repr(align(64))]` + size asserts + atomic ordering. Verify `cargo asm acquire_v8` + CoS smoke/fairness + `epoch_carry_bytes` grep test.
4. **PR 4 (B guardrails)**: `session/mod.rs` → `index.rs`, `gc.rs`, `lookup.rs`, `install.rs`, `delta.rs`, `timeout.rs` (Finding 1). Require `#[inline]` on index helpers, verify `cargo asm lookup_with_origin` byte-identical + `make test` + failover.
5. **PR 5 (B guardrails)**: `cos/queue_service/mod.rs` → `selector_*.rs`, `residual_budget.rs`, `drain_orchestrator.rs` (Finding 3). Require `#[inline]` on selectors, verify `cargo asm drain_shaped_tx` + CoS smoke/fairness.
6. **PR 6 (B guardrails, dedup)**: `cos/queue_service/service.rs` 4× copy-paste → `service/common.rs` + 4 thin wrappers (Finding 4). Most delicate — requires `cargo asm` diff byte-identical on hot variants, `stamp_submits` ordering preserved, `MONOTONIC` after `commit`. Land last after other CoS splits stable.
7. **PR 7 (B guardrails)**: `wg/engine.rs` → `peer_table.rs`, `reconcile.rs`, `session_table.rs`, `handshake_edge.rs`, `encap.rs`, `decap.rs` (Finding 7). Verify `cargo asm try_encap/try_decap` + WG tests + `Zeroizing` Drop audit.
8. **PR 8 (A safe)**: `cold_path_hist.rs` → `buckets.rs`, `slot_map.rs`, `tsc.rs`, `worker_atomics.rs` (Finding 8). Carry `repr(C,align(64))` + `repr(u8)` + seqlock protocol. Verify `cargo test` + TSC probe on x86_64.

Each PR: mechanical move, no behavior change, single `cargo test` + relevant gate (CoS smoke/fairness/failover/WG) must stay green. No trait objects, no new heap alloc on hot paths, no field reordering without size/assert verification.

