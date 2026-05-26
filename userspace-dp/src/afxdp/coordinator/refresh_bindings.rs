//! #1328 Phase 2 — `refresh_bindings` dispatcher + per-branch
//! helpers.
//!
//! Splits the pre-#1328 326-LOC `Coordinator::refresh_bindings`
//! into:
//!   - `copy_live_snapshot(binding, snap)` — bound-slot branch.
//!     Takes `BindingLiveSnapshot` BY VALUE (it owns `String`
//!     fields). The two latency histogram `Vec<u64>` are resized
//!     in place via `.resize() + .copy_from_slice()` so the
//!     existing backing storage on `BindingStatus` is reused —
//!     no per-status-poll allocation.
//!   - `zero_unbound_slot(binding)` — unbound-slot branch, pure
//!     code motion of the field zero-out.
//!
//! The public `Coordinator::refresh_bindings(bindings)` method
//! lives in this file as a thin dispatcher and calls
//! `refresh_cos_owner_worker_map_from_binding_statuses` at the
//! tail, preserving the pre-#1328 contract.
// Use the coordinator's afxdp scope (super::* from coordinator
// pulls in all afxdp items; we re-use the same pattern here).
use super::*;
use super::super::*;

impl Coordinator {
    pub fn refresh_bindings(&mut self, bindings: &mut [BindingStatus]) {
        for binding in bindings.iter_mut() {
            if let Some(live) = self.workers.live.get(&binding.slot) {
                let snap = live.snapshot();
                copy_live_snapshot(binding, snap);
            } else {
                zero_unbound_slot(binding);
            }
        }
        self.refresh_cos_owner_worker_map_from_binding_statuses(bindings);
    }
}

/// Copy a freshly-taken `BindingLiveSnapshot` into the
/// operator-facing `BindingStatus`. Pre-#1328 this was the
/// `if let Some(live) = ...` branch inside `refresh_bindings`;
/// the field-for-field assignment list is preserved verbatim.
///
/// Takes the snapshot by VALUE — it owns `String` fields
/// (`xsk_bind_mode`, `shared_umem_*`, `last_error`) so passing
/// by reference would force per-poll clones. The latency
/// histograms are copied via `.resize() + .copy_from_slice()`
/// against the existing `Vec<u64>` storage in `BindingStatus`
/// to avoid reallocating when capacity already matches.
pub(super) fn copy_live_snapshot(binding: &mut BindingStatus, snap: BindingLiveSnapshot) {
    if snap.bound && !binding.bound {
        eprintln!(
            "refresh_bindings: slot={} transitioning bound=false->true fd={}",
            binding.slot, snap.socket_fd
        );
    }
    binding.bound = snap.bound;
    binding.xsk_registered = snap.xsk_registered;
    binding.xsk_bind_mode = snap.xsk_bind_mode;
    binding.zero_copy = snap.zero_copy;
    binding.socket_fd = snap.socket_fd;
    binding.socket_ifindex = snap.socket_ifindex;
    binding.socket_queue_id = snap.socket_queue_id;
    binding.socket_bind_flags = snap.socket_bind_flags;
    binding.shared_umem_mode = snap.shared_umem_mode;
    binding.shared_umem_group = snap.shared_umem_group;
    binding.shared_umem_socket_role = snap.shared_umem_socket_role;
    binding.shared_umem_disabled_reason = snap.shared_umem_disabled_reason;
    binding.rx_packets = snap.rx_packets;
    binding.rx_bytes = snap.rx_bytes;
    binding.rx_batches = snap.rx_batches;
    binding.rx_wakeups = snap.rx_wakeups;
    binding.metadata_packets = snap.metadata_packets;
    binding.metadata_errors = snap.metadata_errors;
    binding.validated_packets = snap.validated_packets;
    binding.validated_bytes = snap.validated_bytes;
    binding.local_delivery_packets = snap.local_delivery_packets;
    binding.forward_candidate_packets = snap.forward_candidate_packets;
    binding.route_miss_packets = snap.route_miss_packets;
    binding.neighbor_miss_packets = snap.neighbor_miss_packets;
    binding.discard_route_packets = snap.discard_route_packets;
    binding.next_table_packets = snap.next_table_packets;
    binding.exception_packets = snap.exception_packets;
    binding.config_gen_mismatches = snap.config_gen_mismatches;
    binding.fib_gen_mismatches = snap.fib_gen_mismatches;
    binding.unsupported_packets = snap.unsupported_packets;
    binding.flow_cache_hits = snap.flow_cache_hits;
    binding.flow_cache_misses = snap.flow_cache_misses;
    binding.flow_cache_evictions = snap.flow_cache_evictions;
    binding.flow_cache_collision_evictions = snap.flow_cache_collision_evictions;
    // #1219: bridge active_flow_count from BindingLiveSnapshot
    // into BindingStatus so it reaches the wire-visible status.
    binding.active_flow_count = snap.active_flow_count;
    binding.flow_cache_capacity = snap.flow_cache_capacity;
    // #941 Work item D / #943: bridge V_min counters from
    // BindingLiveSnapshot through to BindingStatus so the
    // wire surface (BindingCountersSnapshot) sees them.
    binding.v_min_throttle_hard_cap_overrides = snap.v_min_throttle_hard_cap_overrides;
    binding.v_min_throttles = snap.v_min_throttles;
    binding.session_hits = snap.session_hits;
    binding.session_misses = snap.session_misses;
    binding.session_creates = snap.session_creates;
    binding.session_expires = snap.session_expires;
    binding.session_delta_pending = snap.session_delta_pending;
    binding.session_delta_generated = snap.session_delta_generated;
    binding.session_delta_dropped = snap.session_delta_dropped;
    binding.session_delta_drained = snap.session_delta_drained;
    binding.policy_denied_packets = snap.policy_denied_packets;
    binding.screen_drops = snap.screen_drops;
    binding.syn_cookie_challenges = snap.syn_cookie_challenges;
    binding.syn_cookie_secret_unavailable = snap.syn_cookie_secret_unavailable;
    binding.syn_cookie_syn_ack_sent = snap.syn_cookie_syn_ack_sent;
    binding.syn_cookie_ack_rst_sent = snap.syn_cookie_ack_rst_sent;
    binding.syn_cookie_reply_budget_drops = snap.syn_cookie_reply_budget_drops;
    binding.syn_cookie_ack_valid = snap.syn_cookie_ack_valid;
    binding.syn_cookie_ack_invalid = snap.syn_cookie_ack_invalid;
    binding.syn_cookie_bypass = snap.syn_cookie_bypass;
    binding.snat_packets = snap.snat_packets;
    binding.dnat_packets = snap.dnat_packets;
    binding.slow_path_packets = snap.slow_path_packets;
    binding.slow_path_bytes = snap.slow_path_bytes;
    binding.slow_path_local_delivery_packets = snap.slow_path_local_delivery_packets;
    binding.slow_path_missing_neighbor_packets = snap.slow_path_missing_neighbor_packets;
    binding.slow_path_no_route_packets = snap.slow_path_no_route_packets;
    binding.slow_path_next_table_packets = snap.slow_path_next_table_packets;
    binding.slow_path_forward_build_packets = snap.slow_path_forward_build_packets;
    binding.slow_path_drops = snap.slow_path_drops;
    binding.slow_path_rate_limited = snap.slow_path_rate_limited;
    binding.kernel_rx_dropped = snap.kernel_rx_dropped;
    binding.kernel_rx_invalid_descs = snap.kernel_rx_invalid_descs;
    binding.tx_packets = snap.tx_packets;
    binding.tx_bytes = snap.tx_bytes;
    binding.tx_completions = snap.tx_completions;
    binding.tx_errors = snap.tx_errors;
    binding.tx_shared_recycle_unknown_slot_drops = snap.tx_shared_recycle_unknown_slot_drops;
    binding.redirect_inbox_overflow_drops = snap.redirect_inbox_overflow_drops;
    binding.pending_tx_local_overflow_drops = snap.pending_tx_local_overflow_drops;
    binding.tx_submit_error_drops = snap.tx_submit_error_drops;
    binding.mirrored_packets = snap.mirrored_packets;
    binding.mirrored_bytes = snap.mirrored_bytes;
    binding.mirror_drops_no_frame = snap.mirror_drops_no_frame;
    binding.mirror_drops_tx_frame_reserve = snap.mirror_drops_tx_frame_reserve;
    binding.mirror_drops_no_binding = snap.mirror_drops_no_binding;
    binding.mirror_drops_queue_full = snap.mirror_drops_queue_full;
    binding.mirror_drops_queue_full_same_worker = snap.mirror_drops_queue_full_same_worker;
    binding.mirror_drops_queue_full_cross_worker = snap.mirror_drops_queue_full_cross_worker;
    binding.post_drain_backup_bytes = snap.post_drain_backup_bytes;
    binding.drain_sent_bytes_shaped_unconditional = snap.drain_sent_bytes_shaped_unconditional;
    binding.post_drain_backup_cos_drops = snap.post_drain_backup_cos_drops;
    binding.post_drain_backup_cos_drop_bytes = snap.post_drain_backup_cos_drop_bytes;
    // #710: `snap.no_owner_binding_drops` is not copied into
    // per-binding status — it is summed across all bindings
    // into `ProcessStatus::cos_no_owner_binding_drops_total`
    // at the refresh_status callsite, which is the correct
    // operator-facing scope for this counter.
    binding.direct_tx_packets = snap.direct_tx_packets;
    binding.copy_tx_packets = snap.copy_tx_packets;
    binding.in_place_tx_packets = snap.in_place_tx_packets;
    binding.in_place_vlan_push_desc_packets = snap.in_place_vlan_push_desc_packets;
    binding.in_place_vlan_pop_desc_packets = snap.in_place_vlan_pop_desc_packets;
    binding.in_place_vlan_push_no_headroom_packets = snap.in_place_vlan_push_no_headroom_packets;
    binding.in_place_l2_memmove_fallback_packets = snap.in_place_l2_memmove_fallback_packets;
    binding.direct_tx_no_frame_fallback_packets = snap.direct_tx_no_frame_fallback_packets;
    binding.direct_tx_build_fallback_packets = snap.direct_tx_build_fallback_packets;
    binding.direct_tx_disallowed_fallback_packets = snap.direct_tx_disallowed_fallback_packets;
    binding.debug_pending_fill_frames = snap.debug_pending_fill_frames;
    binding.debug_spare_fill_frames = 0;
    binding.debug_free_tx_frames = snap.debug_free_tx_frames;
    binding.debug_pending_tx_prepared = snap.debug_pending_tx_prepared;
    binding.debug_pending_tx_local = snap.debug_pending_tx_local;
    binding.debug_outstanding_tx = snap.debug_outstanding_tx;
    binding.tx_completion_ring_available = snap.tx_completion_ring_available;
    binding.tx_completion_ring_available_max = snap.tx_completion_ring_available_max;
    binding.debug_in_flight_recycles = snap.debug_in_flight_recycles;
    // #878: per-binding capacities + in-flight gauge flow
    // into BindingStatus so the daemon's fwdstatus
    // Buffer% can compute UMEM and TX-ring fill ratios.
    binding.umem_total_frames = snap.umem_total_frames;
    binding.tx_ring_capacity = snap.tx_ring_capacity;
    binding.umem_inflight_frames = snap.umem_inflight_frames;
    // #802: ring-pressure counters — atomic mirrors of
    // worker-local counters, published on the worker's
    // per-second debug tick. `outstanding_tx` aliases
    // `debug_outstanding_tx` for the operator-facing name.
    binding.dbg_tx_ring_full = snap.dbg_tx_ring_full;
    binding.dbg_sendto_enobufs = snap.dbg_sendto_enobufs;
    // #804: split counters — bound-pending FIFO vs CoS
    // queue admission. Pre-#804 a single `dbg_pending_overflow`
    // was published; the wire name was removed because
    // the semantics were ambiguous for operators.
    binding.dbg_bound_pending_overflow = snap.dbg_bound_pending_overflow;
    binding.dbg_cos_queue_overflow = snap.dbg_cos_queue_overflow;
    binding.rx_fill_ring_empty_descs = snap.rx_fill_ring_empty_descs;
    binding.outstanding_tx = snap.debug_outstanding_tx;
    // #812: per-queue TX submit→completion latency
    // telemetry. Materialize the fixed-cap snapshot
    // array into a freshly-owned Vec<u64> on the wire
    // boundary — reuses the buffer in-place to avoid
    // allocator churn when the BindingStatus entry is
    // refreshed on the ~1s poll cadence.
    binding
        .tx_submit_latency_hist
        .resize(snap.tx_submit_latency_hist.len(), 0);
    binding
        .tx_submit_latency_hist
        .copy_from_slice(&snap.tx_submit_latency_hist);
    binding.tx_submit_latency_count = snap.tx_submit_latency_count;
    binding.tx_submit_latency_sum_ns = snap.tx_submit_latency_sum_ns;
    // #825: per-kick `sendto` latency telemetry mirrors
    // the #812 submit-latency copy path above. Resize
    // the operator-facing Vec<u64> to match the
    // snapshot's fixed-cap array, then copy bucket
    // counts and scalars. `tx_kick_retry_count` is the
    // EAGAIN/EWOULDBLOCK tally (T1 ring-pushback).
    binding
        .tx_kick_latency_hist
        .resize(snap.tx_kick_latency_hist.len(), 0);
    binding
        .tx_kick_latency_hist
        .copy_from_slice(&snap.tx_kick_latency_hist);
    binding.tx_kick_latency_count = snap.tx_kick_latency_count;
    binding.tx_kick_latency_sum_ns = snap.tx_kick_latency_sum_ns;
    binding.tx_kick_retry_count = snap.tx_kick_retry_count;
    binding.last_heartbeat = snap.last_heartbeat;
    binding.last_error = snap.last_error;
    binding.ready = binding.registered
        && binding.bound
        && binding.xsk_registered
        && heartbeat_fresh(snap.last_heartbeat);
}

/// Zero out a `BindingStatus` whose slot has no live worker
/// (unregistered or stopped). Pure code motion of the
/// `else` branch from pre-#1328 `refresh_bindings`. Uses
/// `.clear()` on `Vec`/`String` fields to retain capacity —
/// avoids per-poll allocation when the same slot transitions
/// back to bound.
pub(super) fn zero_unbound_slot(binding: &mut BindingStatus) {
    binding.bound = false;
    binding.xsk_registered = false;
    binding.xsk_bind_mode.clear();
    binding.zero_copy = false;
    binding.socket_fd = 0;
    binding.socket_ifindex = 0;
    binding.socket_queue_id = 0;
    binding.socket_bind_flags = 0;
    binding.rx_packets = 0;
    binding.rx_bytes = 0;
    binding.rx_batches = 0;
    binding.rx_wakeups = 0;
    binding.metadata_packets = 0;
    binding.metadata_errors = 0;
    binding.validated_packets = 0;
    binding.validated_bytes = 0;
    binding.local_delivery_packets = 0;
    binding.forward_candidate_packets = 0;
    binding.route_miss_packets = 0;
    binding.neighbor_miss_packets = 0;
    binding.discard_route_packets = 0;
    binding.next_table_packets = 0;
    binding.exception_packets = 0;
    binding.config_gen_mismatches = 0;
    binding.fib_gen_mismatches = 0;
    binding.unsupported_packets = 0;
    binding.flow_cache_hits = 0;
    binding.flow_cache_misses = 0;
    binding.flow_cache_evictions = 0;
    binding.flow_cache_collision_evictions = 0;
    binding.active_flow_count = 0;
    binding.flow_cache_capacity = 0;
    binding.v_min_throttle_hard_cap_overrides = 0;
    binding.v_min_throttles = 0;
    binding.session_hits = 0;
    binding.session_misses = 0;
    binding.session_creates = 0;
    binding.session_expires = 0;
    binding.session_delta_pending = 0;
    binding.session_delta_generated = 0;
    binding.session_delta_dropped = 0;
    binding.session_delta_drained = 0;
    binding.policy_denied_packets = 0;
    binding.screen_drops = 0;
    binding.syn_cookie_challenges = 0;
    binding.syn_cookie_secret_unavailable = 0;
    binding.syn_cookie_syn_ack_sent = 0;
    binding.syn_cookie_ack_rst_sent = 0;
    binding.syn_cookie_reply_budget_drops = 0;
    binding.syn_cookie_ack_valid = 0;
    binding.syn_cookie_ack_invalid = 0;
    binding.syn_cookie_bypass = 0;
    binding.snat_packets = 0;
    binding.dnat_packets = 0;
    binding.slow_path_packets = 0;
    binding.slow_path_bytes = 0;
    binding.slow_path_local_delivery_packets = 0;
    binding.slow_path_missing_neighbor_packets = 0;
    binding.slow_path_no_route_packets = 0;
    binding.slow_path_next_table_packets = 0;
    binding.slow_path_forward_build_packets = 0;
    binding.slow_path_drops = 0;
    binding.slow_path_rate_limited = 0;
    binding.kernel_rx_dropped = 0;
    binding.kernel_rx_invalid_descs = 0;
    binding.tx_packets = 0;
    binding.tx_bytes = 0;
    binding.tx_completions = 0;
    binding.tx_errors = 0;
    binding.tx_shared_recycle_unknown_slot_drops = 0;
    binding.mirrored_packets = 0;
    binding.mirrored_bytes = 0;
    binding.mirror_drops_no_frame = 0;
    binding.mirror_drops_tx_frame_reserve = 0;
    binding.mirror_drops_no_binding = 0;
    binding.mirror_drops_queue_full = 0;
    binding.mirror_drops_queue_full_same_worker = 0;
    binding.mirror_drops_queue_full_cross_worker = 0;
    binding.post_drain_backup_bytes = 0;
    binding.drain_sent_bytes_shaped_unconditional = 0;
    binding.post_drain_backup_cos_drops = 0;
    binding.post_drain_backup_cos_drop_bytes = 0;
    binding.direct_tx_packets = 0;
    binding.copy_tx_packets = 0;
    binding.in_place_tx_packets = 0;
    binding.in_place_vlan_push_desc_packets = 0;
    binding.in_place_vlan_pop_desc_packets = 0;
    binding.in_place_vlan_push_no_headroom_packets = 0;
    binding.in_place_l2_memmove_fallback_packets = 0;
    binding.direct_tx_no_frame_fallback_packets = 0;
    binding.direct_tx_build_fallback_packets = 0;
    binding.direct_tx_disallowed_fallback_packets = 0;
    binding.debug_pending_fill_frames = 0;
    binding.debug_spare_fill_frames = 0;
    binding.debug_free_tx_frames = 0;
    binding.debug_pending_tx_prepared = 0;
    binding.debug_pending_tx_local = 0;
    binding.debug_outstanding_tx = 0;
    binding.tx_completion_ring_available = 0;
    binding.tx_completion_ring_available_max = 0;
    binding.debug_in_flight_recycles = 0;
    // #878: capacities + in-flight gauge zero when the
    // binding has no live state (slot unregistered). The
    // daemon treats zero umem_total_frames as "unknown"
    // and falls back to the legacy Buffer% display.
    binding.umem_total_frames = 0;
    binding.tx_ring_capacity = 0;
    binding.umem_inflight_frames = 0;
    // #802: ring-pressure counters — zero when the binding
    // has no live state (unregistered slot).
    binding.dbg_tx_ring_full = 0;
    binding.dbg_sendto_enobufs = 0;
    binding.dbg_bound_pending_overflow = 0;
    binding.dbg_cos_queue_overflow = 0;
    binding.rx_fill_ring_empty_descs = 0;
    binding.outstanding_tx = 0;
    // #812: zero the submit-latency histogram when the
    // binding has no live state (unregistered slot).
    binding.tx_submit_latency_hist.clear();
    binding.tx_submit_latency_count = 0;
    binding.tx_submit_latency_sum_ns = 0;
    // #825: zero the kick-latency histogram + retry
    // counter when the binding has no live state.
    binding.tx_kick_latency_hist.clear();
    binding.tx_kick_latency_count = 0;
    binding.tx_kick_latency_sum_ns = 0;
    binding.tx_kick_retry_count = 0;
    binding.last_heartbeat = None;
    binding.last_error.clear();
    binding.ready = false;
}
