//! Per-binding status (`BindingStatus`), its lean
//! `BindingCountersSnapshot` projection (plus the
//! `From<&BindingStatus>` conversion and the `'static + Send`
//! compile-time assertion), `WorkerRuntimeStatus`,
//! `HAGroupStatus`, `QueueStatus`, `ExceptionStatus`, and
//! `SessionDeltaInfo`. Also home to the `u64_is_zero`
//! `skip_serializing_if` helper consumed by
//! `HAGroupStatus.lease_until`; the helper is referenced via the
//! absolute path `crate::protocol::u64_is_zero` from the serde
//! attribute so future moves do not require touching the
//! attribute string.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WorkerRuntimeStatus {
    #[serde(rename = "worker_id", default)]
    pub worker_id: u32,
    #[serde(default)]
    pub tid: u64,
    #[serde(rename = "wall_ns", default)]
    pub wall_ns: u64,
    #[serde(rename = "active_ns", default)]
    pub active_ns: u64,
    #[serde(rename = "idle_spin_ns", default)]
    pub idle_spin_ns: u64,
    #[serde(rename = "idle_block_ns", default)]
    pub idle_block_ns: u64,
    #[serde(rename = "thread_cpu_ns", default)]
    pub thread_cpu_ns: u64,
    #[serde(rename = "work_loops", default)]
    pub work_loops: u64,
    #[serde(rename = "idle_loops", default)]
    pub idle_loops: u64,
    /// #1240: cumulative v8 per-worker queue-lease acquire calls
    /// observed by this worker across its bindings. Operators should
    /// compare `rate()` against per-worker TX rate to diagnose lease-
    /// request frequency imbalance.
    #[serde(rename = "cos_queue_lease_acquire_v8_calls", default)]
    pub cos_queue_lease_acquire_v8_calls: u64,
    /// #1240: cumulative bytes granted by v8 queue-lease acquire calls.
    #[serde(rename = "cos_queue_lease_acquire_v8_granted_bytes", default)]
    pub cos_queue_lease_acquire_v8_granted_bytes: u64,
    /// Current entries in this worker's Rust-owned SessionTable.
    #[serde(rename = "session_table_entries", default)]
    pub session_table_entries: u64,
    /// Capacity of this worker's Rust-owned SessionTable.
    #[serde(rename = "max_sessions", default)]
    pub max_sessions: u64,
    /// #925: true if the worker_loop thread panicked and the supervisor
    /// caught it. Set once on first panic; never cleared in Phase 1.
    /// Operators see DEAD in `cli show chassis forwarding` and must
    /// restart the daemon for the dead worker's bindings to recover.
    #[serde(rename = "dead", default)]
    pub dead: bool,
    /// #925: panic payload string for operator diagnosis.
    /// Cases: `&str` payload → the argument; `String` payload → its
    /// content; non-string payload → literal "non-string panic payload";
    /// worker alive (no panic) → empty.
    #[serde(rename = "panic_message", default)]
    pub panic_message: String,
    /// Rolling last-window delta for `thread_cpu_ns`. Under the normal
    /// ~1 Hz worker publish cadence the rotated window is ~60–61s wide
    /// (one publish-tick of overshoot past `WR_WINDOW_INTERVAL_NS`); a
    /// stalled publisher can widen it further. `window_ns` carries the
    /// exact measured width so rate math is honest regardless of
    /// cadence. Both fields are zero until the first rotation has
    /// fired (~60s after worker start).
    #[serde(rename = "thread_cpu_ns_60s", default)]
    pub thread_cpu_ns_60s: u64,
    #[serde(rename = "wall_ns_60s", default)]
    pub wall_ns_60s: u64,
    #[serde(rename = "active_ns_60s", default)]
    pub active_ns_60s: u64,
    #[serde(rename = "window_ns", default)]
    pub window_ns: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct HAGroupStatus {
    #[serde(rename = "rg_id", default)]
    pub rg_id: i32,
    #[serde(default)]
    pub active: bool,
    #[serde(rename = "watchdog_timestamp", default)]
    pub watchdog_timestamp: u64,
    #[serde(rename = "forwarding_active", default)]
    pub forwarding_active: bool,
    #[serde(
        rename = "lease_state",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub lease_state: String,
    #[serde(
        rename = "lease_until",
        default,
        skip_serializing_if = "crate::protocol::u64_is_zero"
    )]
    pub lease_until: u64,
}

pub(crate) fn u64_is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct QueueStatus {
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    pub last_change: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct BindingStatus {
    pub slot: u32,
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
    #[serde(default)]
    pub ready: bool,
    #[serde(default)]
    pub bound: bool,
    #[serde(rename = "xsk_registered", default)]
    pub xsk_registered: bool,
    #[serde(rename = "xsk_bind_mode", default)]
    pub xsk_bind_mode: String,
    #[serde(rename = "zero_copy", default)]
    pub zero_copy: bool,
    #[serde(rename = "socket_fd", default)]
    pub socket_fd: i32,
    #[serde(rename = "rx_packets", default)]
    pub rx_packets: u64,
    #[serde(rename = "rx_bytes", default)]
    pub rx_bytes: u64,
    #[serde(rename = "rx_batches", default)]
    pub rx_batches: u64,
    #[serde(rename = "rx_wakeups", default)]
    pub rx_wakeups: u64,
    #[serde(rename = "metadata_packets", default)]
    pub metadata_packets: u64,
    #[serde(rename = "metadata_errors", default)]
    pub metadata_errors: u64,
    #[serde(rename = "validated_packets", default)]
    pub validated_packets: u64,
    #[serde(rename = "validated_bytes", default)]
    pub validated_bytes: u64,
    #[serde(rename = "local_delivery_packets", default)]
    pub local_delivery_packets: u64,
    #[serde(rename = "forward_candidate_packets", default)]
    pub forward_candidate_packets: u64,
    #[serde(rename = "route_miss_packets", default)]
    pub route_miss_packets: u64,
    #[serde(rename = "neighbor_miss_packets", default)]
    pub neighbor_miss_packets: u64,
    #[serde(rename = "discard_route_packets", default)]
    pub discard_route_packets: u64,
    #[serde(rename = "next_table_packets", default)]
    pub next_table_packets: u64,
    #[serde(rename = "exception_packets", default)]
    pub exception_packets: u64,
    #[serde(rename = "config_gen_mismatches", default)]
    pub config_gen_mismatches: u64,
    #[serde(rename = "fib_gen_mismatches", default)]
    pub fib_gen_mismatches: u64,
    #[serde(rename = "unsupported_packets", default)]
    pub unsupported_packets: u64,
    #[serde(rename = "flow_cache_hits", default)]
    pub flow_cache_hits: u64,
    #[serde(rename = "flow_cache_misses", default)]
    pub flow_cache_misses: u64,
    #[serde(rename = "flow_cache_evictions", default)]
    pub flow_cache_evictions: u64,
    /// #918: collision-driven subset of `flow_cache_evictions`. An
    /// insert that displaced a different-key entry from the LRU way
    /// of a full set increments this; stale-on-lookup evictions do
    /// not. Acceptance gate watches `collision_evictions / hits`
    /// under load.
    #[serde(rename = "flow_cache_collision_evictions", default)]
    pub flow_cache_collision_evictions: u64,
    /// #1219: snapshot count of distinct active flows on this binding's
    /// flow_cache, refreshed at the ~65ms debug-state tick. Per
    /// `docs/fairness-regimes.md`, the harness reads this via
    /// Prometheus to compute `{a_i}` for the structural CoV gate.
    #[serde(rename = "active_flow_count", default)]
    pub active_flow_count: u32,
    /// Per-binding capacity of the Rust-owned flow cache. This is the
    /// denominator for operator buffer rendering when active_flow_count
    /// is shown as utilization.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: u32,
    /// #941 Work item D / #943: count of V_min hard-cap activations
    /// on this binding. Hard-cap is the escape hatch that fires
    /// after V_MIN_CONSECUTIVE_SKIP_HARD_CAP back-to-back throttle
    /// decisions, force-continuing the drain to recover throughput
    /// under persistent peer-vtime spread. Acceptance gate: under
    /// normal load, override-rate stays below 5 %.
    #[serde(rename = "v_min_throttle_hard_cap_overrides", default)]
    pub v_min_throttle_hard_cap_overrides: u64,
    /// #943: count of regular V_min throttle decisions
    /// (`cos_queue_v_min_continue` returned `false` and the drain
    /// loop early-broke) on this binding. Distinct from the hard-cap
    /// override path (which force-continues despite the throttle).
    /// Together: `v_min_throttles` is "fairness brake fired",
    /// `v_min_throttle_hard_cap_overrides` is "brake too tight, escape
    /// hatch rescued throughput". Ratio is the LAG_THRESHOLD diagnostic.
    #[serde(rename = "v_min_throttles", default)]
    pub v_min_throttles: u64,
    #[serde(rename = "session_hits", default)]
    pub session_hits: u64,
    #[serde(rename = "session_misses", default)]
    pub session_misses: u64,
    #[serde(rename = "session_creates", default)]
    pub session_creates: u64,
    #[serde(rename = "session_expires", default)]
    pub session_expires: u64,
    #[serde(rename = "session_delta_pending", default)]
    pub session_delta_pending: u64,
    #[serde(rename = "session_delta_generated", default)]
    pub session_delta_generated: u64,
    #[serde(rename = "session_delta_dropped", default)]
    pub session_delta_dropped: u64,
    #[serde(rename = "session_delta_drained", default)]
    pub session_delta_drained: u64,
    #[serde(rename = "policy_denied_packets", default)]
    pub policy_denied_packets: u64,
    #[serde(rename = "screen_drops", default)]
    pub screen_drops: u64,
    #[serde(rename = "syn_cookie_challenges", default)]
    pub syn_cookie_challenges: u64,
    #[serde(rename = "syn_cookie_secret_unavailable", default)]
    pub syn_cookie_secret_unavailable: u64,
    #[serde(rename = "syn_cookie_syn_ack_sent", default)]
    pub syn_cookie_syn_ack_sent: u64,
    #[serde(rename = "syn_cookie_ack_rst_sent", default)]
    pub syn_cookie_ack_rst_sent: u64,
    #[serde(rename = "syn_cookie_reply_budget_drops", default)]
    pub syn_cookie_reply_budget_drops: u64,
    #[serde(rename = "syn_cookie_ack_valid", default)]
    pub syn_cookie_ack_valid: u64,
    #[serde(rename = "syn_cookie_ack_invalid", default)]
    pub syn_cookie_ack_invalid: u64,
    #[serde(rename = "syn_cookie_bypass", default)]
    pub syn_cookie_bypass: u64,
    #[serde(rename = "snat_packets", default)]
    pub snat_packets: u64,
    #[serde(rename = "dnat_packets", default)]
    pub dnat_packets: u64,
    #[serde(rename = "slow_path_packets", default)]
    pub slow_path_packets: u64,
    #[serde(rename = "slow_path_bytes", default)]
    pub slow_path_bytes: u64,
    #[serde(rename = "slow_path_local_delivery_packets", default)]
    pub slow_path_local_delivery_packets: u64,
    #[serde(rename = "slow_path_missing_neighbor_packets", default)]
    pub slow_path_missing_neighbor_packets: u64,
    #[serde(rename = "slow_path_no_route_packets", default)]
    pub slow_path_no_route_packets: u64,
    #[serde(rename = "slow_path_next_table_packets", default)]
    pub slow_path_next_table_packets: u64,
    #[serde(rename = "slow_path_forward_build_packets", default)]
    pub slow_path_forward_build_packets: u64,
    #[serde(rename = "slow_path_drops", default)]
    pub slow_path_drops: u64,
    #[serde(rename = "slow_path_rate_limited", default)]
    pub slow_path_rate_limited: u64,
    #[serde(rename = "kernel_rx_dropped", default)]
    pub kernel_rx_dropped: u64,
    #[serde(rename = "kernel_rx_invalid_descs", default)]
    pub kernel_rx_invalid_descs: u64,
    #[serde(rename = "tx_packets", default)]
    pub tx_packets: u64,
    #[serde(rename = "tx_bytes", default)]
    pub tx_bytes: u64,
    #[serde(rename = "tx_errors", default)]
    pub tx_errors: u64,
    // #1307: shared-UMEM recycle requests dropped because their
    // recorded fill slot no longer maps to a live binding. Subset of
    // `tx_errors`.
    #[serde(rename = "tx_shared_recycle_unknown_slot_drops", default)]
    pub tx_shared_recycle_unknown_slot_drops: u64,
    // #710: per-binding subset of `tx_errors` attributed to the
    // redirect-inbox overflow path in `BindingLiveState::enqueue_tx` /
    // `enqueue_tx_owned`. Indicates the owner is not draining redirects
    // fast enough for the rate of incoming redirects from non-owner
    // workers. See #706 / #709.
    #[serde(rename = "redirect_inbox_overflow_drops", default)]
    pub redirect_inbox_overflow_drops: u64,
    // #710: per-binding `pending_tx_local`/`pending_tx_prepared` FIFO
    // overflow drops. Subset of `tx_errors`. Indicates the worker
    // cannot ingest redirected traffic into CoS as fast as it arrives
    // — often the load-bearing drop category on the owner worker
    // under multi-flow load.
    #[serde(rename = "pending_tx_local_overflow_drops", default)]
    pub pending_tx_local_overflow_drops: u64,
    // #710: catch-all counter for frame-level TX submit errors
    // (`TxError::Drop`, scratch-build slice/capacity failures). Subset
    // of `tx_errors`. Non-zero usually indicates a frame-builder bug
    // rather than a scheduler/shaper decision — separate category from
    // the flow-fair admission / redirect-inbox / pending-FIFO drops.
    #[serde(rename = "tx_submit_error_drops", default)]
    pub tx_submit_error_drops: u64,
    #[serde(rename = "mirrored_packets", default)]
    pub mirrored_packets: u64,
    #[serde(rename = "mirrored_bytes", default)]
    pub mirrored_bytes: u64,
    #[serde(rename = "mirror_drops_no_frame", default)]
    pub mirror_drops_no_frame: u64,
    #[serde(rename = "mirror_drops_tx_frame_reserve", default)]
    pub mirror_drops_tx_frame_reserve: u64,
    #[serde(rename = "mirror_drops_no_binding", default)]
    pub mirror_drops_no_binding: u64,
    #[serde(rename = "mirror_drops_queue_full", default)]
    pub mirror_drops_queue_full: u64,
    #[serde(rename = "mirror_drops_queue_full_same_worker", default)]
    pub mirror_drops_queue_full_same_worker: u64,
    #[serde(rename = "mirror_drops_queue_full_cross_worker", default)]
    pub mirror_drops_queue_full_cross_worker: u64,
    // #760 instrumentation: post-CoS backup transmit bytes
    // (drain_pending_tx fallbacks (tx/drain.rs::drain_pending_tx)) that bypass
    // any CoS queue's token gate.
    #[serde(rename = "post_drain_backup_bytes", default)]
    pub post_drain_backup_bytes: u64,
    // #760 instrumentation: binding-scoped bytes observed at the
    // three apply_* tx_bytes sites, written unconditionally. Gap
    // vs the sum of per-queue drain_sent_bytes attributes shaped
    // traffic that bypassed the per-queue write via an apply_*
    // early-return / queue miss.
    #[serde(rename = "drain_sent_bytes_shaped_unconditional", default)]
    pub drain_sent_bytes_shaped_unconditional: u64,
    // #760 (PR #773): CoS-bound items dropped at the post-drain
    // backup filter — cross-worker routing failures the bounded
    // ingest-drain loop didn't absorb. Non-zero is the primary
    // operator signal that the backup-path belt-and-suspenders
    // is catching real leakage.
    #[serde(rename = "post_drain_backup_cos_drops", default)]
    pub post_drain_backup_cos_drops: u64,
    #[serde(rename = "post_drain_backup_cos_drop_bytes", default)]
    pub post_drain_backup_cos_drop_bytes: u64,
    // #710 attribution note: cross-worker CoS "no-owner-binding" drops
    // are exposed at the `ProcessStatus::cos_no_owner_binding_drops_total`
    // top-level field, not per binding. The increment mechanically lands
    // on the landing worker's first binding (no ifindex is meaningful —
    // the drop fires specifically because no binding matched the
    // request's egress), so per-binding attribution would mislead
    // operators during triage.
    #[serde(rename = "direct_tx_packets", default)]
    pub direct_tx_packets: u64,
    #[serde(rename = "copy_tx_packets", default)]
    pub copy_tx_packets: u64,
    #[serde(rename = "in_place_tx_packets", default)]
    pub in_place_tx_packets: u64,
    #[serde(rename = "in_place_vlan_push_desc_packets", default)]
    pub in_place_vlan_push_desc_packets: u64,
    #[serde(rename = "in_place_vlan_pop_desc_packets", default)]
    pub in_place_vlan_pop_desc_packets: u64,
    #[serde(rename = "in_place_vlan_push_no_headroom_packets", default)]
    pub in_place_vlan_push_no_headroom_packets: u64,
    #[serde(rename = "in_place_l2_memmove_fallback_packets", default)]
    pub in_place_l2_memmove_fallback_packets: u64,
    #[serde(rename = "direct_tx_no_frame_fallback_packets", default)]
    pub direct_tx_no_frame_fallback_packets: u64,
    #[serde(rename = "direct_tx_build_fallback_packets", default)]
    pub direct_tx_build_fallback_packets: u64,
    #[serde(rename = "direct_tx_disallowed_fallback_packets", default)]
    pub direct_tx_disallowed_fallback_packets: u64,
    #[serde(rename = "last_heartbeat", skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    #[serde(rename = "tx_completions", default)]
    pub tx_completions: u64,
    #[serde(rename = "socket_ifindex", default)]
    pub socket_ifindex: i32,
    #[serde(rename = "socket_queue_id", default)]
    pub socket_queue_id: u32,
    #[serde(rename = "socket_bind_flags", default)]
    pub socket_bind_flags: u32,
    /// Experimental shared-UMEM bind plan selected by the coordinator.
    /// Empty/default means the binding is using the normal private UMEM path.
    #[serde(rename = "shared_umem_mode", default)]
    pub shared_umem_mode: String,
    #[serde(rename = "shared_umem_group", default)]
    pub shared_umem_group: String,
    #[serde(rename = "shared_umem_socket_role", default)]
    pub shared_umem_socket_role: String,
    #[serde(rename = "shared_umem_disabled_reason", default)]
    pub shared_umem_disabled_reason: String,
    #[serde(rename = "debug_pending_fill_frames", default)]
    pub debug_pending_fill_frames: u32,
    #[serde(rename = "debug_spare_fill_frames", default)]
    pub debug_spare_fill_frames: u32,
    #[serde(rename = "debug_free_tx_frames", default)]
    pub debug_free_tx_frames: u32,
    #[serde(rename = "debug_pending_tx_prepared", default)]
    pub debug_pending_tx_prepared: u32,
    #[serde(rename = "debug_pending_tx_local", default)]
    pub debug_pending_tx_local: u32,
    #[serde(rename = "debug_outstanding_tx", default)]
    pub debug_outstanding_tx: u32,
    /// #1241: last sampled AF_XDP TX completion-ring availability
    /// before completion drain. This is a low-frequency status gauge
    /// published from owner-local worker telemetry; it is not read by
    /// the scheduler.
    #[serde(rename = "tx_completion_ring_available", default)]
    pub tx_completion_ring_available: u32,
    /// #1241: maximum sampled completion-ring availability in the last
    /// debug window.
    #[serde(rename = "tx_completion_ring_available_max", default)]
    pub tx_completion_ring_available_max: u32,
    #[serde(rename = "debug_in_flight_recycles", default)]
    pub debug_in_flight_recycles: u32,
    // #802: ring-pressure instrumentation. Operator-facing cumulative
    // counters for XSK ring saturation diagnosis. See the
    // `line-rate-investigation-plan.md` "DEFERRED-INSTRUMENTATION" rows
    // for semantics. `outstanding_tx` is a gauge (current value) that
    // serves as a proxy for `completion_reap_max_batch`; the real
    // completion-reap-batch histogram is accept-proxy per that plan.
    #[serde(rename = "dbg_tx_ring_full", default)]
    pub dbg_tx_ring_full: u64,
    #[serde(rename = "dbg_sendto_enobufs", default)]
    pub dbg_sendto_enobufs: u64,
    // #804: split from the old conflated `dbg_pending_overflow`. Two
    // distinct write-sites, two distinct wire keys. Pre-#804 snapshots
    // will deserialize both as 0 (`default`), which is the right
    // backward-compat behavior — the old field is no longer present on
    // the wire and consumers that want totals across either path should
    // sum the two explicitly.
    #[serde(rename = "dbg_bound_pending_overflow", default)]
    pub dbg_bound_pending_overflow: u64,
    #[serde(rename = "dbg_cos_queue_overflow", default)]
    pub dbg_cos_queue_overflow: u64,
    #[serde(rename = "rx_fill_ring_empty_descs", default)]
    pub rx_fill_ring_empty_descs: u64,
    #[serde(rename = "outstanding_tx", default)]
    pub outstanding_tx: u32,
    /// #878: per-binding UMEM total frames (set once at worker
    /// construction). Denominator for the daemon's `show chassis
    /// forwarding` Buffer%; numerator is `umem_inflight_frames`.
    /// `default` keeps the wire format additive — a pre-#878 helper
    /// that lacks this field deserializes as zero, which the daemon
    /// treats as "not yet published" and falls back to the legacy
    /// display.
    #[serde(rename = "umem_total_frames", default)]
    pub umem_total_frames: u32,
    /// #878: configured TX-ring depth.
    /// `outstanding_tx / tx_ring_capacity` is the second pressure
    /// signal aggregated by Buffer%.
    #[serde(rename = "tx_ring_capacity", default)]
    pub tx_ring_capacity: u32,
    /// #878: UMEM in-flight gauge, published in a single atomic
    /// store from the worker's per-second debug tick. `default`
    /// preserves wire compat — a pre-#878 helper sends 0 and the
    /// daemon treats `umem_total_frames == 0` (not this field) as
    /// the "not published" signal.
    #[serde(rename = "umem_inflight_frames", default)]
    pub umem_inflight_frames: u32,
    // #812: per-queue TX submit→completion latency telemetry. Emitted
    // in the rich BindingStatus shape; also projected onto the focused
    // `BindingCountersSnapshot` via the `From` impl so the
    // step1-capture consumer can reach it without a second join.
    // `drain_latency_hist` at protocol.rs:881 is the sibling wire
    // contract this mirrors — histograms on the wire are Vec<u64> so
    // serde needs no schema for the fixed-cap array. Default on all
    // three preserves backward-compat for pre-#812 helper payloads
    // (fields absent → zero-valued).
    #[serde(rename = "tx_submit_latency_hist", default)]
    pub tx_submit_latency_hist: Vec<u64>,
    #[serde(rename = "tx_submit_latency_count", default)]
    pub tx_submit_latency_count: u64,
    #[serde(rename = "tx_submit_latency_sum_ns", default)]
    pub tx_submit_latency_sum_ns: u64,
    // #825: per-kick `sendto` latency telemetry. Same wire shape
    // as `tx_submit_latency_*` — 16 log2 buckets via `Vec<u64>`,
    // plus count, sum-ns, and the EAGAIN/EWOULDBLOCK retry
    // tally (T1 ring-pushback signal per #819 §4.1). `default`
    // on each keeps the wire format additive: a pre-#825
    // helper that lacks these fields deserializes as empty/zero
    // rather than erroring.
    #[serde(rename = "tx_kick_latency_hist", default)]
    pub tx_kick_latency_hist: Vec<u64>,
    #[serde(rename = "tx_kick_latency_count", default)]
    pub tx_kick_latency_count: u64,
    #[serde(rename = "tx_kick_latency_sum_ns", default)]
    pub tx_kick_latency_sum_ns: u64,
    #[serde(rename = "tx_kick_retry_count", default)]
    pub tx_kick_retry_count: u64,
    #[serde(rename = "last_error", default)]
    pub last_error: String,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    pub last_change: Option<DateTime<Utc>>,
}

/// #802: focused per-binding ring-pressure snapshot surfaced on
/// `ProcessStatus::per_binding`.
///
/// Fields (see `docs/line-rate-investigation-plan.md` lines 703-724 for
/// the full operator rationale):
/// - `dbg_tx_ring_full`: times the XSK TX ring producer returned 0 slots.
/// - `dbg_sendto_enobufs`: kernel-side TX drop — TX kick returned ENOBUFS.
/// - `dbg_bound_pending_overflow` (#804): drops from the per-binding
///   `bound_pending` FIFO (`pending_tx_local` / `pending_tx_prepared`)
///   overflowing its soft cap. **This does not include CoS admission
///   overflow** — those are counted separately below.
/// - `dbg_cos_queue_overflow` (#804): binding-lifetime CoS queue drops.
///   This includes class-of-service queue admission rejects
///   (`enqueue_cos_item`) and reset-time CoS queue drains. The wire key is
///   historical. Pre-#804 builds conflated this with `bound_pending`
///   overflow under the old `dbg_pending_overflow` wire key; the counter was
///   split so operators can disambiguate shaping pressure from bound-pending
///   pressure.
/// - `rx_fill_ring_empty_descs`: kernel `xdp_statistics_v2` counter of
///   RX fill-ring starvation events.
/// - `outstanding_tx`: accept-proxy for `completion_reap_max_batch` per
///   the investigation plan's disposition. Snapshot of the worker's
///   current in-flight TX gauge at the last publish tick.
/// - `tx_errors`, `tx_submit_error_drops`,
///   `pending_tx_local_overflow_drops`: operator-facing aggregate TX
///   drop attribution, re-surfaced here so the triage view does not
///   require a second join against `BindingStatus`.
///
/// ## Wire-compat
///
/// The split is not wire-compatible on the daemon→operator boundary —
/// we removed the old `dbg_pending_overflow` wire key rather than keep
/// it aliased, because the whole point of the split is to stop
/// operators reading a conflated number. On the helper→daemon boundary
/// both new fields carry `serde(default)` so a helper that pre-dates
/// this split (no fields present) deserializes as zero rather than

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct BindingCountersSnapshot {
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    // #804: explicit rename matches the other fields on this struct
    // (defensive — default serde field→key mapping is identity, but
    // making it explicit here prevents a rename of the Rust field name
    // from silently renaming the wire key and breaking the Go
    // consumer).
    #[serde(rename = "ifindex", default)]
    pub ifindex: i32,
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "dbg_tx_ring_full", default)]
    pub dbg_tx_ring_full: u64,
    #[serde(rename = "dbg_sendto_enobufs", default)]
    pub dbg_sendto_enobufs: u64,
    // #804: split wire keys — `default` on both so a helper snapshot
    // that pre-dates the split (field absent on the wire) deserializes
    // as 0 rather than failing.
    #[serde(rename = "dbg_bound_pending_overflow", default)]
    pub dbg_bound_pending_overflow: u64,
    #[serde(rename = "dbg_cos_queue_overflow", default)]
    pub dbg_cos_queue_overflow: u64,
    #[serde(rename = "rx_fill_ring_empty_descs", default)]
    pub rx_fill_ring_empty_descs: u64,
    #[serde(rename = "outstanding_tx", default)]
    pub outstanding_tx: u32,
    /// #1241: last sampled AF_XDP TX completion-ring availability.
    #[serde(rename = "tx_completion_ring_available", default)]
    pub tx_completion_ring_available: u32,
    /// #1241: maximum sampled completion-ring availability in the last
    /// debug window.
    #[serde(rename = "tx_completion_ring_available_max", default)]
    pub tx_completion_ring_available_max: u32,
    /// #878: per-binding UMEM total frames. Mirror of BindingStatus.
    #[serde(rename = "umem_total_frames", default)]
    pub umem_total_frames: u32,
    /// #878: configured TX-ring depth. Mirror of BindingStatus.
    #[serde(rename = "tx_ring_capacity", default)]
    pub tx_ring_capacity: u32,
    /// #878: UMEM in-flight gauge. Mirror of BindingStatus.
    #[serde(rename = "umem_inflight_frames", default)]
    pub umem_inflight_frames: u32,
    #[serde(rename = "tx_errors", default)]
    pub tx_errors: u64,
    #[serde(rename = "tx_shared_recycle_unknown_slot_drops", default)]
    pub tx_shared_recycle_unknown_slot_drops: u64,
    #[serde(rename = "tx_submit_error_drops", default)]
    pub tx_submit_error_drops: u64,
    #[serde(rename = "pending_tx_local_overflow_drops", default)]
    pub pending_tx_local_overflow_drops: u64,
    #[serde(rename = "mirrored_packets", default)]
    pub mirrored_packets: u64,
    #[serde(rename = "mirrored_bytes", default)]
    pub mirrored_bytes: u64,
    #[serde(rename = "mirror_drops_no_frame", default)]
    pub mirror_drops_no_frame: u64,
    #[serde(rename = "mirror_drops_tx_frame_reserve", default)]
    pub mirror_drops_tx_frame_reserve: u64,
    #[serde(rename = "mirror_drops_no_binding", default)]
    pub mirror_drops_no_binding: u64,
    #[serde(rename = "mirror_drops_queue_full", default)]
    pub mirror_drops_queue_full: u64,
    #[serde(rename = "mirror_drops_queue_full_same_worker", default)]
    pub mirror_drops_queue_full_same_worker: u64,
    #[serde(rename = "mirror_drops_queue_full_cross_worker", default)]
    pub mirror_drops_queue_full_cross_worker: u64,
    // #812: TX submit→completion latency histogram, pulled through
    // from BindingStatus so step1-capture consumers can compute
    // per-queue latency distributions without a second join.
    // `default` keeps pre-#812 consumers parseable — the fields
    // simply deserialize as empty/zero.
    #[serde(rename = "tx_submit_latency_hist", default)]
    pub tx_submit_latency_hist: Vec<u64>,
    #[serde(rename = "tx_submit_latency_count", default)]
    pub tx_submit_latency_count: u64,
    #[serde(rename = "tx_submit_latency_sum_ns", default)]
    pub tx_submit_latency_sum_ns: u64,
    // #825: per-kick `sendto` latency telemetry, pulled through
    // from BindingStatus so step1-capture / P3 consumers can
    // compute per-queue kick-latency distributions without a
    // second join. `default` keeps pre-#825 helpers parseable —
    // the four fields simply deserialize as empty/zero.
    #[serde(rename = "tx_kick_latency_hist", default)]
    pub tx_kick_latency_hist: Vec<u64>,
    #[serde(rename = "tx_kick_latency_count", default)]
    pub tx_kick_latency_count: u64,
    #[serde(rename = "tx_kick_latency_sum_ns", default)]
    pub tx_kick_latency_sum_ns: u64,
    #[serde(rename = "tx_kick_retry_count", default)]
    pub tx_kick_retry_count: u64,
    /// #918: collision-driven subset of flow-cache evictions
    /// (full-set LRU displacement). Surfaces hot-set thrash so
    /// the post-merge acceptance gate (`collision_evictions /
    /// hits < 1 %` under 100E100M load) is observable from the
    /// standard binding-counter snapshot. `default` keeps pre-#918
    /// consumers parseable — the field simply deserializes as 0.
    #[serde(rename = "flow_cache_collision_evictions", default)]
    pub flow_cache_collision_evictions: u64,
    /// #1219: snapshot count of distinct active flows. See
    /// BindingStatus.active_flow_count for full doc.
    #[serde(rename = "active_flow_count", default)]
    pub active_flow_count: u32,
    /// Per-binding flow-cache capacity. Mirrors BindingStatus.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: u32,
    /// #941 Work item D / #943: V_min hard-cap activation count.
    /// Default keeps pre-#943 consumers parseable.
    #[serde(rename = "v_min_throttle_hard_cap_overrides", default)]
    pub v_min_throttle_hard_cap_overrides: u64,
    /// #943: regular V_min throttle decisions. Default keeps
    /// pre-#943 consumers parseable.
    #[serde(rename = "v_min_throttles", default)]
    pub v_min_throttles: u64,
}

// #812 (plan §3.5a / §6.1 test #8): compile-time assertion that
// `BindingCountersSnapshot` can cross the owner-worker →
// control-socket thread boundary without dragging a live borrow
// back into the per-worker sidecar. A `'static + Send` bound on a
// struct type with NO lifetime parameter is mechanically broken by
// any borrowed field added later (Rust's subtyping rule forces the
// struct to carry the reference's lifetime `'a`, and only `'a =
// 'static` satisfies the bound — which is not what a live
// per-worker snapshot would ever produce). `Send` additionally
// rejects `Rc<_>` / `Cell<_>` fields. The named const-item ties
// the failure message to this specific struct so a future
// `#[derive]` reshuffle that breaks Send/'static trips the build
// with a targeted error pointing HERE, not in some downstream
// generic.
//
// This is defense-in-depth on top of the JSON round-trip test
// (§6.1 test #4), which already mechanically requires
// DeserializeOwned.
const _ASSERT_BINDING_COUNTERS_SNAPSHOT_IS_OWNED_STATIC_SEND: () = {
    const fn require_static_send<T: 'static + Send>() {}
    require_static_send::<BindingCountersSnapshot>();
};

// #804: was `impl BindingCountersSnapshot { fn from_binding_status(...) }`.
// Switched to the idiomatic `From` impl so the projection composes with
// iterator adaptors (`.map(BindingCountersSnapshot::from)`) and any
// future `into()` callsites get the conversion for free.
impl From<&BindingStatus> for BindingCountersSnapshot {
    fn from(b: &BindingStatus) -> Self {
        Self {
            worker_id: b.worker_id,
            ifindex: b.ifindex,
            queue_id: b.queue_id,
            dbg_tx_ring_full: b.dbg_tx_ring_full,
            dbg_sendto_enobufs: b.dbg_sendto_enobufs,
            dbg_bound_pending_overflow: b.dbg_bound_pending_overflow,
            dbg_cos_queue_overflow: b.dbg_cos_queue_overflow,
            rx_fill_ring_empty_descs: b.rx_fill_ring_empty_descs,
            outstanding_tx: b.outstanding_tx,
            tx_completion_ring_available: b.tx_completion_ring_available,
            tx_completion_ring_available_max: b.tx_completion_ring_available_max,
            // #878: capacities + in-flight gauge flow into the
            // leaner snapshot so a step1-capture consumer reading
            // PerBinding (not the full BindingStatus) still sees
            // Buffer% inputs.
            umem_total_frames: b.umem_total_frames,
            tx_ring_capacity: b.tx_ring_capacity,
            umem_inflight_frames: b.umem_inflight_frames,
            tx_errors: b.tx_errors,
            tx_shared_recycle_unknown_slot_drops: b.tx_shared_recycle_unknown_slot_drops,
            tx_submit_error_drops: b.tx_submit_error_drops,
            pending_tx_local_overflow_drops: b.pending_tx_local_overflow_drops,
            mirrored_packets: b.mirrored_packets,
            mirrored_bytes: b.mirrored_bytes,
            mirror_drops_no_frame: b.mirror_drops_no_frame,
            mirror_drops_tx_frame_reserve: b.mirror_drops_tx_frame_reserve,
            mirror_drops_no_binding: b.mirror_drops_no_binding,
            mirror_drops_queue_full: b.mirror_drops_queue_full,
            mirror_drops_queue_full_same_worker: b.mirror_drops_queue_full_same_worker,
            mirror_drops_queue_full_cross_worker: b.mirror_drops_queue_full_cross_worker,
            // #812: clone the histogram Vec<u64> by value (owned
            // copy). Avoids any shared-reference aliasing against
            // the `BindingStatus` owner and satisfies the
            // `'static + Send` assert above.
            tx_submit_latency_hist: b.tx_submit_latency_hist.clone(),
            tx_submit_latency_count: b.tx_submit_latency_count,
            tx_submit_latency_sum_ns: b.tx_submit_latency_sum_ns,
            // #825: same discipline as #812 — owned clone of the
            // Vec<u64> and by-value scalars. The `'static + Send`
            // assert at :1446 covers these mechanically (no
            // borrowed fields; u64 and Vec<u64> are Send).
            tx_kick_latency_hist: b.tx_kick_latency_hist.clone(),
            tx_kick_latency_count: b.tx_kick_latency_count,
            tx_kick_latency_sum_ns: b.tx_kick_latency_sum_ns,
            tx_kick_retry_count: b.tx_kick_retry_count,
            // #918: flow under by-value u64; same Send/'static
            // discipline as the other counters.
            flow_cache_collision_evictions: b.flow_cache_collision_evictions,
            // #1219: active flow count snapshot. By-value u32.
            active_flow_count: b.active_flow_count,
            flow_cache_capacity: b.flow_cache_capacity,
            // #941 Work item D / #943: V_min counters propagate from
            // BindingDebugSnapshot through to the wire-visible
            // BindingCountersSnapshot. By-value u64, no Send concerns.
            v_min_throttle_hard_cap_overrides: b.v_min_throttle_hard_cap_overrides,
            v_min_throttles: b.v_min_throttles,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ExceptionStatus {
    pub timestamp: DateTime<Utc>,
    pub slot: u32,
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(rename = "worker_id")]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "ingress_ifindex", default)]
    pub ingress_ifindex: i32,
    pub reason: String,
    #[serde(rename = "packet_length", default)]
    pub packet_length: u32,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "config_generation", default)]
    pub config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "dst_ip", default)]
    pub dst_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    #[serde(rename = "dst_port", default)]
    pub dst_port: u16,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "rule_name", default)]
    pub rule_name: String,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionDeltaInfo {
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub slot: u32,
    #[serde(rename = "queue_id", default)]
    pub queue_id: u32,
    #[serde(rename = "worker_id", default)]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(default)]
    pub event: String,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "dst_ip", default)]
    pub dst_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    #[serde(rename = "dst_port", default)]
    pub dst_port: u16,
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    /// #919/#922: u16 zone-id mirrors. New peers populate these from
    /// `SessionMetadata`; the legacy string fields hold the resolved
    /// zone NAME (or empty when unknown). Older daemons that don't
    /// know about the IDs ignore the new fields and use the names.
    #[serde(rename = "ingress_zone_id", default)]
    pub ingress_zone_id: u16,
    #[serde(rename = "egress_zone_id", default)]
    pub egress_zone_id: u16,
    #[serde(rename = "owner_rg_id", default)]
    pub owner_rg_id: i32,
    #[serde(default)]
    pub disposition: String,
    #[serde(default)]
    pub origin: String,
    #[serde(rename = "egress_ifindex", default)]
    pub egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    pub tx_ifindex: i32,
    #[serde(rename = "tunnel_endpoint_id", default)]
    pub tunnel_endpoint_id: u16,
    #[serde(rename = "tx_vlan_id", default)]
    pub tx_vlan_id: u16,
    #[serde(rename = "next_hop", default)]
    pub next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    pub neighbor_mac: String,
    #[serde(rename = "src_mac", default)]
    pub src_mac: String,
    #[serde(rename = "nat_src_ip", default)]
    pub nat_src_ip: String,
    #[serde(rename = "nat_dst_ip", default)]
    pub nat_dst_ip: String,
    #[serde(rename = "nat_src_port", default)]
    pub nat_src_port: u16,
    #[serde(rename = "nat_dst_port", default)]
    pub nat_dst_port: u16,
    #[serde(rename = "fabric_redirect", default)]
    pub fabric_redirect: bool,
    #[serde(rename = "fabric_ingress", default)]
    pub fabric_ingress: bool,
}

