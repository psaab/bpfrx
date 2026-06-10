//! Control socket request/response wire shapes, `ProcessStatus`
//! (the per-tick status aggregate), and session-sync wire shapes.
//! Deepest module in the `protocol/` DAG: depends on every leaf
//! plus `snapshot` because `ProcessStatus` and `ControlRequest`
//! aggregate them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binding::{
    BindingCountersSnapshot, BindingStatus, ExceptionStatus, HAGroupStatus, QueueStatus,
    SessionDeltaInfo, WorkerRuntimeStatus,
};
use super::cos::{CoSActiveFlowCountStatus, CoSInterfaceStatus};
use super::nat::SourceNatPoolStatus;
use super::resolution::{FlowWorkerStatus, PacketResolution};
use super::security::{
    FirewallFilterTermCounterStatus, PolicyRuleCounterStatus, ThreeColorPolicerStatus,
};
use super::snapshot::{ConfigSnapshot, FabricSnapshot, NeighborSnapshot, UserspaceCapabilities};

pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 3;
pub(crate) const INJECT_PACKET_TUPLE_PROTOCOL_VERSION: i32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ControlRequest {
    #[serde(rename = "type")]
    pub request_type: String,
    #[serde(rename = "suppress_status", default)]
    pub suppress_status: bool,
    #[serde(default)]
    pub snapshot: Option<ConfigSnapshot>,
    #[serde(default)]
    pub forwarding: Option<ForwardingControlRequest>,
    #[serde(rename = "ha_state", default)]
    pub ha_state: Option<HAStateUpdateRequest>,
    #[serde(default)]
    pub queue: Option<QueueControlRequest>,
    #[serde(default)]
    pub binding: Option<BindingControlRequest>,
    #[serde(default)]
    pub packet: Option<InjectPacketRequest>,
    #[serde(rename = "session_sync", default)]
    pub session_sync: Option<SessionSyncRequest>,
    #[serde(rename = "session_deltas", default)]
    pub session_deltas: Option<SessionDeltaDrainRequest>,
    #[serde(rename = "session_export", default)]
    pub session_export: Option<SessionExportRequest>,
    #[serde(default)]
    pub neighbors: Option<Vec<NeighborSnapshot>>,
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    #[serde(rename = "neighbor_replace", default)]
    pub neighbor_replace: bool,
    #[serde(default)]
    pub fabrics: Option<Vec<FabricSnapshot>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ProcessStatus {
    pub pid: i32,
    #[serde(rename = "config_snapshot_protocol_version", default)]
    pub config_snapshot_protocol_version: i32,
    #[serde(rename = "inject_packet_tuple_protocol_version", default)]
    pub inject_packet_tuple_protocol_version: i32,
    #[serde(rename = "started_at")]
    pub started_at: DateTime<Utc>,
    #[serde(rename = "control_socket")]
    pub control_socket: String,
    #[serde(rename = "state_file")]
    pub state_file: String,
    pub workers: usize,
    #[serde(rename = "ring_entries")]
    pub ring_entries: usize,
    #[serde(rename = "helper_mode")]
    pub helper_mode: String,
    #[serde(rename = "io_uring_planned")]
    pub io_uring_planned: bool,
    #[serde(rename = "io_uring_active", default)]
    pub io_uring_active: bool,
    #[serde(rename = "io_uring_mode", default)]
    pub io_uring_mode: String,
    #[serde(rename = "io_uring_last_error", default)]
    pub io_uring_last_error: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "forwarding_armed", default)]
    pub forwarding_armed: bool,
    #[serde(default)]
    pub capabilities: UserspaceCapabilities,
    #[serde(rename = "last_snapshot_generation")]
    pub last_snapshot_generation: u64,
    #[serde(rename = "last_fib_generation", default)]
    pub last_fib_generation: u32,
    #[serde(rename = "last_snapshot_at", skip_serializing_if = "Option::is_none")]
    pub last_snapshot_at: Option<DateTime<Utc>>,
    #[serde(rename = "interface_addresses", default)]
    pub interface_addresses: usize,
    #[serde(rename = "neighbor_entries", default)]
    pub neighbor_entries: usize,
    /// Total entries installed in the Rust-owned worker session tables.
    /// Additive for mixed-version compatibility: older helpers omit it
    /// and Go treats zero max_sessions as "no denominator available".
    #[serde(rename = "session_table_entries", default)]
    pub session_table_entries: usize,
    /// Aggregate capacity of the Rust-owned worker session tables.
    #[serde(rename = "max_sessions", default)]
    pub max_sessions: usize,
    /// #1760: aggregate NAT reverse-key displacement events summed across
    /// the per-worker session tables — the latent 1:N collision (#1758)
    /// made observable. A near-precise upper bound on live collisions
    /// (counts displacement *events*, not distinct flow-pairs). Additive
    /// for mixed-version compatibility: older helpers omit it (defaults to
    /// 0). A nonzero value triggers the structural-fix research; this
    /// counter does NOT resolve #1760.
    #[serde(rename = "nat_reverse_key_collisions", default)]
    pub nat_reverse_key_collisions: u64,
    /// Aggregate per-binding flow-cache capacity across helper-published
    /// binding status rows. Zero means unavailable, not full.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: usize,
    /// Hard capacity for the dynamic neighbor cache. The current
    /// sharded map is growable, so zero intentionally suppresses
    /// utilization rows until Rust owns a real bounded denominator.
    #[serde(rename = "neighbor_cache_capacity", default)]
    pub neighbor_cache_capacity: usize,
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    #[serde(rename = "route_entries", default)]
    pub route_entries: usize,
    #[serde(rename = "worker_heartbeats", default)]
    pub worker_heartbeats: Vec<DateTime<Utc>>,
    /// #869: per-worker busy/idle runtime telemetry.  Empty on
    /// dataplanes that don't publish.  Additive / defaulted for
    /// backward compatibility with older daemon builds.
    #[serde(rename = "worker_runtime", default)]
    pub worker_runtime: Vec<WorkerRuntimeStatus>,
    // #710: cluster-wide aggregate of cross-worker CoS redirects that
    // could not locate a binding for their target egress on the landing
    // worker. Summed across all bindings in `refresh_status` — the
    // per-binding accounting is a mechanical choice (the increment
    // always lands on the landing worker's first binding), so the
    // per-binding view would be misleading as triage signal; the total
    // is the operator-facing number.
    #[serde(rename = "cos_no_owner_binding_drops_total", default)]
    pub cos_no_owner_binding_drops_total: u64,
    /// #1636 option C: proactive-neighbor-warm telemetry. `warm_drops`
    /// counts warm requests dropped because the bounded warmer queue was
    /// full (transient saturation under route churn); `warm_disconnected`
    /// counts requests dropped because the warmer worker thread died
    /// (fatal — warming disabled until restart). Both are the only
    /// operator-visible signal in production builds (debug-log off) and
    /// are surfaced as Prometheus counters by the Go collector. Additive
    /// / defaulted for backward compatibility with older daemons.
    #[serde(rename = "neighbor_warm_drops_total", default)]
    pub neighbor_warm_drops_total: u64,
    #[serde(rename = "neighbor_warm_disconnected_total", default)]
    pub neighbor_warm_disconnected_total: u64,
    /// #1782 cold-start capture instrumentation. Per-binding-summed
    /// count of neg-neigh-cache fast-fails (H1 amplifier signal) and of
    /// `pending_neigh` sibling drops where the `(egress_ifindex,
    /// next_hop)` key was already pending (H5 sibling-drop signal). Both
    /// are surfaced as Prometheus counters by the Go collector. Additive
    /// / defaulted for backward compatibility with older daemons.
    #[serde(rename = "neg_neigh_fast_fail_total", default)]
    pub neg_neigh_fast_fail_total: u64,
    #[serde(rename = "pending_neigh_duplicate_drops_total", default)]
    pub pending_neigh_duplicate_drops_total: u64,
    /// #1789: total failed USERSPACE_SESSIONS BPF-map publishes
    /// (per-binding worker-poll sites summed with the shared no-binding
    /// sites: HA upsert, session-glue worker publish, post-reconcile
    /// replay, activation/reverse prewarm). Always-on cause-side signal
    /// for rising XDP-shim NO_SESSION degraded-path fallbacks (session
    /// map at capacity, stale fd after reconcile). Surfaced as the
    /// Prometheus counter `xpf_userspace_session_publish_errors_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "session_publish_errors_total", default)]
    pub session_publish_errors_total: u64,
    /// #1807: total worker-command-queue poison recoveries (a thread
    /// panicked while holding a `Mutex<VecDeque<WorkerCommand>>`; the
    /// committed queue was recovered via into_inner and the poison
    /// cleared — uniform policy in afxdp/worker_queue.rs, extends
    /// #1790). Nonzero means a worker panic happened and the command
    /// queues kept flowing instead of going permanently deaf. Surfaced
    /// as the Prometheus counter
    /// `xpf_userspace_worker_command_queue_poison_recoveries_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "worker_command_queue_poison_recoveries", default)]
    pub worker_command_queue_poison_recoveries: u64,
    /// #1782 cold-start capture instrumentation. Debug dump of every key
    /// present in the userspace `dynamic_neighbors` mirror, rendered as
    /// `"ifindex ip"` strings. The capture harness greps this at the
    /// pre-connect t0' sample to confirm the data-path next-hop is ABSENT
    /// (the H2 fingerprint). Empty (and omitted) on dataplanes that don't
    /// publish, when the mirror is empty, OR — by default — because the dump
    /// is gated behind the `XPF_DEBUG_NEIGHBOR_KEYS` env var (off unless the
    /// helper is launched with it set for a capture). An empty field
    /// therefore does NOT imply the mirror is empty.
    #[serde(
        rename = "dynamic_neighbor_keys",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub dynamic_neighbor_keys: Vec<String>,
    /// #1769: on-demand neighbor-resolver telemetry. The resolver runs
    /// when a `MissingNeighbor` negative-cache fast-fail nudges a wedged
    /// dst: it issues a single-key RTM_GETNEIGH and either caches a
    /// confirmed lladdr (epoch-guarded) or probes to force kernel
    /// revalidation on a stale one. These are the operator-visible signal
    /// for the #1769 stuck-state (queue depth is a gauge; the rest are
    /// monotonic counters). Additive / defaulted for backward compat.
    #[serde(rename = "neighbor_resolver_queue_depth", default)]
    pub neighbor_resolver_queue_depth: u64,
    #[serde(rename = "neighbor_resolver_enqueue_drops_total", default)]
    pub neighbor_resolver_enqueue_drops_total: u64,
    #[serde(rename = "neighbor_resolver_disconnected_total", default)]
    pub neighbor_resolver_disconnected_total: u64,
    #[serde(rename = "neighbor_resolver_get_attempts_total", default)]
    pub neighbor_resolver_get_attempts_total: u64,
    #[serde(rename = "neighbor_resolver_get_resolved_total", default)]
    pub neighbor_resolver_get_resolved_total: u64,
    #[serde(rename = "neighbor_resolver_probe_on_stale_total", default)]
    pub neighbor_resolver_probe_on_stale_total: u64,
    #[serde(rename = "neighbor_resolver_get_failures_total", default)]
    pub neighbor_resolver_get_failures_total: u64,
    #[serde(rename = "neighbor_resolver_epoch_rejects_total", default)]
    pub neighbor_resolver_epoch_rejects_total: u64,
    /// #1772: neighbor/ARP resolution LATENCY telemetry. Complements the
    /// #1769 count-only resolver telemetry above with TIMING so the
    /// operator's intermittent slow-new-connection symptom is visible.
    /// Histogram buckets are NON-cumulative per-bucket sample counts on a
    /// 16-bucket pow2-ns ladder (bucket `i` upper bound `2^(16+i)` ns;
    /// bucket 15 = `+Inf`; the 3 s blackout class lands in bucket 15).
    /// Additive / defaulted for backward compat.
    /// pending_neigh dwell histogram (`now_ns - queued_ns` at resolve).
    #[serde(rename = "neighbor_pending_dwell_buckets", default)]
    pub neighbor_pending_dwell_buckets: Vec<u64>,
    #[serde(rename = "neighbor_pending_dwell_sum_ns", default)]
    pub neighbor_pending_dwell_sum_ns: u64,
    #[serde(rename = "neighbor_pending_dwell_count", default)]
    pub neighbor_pending_dwell_count: u64,
    /// Resolver single-key RTM_GETNEIGH round-trip-time histogram.
    #[serde(rename = "neighbor_resolver_get_rtt_buckets", default)]
    pub neighbor_resolver_get_rtt_buckets: Vec<u64>,
    #[serde(rename = "neighbor_resolver_get_rtt_sum_ns", default)]
    pub neighbor_resolver_get_rtt_sum_ns: u64,
    #[serde(rename = "neighbor_resolver_get_rtt_count", default)]
    pub neighbor_resolver_get_rtt_count: u64,
    /// pending_neigh timeout-drops + queue-depth high-water mark.
    #[serde(rename = "neighbor_pending_timeout_drops_total", default)]
    pub neighbor_pending_timeout_drops_total: u64,
    #[serde(rename = "neighbor_pending_max_depth", default)]
    pub neighbor_pending_max_depth: u64,
    /// #1771 §2.6: per-key resolver + §2.5 ENOBUFS-re-dump telemetry.
    /// `get_backoff_attempts` is the subset of resolver GET attempts
    /// that were backoff RETRIES (key re-admitted after the per-key
    /// rate-limit window). The `netlink_*` counters instrument the
    /// monitor thread's lost-notification self-heal: ENOBUFS receives,
    /// throttled upsert-only re-dumps issued, and dynamic-neighbor
    /// entries actually (re)added by re-dump replies. The two gauges are
    /// per-binding sums published at the ~65ms debug tick: distinct
    /// unresolved next-hop keys buffered in pending_neigh, and keys held
    /// in the negative caches (lazy-TTL upper bound). All additive /
    /// defaulted for backward compatibility.
    #[serde(rename = "neighbor_resolver_get_backoff_attempts_total", default)]
    pub neighbor_resolver_get_backoff_attempts_total: u64,
    #[serde(rename = "neighbor_netlink_enobufs_total", default)]
    pub neighbor_netlink_enobufs_total: u64,
    #[serde(rename = "neighbor_netlink_redumps_total", default)]
    pub neighbor_netlink_redumps_total: u64,
    #[serde(rename = "neighbor_netlink_redump_upserts_total", default)]
    pub neighbor_netlink_redump_upserts_total: u64,
    #[serde(rename = "neighbor_pending_keys", default)]
    pub neighbor_pending_keys: u64,
    #[serde(rename = "neg_neigh_keys", default)]
    pub neg_neigh_keys: u64,
    /// #802: focused per-binding ring-pressure view. Projected from the
    /// same `BindingLiveState` atomics that back `Self::bindings` — a
    /// compact snapshot of the counters an operator looks at first when
    /// triaging XSK ring saturation (TX full, sendto ENOBUFS, pending-
    /// overflow, fill-ring empty descs, outstanding-tx gauge). Keeping
    /// it as a parallel field (rather than only embedded in
    /// `bindings[].*`) lets the daemon pull just the triage counters on
    /// its poll path without deserializing every field on `BindingStatus`.
    #[serde(rename = "per_binding", default, skip_serializing_if = "Vec::is_empty")]
    pub per_binding: Vec<BindingCountersSnapshot>,
    /// #1249: low-frequency debug snapshot mapping active flow-cache
    /// entries to the worker/RX queue that currently owns them. This
    /// is a diagnostic/status surface, not a scheduler input; workers
    /// publish bounded owned snapshots from their existing debug tick.
    #[serde(rename = "flow_worker_map", default)]
    pub flow_worker_map: Vec<FlowWorkerStatus>,
    #[serde(rename = "flow_worker_map_truncated", default)]
    pub flow_worker_map_truncated: bool,
    /// #1248: class-specific active-flow distribution for CoS
    /// fairness. Aggregated as `(ifindex, queue_id, worker_id) ->
    /// active distinct cached flows` from the same worker debug tick
    /// that publishes `active_flow_count`.
    #[serde(rename = "cos_active_flow_counts", default)]
    pub cos_active_flow_counts: Vec<CoSActiveFlowCountStatus>,
    #[serde(rename = "cos_active_flow_counts_truncated", default)]
    pub cos_active_flow_counts_truncated: bool,
    #[serde(rename = "ha_groups", default)]
    pub ha_groups: Vec<HAGroupStatus>,
    #[serde(default)]
    pub fabrics: Vec<FabricSnapshot>,
    #[serde(default)]
    pub queues: Vec<QueueStatus>,
    #[serde(default)]
    pub bindings: Vec<BindingStatus>,
    #[serde(rename = "recent_session_deltas", default)]
    pub recent_session_deltas: Vec<SessionDeltaInfo>,
    #[serde(rename = "recent_exceptions", default)]
    pub recent_exceptions: Vec<ExceptionStatus>,
    #[serde(rename = "cos_interfaces", default)]
    pub cos_interfaces: Vec<CoSInterfaceStatus>,
    #[serde(rename = "policy_rule_counters", default)]
    pub policy_rule_counters: Vec<PolicyRuleCounterStatus>,
    #[serde(rename = "filter_term_counters", default)]
    pub filter_term_counters: Vec<FirewallFilterTermCounterStatus>,
    #[serde(rename = "three_color_policer_counters", default)]
    pub three_color_policer_counters: Vec<ThreeColorPolicerStatus>,
    #[serde(rename = "source_nat_pools", default)]
    pub source_nat_pools: Vec<SourceNatPoolStatus>,
    #[serde(rename = "last_resolution", skip_serializing_if = "Option::is_none")]
    pub last_resolution: Option<PacketResolution>,
    #[serde(rename = "slow_path", default)]
    pub slow_path: SlowPathStatus,
    #[serde(rename = "debug_worker_threads", default)]
    pub debug_worker_threads: usize,
    #[serde(rename = "debug_identity_slots", default)]
    pub debug_identity_slots: usize,
    #[serde(rename = "debug_live_slots", default)]
    pub debug_live_slots: usize,
    #[serde(rename = "debug_planned_workers", default)]
    pub debug_planned_workers: usize,
    #[serde(rename = "debug_planned_bindings", default)]
    pub debug_planned_bindings: usize,
    #[serde(rename = "debug_reconcile_calls", default)]
    pub debug_reconcile_calls: u64,
    #[serde(rename = "debug_reconcile_stage", default)]
    pub debug_reconcile_stage: String,
    #[serde(rename = "event_stream_connected", default)]
    pub event_stream_connected: bool,
    #[serde(rename = "event_stream_seq", default)]
    pub event_stream_seq: u64,
    #[serde(rename = "event_stream_acked", default)]
    pub event_stream_acked: u64,
    #[serde(rename = "event_stream_sent", default)]
    pub event_stream_sent: u64,
    #[serde(rename = "event_stream_dropped", default)]
    pub event_stream_dropped: u64,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    #[serde(rename = "last_cache_flush_at", default)]
    pub last_cache_flush_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SlowPathStatus {
    #[serde(default)]
    pub active: bool,
    #[serde(rename = "device_name", default)]
    pub device_name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "last_error", default)]
    pub last_error: String,
    #[serde(rename = "queued_packets", default)]
    pub queued_packets: u64,
    #[serde(rename = "injected_packets", default)]
    pub injected_packets: u64,
    #[serde(rename = "injected_bytes", default)]
    pub injected_bytes: u64,
    #[serde(rename = "dropped_packets", default)]
    pub dropped_packets: u64,
    #[serde(rename = "dropped_bytes", default)]
    pub dropped_bytes: u64,
    #[serde(rename = "rate_limited_packets", default)]
    pub rate_limited_packets: u64,
    #[serde(rename = "queue_full_packets", default)]
    pub queue_full_packets: u64,
    #[serde(rename = "write_errors", default)]
    pub write_errors: u64,
}

impl From<crate::slowpath::SlowPathStatus> for SlowPathStatus {
    fn from(value: crate::slowpath::SlowPathStatus) -> Self {
        Self {
            active: value.active,
            device_name: value.device_name,
            mode: value.mode,
            last_error: value.last_error,
            queued_packets: value.queued_packets,
            injected_packets: value.injected_packets,
            injected_bytes: value.injected_bytes,
            dropped_packets: value.dropped_packets,
            dropped_bytes: value.dropped_bytes,
            rate_limited_packets: value.rate_limited_packets,
            queue_full_packets: value.queue_full_packets,
            write_errors: value.write_errors,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ControlResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ProcessStatus>,
    #[serde(
        rename = "session_deltas",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_deltas: Vec<SessionDeltaInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ForwardingControlRequest {
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct HAStateUpdateRequest {
    #[serde(default)]
    pub groups: Vec<HAGroupStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct QueueControlRequest {
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct BindingControlRequest {
    pub slot: u32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct InjectPacketRequest {
    pub slot: u32,
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
    #[serde(rename = "metadata_valid", default)]
    pub metadata_valid: bool,
    #[serde(rename = "destination_ip", default)]
    pub destination_ip: String,
    #[serde(rename = "emit_on_wire", default)]
    pub emit_on_wire: bool,
    #[serde(rename = "tuple_metadata_version", default)]
    pub tuple_metadata_version: i32,
    #[serde(rename = "source_ip", default)]
    pub source_ip: String,
    #[serde(rename = "source_port", default)]
    pub source_port: Option<u16>,
    #[serde(rename = "destination_port", default)]
    pub destination_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionSyncRequest {
    #[serde(default)]
    pub operation: String,
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
    /// Legacy zone-name field. New peers populate `ingress_zone_id`
    /// instead and may leave this empty; preserved for one-release
    /// peer-compat window.
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    /// #919: zone IDs preferred over names. Receiving side prefers
    /// these when nonzero; falls back to name lookup via
    /// `zone_name_to_id` otherwise.
    #[serde(rename = "ingress_zone_id", default)]
    pub ingress_zone_id: u16,
    #[serde(rename = "egress_zone_id", default)]
    pub egress_zone_id: u16,
    #[serde(rename = "owner_rg_id", default)]
    pub owner_rg_id: i32,
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
    #[serde(rename = "fabric_ingress", default)]
    pub fabric_ingress: bool,
    #[serde(rename = "is_reverse", default)]
    pub is_reverse: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionDeltaDrainRequest {
    #[serde(default)]
    pub max: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionExportRequest {
    #[serde(rename = "owner_rgs", default)]
    pub owner_rgs: Vec<i32>,
    #[serde(default)]
    pub max: u32,
}
