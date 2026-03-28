mod afxdp;
mod filter;
mod flowexport;
mod nat;
mod nat64;
mod nptv6;
mod policy;
mod prefix;
mod screen;
mod session;
mod slowpath;
mod state_writer;
#[allow(dead_code)]
mod xsk_ffi;

use afxdp::SyncedSessionEntry;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use state_writer::StateWriter;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SnapshotSummary {
    #[serde(rename = "host_name")]
    host_name: String,
    #[serde(rename = "dataplane_type")]
    dataplane_type: String,
    #[serde(rename = "interface_count")]
    interface_count: usize,
    #[serde(rename = "zone_count")]
    zone_count: usize,
    #[serde(rename = "policy_count")]
    policy_count: usize,
    #[serde(rename = "scheduler_count")]
    scheduler_count: usize,
    #[serde(rename = "ha_enabled")]
    ha_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct InterfaceSnapshot {
    name: String,
    #[serde(default)]
    zone: String,
    #[serde(rename = "linux_name", default)]
    linux_name: String,
    #[serde(rename = "parent_linux_name", default)]
    parent_linux_name: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(rename = "parent_ifindex", default)]
    parent_ifindex: i32,
    #[serde(rename = "rx_queues", default)]
    rx_queues: usize,
    #[serde(rename = "vlan_id", default)]
    vlan_id: i32,
    #[serde(rename = "local_fabric_member", default)]
    local_fabric_member: String,
    #[serde(rename = "redundancy_group", default)]
    redundancy_group: i32,
    #[serde(rename = "unit_count", default)]
    unit_count: usize,
    #[serde(default)]
    tunnel: bool,
    #[serde(default)]
    mtu: i32,
    #[serde(rename = "hardware_addr", default)]
    hardware_addr: String,
    #[serde(default)]
    addresses: Vec<InterfaceAddressSnapshot>,
    #[serde(rename = "filter_input_v4", default)]
    filter_input_v4: String,
    #[serde(rename = "filter_input_v6", default)]
    filter_input_v6: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct InterfaceAddressSnapshot {
    family: String,
    address: String,
    #[serde(default)]
    scope: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct RouteSnapshot {
    table: String,
    family: String,
    destination: String,
    #[serde(rename = "next_hops", default)]
    next_hops: Vec<String>,
    #[serde(default)]
    discard: bool,
    #[serde(rename = "next_table", default)]
    next_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FlowSnapshot {
    #[serde(rename = "allow_dns_reply", default)]
    allow_dns_reply: bool,
    #[serde(rename = "allow_embedded_icmp", default)]
    allow_embedded_icmp: bool,
    #[serde(rename = "tcp_mss_all_tcp", default)]
    tcp_mss_all_tcp: u16,
    #[serde(rename = "tcp_mss_ipsec_vpn", default)]
    tcp_mss_ipsec_vpn: u16,
    #[serde(rename = "tcp_mss_gre_in", default)]
    tcp_mss_gre_in: u16,
    #[serde(rename = "tcp_mss_gre_out", default)]
    tcp_mss_gre_out: u16,
    #[serde(rename = "tcp_session_timeout", default)]
    tcp_session_timeout: u64,
    #[serde(rename = "udp_session_timeout", default)]
    udp_session_timeout: u64,
    #[serde(rename = "icmp_session_timeout", default)]
    icmp_session_timeout: u64,
    #[serde(rename = "gre_acceleration", default)]
    gre_acceleration: bool,
    #[serde(rename = "lo0_filter_input_v4", default)]
    lo0_filter_input_v4: String,
    #[serde(rename = "lo0_filter_input_v6", default)]
    lo0_filter_input_v6: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct NeighborSnapshot {
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    family: String,
    ip: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    router: bool,
    #[serde(rename = "link_local", default)]
    link_local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ConfigSnapshot {
    version: i32,
    generation: u64,
    #[serde(rename = "fib_generation", default)]
    fib_generation: u32,
    #[serde(rename = "generated_at")]
    generated_at: DateTime<Utc>,
    summary: SnapshotSummary,
    #[serde(default)]
    capabilities: UserspaceCapabilities,
    #[serde(rename = "map_pins", default)]
    map_pins: MapPins,
    #[serde(default)]
    zones: Vec<ZoneSnapshot>,
    #[serde(default)]
    interfaces: Vec<InterfaceSnapshot>,
    #[serde(default)]
    fabrics: Vec<FabricSnapshot>,
    #[serde(rename = "tunnel_endpoints", default)]
    tunnel_endpoints: Vec<TunnelEndpointSnapshot>,
    #[serde(default)]
    neighbors: Vec<NeighborSnapshot>,
    #[serde(default)]
    routes: Vec<RouteSnapshot>,
    #[serde(default)]
    flow: FlowSnapshot,
    #[serde(rename = "default_policy", default)]
    default_policy: String,
    #[serde(default)]
    policies: Vec<PolicyRuleSnapshot>,
    #[serde(rename = "source_nat_rules", default)]
    source_nat_rules: Vec<SourceNATRuleSnapshot>,
    #[serde(rename = "static_nat_rules", default)]
    static_nat_rules: Vec<StaticNATRuleSnapshot>,
    #[serde(rename = "destination_nat_rules", default)]
    destination_nat_rules: Vec<DestinationNATRuleSnapshot>,
    #[serde(rename = "nat64_rules", default)]
    nat64_rules: Vec<NAT64RuleSnapshot>,
    #[serde(rename = "nptv6_rules", default)]
    nptv6_rules: Vec<Nptv6RuleSnapshot>,
    #[serde(default)]
    screens: Vec<ScreenProfileSnapshot>,
    #[serde(default)]
    filters: Vec<FirewallFilterSnapshot>,
    #[serde(default)]
    policers: Vec<PolicerSnapshot>,
    #[serde(rename = "flow_export", default)]
    flow_export: Option<FlowExportSnapshot>,
    #[serde(default)]
    userspace: serde_json::Value,
    #[serde(default)]
    config: serde_json::Value,
    #[serde(rename = "defer_workers", default)]
    defer_workers: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ZoneSnapshot {
    name: String,
    #[serde(default)]
    id: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FabricSnapshot {
    name: String,
    #[serde(rename = "parent_interface", default)]
    parent_interface: String,
    #[serde(rename = "parent_linux_name", default)]
    parent_linux_name: String,
    #[serde(rename = "parent_ifindex", default)]
    parent_ifindex: i32,
    #[serde(rename = "overlay_linux_name", default)]
    overlay_linux_name: String,
    #[serde(rename = "overlay_ifindex", default)]
    overlay_ifindex: i32,
    #[serde(rename = "rx_queues", default)]
    rx_queues: usize,
    #[serde(rename = "peer_address", default)]
    peer_address: String,
    #[serde(rename = "local_mac", default)]
    local_mac: String,
    #[serde(rename = "peer_mac", default)]
    peer_mac: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct TunnelEndpointSnapshot {
    #[serde(default)]
    id: u16,
    #[serde(default)]
    interface: String,
    #[serde(rename = "linux_name", default)]
    linux_name: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(default)]
    zone: String,
    #[serde(rename = "redundancy_group", default)]
    redundancy_group: i32,
    #[serde(default)]
    mtu: i32,
    #[serde(default)]
    mode: String,
    #[serde(rename = "outer_family", default)]
    outer_family: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    destination: String,
    #[serde(default)]
    key: u32,
    #[serde(default)]
    ttl: i32,
    #[serde(rename = "transport_table", default)]
    transport_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SourceNATRuleSnapshot {
    name: String,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "to_zone", default)]
    to_zone: String,
    #[serde(rename = "source_addresses", default)]
    source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    destination_addresses: Vec<String>,
    #[serde(rename = "interface_mode", default)]
    interface_mode: bool,
    #[serde(default)]
    off: bool,
    #[serde(rename = "pool_name", default)]
    pool_name: String,
    #[serde(rename = "pool_addresses", default)]
    pool_addresses: Vec<String>,
    #[serde(rename = "port_low", default)]
    port_low: u16,
    #[serde(rename = "port_high", default)]
    port_high: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct StaticNATRuleSnapshot {
    name: String,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "external_ip", default)]
    external_ip: String,
    #[serde(rename = "internal_ip", default)]
    internal_ip: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct DestinationNATRuleSnapshot {
    name: String,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "destination_address", default)]
    destination_address: String,
    #[serde(rename = "destination_port", default)]
    destination_port: u16,
    #[serde(default)]
    protocol: String,
    #[serde(rename = "pool_address", default)]
    pool_address: String,
    #[serde(rename = "pool_port", default)]
    pool_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct NAT64RuleSnapshot {
    name: String,
    #[serde(default)]
    prefix: String,
    #[serde(rename = "pool_addresses", default)]
    pool_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Nptv6RuleSnapshot {
    name: String,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "internal_prefix", default)]
    internal_prefix: String,
    #[serde(rename = "external_prefix", default)]
    external_prefix: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ScreenProfileSnapshot {
    zone: String,
    #[serde(default)]
    land: bool,
    #[serde(rename = "syn_fin", default)]
    syn_fin: bool,
    #[serde(rename = "tcp_no_flag", default)]
    tcp_no_flag: bool,
    #[serde(rename = "fin_no_ack", default)]
    fin_no_ack: bool,
    #[serde(default)]
    winnuke: bool,
    #[serde(rename = "ping_death", default)]
    ping_death: bool,
    #[serde(default)]
    teardrop: bool,
    #[serde(rename = "icmp_fragment", default)]
    icmp_fragment: bool,
    #[serde(rename = "source_route", default)]
    source_route: bool,
    #[serde(rename = "icmp_flood_threshold", default)]
    icmp_flood_threshold: u32,
    #[serde(rename = "udp_flood_threshold", default)]
    udp_flood_threshold: u32,
    #[serde(rename = "syn_flood_threshold", default)]
    syn_flood_threshold: u32,
    #[serde(rename = "session_limit_src", default)]
    session_limit_src: u32,
    #[serde(rename = "session_limit_dst", default)]
    session_limit_dst: u32,
    #[serde(rename = "port_scan_threshold", default)]
    port_scan_threshold: u32,
    #[serde(rename = "ip_sweep_threshold", default)]
    ip_sweep_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FirewallFilterSnapshot {
    name: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    terms: Vec<FirewallTermSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FirewallTermSnapshot {
    name: String,
    #[serde(rename = "source_addresses", default)]
    source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    destination_addresses: Vec<String>,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(rename = "source_ports", default)]
    source_ports: Vec<String>,
    #[serde(rename = "destination_ports", default)]
    destination_ports: Vec<String>,
    #[serde(rename = "dscp_values", default)]
    dscp_values: Vec<u8>,
    #[serde(default)]
    action: String,
    #[serde(default)]
    count: String,
    #[serde(default)]
    log: bool,
    #[serde(default)]
    policer: String,
    #[serde(rename = "routing_instance", default)]
    routing_instance: String,
    #[serde(rename = "forwarding_class", default)]
    forwarding_class: String,
    #[serde(rename = "dscp_rewrite", default)]
    dscp_rewrite: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PolicerSnapshot {
    name: String,
    #[serde(rename = "bandwidth_bps", default)]
    bandwidth_bps: u64,
    #[serde(rename = "burst_bytes", default)]
    burst_bytes: u64,
    #[serde(rename = "discard_excess", default)]
    discard_excess: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct FlowExportSnapshot {
    #[serde(rename = "collector_address", default)]
    collector_address: String,
    #[serde(rename = "collector_port", default)]
    collector_port: u16,
    #[serde(rename = "sampling_rate", default)]
    sampling_rate: u32,
    #[serde(rename = "active_timeout", default)]
    active_timeout: u32,
    #[serde(rename = "inactive_timeout", default)]
    inactive_timeout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PolicyRuleSnapshot {
    name: String,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "to_zone", default)]
    to_zone: String,
    #[serde(rename = "source_addresses", default)]
    source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    destination_addresses: Vec<String>,
    #[serde(default)]
    applications: Vec<String>,
    #[serde(rename = "application_terms", default)]
    application_terms: Vec<PolicyApplicationSnapshot>,
    #[serde(default)]
    action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PolicyApplicationSnapshot {
    name: String,
    #[serde(default)]
    protocol: String,
    #[serde(rename = "source_port", default)]
    source_port: String,
    #[serde(rename = "destination_port", default)]
    destination_port: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct MapPins {
    #[serde(default)]
    ctrl: String,
    #[serde(default)]
    bindings: String,
    #[serde(default)]
    heartbeat: String,
    #[serde(default)]
    xsk: String,
    #[serde(rename = "local_v4", default)]
    local_v4: String,
    #[serde(rename = "local_v6", default)]
    local_v6: String,
    #[serde(default)]
    sessions: String,
    #[serde(rename = "dnat_table", default)]
    dnat_table: String,
    #[serde(rename = "dnat_table_v6", default)]
    dnat_table_v6: String,
    #[serde(default)]
    trace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct UserspaceCapabilities {
    #[serde(rename = "forwarding_supported", default)]
    forwarding_supported: bool,
    #[serde(rename = "unsupported_reasons", default)]
    unsupported_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ControlRequest {
    #[serde(rename = "type")]
    request_type: String,
    #[serde(rename = "suppress_status", default)]
    suppress_status: bool,
    #[serde(default)]
    snapshot: Option<ConfigSnapshot>,
    #[serde(default)]
    forwarding: Option<ForwardingControlRequest>,
    #[serde(rename = "ha_state", default)]
    ha_state: Option<HAStateUpdateRequest>,
    #[serde(rename = "ha_demotion_prepare", default)]
    ha_demotion_prepare: Option<HADemotionPrepareRequest>,
    #[serde(default)]
    queue: Option<QueueControlRequest>,
    #[serde(default)]
    binding: Option<BindingControlRequest>,
    #[serde(default)]
    packet: Option<InjectPacketRequest>,
    #[serde(rename = "session_sync", default)]
    session_sync: Option<SessionSyncRequest>,
    #[serde(rename = "session_deltas", default)]
    session_deltas: Option<SessionDeltaDrainRequest>,
    #[serde(rename = "session_export", default)]
    session_export: Option<SessionExportRequest>,
    #[serde(default)]
    neighbors: Option<Vec<NeighborSnapshot>>,
    #[serde(rename = "neighbor_generation", default)]
    neighbor_generation: u64,
    #[serde(rename = "neighbor_replace", default)]
    neighbor_replace: bool,
    #[serde(default)]
    fabrics: Option<Vec<FabricSnapshot>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ProcessStatus {
    pid: i32,
    #[serde(rename = "started_at")]
    started_at: DateTime<Utc>,
    #[serde(rename = "control_socket")]
    control_socket: String,
    #[serde(rename = "state_file")]
    state_file: String,
    workers: usize,
    #[serde(rename = "ring_entries")]
    ring_entries: usize,
    #[serde(rename = "helper_mode")]
    helper_mode: String,
    #[serde(rename = "io_uring_planned")]
    io_uring_planned: bool,
    #[serde(rename = "io_uring_active", default)]
    io_uring_active: bool,
    #[serde(rename = "io_uring_mode", default)]
    io_uring_mode: String,
    #[serde(rename = "io_uring_last_error", default)]
    io_uring_last_error: String,
    #[serde(default)]
    enabled: bool,
    #[serde(rename = "forwarding_armed", default)]
    forwarding_armed: bool,
    #[serde(default)]
    capabilities: UserspaceCapabilities,
    #[serde(rename = "last_snapshot_generation")]
    last_snapshot_generation: u64,
    #[serde(rename = "last_fib_generation", default)]
    last_fib_generation: u32,
    #[serde(rename = "last_snapshot_at", skip_serializing_if = "Option::is_none")]
    last_snapshot_at: Option<DateTime<Utc>>,
    #[serde(rename = "interface_addresses", default)]
    interface_addresses: usize,
    #[serde(rename = "neighbor_entries", default)]
    neighbor_entries: usize,
    #[serde(rename = "neighbor_generation", default)]
    neighbor_generation: u64,
    #[serde(rename = "route_entries", default)]
    route_entries: usize,
    #[serde(rename = "worker_heartbeats", default)]
    worker_heartbeats: Vec<DateTime<Utc>>,
    #[serde(rename = "ha_groups", default)]
    ha_groups: Vec<HAGroupStatus>,
    #[serde(default)]
    fabrics: Vec<FabricSnapshot>,
    #[serde(default)]
    queues: Vec<QueueStatus>,
    #[serde(default)]
    bindings: Vec<BindingStatus>,
    #[serde(rename = "recent_session_deltas", default)]
    recent_session_deltas: Vec<SessionDeltaInfo>,
    #[serde(rename = "recent_exceptions", default)]
    recent_exceptions: Vec<ExceptionStatus>,
    #[serde(rename = "last_resolution", skip_serializing_if = "Option::is_none")]
    last_resolution: Option<PacketResolution>,
    #[serde(rename = "slow_path", default)]
    slow_path: SlowPathStatus,
    #[serde(rename = "debug_worker_threads", default)]
    debug_worker_threads: usize,
    #[serde(rename = "debug_identity_slots", default)]
    debug_identity_slots: usize,
    #[serde(rename = "debug_live_slots", default)]
    debug_live_slots: usize,
    #[serde(rename = "debug_planned_workers", default)]
    debug_planned_workers: usize,
    #[serde(rename = "debug_planned_bindings", default)]
    debug_planned_bindings: usize,
    #[serde(rename = "debug_reconcile_calls", default)]
    debug_reconcile_calls: u64,
    #[serde(rename = "debug_reconcile_stage", default)]
    debug_reconcile_stage: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SlowPathStatus {
    #[serde(default)]
    active: bool,
    #[serde(rename = "device_name", default)]
    device_name: String,
    #[serde(default)]
    mode: String,
    #[serde(rename = "last_error", default)]
    last_error: String,
    #[serde(rename = "queued_packets", default)]
    queued_packets: u64,
    #[serde(rename = "injected_packets", default)]
    injected_packets: u64,
    #[serde(rename = "injected_bytes", default)]
    injected_bytes: u64,
    #[serde(rename = "dropped_packets", default)]
    dropped_packets: u64,
    #[serde(rename = "dropped_bytes", default)]
    dropped_bytes: u64,
    #[serde(rename = "rate_limited_packets", default)]
    rate_limited_packets: u64,
    #[serde(rename = "queue_full_packets", default)]
    queue_full_packets: u64,
    #[serde(rename = "write_errors", default)]
    write_errors: u64,
}

impl From<slowpath::SlowPathStatus> for SlowPathStatus {
    fn from(value: slowpath::SlowPathStatus) -> Self {
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
struct ControlResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ProcessStatus>,
    #[serde(
        rename = "session_deltas",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    session_deltas: Vec<SessionDeltaInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PacketResolution {
    disposition: String,
    #[serde(rename = "local_ifindex", default)]
    local_ifindex: i32,
    #[serde(rename = "egress_ifindex", default)]
    egress_ifindex: i32,
    #[serde(rename = "ingress_ifindex", default)]
    ingress_ifindex: i32,
    #[serde(rename = "next_hop", default)]
    next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    neighbor_mac: String,
    #[serde(rename = "src_ip", default)]
    src_ip: String,
    #[serde(rename = "dst_ip", default)]
    dst_ip: String,
    #[serde(rename = "src_port", default)]
    src_port: u16,
    #[serde(rename = "dst_port", default)]
    dst_port: u16,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "to_zone", default)]
    to_zone: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ForwardingControlRequest {
    #[serde(default)]
    armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct HAStateUpdateRequest {
    #[serde(default)]
    groups: Vec<HAGroupStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct HADemotionPrepareRequest {
    #[serde(default)]
    groups: Vec<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct HAGroupStatus {
    #[serde(rename = "rg_id", default)]
    rg_id: i32,
    #[serde(default)]
    active: bool,
    #[serde(rename = "watchdog_timestamp", default)]
    watchdog_timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct QueueControlRequest {
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct BindingControlRequest {
    slot: u32,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct QueueStatus {
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(rename = "worker_id")]
    worker_id: u32,
    #[serde(default)]
    interfaces: Vec<String>,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    armed: bool,
    #[serde(default)]
    ready: bool,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    last_change: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct BindingStatus {
    slot: u32,
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(rename = "worker_id")]
    worker_id: u32,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(default)]
    registered: bool,
    #[serde(default)]
    armed: bool,
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    bound: bool,
    #[serde(rename = "xsk_registered", default)]
    xsk_registered: bool,
    #[serde(rename = "xsk_bind_mode", default)]
    xsk_bind_mode: String,
    #[serde(rename = "zero_copy", default)]
    zero_copy: bool,
    #[serde(rename = "socket_fd", default)]
    socket_fd: i32,
    #[serde(rename = "rx_packets", default)]
    rx_packets: u64,
    #[serde(rename = "rx_bytes", default)]
    rx_bytes: u64,
    #[serde(rename = "rx_batches", default)]
    rx_batches: u64,
    #[serde(rename = "rx_wakeups", default)]
    rx_wakeups: u64,
    #[serde(rename = "metadata_packets", default)]
    metadata_packets: u64,
    #[serde(rename = "metadata_errors", default)]
    metadata_errors: u64,
    #[serde(rename = "validated_packets", default)]
    validated_packets: u64,
    #[serde(rename = "validated_bytes", default)]
    validated_bytes: u64,
    #[serde(rename = "local_delivery_packets", default)]
    local_delivery_packets: u64,
    #[serde(rename = "forward_candidate_packets", default)]
    forward_candidate_packets: u64,
    #[serde(rename = "route_miss_packets", default)]
    route_miss_packets: u64,
    #[serde(rename = "neighbor_miss_packets", default)]
    neighbor_miss_packets: u64,
    #[serde(rename = "discard_route_packets", default)]
    discard_route_packets: u64,
    #[serde(rename = "next_table_packets", default)]
    next_table_packets: u64,
    #[serde(rename = "exception_packets", default)]
    exception_packets: u64,
    #[serde(rename = "config_gen_mismatches", default)]
    config_gen_mismatches: u64,
    #[serde(rename = "fib_gen_mismatches", default)]
    fib_gen_mismatches: u64,
    #[serde(rename = "unsupported_packets", default)]
    unsupported_packets: u64,
    #[serde(rename = "flow_cache_hits", default)]
    flow_cache_hits: u64,
    #[serde(rename = "flow_cache_misses", default)]
    flow_cache_misses: u64,
    #[serde(rename = "flow_cache_evictions", default)]
    flow_cache_evictions: u64,
    #[serde(rename = "session_hits", default)]
    session_hits: u64,
    #[serde(rename = "session_misses", default)]
    session_misses: u64,
    #[serde(rename = "session_creates", default)]
    session_creates: u64,
    #[serde(rename = "session_expires", default)]
    session_expires: u64,
    #[serde(rename = "session_delta_pending", default)]
    session_delta_pending: u64,
    #[serde(rename = "session_delta_generated", default)]
    session_delta_generated: u64,
    #[serde(rename = "session_delta_dropped", default)]
    session_delta_dropped: u64,
    #[serde(rename = "session_delta_drained", default)]
    session_delta_drained: u64,
    #[serde(rename = "policy_denied_packets", default)]
    policy_denied_packets: u64,
    #[serde(rename = "screen_drops", default)]
    screen_drops: u64,
    #[serde(rename = "snat_packets", default)]
    snat_packets: u64,
    #[serde(rename = "dnat_packets", default)]
    dnat_packets: u64,
    #[serde(rename = "slow_path_packets", default)]
    slow_path_packets: u64,
    #[serde(rename = "slow_path_bytes", default)]
    slow_path_bytes: u64,
    #[serde(rename = "slow_path_local_delivery_packets", default)]
    slow_path_local_delivery_packets: u64,
    #[serde(rename = "slow_path_missing_neighbor_packets", default)]
    slow_path_missing_neighbor_packets: u64,
    #[serde(rename = "slow_path_no_route_packets", default)]
    slow_path_no_route_packets: u64,
    #[serde(rename = "slow_path_next_table_packets", default)]
    slow_path_next_table_packets: u64,
    #[serde(rename = "slow_path_forward_build_packets", default)]
    slow_path_forward_build_packets: u64,
    #[serde(rename = "slow_path_drops", default)]
    slow_path_drops: u64,
    #[serde(rename = "slow_path_rate_limited", default)]
    slow_path_rate_limited: u64,
    #[serde(rename = "kernel_rx_dropped", default)]
    kernel_rx_dropped: u64,
    #[serde(rename = "kernel_rx_invalid_descs", default)]
    kernel_rx_invalid_descs: u64,
    #[serde(rename = "tx_packets", default)]
    tx_packets: u64,
    #[serde(rename = "tx_bytes", default)]
    tx_bytes: u64,
    #[serde(rename = "tx_errors", default)]
    tx_errors: u64,
    #[serde(rename = "direct_tx_packets", default)]
    direct_tx_packets: u64,
    #[serde(rename = "copy_tx_packets", default)]
    copy_tx_packets: u64,
    #[serde(rename = "in_place_tx_packets", default)]
    in_place_tx_packets: u64,
    #[serde(rename = "direct_tx_no_frame_fallback_packets", default)]
    direct_tx_no_frame_fallback_packets: u64,
    #[serde(rename = "direct_tx_build_fallback_packets", default)]
    direct_tx_build_fallback_packets: u64,
    #[serde(rename = "direct_tx_disallowed_fallback_packets", default)]
    direct_tx_disallowed_fallback_packets: u64,
    #[serde(rename = "last_heartbeat", skip_serializing_if = "Option::is_none")]
    last_heartbeat: Option<DateTime<Utc>>,
    #[serde(rename = "tx_completions", default)]
    tx_completions: u64,
    #[serde(rename = "socket_ifindex", default)]
    socket_ifindex: i32,
    #[serde(rename = "socket_queue_id", default)]
    socket_queue_id: u32,
    #[serde(rename = "socket_bind_flags", default)]
    socket_bind_flags: u32,
    #[serde(rename = "debug_pending_fill_frames", default)]
    debug_pending_fill_frames: u32,
    #[serde(rename = "debug_spare_fill_frames", default)]
    debug_spare_fill_frames: u32,
    #[serde(rename = "debug_free_tx_frames", default)]
    debug_free_tx_frames: u32,
    #[serde(rename = "debug_pending_tx_prepared", default)]
    debug_pending_tx_prepared: u32,
    #[serde(rename = "debug_pending_tx_local", default)]
    debug_pending_tx_local: u32,
    #[serde(rename = "debug_outstanding_tx", default)]
    debug_outstanding_tx: u32,
    #[serde(rename = "debug_in_flight_recycles", default)]
    debug_in_flight_recycles: u32,
    #[serde(rename = "last_error", default)]
    last_error: String,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    last_change: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct ExceptionStatus {
    timestamp: DateTime<Utc>,
    slot: u32,
    #[serde(rename = "queue_id")]
    queue_id: u32,
    #[serde(rename = "worker_id")]
    worker_id: u32,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(rename = "ingress_ifindex", default)]
    ingress_ifindex: i32,
    reason: String,
    #[serde(rename = "packet_length", default)]
    packet_length: u32,
    #[serde(rename = "addr_family", default)]
    addr_family: u8,
    #[serde(default)]
    protocol: u8,
    #[serde(rename = "config_generation", default)]
    config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    fib_generation: u32,
    #[serde(rename = "src_ip", default)]
    src_ip: String,
    #[serde(rename = "dst_ip", default)]
    dst_ip: String,
    #[serde(rename = "src_port", default)]
    src_port: u16,
    #[serde(rename = "dst_port", default)]
    dst_port: u16,
    #[serde(rename = "from_zone", default)]
    from_zone: String,
    #[serde(rename = "to_zone", default)]
    to_zone: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct InjectPacketRequest {
    slot: u32,
    #[serde(rename = "packet_length", default)]
    packet_length: u32,
    #[serde(rename = "addr_family", default)]
    addr_family: u8,
    #[serde(default)]
    protocol: u8,
    #[serde(rename = "config_generation", default)]
    config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    fib_generation: u32,
    #[serde(rename = "metadata_valid", default)]
    metadata_valid: bool,
    #[serde(rename = "destination_ip", default)]
    destination_ip: String,
    #[serde(rename = "emit_on_wire", default)]
    emit_on_wire: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SessionSyncRequest {
    #[serde(default)]
    operation: String,
    #[serde(rename = "addr_family", default)]
    addr_family: u8,
    #[serde(default)]
    protocol: u8,
    #[serde(rename = "src_ip", default)]
    src_ip: String,
    #[serde(rename = "dst_ip", default)]
    dst_ip: String,
    #[serde(rename = "src_port", default)]
    src_port: u16,
    #[serde(rename = "dst_port", default)]
    dst_port: u16,
    #[serde(rename = "ingress_zone", default)]
    ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    egress_zone: String,
    #[serde(rename = "owner_rg_id", default)]
    owner_rg_id: i32,
    #[serde(rename = "egress_ifindex", default)]
    egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    tx_ifindex: i32,
    #[serde(rename = "tunnel_endpoint_id", default)]
    tunnel_endpoint_id: u16,
    #[serde(rename = "tx_vlan_id", default)]
    tx_vlan_id: u16,
    #[serde(rename = "next_hop", default)]
    next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    neighbor_mac: String,
    #[serde(rename = "src_mac", default)]
    src_mac: String,
    #[serde(rename = "nat_src_ip", default)]
    nat_src_ip: String,
    #[serde(rename = "nat_dst_ip", default)]
    nat_dst_ip: String,
    #[serde(rename = "nat_src_port", default)]
    nat_src_port: u16,
    #[serde(rename = "nat_dst_port", default)]
    nat_dst_port: u16,
    #[serde(rename = "fabric_ingress", default)]
    fabric_ingress: bool,
    #[serde(rename = "is_reverse", default)]
    is_reverse: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SessionDeltaDrainRequest {
    #[serde(default)]
    max: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SessionExportRequest {
    #[serde(rename = "owner_rgs", default)]
    owner_rgs: Vec<i32>,
    #[serde(default)]
    max: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct SessionDeltaInfo {
    timestamp: DateTime<Utc>,
    #[serde(default)]
    slot: u32,
    #[serde(rename = "queue_id", default)]
    queue_id: u32,
    #[serde(rename = "worker_id", default)]
    worker_id: u32,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    ifindex: i32,
    #[serde(default)]
    event: String,
    #[serde(rename = "addr_family", default)]
    addr_family: u8,
    #[serde(default)]
    protocol: u8,
    #[serde(rename = "src_ip", default)]
    src_ip: String,
    #[serde(rename = "dst_ip", default)]
    dst_ip: String,
    #[serde(rename = "src_port", default)]
    src_port: u16,
    #[serde(rename = "dst_port", default)]
    dst_port: u16,
    #[serde(rename = "ingress_zone", default)]
    ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    egress_zone: String,
    #[serde(rename = "owner_rg_id", default)]
    owner_rg_id: i32,
    #[serde(rename = "egress_ifindex", default)]
    egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    tx_ifindex: i32,
    #[serde(rename = "tunnel_endpoint_id", default)]
    tunnel_endpoint_id: u16,
    #[serde(rename = "tx_vlan_id", default)]
    tx_vlan_id: u16,
    #[serde(rename = "next_hop", default)]
    next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    neighbor_mac: String,
    #[serde(rename = "src_mac", default)]
    src_mac: String,
    #[serde(rename = "nat_src_ip", default)]
    nat_src_ip: String,
    #[serde(rename = "nat_dst_ip", default)]
    nat_dst_ip: String,
    #[serde(rename = "nat_src_port", default)]
    nat_src_port: u16,
    #[serde(rename = "nat_dst_port", default)]
    nat_dst_port: u16,
    #[serde(rename = "fabric_redirect", default)]
    fabric_redirect: bool,
    #[serde(rename = "fabric_ingress", default)]
    fabric_ingress: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollMode {
    BusyPoll,
    Interrupt,
}

impl PollMode {
    fn from_str(s: &str) -> Self {
        match s {
            "interrupt" => PollMode::Interrupt,
            _ => PollMode::BusyPoll,
        }
    }
}

#[derive(Debug)]
struct Args {
    control_socket: String,
    state_file: String,
    workers: usize,
    ring_entries: usize,
    poll_mode: PollMode,
}

struct ServerState {
    status: ProcessStatus,
    snapshot: Option<ConfigSnapshot>,
    afxdp: afxdp::Coordinator,
    state_writer: Arc<StateWriter>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("bpfrx-userspace-dp: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // Increase socket receive buffer defaults — needed for AF_XDP copy mode
    // to avoid drops when the kernel backlog is large.
    for sysctl in &[
        "/proc/sys/net/core/rmem_default",
        "/proc/sys/net/core/rmem_max",
    ] {
        if let Err(e) = fs::write(sysctl, "16777216") {
            eprintln!("warn: set {sysctl}: {e}");
        } else {
            eprintln!("set {sysctl}=16777216");
        }
    }
    let args = parse_args()?;
    // Enable NAPI busy polling sysctls only in busy-poll mode.
    // In interrupt mode, skip these so the kernel uses normal interrupt delivery.
    if args.poll_mode == PollMode::BusyPoll {
        for (path, val) in &[
            ("/proc/sys/net/core/busy_poll", "50"),
            ("/proc/sys/net/core/busy_read", "50"),
        ] {
            if let Err(e) = fs::write(path, val) {
                eprintln!("warn: set {path}: {e}");
            } else {
                eprintln!("set {path}={val}");
            }
        }
    } else {
        eprintln!("bpfrx-userspace-dp: interrupt mode — skipping busy_poll sysctls");
    }
    if let Some(parent) = Path::new(&args.control_socket).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create control dir: {e}"))?;
    }
    if let Some(parent) = Path::new(&args.state_file).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create state dir: {e}"))?;
    }
    let _ = fs::remove_file(&args.control_socket);

    let listener = UnixListener::bind(&args.control_socket)
        .map_err(|e| format!("listen {}: {e}", args.control_socket))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking listener: {e}"))?;

    let state_writer = Arc::new(StateWriter::new());
    let running = Arc::new(AtomicBool::new(true));
    let state = Arc::new(Mutex::new(ServerState {
        status: ProcessStatus {
            pid: std::process::id() as i32,
            started_at: Utc::now(),
            control_socket: args.control_socket.clone(),
            state_file: args.state_file.clone(),
            workers: args.workers,
            ring_entries: args.ring_entries,
            helper_mode: "rust-afxdp-bootstrap".to_string(),
            io_uring_planned: true,
            io_uring_active: false,
            io_uring_mode: String::new(),
            io_uring_last_error: String::new(),
            enabled: false,
            forwarding_armed: false,
            capabilities: UserspaceCapabilities::default(),
            last_snapshot_generation: 0,
            last_fib_generation: 0,
            last_snapshot_at: None,
            interface_addresses: 0,
            neighbor_entries: 0,
            neighbor_generation: 0,
            route_entries: 0,
            worker_heartbeats: Vec::new(),
            ha_groups: Vec::new(),
            fabrics: Vec::new(),
            queues: Vec::new(),
            bindings: Vec::new(),
            recent_session_deltas: Vec::new(),
            recent_exceptions: Vec::new(),
            last_resolution: None,
            slow_path: SlowPathStatus::default(),
            debug_worker_threads: 0,
            debug_identity_slots: 0,
            debug_live_slots: 0,
            debug_planned_workers: 0,
            debug_planned_bindings: 0,
            debug_reconcile_calls: 0,
            debug_reconcile_stage: String::new(),
        },
        snapshot: None,
        afxdp: {
            let mut c = afxdp::Coordinator::new();
            c.poll_mode = args.poll_mode;
            c
        },
        state_writer: state_writer.clone(),
    }));
    eprintln!("bpfrx-userspace-dp: poll_mode={:?}", args.poll_mode);

    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("install ctrlc handler: {e}"))?;
    }

    write_state(&args.state_file, &state)?;

    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_stream(stream, &args.state_file, state.clone(), running.clone());
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(format!("accept: {err}")),
        }
    }
    {
        let mut guard = state.lock().expect("state poisoned");
        guard.afxdp.stop();
        refresh_status(&mut guard);
    }
    afxdp::remove_kernel_rst_suppression();
    write_state(&args.state_file, &state)?;
    let _ = fs::remove_file(&args.control_socket);
    Ok(())
}

fn parse_args() -> Result<Args, String> {
    let mut control_socket = env::temp_dir()
        .join("bpfrx-userspace-dp")
        .join("control.sock")
        .to_string_lossy()
        .to_string();
    let mut state_file = env::temp_dir()
        .join("bpfrx-userspace-dp")
        .join("state.json")
        .to_string_lossy()
        .to_string();
    let mut workers = 1usize;
    let mut ring_entries = 4096usize;
    let mut poll_mode = PollMode::BusyPoll;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let val = args
            .next()
            .ok_or_else(|| format!("missing value for argument {arg}"))?;
        match arg.as_str() {
            "--control-socket" => control_socket = val,
            "--state-file" => state_file = val,
            "--workers" => {
                workers = val
                    .parse::<usize>()
                    .map_err(|e| format!("parse --workers: {e}"))?
                    .max(1)
            }
            "--ring-entries" => {
                ring_entries = val
                    .parse::<usize>()
                    .map_err(|e| format!("parse --ring-entries: {e}"))?
                    .max(1)
            }
            "--poll-mode" => poll_mode = PollMode::from_str(&val),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    Ok(Args {
        control_socket,
        state_file,
        workers,
        ring_entries,
        poll_mode,
    })
}

fn handle_stream(
    stream: UnixStream,
    state_file: &str,
    state: Arc<Mutex<ServerState>>,
    running: Arc<AtomicBool>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set write timeout: {e}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("clone stream for read: {e}"))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read request: {e}"))?;
    let request: ControlRequest =
        serde_json::from_str(line.trim_end()).map_err(|e| format!("decode request: {e}"))?;

    let mut response = ControlResponse {
        ok: true,
        error: String::new(),
        status: None,
        session_deltas: Vec::new(),
    };
    let mut persist_state = false;

    {
        let mut guard = state.lock().expect("server state poisoned");
        match request.request_type.as_str() {
            "ping" | "status" => {}
            "apply_snapshot" => {
                if let Some(snapshot) = request.snapshot {
                    eprintln!(
                        "CTRL_REQ: apply_snapshot generation={} fib_generation={} forwarding_armed_before={}",
                        snapshot.generation, snapshot.fib_generation, guard.status.forwarding_armed
                    );
                    guard.status.last_snapshot_generation = snapshot.generation;
                    guard.status.last_fib_generation = snapshot.fib_generation;
                    guard.status.last_snapshot_at = Some(snapshot.generated_at);
                    guard.status.capabilities = snapshot.capabilities.clone();
                    let existing_bindings = guard.status.bindings.clone();
                    let previous_snapshot = guard.snapshot.as_ref();
                    let same_plan = previous_snapshot.is_some_and(|prev| {
                        let prev_key = snapshot_binding_plan_key(prev);
                        let next_key = snapshot_binding_plan_key(&snapshot);
                        let same = prev_key == next_key;
                        if !same {
                            eprintln!(
                                "CTRL_REQ: binding plan changed prev_key={} next_key={}",
                                prev_key, next_key
                            );
                        }
                        same
                    });
                    if same_plan {
                        guard.afxdp.refresh_runtime_snapshot(&snapshot);
                        guard.snapshot = Some(snapshot);
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        let defer_workers = snapshot.defer_workers;
                        guard.snapshot = Some(snapshot);
                        let replanned = replan_queues(
                            guard.snapshot.as_ref(),
                            guard.status.workers,
                            &existing_bindings,
                        );
                        guard.status.bindings = replanned;
                        if defer_workers {
                            eprintln!(
                                "CTRL_REQ: apply_snapshot defer_workers=true — skipping worker spawn (RETH MAC pending)"
                            );
                        } else {
                            reconcile_status_bindings(&mut guard);
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    }
                } else {
                    response.ok = false;
                    response.error = "missing snapshot".to_string();
                }
            }
            "set_forwarding_state" => {
                if let Some(forwarding_req) = request.forwarding {
                    eprintln!(
                        "CTRL_REQ: set_forwarding_state armed={} forwarding_armed_before={}",
                        forwarding_req.armed, guard.status.forwarding_armed
                    );
                    if forwarding_req.armed && !guard.status.capabilities.forwarding_supported {
                        response.ok = false;
                        response.error = forwarding_unsupported_error(&guard.status.capabilities);
                    } else {
                        guard.status.forwarding_armed = forwarding_req.armed;
                        set_bindings_forwarding_armed(&mut guard.status, forwarding_req.armed);
                        reconcile_status_bindings(&mut guard);
                        if forwarding_req.armed {
                            wait_for_binding_settle(&mut guard, Duration::from_secs(2));
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    }
                } else {
                    response.ok = false;
                    response.error = "missing forwarding state".to_string();
                }
            }
            "update_ha_state" => {
                if let Some(ha_req) = request.ha_state {
                    #[cfg(feature = "debug-log")]
                    eprintln!(
                        "CTRL_REQ: update_ha_state groups={} forwarding_armed={}",
                        ha_req.groups.len(),
                        guard.status.forwarding_armed
                    );
                    guard.status.ha_groups = ha_req.groups.clone();
                    guard.afxdp.update_ha_state(&ha_req.groups);
                    refresh_status(&mut guard);
                    persist_state = true;
                } else {
                    response.ok = false;
                    response.error = "missing HA state".to_string();
                }
            }
            "prepare_ha_demotion" => {
                if let Some(prepare_req) = request.ha_demotion_prepare {
                    match guard.afxdp.prepare_ha_demotion(&prepare_req.groups) {
                        Ok(()) => {
                            refresh_status(&mut guard);
                        }
                        Err(err) => {
                            response.ok = false;
                            response.error = err;
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing HA demotion prepare".to_string();
                }
            }
            "update_fabrics" => {
                if let Some(fabrics) = request.fabrics.as_ref() {
                    guard.afxdp.refresh_fabric_links(fabrics);
                    refresh_status(&mut guard);
                }
            }
            "update_neighbors" => {
                if let Some(neighbors) = request.neighbors.as_ref() {
                    let replace = request.neighbor_replace;
                    let mut resolved = Vec::with_capacity(neighbors.len());
                    for neigh in neighbors {
                        if neigh.ifindex <= 0 || neigh.mac.is_empty() {
                            continue;
                        }
                        let Ok(ip) = neigh.ip.parse::<std::net::IpAddr>() else {
                            continue;
                        };
                        let Some(mac) = afxdp::parse_mac_str(&neigh.mac) else {
                            continue;
                        };
                        if !afxdp::neighbor_state_usable_str(&neigh.state) {
                            continue;
                        }
                        resolved.push((neigh.ifindex, ip, afxdp::NeighborEntry { mac }));
                    }
                    guard.afxdp.apply_manager_neighbors(replace, &resolved);
                    refresh_status(&mut guard);
                }
            }
            "set_queue_state" => {
                if let Some(queue_req) = request.queue {
                    let mut found = false;
                    let mut registration_changed = false;
                    for binding in guard
                        .status
                        .bindings
                        .iter_mut()
                        .filter(|b| b.queue_id == queue_req.queue_id)
                    {
                        if binding.registered != queue_req.registered {
                            registration_changed = true;
                        }
                        binding.registered = queue_req.registered;
                        binding.armed = queue_req.armed && queue_req.registered;
                        binding.last_change = Some(Utc::now());
                        found = true;
                    }
                    if found {
                        if registration_changed {
                            reconcile_status_bindings(&mut guard);
                            wait_for_binding_settle(&mut guard, Duration::from_secs(2));
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        response.ok = false;
                        response.error = format!("unknown queue {}", queue_req.queue_id);
                    }
                } else {
                    response.ok = false;
                    response.error = "missing queue state".to_string();
                }
            }
            "set_binding_state" => {
                if let Some(binding_req) = request.binding {
                    if let Some(binding) = guard
                        .status
                        .bindings
                        .iter_mut()
                        .find(|b| b.slot == binding_req.slot)
                    {
                        let registration_changed = binding.registered != binding_req.registered;
                        binding.registered = binding_req.registered;
                        binding.armed = binding_req.armed && binding_req.registered;
                        binding.last_change = Some(Utc::now());
                        if registration_changed {
                            reconcile_status_bindings(&mut guard);
                            wait_for_binding_settle(&mut guard, Duration::from_secs(2));
                        }
                        refresh_status(&mut guard);
                        persist_state = true;
                    } else {
                        response.ok = false;
                        response.error = format!("unknown binding slot {}", binding_req.slot);
                    }
                } else {
                    response.ok = false;
                    response.error = "missing binding state".to_string();
                }
            }
            "inject_packet" => {
                if let Some(packet_req) = request.packet {
                    match guard.afxdp.inject_test_packet(packet_req) {
                        Ok(()) => {
                            refresh_status(&mut guard);
                            persist_state = true;
                        }
                        Err(err) => {
                            response.ok = false;
                            response.error = err;
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing packet injection request".to_string();
                }
            }
            "sync_session" => {
                if let Some(sync_req) = request.session_sync {
                    match sync_req.operation.as_str() {
                        "upsert" => match build_synced_session_entry(&sync_req) {
                            Ok(entry) => {
                                guard.afxdp.upsert_synced_session(entry);
                            }
                            Err(err) => {
                                response.ok = false;
                                response.error = err;
                            }
                        },
                        "delete" => match build_synced_session_key(&sync_req) {
                            Ok(key) => {
                                guard.afxdp.delete_synced_session(key);
                            }
                            Err(err) => {
                                response.ok = false;
                                response.error = err;
                            }
                        },
                        other => {
                            response.ok = false;
                            response.error = format!("unknown session sync operation {other}");
                        }
                    }
                } else {
                    response.ok = false;
                    response.error = "missing session sync request".to_string();
                }
            }
            "drain_session_deltas" => {
                let max = request
                    .session_deltas
                    .as_ref()
                    .map(|req| req.max)
                    .unwrap_or(256)
                    .max(1) as usize;
                response.session_deltas = guard.afxdp.drain_session_deltas(max);
                refresh_status(&mut guard);
                persist_state = true;
            }
            "export_owner_rg_sessions" => {
                let export_req = request.session_export.unwrap_or_default();
                match guard
                    .afxdp
                    .export_owner_rg_sessions(&export_req.owner_rgs, export_req.max as usize)
                {
                    Ok(deltas) => {
                        response.session_deltas = deltas;
                        refresh_status(&mut guard);
                        persist_state = true;
                    }
                    Err(err) => {
                        response.ok = false;
                        response.error = err;
                    }
                }
            }
            "rebind" => {
                // After a link DOWN/UP cycle (e.g. RETH MAC programming),
                // the kernel destroys the XSK receive queue.  Stop all
                // workers, clear binding state, and reconcile to recreate
                // the AF_XDP sockets from scratch.
                //
                // No settle wait — worker threads create sockets async.
                // The response returns immediately; sockets become ready
                // within ~100ms as worker threads complete binding.
                eprintln!("rebind: stopping workers and recreating AF_XDP sockets");
                guard.afxdp.stop();
                for binding in &mut guard.status.bindings {
                    binding.bound = false;
                    binding.xsk_registered = false;
                    binding.xsk_bind_mode.clear();
                    binding.zero_copy = false;
                    binding.socket_fd = 0;
                    binding.ready = false;
                    binding.last_error.clear();
                }
                reconcile_status_bindings(&mut guard);
                refresh_status(&mut guard);
                persist_state = true;
                eprintln!(
                    "rebind: initiated, forwarding_armed={} bindings={}",
                    guard.status.forwarding_armed,
                    guard.status.bindings.len()
                );
            }
            "stop_workers" => {
                // Stop all AF_XDP workers without recreating them.
                // Used by PrepareLinkCycle: stops workers BEFORE link
                // DOWN/UP so they don't access DMA-mapped UMEM pages
                // that the NIC unmaps during link cycle. The subsequent
                // "rebind" request (sent by NotifyLinkCycle after the
                // link is back UP) recreates workers with fresh sockets.
                eprintln!("stop_workers: stopping all AF_XDP workers");
                guard.afxdp.stop();
                for binding in &mut guard.status.bindings {
                    binding.bound = false;
                    binding.xsk_registered = false;
                    binding.xsk_bind_mode.clear();
                    binding.zero_copy = false;
                    binding.socket_fd = 0;
                    binding.ready = false;
                    binding.last_error.clear();
                }
                refresh_status(&mut guard);
                persist_state = true;
                eprintln!(
                    "stop_workers: all workers stopped, bindings={}",
                    guard.status.bindings.len()
                );
            }
            "shutdown" => {
                guard.afxdp.stop();
                running.store(false, Ordering::SeqCst);
                persist_state = true;
            }
            other => {
                response.ok = false;
                response.error = format!("unknown request type {other}");
            }
        }
        if !request.suppress_status {
            refresh_status(&mut guard);
            response.status = Some(guard.status.clone());
        }
    }

    if persist_state {
        write_state(state_file, &state)?;
    }

    let mut writer = BufWriter::new(stream);
    serde_json::to_writer(&mut writer, &response).map_err(|e| format!("encode response: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("write response newline: {e}"))?;
    writer.flush().map_err(|e| format!("flush response: {e}"))?;
    Ok(())
}

fn refresh_status(state: &mut ServerState) {
    state.afxdp.refresh_bindings(&mut state.status.bindings);
    let writer_status = state.state_writer.status();
    state.status.io_uring_active = writer_status.active;
    state.status.io_uring_mode = writer_status.mode;
    state.status.io_uring_last_error = writer_status.last_error;
    state.status.interface_addresses = state
        .snapshot
        .as_ref()
        .map(|s| s.interfaces.iter().map(|iface| iface.addresses.len()).sum())
        .unwrap_or(0);
    let (neighbor_entries, neighbor_generation) = state.afxdp.dynamic_neighbor_status();
    state.status.neighbor_entries = neighbor_entries;
    state.status.neighbor_generation = neighbor_generation;
    state.status.route_entries = state.snapshot.as_ref().map(|s| s.routes.len()).unwrap_or(0);
    state.status.fabrics = state
        .snapshot
        .as_ref()
        .map(|s| s.fabrics.clone())
        .unwrap_or_default();
    state.status.worker_heartbeats = state.afxdp.worker_heartbeats();
    state.status.debug_worker_threads = state.afxdp.worker_count();
    state.status.debug_identity_slots = state.afxdp.identity_count();
    state.status.debug_live_slots = state.afxdp.live_count();
    let (planned_workers, planned_bindings) = state.afxdp.planned_counts();
    state.status.debug_planned_workers = planned_workers;
    state.status.debug_planned_bindings = planned_bindings;
    let (reconcile_calls, reconcile_stage) = state.afxdp.reconcile_debug();
    state.status.debug_reconcile_calls = reconcile_calls;
    state.status.debug_reconcile_stage = reconcile_stage;
    state.status.ha_groups = state.afxdp.ha_groups();
    // Report enabled when all bindings are registered+armed (XSKMAP slots
    // populated). The per-queue xsk_rx_confirmed heartbeat gating handles
    // queues whose XSK RQ hasn't been bootstrapped yet — those get XDP_PASS
    // until they bootstrap naturally from background traffic.
    // Previously this required all bindings to be `ready` (first RX packet
    // received), which created a deadlock: ctrl=0 → XDP_PASS → no XSK RX
    // → not ready → ctrl stays 0.
    state.status.enabled = state.status.forwarding_armed
        && state.status.capabilities.forwarding_supported
        && !state.status.bindings.is_empty()
        && state
            .status
            .bindings
            .iter()
            .all(|b| b.registered && b.armed);
    state.status.queues = summarize_queues(&state.status.bindings);
    state.status.recent_session_deltas = state.afxdp.recent_session_deltas();
    state.status.recent_exceptions = state.afxdp.recent_exceptions();
    state.status.last_resolution = state.afxdp.last_resolution();
    state.status.slow_path = state.afxdp.slow_path_status().into();
}

fn forwarding_unsupported_error(cap: &UserspaceCapabilities) -> String {
    if cap.unsupported_reasons.is_empty() {
        return "userspace live forwarding is not supported for the current configuration"
            .to_string();
    }
    format!(
        "userspace live forwarding is not supported: {}",
        cap.unsupported_reasons.join("; ")
    )
}

fn build_synced_session_key(
    req: &SessionSyncRequest,
) -> Result<crate::session::SessionKey, String> {
    Ok(crate::session::SessionKey {
        addr_family: req.addr_family,
        protocol: req.protocol,
        src_ip: req
            .src_ip
            .parse()
            .map_err(|e| format!("parse src_ip {}: {e}", req.src_ip))?,
        dst_ip: req
            .dst_ip
            .parse()
            .map_err(|e| format!("parse dst_ip {}: {e}", req.dst_ip))?,
        src_port: req.src_port,
        dst_port: req.dst_port,
    })
}

fn build_synced_session_entry(req: &SessionSyncRequest) -> Result<SyncedSessionEntry, String> {
    let key = build_synced_session_key(req)?;
    let next_hop = if req.next_hop.is_empty() {
        None
    } else {
        Some(
            req.next_hop
                .parse()
                .map_err(|e| format!("parse next_hop {}: {e}", req.next_hop))?,
        )
    };
    let neighbor_mac = parse_session_sync_mac(&req.neighbor_mac)
        .map_err(|e| format!("parse neighbor_mac {}: {e}", req.neighbor_mac))?;
    let src_mac = parse_session_sync_mac(&req.src_mac)
        .map_err(|e| format!("parse src_mac {}: {e}", req.src_mac))?;
    let tx_ifindex = if req.tunnel_endpoint_id != 0 {
        req.tx_ifindex.max(0)
    } else if req.tx_ifindex > 0 {
        req.tx_ifindex
    } else {
        req.egress_ifindex
    };
    let nat_src = if req.nat_src_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_src_ip
                .parse()
                .map_err(|e| format!("parse nat_src_ip {}: {e}", req.nat_src_ip))?,
        )
    };
    let nat_dst = if req.nat_dst_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_dst_ip
                .parse()
                .map_err(|e| format!("parse nat_dst_ip {}: {e}", req.nat_dst_ip))?,
        )
    };
    let nat_src_port = if req.nat_src_port != 0 {
        Some(req.nat_src_port)
    } else {
        None
    };
    let nat_dst_port = if req.nat_dst_port != 0 {
        Some(req.nat_dst_port)
    } else {
        None
    };
    Ok(SyncedSessionEntry {
        protocol: req.protocol,
        tcp_flags: 0,
        key,
        decision: crate::session::SessionDecision {
            resolution: afxdp::ForwardingResolution {
                disposition: if req.egress_ifindex > 0
                    || req.tx_ifindex > 0
                    || req.tunnel_endpoint_id != 0
                {
                    afxdp::ForwardingDisposition::ForwardCandidate
                } else {
                    afxdp::ForwardingDisposition::NoRoute
                },
                local_ifindex: 0,
                egress_ifindex: req.egress_ifindex,
                tx_ifindex,
                tunnel_endpoint_id: req.tunnel_endpoint_id,
                next_hop,
                neighbor_mac,
                src_mac,
                tx_vlan_id: req.tx_vlan_id,
            },
            nat: crate::nat::NatDecision {
                rewrite_src: nat_src,
                rewrite_dst: nat_dst,
                rewrite_src_port: nat_src_port,
                rewrite_dst_port: nat_dst_port,
                ..crate::nat::NatDecision::default()
            },
        },
        metadata: crate::session::SessionMetadata {
            ingress_zone: req.ingress_zone.clone().into(),
            egress_zone: req.egress_zone.clone().into(),
            owner_rg_id: req.owner_rg_id,
            fabric_ingress: req.fabric_ingress,
            is_reverse: req.is_reverse,
            synced: true,
            nat64_reverse: None,
        },
    })
}

fn parse_session_sync_mac(value: &str) -> Result<Option<[u8; 6]>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut out = [0u8; 6];
    let mut count = 0usize;
    for (i, part) in value.split(':').enumerate() {
        if i >= out.len() {
            return Err("too many octets".to_string());
        }
        out[i] = u8::from_str_radix(part, 16).map_err(|e| e.to_string())?;
        count += 1;
    }
    if count != out.len() {
        return Err("expected 6 octets".to_string());
    }
    Ok(Some(out))
}

fn reconcile_status_bindings(state: &mut ServerState) {
    if !should_run_afxdp(&state.status) {
        state.afxdp.stop();
        state.status.bindings.iter_mut().for_each(|binding| {
            binding.bound = false;
            binding.xsk_registered = false;
            binding.xsk_bind_mode.clear();
            binding.zero_copy = false;
            binding.socket_fd = 0;
            binding.ready = false;
            binding.last_error.clear();
        });
        return;
    }
    let snapshot = state.snapshot.clone();
    let ring_entries = state.status.ring_entries;
    let mut bindings = std::mem::take(&mut state.status.bindings);
    state
        .afxdp
        .reconcile(snapshot.as_ref(), &mut bindings, ring_entries);
    state.status.bindings = bindings;
}

fn should_run_afxdp(status: &ProcessStatus) -> bool {
    status.forwarding_armed && status.capabilities.forwarding_supported
}

fn set_bindings_forwarding_armed(status: &mut ProcessStatus, armed: bool) {
    for binding in &mut status.bindings {
        binding.armed = armed && binding.registered;
        binding.last_change = Some(Utc::now());
    }
}

fn wait_for_binding_settle(state: &mut ServerState, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        refresh_status(state);
        if bindings_settled(&state.status.bindings) || Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn bindings_settled(bindings: &[BindingStatus]) -> bool {
    bindings.iter().all(|binding| {
        if !binding.registered {
            return !binding.bound && !binding.xsk_registered;
        }
        binding.ready || !binding.last_error.is_empty()
    })
}

#[cfg(test)]
fn same_binding_plan(current: &ConfigSnapshot, next: &ConfigSnapshot) -> bool {
    snapshot_binding_plan_key(current) == snapshot_binding_plan_key(next)
}

fn snapshot_binding_plan_key(snapshot: &ConfigSnapshot) -> String {
    let mut out = String::new();
    let workers = snapshot
        .userspace
        .get("workers")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let ring_entries = snapshot
        .userspace
        .get("ring_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    out.push_str(&format!("workers={workers};ring={ring_entries};"));
    for iface in snapshot
        .interfaces
        .iter()
        .filter(|iface| include_userspace_binding_interface(iface))
    {
        out.push_str(&format!(
            "iface={}/{}/{}/{}/{}/{};",
            iface.name,
            iface.linux_name,
            iface.ifindex,
            iface.parent_ifindex,
            iface.rx_queues,
            iface.tunnel
        ));
    }
    for fab in &snapshot.fabrics {
        out.push_str(&format!(
            "fabric={}/{}/{}/{};",
            fab.name, fab.parent_linux_name, fab.parent_ifindex, fab.rx_queues
        ));
    }
    out
}

fn include_userspace_binding_interface(iface: &InterfaceSnapshot) -> bool {
    if iface.zone.is_empty() {
        return false;
    }
    if iface.tunnel {
        return false;
    }
    if !iface.local_fabric_member.is_empty() {
        return false;
    }
    let base = iface.name.split('.').next().unwrap_or(iface.name.as_str());
    if base.starts_with("fxp") || base.starts_with("em") || base.starts_with("fab") || base == "lo0"
    {
        return false;
    }
    !matches!(iface.zone.as_str(), "mgmt" | "control")
}

fn replan_queues(
    snapshot: Option<&ConfigSnapshot>,
    workers: usize,
    existing: &[BindingStatus],
) -> Vec<BindingStatus> {
    let mut candidates: Vec<(String, usize)> = Vec::new();
    let mut ifindex_by_name: BTreeMap<String, i32> = BTreeMap::new();
    let mut seen_linux: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(snapshot) = snapshot {
        for iface in &snapshot.interfaces {
            if !is_userspace_candidate_interface(&iface.name) {
                continue;
            }
            let linux_name = if iface.linux_name.is_empty() {
                linux_ifname(&iface.name)
            } else {
                iface.linux_name.clone()
            };
            let rx_queues = if iface.rx_queues > 0 {
                iface.rx_queues
            } else {
                rx_queue_count(&linux_name)
            };
            if rx_queues > 0 {
                ifindex_by_name.insert(linux_name.clone(), iface.ifindex);
                seen_linux.insert(linux_name.clone());
                candidates.push((linux_name, rx_queues));
            }
        }
        // Include fabric parent interfaces so the userspace DP can transmit
        // fabric-redirect packets via XSK TX (and receive fabric ingress).
        for fabric in &snapshot.fabrics {
            if fabric.parent_ifindex <= 0 || fabric.parent_linux_name.is_empty() {
                continue;
            }
            if seen_linux.contains(&fabric.parent_linux_name) {
                continue;
            }
            let rx_queues = if fabric.rx_queues > 0 {
                fabric.rx_queues
            } else {
                rx_queue_count(&fabric.parent_linux_name)
            };
            let rx_queues = rx_queues.max(1); // fabric needs at least 1 queue for TX
            ifindex_by_name.insert(fabric.parent_linux_name.clone(), fabric.parent_ifindex);
            seen_linux.insert(fabric.parent_linux_name.clone());
            candidates.push((fabric.parent_linux_name.clone(), rx_queues));
        }
    }
    replan_bindings_from_candidates(workers, existing, candidates, ifindex_by_name)
}

fn replan_bindings_from_candidates(
    workers: usize,
    existing: &[BindingStatus],
    candidates: Vec<(String, usize)>,
    ifindex_by_name: BTreeMap<String, i32>,
) -> Vec<BindingStatus> {
    let mut existing_by_slot = BTreeMap::new();
    for binding in existing {
        existing_by_slot.insert(binding.slot, binding.clone());
    }
    if candidates.is_empty() {
        return Vec::new();
    }
    let queue_count = candidates.iter().map(|(_, rx)| *rx).min().unwrap_or(0);
    let interfaces = candidates
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(queue_count * interfaces.len());
    let mut slot = 0u32;
    for queue_id in 0..queue_count {
        for iface in &interfaces {
            let mut binding = existing_by_slot.remove(&slot).unwrap_or_default();
            let had_existing = binding.last_change.is_some()
                || binding.registered
                || binding.armed
                || binding.ready
                || binding.bound
                || binding.xsk_registered;
            binding.slot = slot;
            binding.queue_id = queue_id as u32;
            binding.worker_id = (queue_id % workers.max(1)) as u32;
            binding.interface = iface.clone();
            binding.ifindex = *ifindex_by_name.get(iface).unwrap_or(&0);
            if binding.ifindex <= 0 {
                binding.registered = false;
                binding.armed = false;
                binding.ready = false;
            } else if !had_existing {
                binding.registered = true;
            }
            if binding.last_change.is_none() {
                binding.last_change = Some(Utc::now());
            }
            out.push(binding);
            slot += 1;
        }
    }
    out
}

fn summarize_queues(bindings: &[BindingStatus]) -> Vec<QueueStatus> {
    let mut by_queue: BTreeMap<u32, Vec<&BindingStatus>> = BTreeMap::new();
    for binding in bindings {
        by_queue.entry(binding.queue_id).or_default().push(binding);
    }
    let mut out = Vec::with_capacity(by_queue.len());
    for (queue_id, group) in by_queue {
        let worker_id = group.first().map(|b| b.worker_id).unwrap_or(0);
        let interfaces = group
            .iter()
            .map(|b| b.interface.clone())
            .collect::<Vec<_>>();
        let registered = !group.is_empty() && group.iter().all(|b| b.registered);
        let armed = !group.is_empty() && group.iter().all(|b| b.registered && b.armed);
        let ready = !group.is_empty() && group.iter().all(|b| b.registered && b.ready);
        let last_change = group.iter().filter_map(|b| b.last_change).max();
        out.push(QueueStatus {
            queue_id,
            worker_id,
            interfaces,
            registered,
            armed,
            ready,
            last_change,
        });
    }
    out
}

fn is_userspace_candidate_interface(name: &str) -> bool {
    name.starts_with("ge-") || name.starts_with("xe-") || name.starts_with("et-")
}

fn linux_ifname(name: &str) -> String {
    name.replace('/', "-")
}

fn rx_queue_count(name: &str) -> usize {
    let path = format!("/sys/class/net/{name}/queues");
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let count = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|entry| entry.starts_with("rx-"))
        .count();
    count.max(1)
}

fn write_state(state_file: &str, state: &Arc<Mutex<ServerState>>) -> Result<(), String> {
    #[derive(Serialize)]
    struct Payload<'a> {
        status: &'a ProcessStatus,
        snapshot: &'a Option<ConfigSnapshot>,
    }

    let mut guard = state.lock().expect("state poisoned");
    refresh_status(&mut guard);
    let payload = Payload {
        status: &guard.status,
        snapshot: &guard.snapshot,
    };
    let data = serde_json::to_vec_pretty(&payload).map_err(|e| format!("encode state: {e}"))?;
    let mut bytes = data;
    bytes.push(b'\n');
    guard
        .state_writer
        .persist(state_file, bytes)
        .map_err(|e| format!("write state file: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_binding_plan_ignores_runtime_only_snapshot_changes() {
        let current = ConfigSnapshot {
            userspace: serde_json::json!({
                "binary": "/usr/libexec/bpfrx-userspace-dp",
                "control_socket": "/run/bpfrx/control.sock",
                "state_file": "/run/bpfrx/state.json",
                "workers": 2,
                "ring_entries": 2048,
                "poll_mode": "interrupt",
            }),
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1.0".to_string(),
                    zone: "lan".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 11,
                    rx_queues: 4,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "fab0".to_string(),
                    zone: "control".to_string(),
                    linux_name: "fab0".to_string(),
                    ifindex: 149,
                    rx_queues: 16,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "gr-0/0/0.0".to_string(),
                    zone: "sfmix".to_string(),
                    linux_name: "gr-0-0-0".to_string(),
                    ifindex: 586,
                    rx_queues: 1,
                    tunnel: true,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "fxp0.0".to_string(),
                    zone: "mgmt".to_string(),
                    linux_name: "fxp0".to_string(),
                    ifindex: 42,
                    rx_queues: 1,
                    ..Default::default()
                },
            ],
            fabrics: vec![FabricSnapshot {
                name: "fab0".to_string(),
                parent_linux_name: "ge-0-0-0".to_string(),
                parent_ifindex: 21,
                rx_queues: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut next = current.clone();
        next.userspace = serde_json::json!({
            "binary": "/tmp/other-helper",
            "control_socket": "/tmp/control.sock",
            "state_file": "/tmp/state.json",
            "workers": 2,
            "ring_entries": 2048,
            "poll_mode": "busy-poll",
        });
        next.interfaces.push(InterfaceSnapshot {
            name: "em0.0".to_string(),
            zone: "mgmt".to_string(),
            linux_name: "em0".to_string(),
            ifindex: 99,
            rx_queues: 1,
            ..Default::default()
        });
        next.interfaces[1].ifindex = 154;

        assert!(same_binding_plan(&current, &next));
    }

    #[test]
    fn same_binding_plan_detects_binding_topology_change() {
        let current = ConfigSnapshot {
            userspace: serde_json::json!({
                "workers": 2,
                "ring_entries": 2048,
            }),
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0/0/1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 11,
                rx_queues: 4,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut next = current.clone();
        next.interfaces[0].rx_queues = 8;

        assert!(!same_binding_plan(&current, &next));
    }

    #[test]
    fn queue_planner_filters_non_data_interfaces() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 11,
                    rx_queues: 1,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "xe-0/0/0".to_string(),
                    linux_name: "xe-0-0-0".to_string(),
                    ifindex: 12,
                    rx_queues: 1,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "fab0".to_string(),
                    linux_name: "fab0".to_string(),
                    ifindex: 13,
                    rx_queues: 4,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 2, &[]);
        assert_eq!(bindings.len(), 2);
        assert!(bindings.iter().all(|b| {
            b.interface.starts_with("ge-")
                || b.interface.starts_with("xe-")
                || b.interface.starts_with("et-")
        }));
        assert!(bindings.iter().all(|b| b.registered));
    }

    #[test]
    fn queue_planner_includes_fabric_parent_interface() {
        // The fabric parent (ge-0/0/0) is not in snapshot.interfaces but is
        // referenced by snapshot.fabrics.  It needs an XSK binding so the
        // userspace DP can transmit fabric-redirect packets.
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 11,
                    rx_queues: 1,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "ge-0/0/2".to_string(),
                    linux_name: "ge-0-0-2".to_string(),
                    ifindex: 12,
                    rx_queues: 1,
                    ..Default::default()
                },
            ],
            fabrics: vec![FabricSnapshot {
                name: "fab0".to_string(),
                parent_interface: "ge-0/0/0".to_string(),
                parent_linux_name: "ge-0-0-0".to_string(),
                parent_ifindex: 21,
                overlay_linux_name: "fab0".to_string(),
                overlay_ifindex: 101,
                rx_queues: 1,
                peer_address: "10.99.13.2".to_string(),
                local_mac: String::new(),
                peer_mac: String::new(),
            }],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 1, &[]);
        // Should have 3 bindings: ge-0-0-1, ge-0-0-2, ge-0-0-0 (fabric parent)
        assert_eq!(bindings.len(), 3);
        let fabric_binding = bindings
            .iter()
            .find(|b| b.interface == "ge-0-0-0")
            .expect("fabric parent binding missing");
        assert_eq!(fabric_binding.ifindex, 21);
        assert!(fabric_binding.registered);
    }

    #[test]
    fn queue_planner_deduplicates_fabric_parent_already_in_interfaces() {
        // When the fabric parent is already in snapshot.interfaces (e.g. as a
        // RETH member), it should not be duplicated.
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0/0/0".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                ifindex: 21,
                rx_queues: 1,
                ..Default::default()
            }],
            fabrics: vec![FabricSnapshot {
                name: "fab0".to_string(),
                parent_interface: "ge-0/0/0".to_string(),
                parent_linux_name: "ge-0-0-0".to_string(),
                parent_ifindex: 21,
                overlay_linux_name: "fab0".to_string(),
                overlay_ifindex: 101,
                rx_queues: 1,
                peer_address: "10.99.13.2".to_string(),
                local_mac: String::new(),
                peer_mac: String::new(),
            }],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 1, &[]);
        // ge-0-0-0 appears in both interfaces and fabrics but should only
        // produce one binding.
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].interface, "ge-0-0-0");
        assert_eq!(bindings[0].ifindex, 21);
    }

    #[test]
    fn build_synced_session_entry_preserves_fabric_ingress() {
        let req = SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: "10.0.61.102".to_string(),
            dst_ip: "172.16.80.200".to_string(),
            src_port: 40000,
            dst_port: 5201,
            ingress_zone: "lan".to_string(),
            egress_zone: "wan".to_string(),
            owner_rg_id: 1,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tx_vlan_id: 80,
            fabric_ingress: true,
            ..SessionSyncRequest::default()
        };

        let entry = build_synced_session_entry(&req).expect("synced session entry");
        assert!(entry.metadata.fabric_ingress);
        assert!(entry.metadata.synced);
        assert_eq!(entry.metadata.owner_rg_id, 1);
    }

    #[test]
    fn build_synced_session_entry_preserves_tunnel_endpoint_id() {
        let req = SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: libc::AF_INET as u8,
            protocol: 1,
            src_ip: "10.0.61.102".to_string(),
            dst_ip: "10.255.192.41".to_string(),
            ingress_zone: "lan".to_string(),
            egress_zone: "sfmix".to_string(),
            egress_ifindex: 586,
            tx_ifindex: 0,
            tunnel_endpoint_id: 3,
            ..SessionSyncRequest::default()
        };

        let entry = build_synced_session_entry(&req).expect("synced session entry");
        assert_eq!(entry.decision.resolution.tunnel_endpoint_id, 3);
        assert_eq!(entry.decision.resolution.egress_ifindex, 586);
        assert_eq!(
            entry.decision.resolution.disposition,
            afxdp::ForwardingDisposition::ForwardCandidate
        );
    }

    #[test]
    fn queue_planner_preserves_existing_state() {
        let existing = vec![BindingStatus {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: "ge-0-0-1".to_string(),
            ifindex: 11,
            registered: true,
            armed: true,
            ready: true,
            last_change: Some(Utc::now()),
            ..Default::default()
        }];
        let bindings = replan_bindings_from_candidates(
            1,
            &existing,
            vec![("ge-0-0-1".to_string(), 1)],
            BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        );
        if let Some(b0) = bindings.iter().find(|b| b.slot == 0) {
            assert!(b0.registered);
            assert!(b0.armed);
            assert!(b0.ready);
        } else {
            panic!("binding 0 missing");
        }
    }

    #[test]
    fn queue_planner_ignores_tunnel_netdevices_for_transit() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "gr-0/0/0.0".to_string(),
                    linux_name: "gr-0-0-0".to_string(),
                    ifindex: 586,
                    rx_queues: 1,
                    tunnel: true,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "ge-0/0/2.80".to_string(),
                    linux_name: "ge-0-0-2.80".to_string(),
                    ifindex: 24,
                    parent_ifindex: 6,
                    rx_queues: 1,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 1, &[]);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].interface, "ge-0-0-2.80");
        assert_eq!(bindings[0].ifindex, 24);
    }

    #[test]
    fn queue_planner_preserves_manual_unregistration() {
        let existing = vec![BindingStatus {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: "ge-0-0-1".to_string(),
            ifindex: 11,
            registered: false,
            armed: false,
            last_change: Some(Utc::now()),
            ..Default::default()
        }];
        let bindings = replan_bindings_from_candidates(
            1,
            &existing,
            vec![("ge-0-0-1".to_string(), 1)],
            BTreeMap::from([("ge-0-0-1".to_string(), 11)]),
        );
        let b0 = bindings.iter().find(|b| b.slot == 0).expect("binding 0");
        assert!(!b0.registered);
        assert!(!b0.armed);
    }

    #[test]
    fn queue_planner_keeps_queue_zero_available_for_userspace() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    ifindex: 11,
                    rx_queues: 2,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "reth1.0".to_string(),
                    linux_name: "reth1".to_string(),
                    parent_linux_name: "ge-0-0-1".to_string(),
                    ifindex: 21,
                    addresses: vec![InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "10.0.61.1/24".to_string(),
                        scope: 0,
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 2, &[]);
        let q0 = bindings
            .iter()
            .find(|b| b.interface == "ge-0-0-1" && b.queue_id == 0)
            .expect("queue 0 binding");
        let q1 = bindings
            .iter()
            .find(|b| b.interface == "ge-0-0-1" && b.queue_id == 1)
            .expect("queue 1 binding");
        assert!(q0.registered);
        assert!(q1.registered);
    }

    #[test]
    fn queue_planner_uses_smallest_queue_count() {
        let snapshot = ConfigSnapshot {
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/1".to_string(),
                    linux_name: "ge-0-0-1".to_string(),
                    rx_queues: 4,
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "ge-0/0/2".to_string(),
                    linux_name: "ge-0-0-2".to_string(),
                    rx_queues: 2,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let bindings = replan_queues(Some(&snapshot), 2, &[]);
        assert_eq!(bindings.len(), 4);
        let queues = summarize_queues(&bindings);
        assert_eq!(queues.len(), 2);
        for (idx, q) in queues.iter().enumerate() {
            assert_eq!(q.queue_id, idx as u32);
            assert_eq!(
                q.interfaces,
                vec!["ge-0-0-1".to_string(), "ge-0-0-2".to_string()]
            );
            assert!(!q.registered);
        }
    }

    #[test]
    fn afxdp_runtime_stays_off_when_forwarding_is_unarmed() {
        let status = ProcessStatus {
            forwarding_armed: false,
            capabilities: UserspaceCapabilities {
                forwarding_supported: true,
                unsupported_reasons: Vec::new(),
            },
            ..Default::default()
        };
        assert!(!should_run_afxdp(&status));
    }

    #[test]
    fn afxdp_runtime_stays_off_when_forwarding_is_unsupported() {
        let status = ProcessStatus {
            forwarding_armed: true,
            capabilities: UserspaceCapabilities {
                forwarding_supported: false,
                unsupported_reasons: vec!["ha".to_string()],
            },
            ..Default::default()
        };
        assert!(!should_run_afxdp(&status));
    }

    #[test]
    fn afxdp_runtime_starts_only_when_armed_and_supported() {
        let status = ProcessStatus {
            forwarding_armed: true,
            capabilities: UserspaceCapabilities {
                forwarding_supported: true,
                unsupported_reasons: Vec::new(),
            },
            ..Default::default()
        };
        assert!(should_run_afxdp(&status));
    }

    #[test]
    fn forwarding_arm_updates_registered_bindings() {
        let mut status = ProcessStatus {
            bindings: vec![
                BindingStatus {
                    registered: true,
                    ..Default::default()
                },
                BindingStatus {
                    registered: false,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        set_bindings_forwarding_armed(&mut status, true);
        assert!(status.bindings[0].armed);
        assert!(!status.bindings[1].armed);
        set_bindings_forwarding_armed(&mut status, false);
        assert!(!status.bindings[0].armed);
        assert!(!status.bindings[1].armed);
    }
}
