//! Control request/response and snapshot schema types shared between the
//! control socket server (`main.rs`) and the AF_XDP coordinator (`afxdp.rs`).
//!
//! All types are `pub(crate)` so they are visible across the crate without
//! being part of the public API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Snapshot schema
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SnapshotSummary {
    #[serde(rename = "host_name")]
    pub host_name: String,
    #[serde(rename = "dataplane_type")]
    pub dataplane_type: String,
    #[serde(rename = "interface_count")]
    pub interface_count: usize,
    #[serde(rename = "zone_count")]
    pub zone_count: usize,
    #[serde(rename = "policy_count")]
    pub policy_count: usize,
    #[serde(rename = "scheduler_count")]
    pub scheduler_count: usize,
    #[serde(rename = "ha_enabled")]
    pub ha_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct InterfaceSnapshot {
    pub name: String,
    #[serde(default)]
    pub zone: String,
    #[serde(rename = "linux_name", default)]
    pub linux_name: String,
    #[serde(rename = "parent_linux_name", default)]
    pub parent_linux_name: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "parent_ifindex", default)]
    pub parent_ifindex: i32,
    #[serde(rename = "rx_queues", default)]
    pub rx_queues: usize,
    #[serde(rename = "vlan_id", default)]
    pub vlan_id: i32,
    #[serde(rename = "local_fabric_member", default)]
    pub local_fabric_member: String,
    #[serde(rename = "redundancy_group", default)]
    pub redundancy_group: i32,
    #[serde(rename = "unit_count", default)]
    pub unit_count: usize,
    #[serde(default)]
    pub tunnel: bool,
    #[serde(default)]
    pub mtu: i32,
    #[serde(rename = "hardware_addr", default)]
    pub hardware_addr: String,
    #[serde(default)]
    pub addresses: Vec<InterfaceAddressSnapshot>,
    #[serde(rename = "filter_input_v4", default)]
    pub filter_input_v4: String,
    #[serde(rename = "filter_output_v4", default)]
    pub filter_output_v4: String,
    #[serde(rename = "filter_input_v6", default)]
    pub filter_input_v6: String,
    #[serde(rename = "filter_output_v6", default)]
    pub filter_output_v6: String,
    #[serde(
        rename = "cos_shaping_rate_bytes_per_sec",
        alias = "cos_shaping_rate_bps",
        default
    )]
    pub cos_shaping_rate_bytes_per_sec: u64,
    #[serde(rename = "cos_shaping_burst_bytes", default)]
    pub cos_shaping_burst_bytes: u64,
    #[serde(rename = "cos_scheduler_map", default)]
    pub cos_scheduler_map: String,
    #[serde(rename = "cos_dscp_classifier", default)]
    pub cos_dscp_classifier: String,
    #[serde(rename = "cos_ieee8021_classifier", default)]
    pub cos_ieee8021_classifier: String,
    #[serde(rename = "cos_dscp_rewrite_rule", default)]
    pub cos_dscp_rewrite_rule: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ClassOfServiceSnapshot {
    #[serde(rename = "forwarding_classes", default)]
    pub forwarding_classes: Vec<CoSForwardingClassSnapshot>,
    #[serde(rename = "dscp_classifiers", default)]
    pub dscp_classifiers: Vec<CoSDSCPClassifierSnapshot>,
    #[serde(rename = "ieee8021_classifiers", default)]
    pub ieee8021_classifiers: Vec<CoSIEEE8021ClassifierSnapshot>,
    #[serde(rename = "dscp_rewrite_rules", default)]
    pub dscp_rewrite_rules: Vec<CoSDSCPRewriteRuleSnapshot>,
    #[serde(rename = "schedulers", default)]
    pub schedulers: Vec<CoSSchedulerSnapshot>,
    #[serde(rename = "scheduler_maps", default)]
    pub scheduler_maps: Vec<CoSSchedulerMapSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSForwardingClassSnapshot {
    pub name: String,
    #[serde(default)]
    pub queue: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPClassifierSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSDSCPClassifierEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPClassifierEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSIEEE8021ClassifierSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSIEEE8021ClassifierEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSIEEE8021ClassifierEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    #[serde(rename = "code_points", default)]
    pub code_points: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPRewriteRuleSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSDSCPRewriteRuleEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSDSCPRewriteRuleEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "loss_priority", default)]
    pub loss_priority: String,
    #[serde(rename = "dscp_value", default)]
    pub dscp_value: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSSchedulerSnapshot {
    pub name: String,
    #[serde(rename = "transmit_rate_bytes", default)]
    pub transmit_rate_bytes: u64,
    #[serde(rename = "transmit_rate_exact", default)]
    pub transmit_rate_exact: bool,
    #[serde(default)]
    pub priority: String,
    #[serde(rename = "buffer_size_bytes", default)]
    pub buffer_size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSSchedulerMapSnapshot {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<CoSSchedulerMapEntrySnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSSchedulerMapEntrySnapshot {
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(default)]
    pub scheduler: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct InterfaceAddressSnapshot {
    pub family: String,
    pub address: String,
    #[serde(default)]
    pub scope: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct RouteSnapshot {
    pub table: String,
    pub family: String,
    pub destination: String,
    #[serde(rename = "next_hops", default)]
    pub next_hops: Vec<String>,
    #[serde(default)]
    pub discard: bool,
    #[serde(rename = "next_table", default)]
    pub next_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FlowSnapshot {
    #[serde(rename = "allow_dns_reply", default)]
    pub allow_dns_reply: bool,
    #[serde(rename = "allow_embedded_icmp", default)]
    pub allow_embedded_icmp: bool,
    #[serde(rename = "tcp_mss_all_tcp", default)]
    pub tcp_mss_all_tcp: u16,
    #[serde(rename = "tcp_mss_ipsec_vpn", default)]
    pub tcp_mss_ipsec_vpn: u16,
    #[serde(rename = "tcp_mss_gre_in", default)]
    pub tcp_mss_gre_in: u16,
    #[serde(rename = "tcp_mss_gre_out", default)]
    pub tcp_mss_gre_out: u16,
    #[serde(rename = "tcp_session_timeout", default)]
    pub tcp_session_timeout: u64,
    #[serde(rename = "udp_session_timeout", default)]
    pub udp_session_timeout: u64,
    #[serde(rename = "icmp_session_timeout", default)]
    pub icmp_session_timeout: u64,
    #[serde(rename = "gre_acceleration", default)]
    pub gre_acceleration: bool,
    #[serde(rename = "lo0_filter_input_v4", default)]
    pub lo0_filter_input_v4: String,
    #[serde(rename = "lo0_filter_input_v6", default)]
    pub lo0_filter_input_v6: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NeighborSnapshot {
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub ifindex: i32,
    pub family: String,
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub router: bool,
    #[serde(rename = "link_local", default)]
    pub link_local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ConfigSnapshot {
    pub version: i32,
    pub generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "generated_at")]
    pub generated_at: DateTime<Utc>,
    pub summary: SnapshotSummary,
    #[serde(default)]
    pub capabilities: UserspaceCapabilities,
    #[serde(rename = "map_pins", default)]
    pub map_pins: MapPins,
    #[serde(default)]
    pub zones: Vec<ZoneSnapshot>,
    #[serde(default)]
    pub interfaces: Vec<InterfaceSnapshot>,
    #[serde(default)]
    pub fabrics: Vec<FabricSnapshot>,
    #[serde(rename = "tunnel_endpoints", default)]
    pub tunnel_endpoints: Vec<TunnelEndpointSnapshot>,
    #[serde(default)]
    pub neighbors: Vec<NeighborSnapshot>,
    #[serde(default)]
    pub routes: Vec<RouteSnapshot>,
    #[serde(default)]
    pub flow: FlowSnapshot,
    #[serde(rename = "default_policy", default)]
    pub default_policy: String,
    #[serde(default)]
    pub policies: Vec<PolicyRuleSnapshot>,
    #[serde(rename = "source_nat_rules", default)]
    pub source_nat_rules: Vec<SourceNATRuleSnapshot>,
    #[serde(rename = "static_nat_rules", default)]
    pub static_nat_rules: Vec<StaticNATRuleSnapshot>,
    #[serde(rename = "destination_nat_rules", default)]
    pub destination_nat_rules: Vec<DestinationNATRuleSnapshot>,
    #[serde(rename = "nat64_rules", default)]
    pub nat64_rules: Vec<NAT64RuleSnapshot>,
    #[serde(rename = "nptv6_rules", default)]
    pub nptv6_rules: Vec<Nptv6RuleSnapshot>,
    #[serde(default)]
    pub screens: Vec<ScreenProfileSnapshot>,
    #[serde(default)]
    pub filters: Vec<FirewallFilterSnapshot>,
    #[serde(default)]
    pub policers: Vec<PolicerSnapshot>,
    #[serde(rename = "class_of_service", default)]
    pub class_of_service: Option<ClassOfServiceSnapshot>,
    #[serde(rename = "flow_export", default)]
    pub flow_export: Option<FlowExportSnapshot>,
    #[serde(default)]
    pub userspace: serde_json::Value,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(rename = "defer_workers", default)]
    pub defer_workers: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ZoneSnapshot {
    pub name: String,
    #[serde(default)]
    pub id: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FabricSnapshot {
    pub name: String,
    #[serde(rename = "parent_interface", default)]
    pub parent_interface: String,
    #[serde(rename = "parent_linux_name", default)]
    pub parent_linux_name: String,
    #[serde(rename = "parent_ifindex", default)]
    pub parent_ifindex: i32,
    #[serde(rename = "overlay_linux_name", default)]
    pub overlay_linux_name: String,
    #[serde(rename = "overlay_ifindex", default)]
    pub overlay_ifindex: i32,
    #[serde(rename = "rx_queues", default)]
    pub rx_queues: usize,
    #[serde(rename = "peer_address", default)]
    pub peer_address: String,
    #[serde(rename = "local_mac", default)]
    pub local_mac: String,
    #[serde(rename = "peer_mac", default)]
    pub peer_mac: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct TunnelEndpointSnapshot {
    #[serde(default)]
    pub id: u16,
    #[serde(default)]
    pub interface: String,
    #[serde(rename = "linux_name", default)]
    pub linux_name: String,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(default)]
    pub zone: String,
    #[serde(rename = "redundancy_group", default)]
    pub redundancy_group: i32,
    #[serde(default)]
    pub mtu: i32,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "outer_family", default)]
    pub outer_family: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub key: u32,
    #[serde(default)]
    pub ttl: i32,
    #[serde(rename = "transport_table", default)]
    pub transport_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SourceNATRuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    #[serde(rename = "interface_mode", default)]
    pub interface_mode: bool,
    #[serde(default)]
    pub off: bool,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
    #[serde(rename = "pool_addresses", default)]
    pub pool_addresses: Vec<String>,
    #[serde(rename = "port_low", default)]
    pub port_low: u16,
    #[serde(rename = "port_high", default)]
    pub port_high: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct StaticNATRuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "external_ip", default)]
    pub external_ip: String,
    #[serde(rename = "internal_ip", default)]
    pub internal_ip: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct DestinationNATRuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "destination_address", default)]
    pub destination_address: String,
    #[serde(rename = "destination_port", default)]
    pub destination_port: u16,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "pool_address", default)]
    pub pool_address: String,
    #[serde(rename = "pool_port", default)]
    pub pool_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct NAT64RuleSnapshot {
    pub name: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(rename = "pool_addresses", default)]
    pub pool_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct Nptv6RuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "internal_prefix", default)]
    pub internal_prefix: String,
    #[serde(rename = "external_prefix", default)]
    pub external_prefix: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ScreenProfileSnapshot {
    pub zone: String,
    #[serde(default)]
    pub land: bool,
    #[serde(rename = "syn_fin", default)]
    pub syn_fin: bool,
    #[serde(rename = "tcp_no_flag", default)]
    pub tcp_no_flag: bool,
    #[serde(rename = "fin_no_ack", default)]
    pub fin_no_ack: bool,
    #[serde(default)]
    pub winnuke: bool,
    #[serde(rename = "ping_death", default)]
    pub ping_death: bool,
    #[serde(default)]
    pub teardrop: bool,
    #[serde(rename = "icmp_fragment", default)]
    pub icmp_fragment: bool,
    #[serde(rename = "source_route", default)]
    pub source_route: bool,
    #[serde(rename = "icmp_flood_threshold", default)]
    pub icmp_flood_threshold: u32,
    #[serde(rename = "udp_flood_threshold", default)]
    pub udp_flood_threshold: u32,
    #[serde(rename = "syn_flood_threshold", default)]
    pub syn_flood_threshold: u32,
    #[serde(rename = "session_limit_src", default)]
    pub session_limit_src: u32,
    #[serde(rename = "session_limit_dst", default)]
    pub session_limit_dst: u32,
    #[serde(rename = "port_scan_threshold", default)]
    pub port_scan_threshold: u32,
    #[serde(rename = "ip_sweep_threshold", default)]
    pub ip_sweep_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallFilterSnapshot {
    pub name: String,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub terms: Vec<FirewallTermSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallTermSnapshot {
    pub name: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(rename = "source_ports", default)]
    pub source_ports: Vec<String>,
    #[serde(rename = "destination_ports", default)]
    pub destination_ports: Vec<String>,
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub count: String,
    #[serde(default)]
    pub log: bool,
    #[serde(default)]
    pub policer: String,
    #[serde(rename = "routing_instance", default)]
    pub routing_instance: String,
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "dscp_rewrite", default)]
    pub dscp_rewrite: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicerSnapshot {
    pub name: String,
    #[serde(rename = "bandwidth_bps", default)]
    pub bandwidth_bps: u64,
    #[serde(rename = "burst_bytes", default)]
    pub burst_bytes: u64,
    #[serde(rename = "discard_excess", default)]
    pub discard_excess: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FlowExportSnapshot {
    #[serde(rename = "collector_address", default)]
    pub collector_address: String,
    #[serde(rename = "collector_port", default)]
    pub collector_port: u16,
    #[serde(rename = "sampling_rate", default)]
    pub sampling_rate: u32,
    #[serde(rename = "active_timeout", default)]
    pub active_timeout: u32,
    #[serde(rename = "inactive_timeout", default)]
    pub inactive_timeout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyRuleSnapshot {
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(rename = "application_terms", default)]
    pub application_terms: Vec<PolicyApplicationSnapshot>,
    #[serde(default)]
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyApplicationSnapshot {
    pub name: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "source_port", default)]
    pub source_port: String,
    #[serde(rename = "destination_port", default)]
    pub destination_port: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct MapPins {
    #[serde(default)]
    pub ctrl: String,
    #[serde(default)]
    pub bindings: String,
    #[serde(default)]
    pub heartbeat: String,
    #[serde(default)]
    pub xsk: String,
    #[serde(rename = "local_v4", default)]
    pub local_v4: String,
    #[serde(rename = "local_v6", default)]
    pub local_v6: String,
    #[serde(default)]
    pub sessions: String,
    #[serde(rename = "conntrack_v4", default)]
    pub conntrack_v4: String,
    #[serde(rename = "conntrack_v6", default)]
    pub conntrack_v6: String,
    #[serde(rename = "dnat_table", default)]
    pub dnat_table: String,
    #[serde(rename = "dnat_table_v6", default)]
    pub dnat_table_v6: String,
    #[serde(default)]
    pub trace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct UserspaceCapabilities {
    #[serde(rename = "forwarding_supported", default)]
    pub forwarding_supported: bool,
    #[serde(rename = "unsupported_reasons", default)]
    pub unsupported_reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Control request / response
// ---------------------------------------------------------------------------

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
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    #[serde(rename = "route_entries", default)]
    pub route_entries: usize,
    #[serde(rename = "worker_heartbeats", default)]
    pub worker_heartbeats: Vec<DateTime<Utc>>,
    // #710: cluster-wide aggregate of cross-worker CoS redirects that
    // could not locate a binding for their target egress on the landing
    // worker. Summed across all bindings in `refresh_status` — the
    // per-binding accounting is a mechanical choice (the increment
    // always lands on the landing worker's first binding), so the
    // per-binding view would be misleading as triage signal; the total
    // is the operator-facing number.
    #[serde(rename = "cos_no_owner_binding_drops_total", default)]
    pub cos_no_owner_binding_drops_total: u64,
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
    #[serde(rename = "filter_term_counters", default)]
    pub filter_term_counters: Vec<FirewallFilterTermCounterStatus>,
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
pub(crate) struct CoSInterfaceStatus {
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "interface_name", default)]
    pub interface_name: String,
    #[serde(
        rename = "owner_worker_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_worker_id: Option<u32>,
    #[serde(rename = "shaping_rate_bytes", default)]
    pub shaping_rate_bytes: u64,
    #[serde(rename = "burst_bytes", default)]
    pub burst_bytes: u64,
    #[serde(rename = "worker_instances", default)]
    pub worker_instances: usize,
    #[serde(rename = "nonempty_queues", default)]
    pub nonempty_queues: usize,
    #[serde(rename = "runnable_queues", default)]
    pub runnable_queues: usize,
    #[serde(rename = "timer_level0_sleepers", default)]
    pub timer_level0_sleepers: usize,
    #[serde(rename = "timer_level1_sleepers", default)]
    pub timer_level1_sleepers: usize,
    #[serde(default)]
    pub queues: Vec<CoSQueueStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct CoSQueueStatus {
    #[serde(rename = "queue_id", default)]
    pub queue_id: u8,
    #[serde(
        rename = "owner_worker_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_worker_id: Option<u32>,
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(default)]
    pub priority: u8,
    #[serde(default)]
    pub exact: bool,
    #[serde(rename = "transmit_rate_bytes", default)]
    pub transmit_rate_bytes: u64,
    #[serde(rename = "buffer_bytes", default)]
    pub buffer_bytes: u64,
    #[serde(rename = "worker_instances", default)]
    pub worker_instances: usize,
    #[serde(rename = "queued_packets", default)]
    pub queued_packets: u64,
    #[serde(rename = "queued_bytes", default)]
    pub queued_bytes: u64,
    #[serde(rename = "runnable_instances", default)]
    pub runnable_instances: usize,
    #[serde(rename = "parked_instances", default)]
    pub parked_instances: usize,
    #[serde(rename = "next_wakeup_tick", default)]
    pub next_wakeup_tick: u64,
    #[serde(rename = "surplus_deficit_bytes", default)]
    pub surplus_deficit_bytes: u64,
    // #710 drop-reason counters, aggregated across worker instances for
    // this (ifindex, queue_id). `parks` are not drops — the queue is
    // only deferred until its root/queue token bucket refills — but
    // tracking them alongside drops tells an operator which *scheduler*
    // decision is limiting the queue. See `types::CoSQueueDropCounters`
    // for per-reason semantics and refs to the issues driving each.
    #[serde(rename = "admission_flow_share_drops", default)]
    pub admission_flow_share_drops: u64,
    #[serde(rename = "admission_buffer_drops", default)]
    pub admission_buffer_drops: u64,
    /// #718: packets ECN CE-marked at admission (not dropped). A rising
    /// counter here indicates the admission-threshold signalling is
    /// steering ECN-negotiated TCP flows; operators should see
    /// per-queue retrans rates fall while this increments.
    #[serde(rename = "admission_ecn_marked", default)]
    pub admission_ecn_marked: u64,
    /// #708: packets tail-dropped by the per-SFQ-bucket pacing gate
    /// because the target bucket had fewer pacing tokens than the
    /// packet's byte count. Sits *after* the ECN marker in
    /// `enqueue_cos_item` so ECT packets above the ECN threshold get
    /// marked on the previously-admitted packet AND tail-dropped
    /// here — consistent signals for the sender. A non-zero value
    /// with a steady `admission_ecn_marked` means pacing is absorbing
    /// microbursts the ECN marker couldn't catch in time.
    /// Zero with a steady `admission_flow_share_drops` means the
    /// residual is not microburst-driven; per plan §3 that is a valid
    /// "gate implemented, dormant on workload" outcome.
    #[serde(rename = "admission_pacing_drops", default)]
    pub admission_pacing_drops: u64,
    #[serde(rename = "root_token_starvation_parks", default)]
    pub root_token_starvation_parks: u64,
    #[serde(rename = "queue_token_starvation_parks", default)]
    pub queue_token_starvation_parks: u64,
    #[serde(rename = "tx_ring_full_submit_stalls", default)]
    pub tx_ring_full_submit_stalls: u64,
    // #709: owner-profile telemetry for exact queues with a single
    // owner binding. See `docs/709-owner-hotspot-plan.md` for the
    // measurement methodology. These fields are populated from the
    // owner binding's `BindingLiveState` when the queue is exact and
    // not shared; for shared_exact and non-exact queues they are
    // zero. The serde wire format is the cross-language contract to
    // Go (pkg/dataplane/userspace/protocol.go); rename strings MUST
    // match byte-for-byte. Histograms are `Vec<u64>` on the wire so
    // serde can serialise them without a schema for the fixed-size
    // array; the Rust side always fills them to DRAIN_HIST_BUCKETS.
    #[serde(rename = "drain_latency_hist", default)]
    pub drain_latency_hist: Vec<u64>,
    #[serde(rename = "drain_invocations", default)]
    pub drain_invocations: u64,
    #[serde(rename = "drain_noop_invocations", default)]
    pub drain_noop_invocations: u64,
    #[serde(rename = "redirect_acquire_hist", default)]
    pub redirect_acquire_hist: Vec<u64>,
    #[serde(rename = "owner_pps", default)]
    pub owner_pps: u64,
    #[serde(rename = "peer_pps", default)]
    pub peer_pps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallFilterTermCounterStatus {
    #[serde(default)]
    pub family: String,
    #[serde(rename = "filter_name", default)]
    pub filter_name: String,
    #[serde(rename = "term_name", default)]
    pub term_name: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
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
pub(crate) struct PacketResolution {
    pub disposition: String,
    #[serde(rename = "local_ifindex", default)]
    pub local_ifindex: i32,
    #[serde(rename = "egress_ifindex", default)]
    pub egress_ifindex: i32,
    #[serde(rename = "ingress_ifindex", default)]
    pub ingress_ifindex: i32,
    #[serde(rename = "next_hop", default)]
    pub next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    pub neighbor_mac: String,
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
    #[serde(rename = "lease_until", default, skip_serializing_if = "u64_is_zero")]
    pub lease_until: u64,
}

pub(crate) fn u64_is_zero(value: &u64) -> bool {
    *value == 0
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
    #[serde(rename = "debug_in_flight_recycles", default)]
    pub debug_in_flight_recycles: u32,
    #[serde(rename = "last_error", default)]
    pub last_error: String,
    #[serde(rename = "last_change", skip_serializing_if = "Option::is_none")]
    pub last_change: Option<DateTime<Utc>>,
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
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
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
