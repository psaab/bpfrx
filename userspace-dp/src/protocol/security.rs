//! Security-policy DTOs (screens, firewall filters, policers, three-color
//! policers, flow-export, zone policy rules, policy applications) plus
//! their runtime counter twins. Leaf module — no cross-domain protocol
//! refs.

use serde::{Deserialize, Serialize};

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
    /// #1137: TCP SYN packet that's also the first fragment of a
    /// fragmented datagram — a fragmentation-based attack signature.
    #[serde(rename = "syn_frag", default)]
    pub syn_frag: bool,
    #[serde(rename = "source_route", default)]
    pub source_route: bool,
    #[serde(rename = "icmp_flood_threshold", default)]
    pub icmp_flood_threshold: u32,
    #[serde(rename = "udp_flood_threshold", default)]
    pub udp_flood_threshold: u32,
    #[serde(rename = "syn_flood_threshold", default)]
    pub syn_flood_threshold: u32,
    #[serde(rename = "syn_cookie", default)]
    pub syn_cookie: bool,
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
pub(crate) struct ThreeColorPolicerSnapshot {
    pub name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "color_blind", default)]
    pub color_blind: bool,
    #[serde(rename = "committed_rate_bytes_per_sec", default)]
    pub committed_rate_bytes_per_sec: u64,
    #[serde(rename = "committed_burst_bytes", default)]
    pub committed_burst_bytes: u64,
    #[serde(rename = "peak_or_excess_rate_bytes_per_sec", default)]
    pub peak_or_excess_rate_bytes_per_sec: u64,
    #[serde(rename = "peak_or_excess_burst_bytes", default)]
    pub peak_or_excess_burst_bytes: u64,
    #[serde(rename = "then_action", default)]
    pub then_action: String,
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
    #[serde(rename = "rule_id", default)]
    pub rule_id: String,
    #[serde(rename = "policy_id", default)]
    pub policy_id: u32,
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "scheduler_name", default)]
    pub scheduler_name: String,
    #[serde(default)]
    pub inactive: bool,
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
pub(crate) struct PolicyRuleCounterStatus {
    #[serde(rename = "rule_id", default)]
    pub rule_id: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
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
pub(crate) struct ThreeColorPolicerStatus {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "color_blind", default)]
    pub color_blind: bool,
    #[serde(rename = "green_packets", default)]
    pub green_packets: u64,
    #[serde(rename = "green_bytes", default)]
    pub green_bytes: u64,
    #[serde(rename = "yellow_packets", default)]
    pub yellow_packets: u64,
    #[serde(rename = "yellow_bytes", default)]
    pub yellow_bytes: u64,
    #[serde(rename = "red_packets", default)]
    pub red_packets: u64,
    #[serde(rename = "red_bytes", default)]
    pub red_bytes: u64,
    #[serde(rename = "drop_packets", default)]
    pub drop_packets: u64,
    #[serde(rename = "drop_bytes", default)]
    pub drop_bytes: u64,
}


