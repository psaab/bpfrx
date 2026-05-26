//! NAT rule snapshots (Source/Destination/Static/NAT64/Nptv6) and
//! per-pool status (`SourceNatPoolStatus`). Leaf module — no cross-domain
//! protocol refs.

use serde::{Deserialize, Serialize};

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
    #[serde(rename = "address_persistent", default)]
    pub address_persistent: bool,
    #[serde(rename = "persistent_nat", default)]
    pub persistent_nat: bool,
    #[serde(rename = "persistent_nat_permit_any_remote_host", default)]
    pub persistent_nat_permit_any_remote_host: bool,
    #[serde(rename = "persistent_nat_inactivity_timeout", default)]
    pub persistent_nat_inactivity_timeout: i64,
    #[serde(rename = "pool_unusable", default)]
    pub pool_unusable: bool,
    #[serde(rename = "pool_unusable_reason", default)]
    pub pool_unusable_reason: String,
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

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct SourceNatPoolStatus {
    #[serde(rename = "rule_name", default)]
    pub rule_name: String,
    #[serde(rename = "pool_name", default)]
    pub pool_name: String,
    #[serde(rename = "address_count", default)]
    pub address_count: usize,
    #[serde(rename = "port_low", default)]
    pub port_low: u16,
    #[serde(rename = "port_high", default)]
    pub port_high: u16,
    #[serde(rename = "persistent_nat", default)]
    pub persistent_nat: bool,
    #[serde(rename = "persistent_nat_permit_any_remote_host", default)]
    pub persistent_nat_permit_any_remote_host: bool,
    #[serde(rename = "persistent_nat_inactivity_timeout", default)]
    pub persistent_nat_inactivity_timeout: i64,
    #[serde(rename = "live_flows", default)]
    pub live_flows: u64,
    #[serde(rename = "used_ports", default)]
    pub used_ports: u64,
    #[serde(rename = "persistent_leases", default)]
    pub persistent_leases: u64,
    #[serde(rename = "max_tracked_flows", default)]
    pub max_tracked_flows: u64,
    #[serde(rename = "allocations_total", default)]
    pub allocations_total: u64,
    #[serde(rename = "reuses_total", default)]
    pub reuses_total: u64,
    #[serde(rename = "exhaustion_total", default)]
    pub exhaustion_total: u64,
}

