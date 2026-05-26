//! Per-packet trace types (`PacketResolution`, `FlowTupleStatus`,
//! `FlowWorkerStatus`). `FlowTupleStatus::from_session_key` consumes the
//! crate-level `crate::session::SessionKey` and is the only outside
//! dependency.

use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct FlowTupleStatus {
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
}

impl FlowTupleStatus {
    pub(crate) fn from_session_key(key: &crate::session::SessionKey) -> Self {
        Self {
            addr_family: key.addr_family,
            protocol: key.protocol,
            src_ip: key.src_ip.to_string(),
            dst_ip: key.dst_ip.to_string(),
            src_port: key.src_port,
            dst_port: key.dst_port,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct FlowWorkerStatus {
    #[serde(default)]
    pub slot: u32,
    #[serde(rename = "queue_id", default)]
    pub queue_id: u32,
    #[serde(rename = "worker_id", default)]
    pub worker_id: u32,
    #[serde(default)]
    pub interface: std::sync::Arc<str>,
    #[serde(default)]
    pub ifindex: i32,
    #[serde(rename = "ingress_ifindex", default)]
    pub ingress_ifindex: i32,
    #[serde(rename = "egress_ifindex", default)]
    pub egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    pub tx_ifindex: i32,
    #[serde(rename = "session_key", default)]
    pub session_key: FlowTupleStatus,
    #[serde(rename = "forward_wire_key", default)]
    pub forward_wire_key: FlowTupleStatus,
    #[serde(rename = "reverse_canonical_key", default)]
    pub reverse_canonical_key: FlowTupleStatus,
    #[serde(
        rename = "cos_queue_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cos_queue_id: Option<u8>,
    #[serde(
        rename = "dscp_rewrite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dscp_rewrite: Option<u8>,
    #[serde(rename = "age_epochs", default)]
    pub age_epochs: u16,
    #[serde(rename = "observed_bytes", default)]
    pub observed_bytes: u64,
}

