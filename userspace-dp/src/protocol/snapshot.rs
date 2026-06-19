//! Configuration snapshot DTOs published by the daemon over the control
//! socket. Maps the daemon's typed Junos config into the wire shapes the
//! Rust userspace dataplane consumes. See `protocol/mod.rs` for the
//! domain split overview (#1325).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::cos::ClassOfServiceSnapshot;
use super::nat::{
    DestinationNATRuleSnapshot, NAT64RuleSnapshot, Nptv6RuleSnapshot, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot,
};
use super::security::{
    AddressBookSnapshot, FirewallFilterSnapshot, FlowExportSnapshot, PolicerSnapshot,
    PolicyRuleSnapshot, ScreenProfileSnapshot, ThreeColorPolicerSnapshot,
};

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
    /// #1614 A1: operator-selectable oversubscription policy.
    /// "" or "proportional" (default) → current scheduler unchanged
    /// bit-for-bit. "guarantee-rate" → two-phase waterfill allocator
    /// using `cos_oversubscription_guarantee_fraction`.
    #[serde(rename = "cos_oversubscription_policy", default)]
    pub cos_oversubscription_policy: String,
    /// #1614 A1: Phase 1 budget fraction (0.0..1.0) when
    /// `cos_oversubscription_policy == "guarantee-rate"`. Default 0
    /// (which makes the new allocator a no-op even if mode is set;
    /// belt-and-suspenders).
    #[serde(rename = "cos_oversubscription_guarantee_fraction", default)]
    pub cos_oversubscription_guarantee_fraction: f64,
    /// #1614 A2: priority-low minimum share in bytes per second.
    /// WIRE SURFACE ONLY in PR #1618 — the per-pass `cap_eff`
    /// subtraction in the selector is deferred to a focused
    /// follow-up issue. Default 0 (no min-share). The runtime
    /// reads this field through `CoSInterfaceConfig` to plumb the
    /// value into `CoSInterfaceRuntime`, but no hot-path code
    /// consumes it yet.
    #[serde(rename = "cos_priority_low_min_share_bytes", default)]
    pub cos_priority_low_min_share_bytes: u64,
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
    /// `security alg <proto> disable` bitfield (#2008 H3/H4): bit 0 DNS,
    /// bit 1 FTP, bit 2 SIP, bit 3 TFTP. Matches the Go `algDisableFlags`
    /// encoding. Absent / 0 on snapshots from old Go binaries (additive
    /// field). The dataplane reads this to suppress ALG-type tagging for a
    /// disabled ALG; Junos `alg disable` turns the ALG off, it never drops
    /// traffic.
    #[serde(rename = "alg_disable_flags", default)]
    pub alg_disable_flags: u8,
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
    /// #1606: address-book table (content-hashed deduplication).
    /// Empty on snapshots from old Go binaries (v3-additive field).
    #[serde(rename = "address_books", default)]
    pub address_books: Vec<AddressBookSnapshot>,
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
    #[serde(rename = "syn_cookie_master_key", default)]
    pub syn_cookie_master_key: String,
    #[serde(default)]
    pub filters: Vec<FirewallFilterSnapshot>,
    #[serde(default)]
    pub policers: Vec<PolicerSnapshot>,
    #[serde(rename = "three_color_policers", default)]
    pub three_color_policers: Vec<ThreeColorPolicerSnapshot>,
    #[serde(rename = "class_of_service", default)]
    pub class_of_service: Option<ClassOfServiceSnapshot>,
    #[serde(rename = "flow_export", default)]
    pub flow_export: Option<FlowExportSnapshot>,
    #[serde(rename = "mirror_configs", default)]
    pub mirror_configs: Vec<MirrorConfigSnapshot>,
    #[serde(default)]
    pub userspace: serde_json::Value,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(rename = "defer_workers", default)]
    pub defer_workers: bool,
    /// #1620: cold-path latency histogram sample mask. `Some(mask)`
    /// means an explicit operator setting; `None` means "use the
    /// built-in default 0xff" (1-in-256 sampling). The wire shape is
    /// `Option<u64>` per #1620 plan §4.3 to prevent the
    /// default-skew bug where an older Go daemon serializes the
    /// field absent and a `u64` deserializes to 0 (= 1-in-1, the
    /// wrong default).
    ///
    /// Go-side mirror: `pkg/dataplane/userspace/protocol.go` carries
    /// `ColdPathSampleMask *uint64 json:"cold_path_sample_mask,omitempty"`.
    /// The Go-side CLI validates the mask is a power-of-two-minus-one
    /// and rejects `mask == 0` unless `--enable-cold-path-1-in-1-sampling`
    /// is explicitly set.
    #[serde(rename = "cold_path_sample_mask", default,
            skip_serializing_if = "Option::is_none")]
    pub cold_path_sample_mask: Option<u64>,
}


#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct MirrorConfigSnapshot {
    #[serde(rename = "ingress_ifindex", default)]
    pub ingress_ifindex: i32,
    #[serde(rename = "output_ifindex", default)]
    pub output_ifindex: i32,
    #[serde(default)]
    pub rate: u32,
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

#[derive(Clone, Serialize, Deserialize, Default)]
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
    // WireGuard fields. All `#[serde(default)]` so this stays
    // wire-compatible with old daemons that don't populate them.
    // See docs/pr/wireguard-clean/plan.md for the design.
    #[serde(rename = "wg_listen_port", default)]
    pub wg_listen_port: u16,
    /// Local static private key for the WG interface, hex-encoded
    /// (64 chars for 32 bytes). Empty when `mode != "wireguard"`.
    ///
    /// This field is intentionally `skip_serializing` so it CANNOT
    /// be written back out via any `serde_json` round-trip. The
    /// userspace dataplane persists a JSON snapshot of `ServerState`
    /// to disk via `server::helpers::write_state`, which used to
    /// include this private key in plaintext (Copilot inline review
    /// caught this on the final pre-merge round). Deserialization
    /// still works — the control plane delivers the key on the
    /// control socket via the `default` path. The custom Debug impl
    /// on `TunnelEndpointSnapshot` redacts this field to keep any
    /// future accidental `{:?}` log line from leaking key material.
    #[serde(rename = "wg_local_privkey_hex", default, skip_serializing)]
    pub wg_local_privkey_hex: String,
    /// Peer's static public key, hex-encoded. The WG engine uses
    /// this as the encap key — not AllowedIPs LPM. See plan §
    /// "Engine keying" for why this matters.
    #[serde(rename = "wg_peer_pubkey_hex", default)]
    pub wg_peer_pubkey_hex: String,
    /// Peer AllowedIPs, as CIDR strings. Only consulted on the
    /// decap path (inner src-IP gate); never used to choose a peer
    /// on egress.
    #[serde(rename = "wg_allowed_ips", default)]
    pub wg_allowed_ips: Vec<String>,
    /// Optional peer endpoint (`IP:port`) for initiator-role
    /// handshakes. Empty for responder-only.
    #[serde(rename = "wg_endpoint", default)]
    pub wg_endpoint: String,
    /// Optional persistent keepalive in seconds. 0 = off.
    #[serde(rename = "wg_keepalive_secs", default)]
    pub wg_keepalive_secs: u16,
}

impl std::fmt::Debug for TunnelEndpointSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manually redact `wg_local_privkey_hex`. Use a placeholder
        // that records only whether a key was set so debug logs
        // remain useful for triage without leaking key material.
        let privkey_state = if self.wg_local_privkey_hex.is_empty() {
            "<unset>"
        } else {
            "<redacted>"
        };
        f.debug_struct("TunnelEndpointSnapshot")
            .field("id", &self.id)
            .field("interface", &self.interface)
            .field("linux_name", &self.linux_name)
            .field("ifindex", &self.ifindex)
            .field("zone", &self.zone)
            .field("redundancy_group", &self.redundancy_group)
            .field("mtu", &self.mtu)
            .field("mode", &self.mode)
            .field("outer_family", &self.outer_family)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("key", &self.key)
            .field("ttl", &self.ttl)
            .field("transport_table", &self.transport_table)
            .field("wg_listen_port", &self.wg_listen_port)
            .field("wg_local_privkey_hex", &privkey_state)
            .field("wg_peer_pubkey_hex", &self.wg_peer_pubkey_hex)
            .field("wg_allowed_ips", &self.wg_allowed_ips)
            .field("wg_endpoint", &self.wg_endpoint)
            .field("wg_keepalive_secs", &self.wg_keepalive_secs)
            .finish()
    }
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


#[cfg(test)]
mod wg_snapshot_tests {
    use super::*;

    // #1432 S2a privkey hygiene: wg_local_privkey_hex is skip_serializing
    // so the on-disk state snapshot the helper persists never leaks the
    // private key, while deserialization (control-socket delivery) still
    // populates it via the default path.
    #[test]
    fn wg_local_privkey_hex_is_skipped_in_state_snapshot() {
        let snap = TunnelEndpointSnapshot {
            id: 1,
            mode: "wireguard".into(),
            wg_local_privkey_hex:
                "a01010101010101010101010101010101010101010101010101010101010101a".into(),
            wg_peer_pubkey_hex:
                "b02020202020202020202020202020202020202020202020202020202020202b".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            !json.contains("wg_local_privkey_hex"),
            "private key field must be skip_serializing, got: {json}"
        );
        assert!(
            !json.contains("a01010101"),
            "private key value must not appear in serialized snapshot"
        );
        // The non-secret peer pubkey IS serialized.
        assert!(json.contains("wg_peer_pubkey_hex"));

        // Deserialization (control-socket path) still populates the key.
        let with_key = r#"{"id":1,"mode":"wireguard","wg_local_privkey_hex":"a01010101010101010101010101010101010101010101010101010101010101a"}"#;
        let parsed: TunnelEndpointSnapshot = serde_json::from_str(with_key).unwrap();
        assert_eq!(
            parsed.wg_local_privkey_hex,
            "a01010101010101010101010101010101010101010101010101010101010101a"
        );
    }

    // The redacted Debug impl must not print the private key.
    #[test]
    fn wg_local_privkey_redacted_in_debug() {
        let snap = TunnelEndpointSnapshot {
            id: 1,
            mode: "wireguard".into(),
            wg_local_privkey_hex: "deadbeefdeadbeef".into(),
            ..Default::default()
        };
        let dbg = format!("{snap:?}");
        assert!(!dbg.contains("deadbeef"), "Debug must redact the private key: {dbg}");
    }
}
