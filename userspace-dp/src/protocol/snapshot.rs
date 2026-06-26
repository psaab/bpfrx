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
    AddressBookSnapshot, AppCatalogEntry, FirewallFilterSnapshot, FlowExportSnapshot,
    PolicerSnapshot, PolicyRuleSnapshot, ScreenProfileSnapshot, ThreeColorPolicerSnapshot,
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
    /// Bare routing-instance name this interface belongs to ("" = the
    /// default instance). Used to scope connected routes rebuilt from
    /// interface addresses to the owning routing table (#2388). Additive
    /// via serde default: absent on snapshots from an old Go binary, in
    /// which case the interface is treated as the default instance (the
    /// pre-#2388 global behavior).
    #[serde(rename = "routing_instance", default)]
    pub routing_instance: String,
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
    /// Junos route preference (administrative distance; lower = more
    /// preferred, default 5). The FIB tie-breaks two same-prefix routes in
    /// a table by ascending preference BEFORE insertion order (#2390).
    /// serde default 0 keeps wire parity with an old Go binary that omits
    /// the field (0 is the most-preferred value; for the common
    /// single-route-per-prefix case the tie-break never fires, so behavior
    /// is unchanged).
    #[serde(default)]
    pub preference: i32,
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
    /// `security flow power-mode-disable` (#2008 H14). On vSRX power-mode is
    /// an express datapath; disabling it forces the regular flow path. The
    /// userspace dataplane has a single forwarding path, so this is threaded
    /// into ForwardingState for parity and config truth. Absent / false on
    /// snapshots from old Go binaries (additive field).
    #[serde(rename = "power_mode_disable", default)]
    pub power_mode_disable: bool,
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
    /// #2008 M5: L3/L4 application-identification catalog. Empty on snapshots
    /// from old Go binaries (additive field) — every session then keeps app_id
    /// 0, the existing unknown default.
    #[serde(rename = "app_catalog", default)]
    pub app_catalog: Vec<AppCatalogEntry>,
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
    /// #2130: reserved wire field. Flow export (NetFlow v9 / IPFIX) is owned
    /// entirely by the Go control plane (pkg/flowexport); the dataplane emits
    /// no flow records. The dead Rust FlowExporter that once consumed this was
    /// removed, but the field is retained as documented-reserved to preserve
    /// the #1977 NUM_WIDTH decode-safety tests (protocol/tests.rs) and avoid a
    /// cross-language wire-protocol break. It is deserialized and ignored.
    #[allow(dead_code)]
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

/// Default MTU floor for the slow-path TUN (#2408). The kernel creates a TUN
/// at 1500 by default; never set it below that even if the snapshot carries
/// no usable interface MTU.
pub(crate) const SLOW_PATH_MTU_FLOOR: i32 = 1500;

impl ConfigSnapshot {
    /// MTU to program on the slow-path TUN (#2408).
    ///
    /// Firewall-local and exception packets are reinjected through the
    /// slow-path TUN device, which the kernel creates at the default 1500
    /// MTU. On a jumbo-frame topology a reinjected frame larger than 1500
    /// is silently dropped on the TUN egress. The TUN must therefore accept
    /// any frame the dataplane handles, so size it to the LARGEST configured
    /// data-interface MTU (clamped to a 1500 floor so we never shrink the
    /// kernel default). Sourced from the per-interface MTU the control plane
    /// already carries in the snapshot — never hardcoded.
    pub(crate) fn slow_path_mtu(&self) -> i32 {
        self.interfaces
            .iter()
            .map(|iface| iface.mtu)
            .filter(|mtu| *mtu > 0)
            .max()
            .unwrap_or(SLOW_PATH_MTU_FLOOR)
            .max(SLOW_PATH_MTU_FLOOR)
    }
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
    /// #3070: whether the zone declared a `host-inbound-traffic` stanza. When
    /// false the dataplane preserves admit-all for host-bound (local-delivery)
    /// traffic on this zone; when true it default-denies host-bound traffic
    /// whose system-service / protocol is not in the sets below (Junos
    /// host-inbound posture). serde(default) keeps wire parity with an older Go
    /// control plane that omits the field (#1961).
    #[serde(rename = "host_inbound_configured", default)]
    pub host_inbound_configured: bool,
    /// #3070: the zone's `host-inbound-traffic system-services` tokens
    /// (lower-cased Junos names: ssh, ping, dhcp, ike, ...). Classified to L4
    /// signatures at build time (`zone_host_inbound_from_snapshot`).
    #[serde(rename = "host_inbound_system_services", default)]
    pub host_inbound_system_services: Vec<String>,
    /// #3070: the zone's `host-inbound-traffic protocols` tokens (lower-cased
    /// Junos names: ospf, bgp, router-discovery, ...).
    #[serde(rename = "host_inbound_protocols", default)]
    pub host_inbound_protocols: Vec<String>,
    /// #3071: Junos `security zones security-zone <z> tcp-rst`. When true,
    /// a TCP flow DENIED by policy/default-deny whose INGRESS (from) zone is
    /// this zone is answered with a TCP RST toward the source instead of the
    /// silent drop `deny` otherwise produces. Non-TCP denied traffic is
    /// unaffected. Additive via serde default: a snapshot from an old Go
    /// binary lacks the field, in which case the zone is treated as tcp-rst
    /// off (the pre-#3071 silent-drop behavior).
    #[serde(rename = "tcp_rst", default)]
    pub tcp_rst: bool,
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
    /// Ordered per-peer set (#1434 multi-peer). The Go control plane
    /// sorts by pubkey at the snapshot-builder boundary so both HA
    /// nodes serialize byte-identical snapshots. The engine peer table
    /// is fed from this slice; RX/decap demuxes by receiver_index
    /// across ALL peers, and TX/encap selects the peer by inner-dst
    /// AllowedIPs LPM (#1434 B1b).
    #[serde(rename = "wg_peers", default)]
    pub wg_peers: Vec<TunnelWgPeerSnapshot>,
}

/// One WireGuard peer on the Go→Rust wire (#1434). Mirrors the Go
/// TunnelWgPeerWire (pkg/dataplane/userspace/protocol.go). Keep json
/// tags identical on BOTH sides.
#[derive(Clone, Serialize, Deserialize, Default)]
pub(crate) struct TunnelWgPeerSnapshot {
    /// Peer's static public key, hex-encoded.
    #[serde(rename = "wg_peer_pubkey_hex", default)]
    pub wg_peer_pubkey_hex: String,
    /// Peer AllowedIPs, as CIDR strings. Consulted on the decap path
    /// (inner src-IP gate) AND on the encap path (#1434 B1b inner-dst
    /// → peer LPM).
    #[serde(rename = "wg_allowed_ips", default)]
    pub wg_allowed_ips: Vec<String>,
    /// Optional peer endpoint (`IP:port`) for initiator-role
    /// handshakes. Empty for responder-only.
    #[serde(rename = "wg_endpoint", default)]
    pub wg_endpoint: String,
    /// Optional persistent keepalive in seconds. 0 = off.
    #[serde(rename = "wg_keepalive_secs", default)]
    pub wg_keepalive_secs: u16,
    /// Optional per-peer preshared key, hex-encoded (#1434 B2). Empty
    /// = zero PSK. SECRET: like wg_local_privkey_hex it is delivered
    /// on the control socket (the engine needs it) but is
    /// `skip_serializing` so it can NEVER be written back into the
    /// on-disk state snapshot. The custom Debug impl on
    /// TunnelEndpointSnapshot redacts the whole peer set; see also the
    /// per-peer Debug below.
    #[serde(rename = "wg_preshared_key_hex", default, skip_serializing)]
    pub wg_preshared_key_hex: String,
}

impl std::fmt::Debug for TunnelWgPeerSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the PSK; the pubkey/allowed-ips/endpoint are not
        // secret and are useful for triage.
        let psk_state = if self.wg_preshared_key_hex.is_empty() {
            "<unset>"
        } else {
            "<redacted>"
        };
        f.debug_struct("TunnelWgPeerSnapshot")
            .field("wg_peer_pubkey_hex", &self.wg_peer_pubkey_hex)
            .field("wg_allowed_ips", &self.wg_allowed_ips)
            .field("wg_endpoint", &self.wg_endpoint)
            .field("wg_keepalive_secs", &self.wg_keepalive_secs)
            .field("wg_preshared_key_hex", &psk_state)
            .finish()
    }
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
            // wg_peers uses TunnelWgPeerSnapshot's own Debug, which
            // redacts each peer's PSK.
            .field("wg_peers", &self.wg_peers)
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
            wg_peers: vec![TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex:
                    "b02020202020202020202020202020202020202020202020202020202020202b".into(),
                ..Default::default()
            }],
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

#[cfg(test)]
mod zone_tcp_rst_tests {
    use super::*;

    // #3071: the per-zone `tcp-rst` knob round-trips over the JSON control
    // wire byte-identically with the Go ZoneSnapshot (`tcp_rst`).
    #[test]
    fn zone_snapshot_tcp_rst_serializes_to_tcp_rst_key() {
        let z = ZoneSnapshot {
            name: "trust".to_string(),
            id: 1,
            tcp_rst: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&z).expect("serialize");
        assert!(
            json.contains("\"tcp_rst\":true"),
            "expected tcp_rst:true in wire JSON, got {json}"
        );
    }

    // Decode the EXACT shape the Go emitter produces for a tcp-rst zone.
    #[test]
    fn zone_snapshot_decodes_go_tcp_rst_payload() {
        let z: ZoneSnapshot =
            serde_json::from_str(r#"{"name":"trust","id":1,"tcp_rst":true}"#).expect("decode");
        assert_eq!(z.name, "trust");
        assert_eq!(z.id, 1);
        assert!(z.tcp_rst, "tcp_rst must decode to true");
    }

    // Cross-version default: a snapshot from an old Go binary omits the field
    // (omitempty), and serde must default it to false (pre-#3071 silent drop).
    #[test]
    fn zone_snapshot_missing_tcp_rst_defaults_false() {
        let z: ZoneSnapshot = serde_json::from_str(r#"{"name":"untrust","id":2}"#).expect("decode");
        assert!(!z.tcp_rst, "missing tcp_rst must default to false");
    }
}

#[cfg(test)]
mod slow_path_mtu_tests {
    use super::*;

    fn iface(mtu: i32) -> InterfaceSnapshot {
        InterfaceSnapshot {
            mtu,
            ..Default::default()
        }
    }

    // #2408: the slow-path TUN MTU must track the LARGEST configured
    // data-interface MTU so reinjected jumbo frames are not dropped. This
    // FAILS if the helper hardcodes 1500 / does not pick the max.
    #[test]
    fn picks_largest_interface_mtu_for_jumbo() {
        let snap = ConfigSnapshot {
            interfaces: vec![iface(1500), iface(9000), iface(1400)],
            ..Default::default()
        };
        assert_eq!(snap.slow_path_mtu(), 9000);
    }

    // The value is SOURCED from the interface MTU, not the 1500 default — a
    // single configured interface at 8000 must propagate.
    #[test]
    fn sources_value_from_single_interface() {
        let snap = ConfigSnapshot {
            interfaces: vec![iface(8000)],
            ..Default::default()
        };
        assert_eq!(snap.slow_path_mtu(), 8000);
    }

    // Never shrink below the kernel default TUN MTU (1500 floor), even if
    // some interface carries a smaller MTU.
    #[test]
    fn never_below_1500_floor() {
        let snap = ConfigSnapshot {
            interfaces: vec![iface(1280), iface(576)],
            ..Default::default()
        };
        assert_eq!(snap.slow_path_mtu(), SLOW_PATH_MTU_FLOOR);
        assert_eq!(SLOW_PATH_MTU_FLOOR, 1500);
    }

    // No interfaces / no usable MTU -> the 1500 floor, never 0.
    #[test]
    fn empty_or_zero_mtu_falls_back_to_floor() {
        let empty = ConfigSnapshot::default();
        assert_eq!(empty.slow_path_mtu(), SLOW_PATH_MTU_FLOOR);

        let zeros = ConfigSnapshot {
            interfaces: vec![iface(0), iface(-1)],
            ..Default::default()
        };
        assert_eq!(zeros.slow_path_mtu(), SLOW_PATH_MTU_FLOOR);
    }

    // Non-positive (0 / negative) MTUs are ignored; the largest positive wins.
    #[test]
    fn ignores_nonpositive_mtus() {
        let snap = ConfigSnapshot {
            interfaces: vec![iface(0), iface(9216), iface(-9), iface(1500)],
            ..Default::default()
        };
        assert_eq!(snap.slow_path_mtu(), 9216);
    }
}
