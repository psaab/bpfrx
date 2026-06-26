// Forwarding/routing types extracted from afxdp/types/mod.rs (Issue 68.2).
// Includes the forwarding-state aggregator, connected/non-connected
// route entries, egress and tunnel-endpoint descriptors, fabric-link
// descriptor, forwarding disposition + resolution enums, and the
// per-binding lookup table.
//
// Pure relocation. Original `pub(super)` widened to `pub(in crate::afxdp)`
// in this file; types/mod.rs re-exports via `pub(in crate::afxdp) use
// forwarding::*;` so external call sites resolve unchanged.

use super::*;

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct ForwardingState {
    pub(in crate::afxdp) local_v4: FastSet<Ipv4Addr>,
    pub(in crate::afxdp) local_v6: FastSet<Ipv6Addr>,
    pub(in crate::afxdp) interface_nat_v4: FastMap<Ipv4Addr, i32>,
    pub(in crate::afxdp) interface_nat_v6: FastMap<Ipv6Addr, i32>,
    pub(in crate::afxdp) connected_v4: Vec<ConnectedRouteV4>,
    pub(in crate::afxdp) connected_v6: Vec<ConnectedRouteV6>,
    pub(in crate::afxdp) routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    pub(in crate::afxdp) routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    pub(in crate::afxdp) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
    pub(in crate::afxdp) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
    /// #2327: kind-segregated, outer-tuple-keyed index for the GRE
    /// decap fast path. Keyed by the OUTER tuple as seen FROM THE
    /// ENDPOINT's perspective — `(outer_family, endpoint.source,
    /// endpoint.destination)` — so a received GRE frame is matched with
    /// `(meta.addr_family, outer_dst, outer_src)`. Only `mode == "gre"`
    /// / `"ip6gre"` endpoints are indexed (kind-segregation): a GRE
    /// (proto-47) packet can NEVER be decapped against a WireGuard or
    /// any non-GRE row even if its outer tuple/key collide. Each bucket
    /// is a `Vec<u16>` of endpoint IDs so a duplicate outer tuple
    /// (keyed vs unkeyed, or different logical ifindex) is disambiguated
    /// by the GRE key at lookup rather than resolved non-deterministically
    /// by a first-match scan. Replaces the per-packet O(N)
    /// `tunnel_endpoints.values().find(...)` scan (agy #4).
    pub(in crate::afxdp) gre_decap_index: FastMap<(i32, IpAddr, IpAddr), Vec<u16>>,
    /// WireGuard engines keyed by tunnel_endpoint_id (#1432 S2a). One
    /// per `mode == "wireguard"` endpoint. Shared (`Arc`) so workers
    /// hold the engine across a forwarding-state ArcSwap; engine
    /// identity is reused across reloads when the endpoint config is
    /// unchanged (see `forwarding_build::wg`), so the TAI64N clock and
    /// live sessions survive a commit that does not touch the tunnel.
    pub(in crate::afxdp) wg_engines: FastMap<u16, std::sync::Arc<crate::afxdp::wg::WgEngine>>,
    /// True iff any WG engine is configured. Cheap single-bool gate so
    /// non-WG paths never probe `wg_engines` per packet (#1432 §4.5).
    pub(in crate::afxdp) has_wg_tunnels: bool,
    pub(in crate::afxdp) neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    pub(in crate::afxdp) ifindex_to_name: FastMap<i32, String>,
    pub(in crate::afxdp) ifindex_to_config_name: FastMap<i32, String>,
    /// #921: ifindex → zone ID (was `FastMap<i32, String>`). Built
    /// at config-commit time from the snapshot's per-interface
    /// zone NAME via the `zone_name_to_id` lookup. Hot-path callers
    /// read u16 directly; slow-path display sites translate via
    /// `zone_id_to_name`. Unknown / dropped zones map to `0`.
    pub(in crate::afxdp) ifindex_to_zone_id: FastMap<i32, u16>,
    pub(in crate::afxdp) zone_name_to_id: FastMap<String, u16>,
    pub(in crate::afxdp) zone_id_to_name: FastMap<u16, String>,
    /// #3071: zone IDs (from `ZoneSnapshot.tcp_rst`) with Junos `tcp-rst`
    /// enabled. A TCP flow DENIED by policy/default-deny whose ingress
    /// (from) zone is present here is answered with a TCP RST toward the
    /// source instead of a silent drop. Absent zone ⇒ tcp-rst off.
    pub(in crate::afxdp) zone_tcp_rst: FastMap<u16, bool>,
    pub(in crate::afxdp) egress: FastMap<i32, EgressInterface>,
    pub(in crate::afxdp) ingress_logical_ifindex: FastMap<(i32, u16), i32>,
    pub(in crate::afxdp) fabrics: Vec<FabricLink>,
    pub(in crate::afxdp) allow_dns_reply: bool,
    pub(in crate::afxdp) allow_embedded_icmp: bool,
    /// `security alg <proto> disable` bitfield (#2008 H3/H4): bit 0 DNS,
    /// bit 1 FTP, bit 2 SIP, bit 3 TFTP. Read at session-create time to
    /// suppress ALG-type tagging for a disabled ALG. Junos `alg disable`
    /// turns the ALG off; it never drops traffic, so a set bit only
    /// changes the session's reported alg_type to 0 (none).
    pub(in crate::afxdp) alg_disable_flags: u8,
    /// #2008 M5: L3/L4 application-identification catalog. Resolves a session's
    /// 5-tuple to the numeric app_id stamped on the conntrack session at
    /// create time, so `show security flow session` reports a real application
    /// name. Empty when the Go snapshot carries no catalog (AppID disabled or
    /// an old Go binary) — sessions then keep app_id 0 (unknown).
    pub(in crate::afxdp) app_catalog: AppCatalog,
    pub(in crate::afxdp) session_timeouts: crate::session::SessionTimeouts,
    pub(in crate::afxdp) policy: PolicyState,
    pub(in crate::afxdp) source_nat_rules: Vec<SourceNatRule>,
    pub(in crate::afxdp) static_nat: StaticNatTable,
    pub(in crate::afxdp) dnat_table: DnatTable,
    pub(in crate::afxdp) nat64: Nat64State,
    pub(in crate::afxdp) nptv6: Nptv6State,
    pub(in crate::afxdp) screen_profiles: FastMap<String, ScreenProfile>,
    pub(in crate::afxdp) syn_cookie_master_key: Option<[u8; 16]>,
    pub(in crate::afxdp) tunnel_interfaces: FastSet<i32>,
    pub(in crate::afxdp) filter_state: crate::filter::FilterState,
    pub(in crate::afxdp) cos: CoSState,
    pub(in crate::afxdp) tx_selection_enabled_v4: bool,
    pub(in crate::afxdp) tx_selection_enabled_v6: bool,
    #[allow(dead_code)]
    pub(in crate::afxdp) gre_acceleration: bool,
    /// `security flow power-mode-disable` (#2008 H14). vSRX power-mode is an
    /// express datapath; this flag forces the regular flow path when set. The
    /// userspace dataplane has a single forwarding path, so the flag is held
    /// for config truth/parity and does not currently switch behavior (there
    /// is no express/regular split to select between).
    #[allow(dead_code)]
    pub(in crate::afxdp) power_mode_disable: bool,
    // #2130: the dead Rust FlowExporter + its flow_export_config field were
    // removed. Flow export is owned by the Go control plane (pkg/flowexport);
    // the dataplane emits no flow records.
    pub(in crate::afxdp) mirror_configs: FastMap<i32, MirrorRuntimeConfig>,
    pub(in crate::afxdp) tcp_mss_all_tcp: u16,
    pub(in crate::afxdp) tcp_mss_ipsec_vpn: u16,
    pub(in crate::afxdp) tcp_mss_gre_in: u16,
    pub(in crate::afxdp) tcp_mss_gre_out: u16,
    /// #1620: cold-path latency histogram sample mask delivered via
    /// `ConfigSnapshot.cold_path_sample_mask`. `0xff` = 1-in-256
    /// (default); `0` = 1-in-1 (bounded-cohort microbench only,
    /// requires operator-explicit `--enable-cold-path-1-in-1-sampling`
    /// on the Go side). Read by the poll_descriptor pre-eval gate;
    /// updated atomically via ArcSwap on every snapshot apply.
    pub(in crate::afxdp) cold_path_sample_mask: u64,
    /// #1636 option D: how long a queued packet with an unresolved
    /// neighbor is held before being dropped + recycled. Computed per
    /// snapshot in `build_forwarding_state_with_policy_counters_and_previous`
    /// (`compute_pending_neigh_timeout_ns`): 800ms when the kernel
    /// `retrans_time_ms` is <= NEIGH_RETRANS_FAST_THRESHOLD_MS (300ms —
    /// the daemon writes 250 but the kernel jiffy-rounds it to 252 on
    /// HZ=100) on all dataplane interfaces (v4 AND v6) so a dropped SYN is
    /// re-driven before the client's first TCP RTO; otherwise the safe
    /// 2000ms default (sysctl unapplied → fail closed). Re-evaluated every
    /// snapshot so a mid-life sysctl change is picked up. `0` (the
    /// Default) means "unset" — callers fall back to
    /// `PENDING_NEIGH_TIMEOUT_NS`.
    pub(in crate::afxdp) pending_neigh_timeout_ns: u64,
    /// #1635: direct `(from_zone_id, to_zone_id) → slot` map for the
    /// cold-path histogram, built at config apply from the configured
    /// policy zone-pairs. Replaces the splitmix64 16-slot hash. Shared
    /// by all bindings on a worker; read on every sampled session-miss
    /// via `lookup_slot`. Rotated via the ForwardingState ArcSwap.
    pub(in crate::afxdp) cold_path_slot_map:
        std::sync::Arc<crate::afxdp::cold_path_hist::ColdPathSlotMap>,
}

impl ForwardingState {
    /// #3071: true iff zone `zone_id` has Junos `tcp-rst` enabled. Used by the
    /// policy-deny path to decide whether a denied TCP flow whose ingress
    /// (from) zone is `zone_id` gets a TCP RST instead of a silent drop. An
    /// unconfigured / unknown zone (e.g. `0`) is always tcp-rst off.
    pub(in crate::afxdp) fn zone_tcp_rst_enabled(&self, zone_id: u16) -> bool {
        self.zone_tcp_rst.get(&zone_id).copied().unwrap_or(false)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct MirrorRuntimeConfig {
    pub(in crate::afxdp) output_ifindex: i32,
    pub(in crate::afxdp) rate: u32,
}

/// One resolved equal-cost next-hop candidate for a static route (#2389).
/// A route with multiple configured next-hops retains every resolved
/// candidate so the lookup can distribute flows across them and skip a
/// dead candidate. `next_hop == None` with a non-zero `ifindex` is an
/// interface-only ("via <if>") candidate.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct RouteNextHopV4 {
    pub(in crate::afxdp) next_hop: Option<Ipv4Addr>,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct RouteNextHopV6 {
    pub(in crate::afxdp) next_hop: Option<Ipv6Addr>,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// #2388: canonical routing-table name this connected route belongs to
    /// (e.g. "inet.0" or "tenant-a.inet.0"). The lookup filters connected
    /// routes by table so a per-VRF / next-table lookup never matches a
    /// connected prefix owned by a different routing-instance. The
    /// connected vec holds one entry per interface address, so the
    /// per-packet linear scan plus a string compare stays cheap.
    pub(in crate::afxdp) table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ConnectedRouteV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    pub(in crate::afxdp) ifindex: i32,
    pub(in crate::afxdp) tunnel_endpoint_id: u16,
    /// #2388: canonical routing-table name. See `ConnectedRouteV4::table`.
    pub(in crate::afxdp) table: String,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV4 {
    pub(in crate::afxdp) prefix: PrefixV4,
    /// #2389: all resolved equal-cost next-hops. Always non-empty for a
    /// forwarding (non-discard, non-next-table) route; built from the full
    /// `RouteSnapshot.next_hops` vector. The legacy single `next_hop` /
    /// `ifindex` / `tunnel_endpoint_id` accessors below select the FIRST
    /// candidate so existing call sites are unchanged; the multipath
    /// selector reads the whole slice.
    pub(in crate::afxdp) next_hops: Vec<RouteNextHopV4>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) next_table: String,
    /// #2390: Junos route preference (admin distance; lower = preferred).
    pub(in crate::afxdp) preference: i32,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct RouteEntryV6 {
    pub(in crate::afxdp) prefix: PrefixV6,
    /// #2389: all resolved equal-cost next-hops. See `RouteEntryV4`.
    pub(in crate::afxdp) next_hops: Vec<RouteNextHopV6>,
    pub(in crate::afxdp) discard: bool,
    pub(in crate::afxdp) next_table: String,
    /// #2390: Junos route preference (admin distance; lower = preferred).
    pub(in crate::afxdp) preference: i32,
}

impl RouteEntryV4 {
    /// First (primary) next-hop ifindex, or 0 if the route has no resolved
    /// next-hop (discard / next-table). Preserves the pre-#2389 single
    /// next-hop accessor for call sites that do not multipath-select.
    pub(in crate::afxdp) fn ifindex(&self) -> i32 {
        self.next_hops.first().map(|nh| nh.ifindex).unwrap_or(0)
    }
    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
        self.next_hops
            .first()
            .map(|nh| nh.tunnel_endpoint_id)
            .unwrap_or(0)
    }
    pub(in crate::afxdp) fn next_hop(&self) -> Option<Ipv4Addr> {
        self.next_hops.first().and_then(|nh| nh.next_hop)
    }
}

impl RouteEntryV6 {
    pub(in crate::afxdp) fn ifindex(&self) -> i32 {
        self.next_hops.first().map(|nh| nh.ifindex).unwrap_or(0)
    }
    pub(in crate::afxdp) fn tunnel_endpoint_id(&self) -> u16 {
        self.next_hops
            .first()
            .map(|nh| nh.tunnel_endpoint_id)
            .unwrap_or(0)
    }
    pub(in crate::afxdp) fn next_hop(&self) -> Option<Ipv6Addr> {
        self.next_hops.first().and_then(|nh| nh.next_hop)
    }
}

#[cfg(test)]
impl RouteEntryV4 {
    /// Test-only single-next-hop constructor preserving the pre-#2389
    /// `{ ifindex, tunnel_endpoint_id, next_hop }` shape so existing FIB
    /// tests read straightforwardly.
    pub(in crate::afxdp) fn single(
        prefix: PrefixV4,
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv4Addr>,
        discard: bool,
        next_table: String,
        preference: i32,
    ) -> Self {
        RouteEntryV4 {
            prefix,
            next_hops: vec![RouteNextHopV4 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }],
            discard,
            next_table,
            preference,
        }
    }
}

#[cfg(test)]
impl RouteEntryV6 {
    pub(in crate::afxdp) fn single(
        prefix: PrefixV6,
        ifindex: i32,
        tunnel_endpoint_id: u16,
        next_hop: Option<Ipv6Addr>,
        discard: bool,
        next_table: String,
        preference: i32,
    ) -> Self {
        RouteEntryV6 {
            prefix,
            next_hops: vec![RouteNextHopV6 {
                next_hop,
                ifindex,
                tunnel_endpoint_id,
            }],
            discard,
            next_table,
            preference,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct EgressInterface {
    pub(in crate::afxdp) bind_ifindex: i32,
    pub(in crate::afxdp) vlan_id: u16,
    pub(in crate::afxdp) mtu: usize,
    pub(in crate::afxdp) src_mac: [u8; 6],
    /// #921: u16 zone ID (was `zone: String`). Resolved at config
    /// build time via `zone_name_to_id`; `0` means "unknown" (the
    /// zone wasn't in the snapshot's zones list, or had a reserved
    /// id and was dropped).
    pub(in crate::afxdp) zone_id: u16,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) primary_v4: Option<Ipv4Addr>,
    pub(in crate::afxdp) primary_v6: Option<Ipv6Addr>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub(in crate::afxdp) struct TunnelEndpoint {
    pub(in crate::afxdp) id: u16,
    pub(in crate::afxdp) logical_ifindex: i32,
    /// #1865: the snapshot row's attachment label (linux_name, else
    /// the logical interface name) carried so the telemetry row name
    /// fallback chain matches the plan: ifindex_to_name -> this ->
    /// wg-endpoint-<id>. Same convention as
    /// `wg_tombstone_respawn_coherent`'s row_label.
    pub(in crate::afxdp) interface_label: String,
    /// #1873 R-D: the LOGICAL config interface name (snapshot row's
    /// `interface`, e.g. "wg0.0") — the purge-owner identity. NEVER
    /// linux_name (a cosmetic kernel rename must not purge sessions)
    /// and NEVER interface_label (which prefers linux_name).
    pub(in crate::afxdp) interface: String,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) mode: String,
    pub(in crate::afxdp) outer_family: i32,
    pub(in crate::afxdp) source: IpAddr,
    pub(in crate::afxdp) destination: IpAddr,
    pub(in crate::afxdp) key: u32,
    pub(in crate::afxdp) ttl: u8,
    pub(in crate::afxdp) transport_table: String,
    // WireGuard (#1432 S2a, multi-peer #1434). Populated only when
    // mode == "wireguard".
    pub(in crate::afxdp) wg_listen_port: u16,
    /// Local static X25519 private key, hex-decoded. Zeroized on drop
    /// and redacted in Debug — must never leak via `{:?}` or the
    /// on-disk state snapshot.
    pub(in crate::afxdp) wg_local_privkey: zeroize::Zeroizing<[u8; 32]>,
    /// Ordered per-peer set (#1434). Built from the sorted-by-pubkey
    /// wire slice; the engine peer table is fed from this, and the
    /// encap path LPM-selects the peer by inner-dst (#1434 B1b).
    pub(in crate::afxdp) wg_peers: Vec<WgRuntimePeer>,
}

/// One WireGuard peer as hydrated into the runtime forwarding state
/// (#1434). Decoded/parsed from the wire `TunnelWgPeerSnapshot`.
#[derive(Clone)]
pub(in crate::afxdp) struct WgRuntimePeer {
    pub(in crate::afxdp) pubkey: [u8; 32],
    pub(in crate::afxdp) allowed_ips: Vec<ipnet::IpNet>,
    pub(in crate::afxdp) endpoint: Option<std::net::SocketAddr>,
    pub(in crate::afxdp) keepalive_secs: u16,
    /// Per-peer preshared key (#1434 B2), hex-decoded. 32 zero bytes =
    /// no PSK. Zeroized on drop; redacted in the Debug impl. Must never
    /// leak via `{:?}` or the on-disk state snapshot.
    pub(in crate::afxdp) preshared_key: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for WgRuntimePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let psk_state = if *self.preshared_key == [0u8; 32] {
            "<unset>"
        } else {
            "<redacted>"
        };
        f.debug_struct("WgRuntimePeer")
            .field("pubkey", &self.pubkey)
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("preshared_key", &psk_state)
            .finish()
    }
}

impl std::fmt::Debug for TunnelEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact wg_local_privkey end-to-end (#1432 S2a invariant).
        f.debug_struct("TunnelEndpoint")
            .field("id", &self.id)
            .field("logical_ifindex", &self.logical_ifindex)
            .field("interface_label", &self.interface_label)
            .field("redundancy_group", &self.redundancy_group)
            .field("mode", &self.mode)
            .field("outer_family", &self.outer_family)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("key", &self.key)
            .field("ttl", &self.ttl)
            .field("transport_table", &self.transport_table)
            .field("wg_listen_port", &self.wg_listen_port)
            .field(
                "wg_local_privkey",
                &if self.mode == "wireguard" {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            // wg_peers uses WgRuntimePeer's own Debug, which redacts
            // each peer's PSK.
            .field("wg_peers", &self.wg_peers)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(in crate::afxdp) struct FabricLink {
    pub(in crate::afxdp) parent_ifindex: i32,
    pub(in crate::afxdp) overlay_ifindex: i32,
    pub(in crate::afxdp) peer_addr: IpAddr,
    pub(in crate::afxdp) peer_mac: [u8; 6],
    pub(in crate::afxdp) local_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ForwardingDisposition {
    LocalDelivery,
    ForwardCandidate,
    FabricRedirect,
    HAInactive,
    PolicyDenied,
    NoRoute,
    MissingNeighbor,
    DiscardRoute,
    NextTableUnsupported,
}

impl ForwardingDisposition {
    /// Whether this disposition produces a stable forwarding decision that can
    /// be stored in the per-worker flow cache.
    ///
    /// Cacheable:
    ///   - `ForwardCandidate`: Normal forwarded traffic with a resolved
    ///     neighbor and egress interface. The common fast path.
    ///   - `FabricRedirect`: Targets a fabric overlay binding. Cacheable
    ///     because each cache entry captures the owning RG epoch into
    ///     `FlowCacheStamp::owner_rg_epoch` at insert time
    ///     (`flow_cache.rs:60-83`), and `FlowCache::lookup`
    ///     (`flow_cache.rs:314-347`) treats the entry as a miss when
    ///     `current_epoch != entry.stamp.owner_rg_epoch`. The owning RG
    ///     bumps its epoch on every active/standby flip, so the window
    ///     in which a cached `FabricRedirect` could point at a stale
    ///     fabric peer is bounded by the next RG epoch bump (#1065).
    ///
    /// Not cacheable:
    ///   - `LocalDelivery`: Delivered to the kernel stack, not forwarded
    ///     through XSK bindings. No rewrite descriptor to cache.
    ///   - `HAInactive`: The owning RG is not active on this node. Transient
    ///     state that changes on failover — must never be cached.
    ///   - `PolicyDenied`: Packet was denied by policy. Drop decisions are
    ///     not cached to allow policy changes to take effect immediately.
    ///   - `NoRoute`: No route to destination. Transient — may resolve when
    ///     FIB is updated.
    ///   - `MissingNeighbor`: Route exists but ARP/NDP is unresolved.
    ///     Transient — resolves when the neighbor entry appears.
    ///   - `DiscardRoute`: Matched a discard/reject route. Not cacheable for
    ///     the same reason as PolicyDenied.
    ///   - `NextTableUnsupported`: Inter-VRF route leaking hit an
    ///     unsupported next-table. Permanent miss, not worth caching.
    pub(in crate::afxdp) fn is_cacheable(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        )
    }

    /// Whether a frame with this disposition is eligible for the generic
    /// kernel slow-path reinjection (the filtered wrapper
    /// `maybe_reinject_slow_path` and the trailing chokepoint at
    /// `poll_descriptor::poll_binding_process_descriptor`).
    ///
    /// This is the single source of truth for the slow-path allow-list
    /// (#1913). A disposition that is NOT eligible must be dropped, NOT
    /// handed to the kernel FIB.
    ///
    /// Eligible (reinject to the kernel slow path):
    ///   - `LocalDelivery`: terminate at the kernel stack (or a local
    ///     tunnel-delivery channel) — this is the intended destination.
    ///   - `NoRoute`: userspace has no route, but the kernel FIB may
    ///     (e.g. a route the helper has not yet learned); let the kernel
    ///     try, rate-limited.
    ///   - `MissingNeighbor`: route exists, ARP/NDP unresolved; the kernel
    ///     can resolve and forward (the userspace prober runs in parallel).
    ///   - `NextTableUnsupported`: inter-VRF next-table the helper does not
    ///     implement; defer to the kernel FIB.
    ///
    /// NOT eligible (drop — do NOT reinject):
    ///   - `PolicyDenied`: a zone-policy DENY. Reinjecting would silently
    ///     bypass the firewall by forwarding the packet via the kernel FIB
    ///     (the bug #1913 fixes).
    ///   - `HAInactive`: the owning RG is not active on this node;
    ///     reinjecting hands the packet to the standby's kernel FIB
    ///     (duplicate/asymmetric forwarding, wrong-node plaintext send).
    ///   - `DiscardRoute`: matched a discard/reject route whose entire
    ///     purpose is to drop the traffic.
    ///   - `ForwardCandidate` / `FabricRedirect`: handled by the forward /
    ///     fabric path, never the generic slow path. The ONE intentional
    ///     unfiltered `_from_frame` caller — the ForwardCandidate
    ///     build-failure fallback in `tx/dispatch/slow_path.rs` — bypasses
    ///     this predicate on purpose; see the doc on
    ///     `maybe_reinject_slow_path_from_frame`. (#1946: `FabricRedirect`
    ///     with no fabric XSK binding, or whose build/enqueue failed, is
    ///     dropped fail-closed + counted, never reinjected — a
    ///     cross-chassis L2 redirect is not kernel-FIB routable.)
    pub(in crate::afxdp) fn is_slow_path_eligible(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::LocalDelivery
                | ForwardingDisposition::NoRoute
                | ForwardingDisposition::MissingNeighbor
                | ForwardingDisposition::NextTableUnsupported
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ForwardingResolution {
    pub(crate) disposition: ForwardingDisposition,
    pub(crate) local_ifindex: i32,
    pub(crate) egress_ifindex: i32,
    pub(crate) tx_ifindex: i32,
    pub(crate) tunnel_endpoint_id: u16,
    pub(crate) next_hop: Option<IpAddr>,
    pub(crate) neighbor_mac: Option<[u8; 6]>,
    pub(crate) src_mac: Option<[u8; 6]>,
    pub(crate) tx_vlan_id: u16,
}

impl ForwardingResolution {
    pub(in crate::afxdp) fn status(
        self,
        debug: Option<&ResolutionDebug>,
        forwarding: &ForwardingState,
    ) -> PacketResolution {
        PacketResolution {
            disposition: match self.disposition {
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            local_ifindex: self.local_ifindex,
            egress_ifindex: self.egress_ifindex,
            ingress_ifindex: debug.map(|d| d.ingress_ifindex).unwrap_or_default(),
            next_hop: self.next_hop.map(|ip| ip.to_string()).unwrap_or_default(),
            neighbor_mac: self.neighbor_mac.map(format_mac).unwrap_or_default(),
            src_ip: debug
                .and_then(|d| d.src_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dst_ip: debug
                .and_then(|d| d.dst_ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            src_port: debug.map(|d| d.src_port).unwrap_or_default(),
            dst_port: debug.map(|d| d.dst_port).unwrap_or_default(),
            from_zone: debug
                .and_then(|d| d.from_zone)
                .and_then(|id| forwarding.zone_id_to_name.get(&id).cloned())
                .unwrap_or_default(),
            to_zone: debug
                .and_then(|d| d.to_zone)
                .and_then(|id| forwarding.zone_id_to_name.get(&id).cloned())
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct BindingIdentity {
    pub(in crate::afxdp) slot: u32,
    pub(in crate::afxdp) queue_id: u32,
    pub(in crate::afxdp) worker_id: u32,
    pub(in crate::afxdp) interface: Arc<str>,
    pub(in crate::afxdp) ifindex: i32,
}

#[derive(Clone, Debug, Default)]
pub(in crate::afxdp) struct WorkerBindingLookup {
    pub(in crate::afxdp) by_if_queue: FastMap<(i32, u32), usize>,
    pub(in crate::afxdp) first_by_if: FastMap<i32, usize>,
    pub(in crate::afxdp) all_by_if: FastMap<i32, Vec<usize>>,
    pub(in crate::afxdp) by_slot: FastMap<u32, usize>,
}

impl WorkerBindingLookup {
    pub(in crate::afxdp) fn from_bindings(bindings: &[BindingWorker]) -> Self {
        let mut lookup = Self::default();
        for (index, binding) in bindings.iter().enumerate() {
            lookup
                .by_if_queue
                .insert((binding.ifindex, binding.queue_id), index);
            lookup.first_by_if.entry(binding.ifindex).or_insert(index);
            lookup
                .all_by_if
                .entry(binding.ifindex)
                .or_default()
                .push(index);
            lookup.by_slot.insert(binding.slot, index);
        }
        lookup
    }

    pub(in crate::afxdp) fn target_index(
        &self,
        current_index: usize,
        current_ifindex: i32,
        ingress_queue_id: u32,
        egress_ifindex: i32,
    ) -> Option<usize> {
        if current_ifindex == egress_ifindex {
            return Some(current_index);
        }
        self.by_if_queue
            .get(&(egress_ifindex, ingress_queue_id))
            .copied()
            .or_else(|| self.first_by_if.get(&egress_ifindex).copied())
    }

    pub(in crate::afxdp) fn slot_index(&self, slot: u32) -> Option<usize> {
        self.by_slot.get(&slot).copied()
    }

    pub(in crate::afxdp) fn fabric_target_index(
        &self,
        egress_ifindex: i32,
        flow_hash: u64,
    ) -> Option<usize> {
        let indices = self.all_by_if.get(&egress_ifindex)?;
        if indices.is_empty() {
            return None;
        }
        Some(indices[(flow_hash as usize) % indices.len()])
    }
}
