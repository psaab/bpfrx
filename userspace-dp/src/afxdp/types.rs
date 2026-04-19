use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub(super) type FastMap<K, V> = FxHashMap<K, V>;
pub(super) type FastSet<T> = FxHashSet<T>;
pub(super) type OwnerRgSessionIndex = FastMap<i32, FastSet<SessionKey>>;

#[derive(Clone)]
pub(super) struct SharedSessionOwnerRgIndexes {
    pub(super) sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) nat_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) forward_wire_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(super) reverse_prewarm_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
}

impl Default for SharedSessionOwnerRgIndexes {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            reverse_prewarm_sessions: Arc::new(Mutex::new(FastMap::default())),
        }
    }
}

impl SharedSessionOwnerRgIndexes {
    pub(super) fn clear(&self) {
        if let Ok(mut index) = self.sessions.lock() {
            index.clear();
        }
        if let Ok(mut index) = self.nat_sessions.lock() {
            index.clear();
        }
        if let Ok(mut index) = self.forward_wire_sessions.lock() {
            index.clear();
        }
        if let Ok(mut index) = self.reverse_prewarm_sessions.lock() {
            index.clear();
        }
    }
}

/// Packet buffered while waiting for ARP/NDP neighbor resolution.
pub(super) struct PendingNeighPacket {
    pub(super) addr: u64,
    pub(super) desc: XdpDesc,
    pub(super) meta: UserspaceDpMeta,
    pub(super) decision: SessionDecision,
    pub(super) queued_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UserspaceDpMeta {
    pub(super) magic: u32,
    pub(super) version: u16,
    pub(super) length: u16,
    pub(super) ingress_ifindex: u32,
    pub(super) rx_queue_index: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_pcp: u8,
    pub(super) ingress_vlan_present: u8,
    pub(super) ingress_zone: u16,
    pub(super) routing_table: u32,
    pub(super) l3_offset: u16,
    pub(super) l4_offset: u16,
    pub(super) payload_offset: u16,
    pub(super) pkt_len: u16,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) tcp_flags: u8,
    pub(super) meta_flags: u8,
    pub(super) dscp: u8,
    pub(super) dscp_rewrite: u8,
    pub(super) reserved: u16,
    pub(super) flow_src_port: u16,
    pub(super) flow_dst_port: u16,
    pub(super) flow_src_addr: [u8; 16],
    pub(super) flow_dst_addr: [u8; 16],
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) reserved2: u32,
}

const _: [(); 96] = [(); std::mem::size_of::<UserspaceDpMeta>()];
const _: [(); 18] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_pcp)];
const _: [(); 19] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_vlan_present)];
const _: [(); 20] = [(); std::mem::offset_of!(UserspaceDpMeta, ingress_zone)];
const _: [(); 24] = [(); std::mem::offset_of!(UserspaceDpMeta, routing_table)];
const _: [(); 36] = [(); std::mem::offset_of!(UserspaceDpMeta, addr_family)];
const _: [(); 40] = [(); std::mem::offset_of!(UserspaceDpMeta, dscp)];
const _: [(); 80] = [(); std::mem::offset_of!(UserspaceDpMeta, config_generation)];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct ForwardPacketMeta {
    pub(super) ingress_ifindex: u32,
    pub(super) ingress_vlan_id: u16,
    pub(super) ingress_pcp: u8,
    pub(super) ingress_vlan_present: u8,
    pub(super) l3_offset: u16,
    pub(super) l4_offset: u16,
    pub(super) payload_offset: u16,
    pub(super) pkt_len: u16,
    pub(super) addr_family: u8,
    pub(super) protocol: u8,
    pub(super) tcp_flags: u8,
    pub(super) meta_flags: u8,
    pub(super) dscp: u8,
    pub(super) flow_src_port: u16,
    pub(super) flow_dst_port: u16,
}

impl From<UserspaceDpMeta> for ForwardPacketMeta {
    fn from(meta: UserspaceDpMeta) -> Self {
        Self {
            ingress_ifindex: meta.ingress_ifindex,
            ingress_vlan_id: meta.ingress_vlan_id,
            ingress_pcp: meta.ingress_pcp,
            ingress_vlan_present: meta.ingress_vlan_present,
            l3_offset: meta.l3_offset,
            l4_offset: meta.l4_offset,
            payload_offset: meta.payload_offset,
            pkt_len: meta.pkt_len,
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            tcp_flags: meta.tcp_flags,
            meta_flags: meta.meta_flags,
            dscp: meta.dscp,
            flow_src_port: meta.flow_src_port,
            flow_dst_port: meta.flow_dst_port,
        }
    }
}

impl From<ForwardPacketMeta> for UserspaceDpMeta {
    fn from(meta: ForwardPacketMeta) -> Self {
        Self {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            ingress_ifindex: meta.ingress_ifindex,
            rx_queue_index: 0,
            ingress_vlan_id: meta.ingress_vlan_id,
            ingress_pcp: meta.ingress_pcp,
            ingress_vlan_present: meta.ingress_vlan_present,
            ingress_zone: 0,
            routing_table: 0,
            l3_offset: meta.l3_offset,
            l4_offset: meta.l4_offset,
            payload_offset: meta.payload_offset,
            pkt_len: meta.pkt_len,
            addr_family: meta.addr_family,
            protocol: meta.protocol,
            tcp_flags: meta.tcp_flags,
            meta_flags: meta.meta_flags,
            dscp: meta.dscp,
            dscp_rewrite: 0,
            reserved: 0,
            flow_src_port: meta.flow_src_port,
            flow_dst_port: meta.flow_dst_port,
            flow_src_addr: [0; 16],
            flow_dst_addr: [0; 16],
            config_generation: 0,
            fib_generation: 0,
            reserved2: 0,
        }
    }
}
#[repr(C)]
pub(super) struct XdpOptions {
    pub(super) flags: u32,
}

pub(super) struct WorkerHandle {
    pub(super) stop: Arc<AtomicBool>,
    pub(super) heartbeat: Arc<AtomicU64>,
    pub(super) commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    pub(super) session_export_ack: Arc<AtomicU64>,
    pub(super) cos_status: Arc<ArcSwap<Vec<crate::protocol::CoSInterfaceStatus>>>,
    pub(super) join: Option<JoinHandle<()>>,
}

pub(super) struct LocalTunnelSourceHandle {
    pub(super) stop: Arc<AtomicBool>,
    pub(super) join: Option<JoinHandle<()>>,
}

pub(super) struct BindingPlan {
    pub(super) status: BindingStatus,
    pub(super) live: Arc<BindingLiveState>,
    pub(super) xsk_map_fd: c_int,
    pub(super) heartbeat_map_fd: c_int,
    pub(super) session_map_fd: c_int,
    pub(super) conntrack_v4_fd: c_int,
    pub(super) conntrack_v6_fd: c_int,
    pub(super) ring_entries: u32,
    pub(super) bind_strategy: AfXdpBindStrategy,
    pub(super) poll_mode: crate::PollMode,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ValidationState {
    pub(super) snapshot_installed: bool,
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PacketDisposition {
    Valid,
    NoSnapshot,
    ConfigGenerationMismatch,
    FibGenerationMismatch,
    UnsupportedPacket,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ForwardingState {
    pub(super) local_v4: FastSet<Ipv4Addr>,
    pub(super) local_v6: FastSet<Ipv6Addr>,
    pub(super) interface_nat_v4: FastMap<Ipv4Addr, i32>,
    pub(super) interface_nat_v6: FastMap<Ipv6Addr, i32>,
    pub(super) connected_v4: Vec<ConnectedRouteV4>,
    pub(super) connected_v6: Vec<ConnectedRouteV6>,
    pub(super) routes_v4: FastMap<String, Vec<RouteEntryV4>>,
    pub(super) routes_v6: FastMap<String, Vec<RouteEntryV6>>,
    pub(super) tunnel_endpoints: FastMap<u16, TunnelEndpoint>,
    pub(super) tunnel_endpoint_by_ifindex: FastMap<i32, u16>,
    pub(super) neighbors: FastMap<(i32, IpAddr), NeighborEntry>,
    pub(super) ifindex_to_name: FastMap<i32, String>,
    pub(super) ifindex_to_config_name: FastMap<i32, String>,
    pub(super) ifindex_to_zone: FastMap<i32, String>,
    pub(super) zone_name_to_id: FastMap<String, u16>,
    pub(super) zone_id_to_name: FastMap<u16, String>,
    pub(super) egress: FastMap<i32, EgressInterface>,
    pub(super) ingress_logical_ifindex: FastMap<(i32, u16), i32>,
    pub(super) fabrics: Vec<FabricLink>,
    pub(super) allow_dns_reply: bool,
    pub(super) allow_embedded_icmp: bool,
    pub(super) session_timeouts: crate::session::SessionTimeouts,
    pub(super) policy: PolicyState,
    pub(super) source_nat_rules: Vec<SourceNatRule>,
    pub(super) static_nat: StaticNatTable,
    pub(super) dnat_table: DnatTable,
    pub(super) nat64: Nat64State,
    pub(super) nptv6: Nptv6State,
    pub(super) screen_profiles: FastMap<String, ScreenProfile>,
    pub(super) tunnel_interfaces: FastSet<i32>,
    pub(super) filter_state: crate::filter::FilterState,
    pub(super) cos: CoSState,
    pub(super) tx_selection_enabled_v4: bool,
    pub(super) tx_selection_enabled_v6: bool,
    #[allow(dead_code)]
    pub(super) gre_acceleration: bool,
    pub(super) flow_export_config: Option<crate::flowexport::FlowExportConfig>,
    pub(super) tcp_mss_all_tcp: u16,
    pub(super) tcp_mss_ipsec_vpn: u16,
    pub(super) tcp_mss_gre_in: u16,
    pub(super) tcp_mss_gre_out: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSState {
    pub(super) interfaces: FastMap<i32, CoSInterfaceConfig>,
    pub(super) dscp_classifiers: FastMap<String, CoSDSCPClassifierConfig>,
    pub(super) ieee8021_classifiers: FastMap<String, CoSIEEE8021ClassifierConfig>,
    pub(super) dscp_rewrite_rules: FastMap<String, CoSDSCPRewriteRuleConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoSInterfaceConfig {
    pub(super) shaping_rate_bytes: u64,
    pub(super) burst_bytes: u64,
    pub(super) default_queue: u8,
    pub(super) dscp_classifier: String,
    pub(super) ieee8021_classifier: String,
    pub(super) dscp_queue_by_dscp: [u8; 64],
    pub(super) ieee8021_queue_by_pcp: [u8; 8],
    pub(super) queue_by_forwarding_class: FastMap<String, u8>,
    pub(super) queues: Vec<CoSQueueConfig>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSDSCPClassifierConfig {
    pub(super) queue_by_dscp: FastMap<u8, u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSIEEE8021ClassifierConfig {
    pub(super) queue_by_pcp: FastMap<u8, u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSDSCPRewriteRuleConfig {
    pub(super) dscp_by_forwarding_class: FastMap<String, u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoSQueueConfig {
    pub(super) queue_id: u8,
    pub(super) forwarding_class: String,
    pub(super) priority: u8,
    pub(super) transmit_rate_bytes: u64,
    pub(super) exact: bool,
    pub(super) surplus_weight: u32,
    pub(super) buffer_bytes: u64,
    pub(super) dscp_rewrite: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) enum HAForwardingLease {
    #[default]
    Inactive,
    ActiveUntil(u64),
}

impl HAForwardingLease {
    pub(super) fn active(self, now_secs: u64) -> bool {
        matches!(self, Self::ActiveUntil(until) if until != 0 && now_secs <= until)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct HAGroupRuntime {
    pub(super) active: bool,
    pub(super) watchdog_timestamp: u64,
    pub(super) lease: HAForwardingLease,
}

impl HAGroupRuntime {
    pub(super) fn active_lease_until(watchdog_timestamp: u64, now_secs: u64) -> HAForwardingLease {
        HAForwardingLease::ActiveUntil(
            watchdog_timestamp
                .max(now_secs)
                .saturating_add(super::HA_WATCHDOG_STALE_AFTER_SECS),
        )
    }

    pub(super) fn is_forwarding_active(self, now_secs: u64) -> bool {
        self.active && self.lease.active(now_secs)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectedRouteV4 {
    pub(super) prefix: PrefixV4,
    pub(super) ifindex: i32,
    pub(super) tunnel_endpoint_id: u16,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectedRouteV6 {
    pub(super) prefix: PrefixV6,
    pub(super) ifindex: i32,
    pub(super) tunnel_endpoint_id: u16,
}

#[derive(Clone, Debug)]
pub(super) struct RouteEntryV4 {
    pub(super) prefix: PrefixV4,
    pub(super) ifindex: i32,
    pub(super) tunnel_endpoint_id: u16,
    pub(super) next_hop: Option<Ipv4Addr>,
    pub(super) discard: bool,
    pub(super) next_table: String,
}

#[derive(Clone, Debug)]
pub(super) struct RouteEntryV6 {
    pub(super) prefix: PrefixV6,
    pub(super) ifindex: i32,
    pub(super) tunnel_endpoint_id: u16,
    pub(super) next_hop: Option<Ipv6Addr>,
    pub(super) discard: bool,
    pub(super) next_table: String,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(super) struct EgressInterface {
    pub(super) bind_ifindex: i32,
    pub(super) vlan_id: u16,
    pub(super) mtu: usize,
    pub(super) src_mac: [u8; 6],
    pub(super) zone: String,
    pub(super) redundancy_group: i32,
    pub(super) primary_v4: Option<Ipv4Addr>,
    pub(super) primary_v6: Option<Ipv6Addr>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(super) struct TunnelEndpoint {
    pub(super) id: u16,
    pub(super) logical_ifindex: i32,
    pub(super) redundancy_group: i32,
    pub(super) mode: String,
    pub(super) outer_family: i32,
    pub(super) source: IpAddr,
    pub(super) destination: IpAddr,
    pub(super) key: u32,
    pub(super) ttl: u8,
    pub(super) transport_table: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct FabricLink {
    pub(super) parent_ifindex: i32,
    pub(super) overlay_ifindex: i32,
    pub(super) peer_addr: IpAddr,
    pub(super) peer_mac: [u8; 6],
    pub(super) local_mac: [u8; 6],
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
    ///
    /// Not cacheable:
    ///   - `FabricRedirect`: Targets a fabric overlay binding that differs
    ///     from the normal egress binding. Fabric target selection depends on
    ///     per-packet queue hashing and binding availability, which the cache
    ///     entry cannot capture. Also, fabric sessions may flip back to
    ///     ForwardCandidate after failback, making cached fabric entries stale.
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
    pub(super) fn is_cacheable(self) -> bool {
        matches!(
            self,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
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
    pub(super) fn status(self, debug: Option<&ResolutionDebug>) -> PacketResolution {
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
                .and_then(|d| d.from_zone.as_ref().map(|zone| zone.to_string()))
                .unwrap_or_default(),
            to_zone: debug
                .and_then(|d| d.to_zone.as_ref().map(|zone| zone.to_string()))
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct BindingIdentity {
    pub(super) slot: u32,
    pub(super) queue_id: u32,
    pub(super) worker_id: u32,
    pub(super) interface: Arc<str>,
    pub(super) ifindex: i32,
}

#[derive(Clone, Debug, Default)]
pub(super) struct WorkerBindingLookup {
    pub(super) by_if_queue: FastMap<(i32, u32), usize>,
    pub(super) first_by_if: FastMap<i32, usize>,
    pub(super) all_by_if: FastMap<i32, Vec<usize>>,
    pub(super) by_slot: FastMap<u32, usize>,
}

impl WorkerBindingLookup {
    pub(super) fn from_bindings(bindings: &[BindingWorker]) -> Self {
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

    pub(super) fn target_index(
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

    pub(super) fn slot_index(&self, slot: u32) -> Option<usize> {
        self.by_slot.get(&slot).copied()
    }

    pub(super) fn fabric_target_index(&self, egress_ifindex: i32, flow_hash: u64) -> Option<usize> {
        let indices = self.all_by_if.get(&egress_ifindex)?;
        if indices.is_empty() {
            return None;
        }
        Some(indices[(flow_hash as usize) % indices.len()])
    }
}

pub(super) const COS_FAST_QUEUE_INDEX_MISS: u16 = u16::MAX;
/// Number of SFQ flow buckets per flow-fair CoS queue.
///
/// Sized to keep birthday-paradox collision probability well below 15%
/// at the production-regime flow count (N ≤ 64 concurrent flows per
/// queue). At 16 flows the collision rate is ~11% (was ~88% at the
/// prior 64-bucket sizing); at 32 flows ~38%; at 64 flows ~87%.
/// Collisions cost fairness — two flows in the same bucket share one
/// SFQ dequeue slot and one admission-cap slice (#705) — so making
/// them rare is directly fairness-load-bearing. See #711.
///
/// Per-queue memory overhead:
///   `flow_bucket_bytes: [u64; N]`    =  8 KB
///   `flow_bucket_items: [VecDeque; N]` = 24 KB inline headers
///   `flow_rr_buckets: FlowRrRing` (`[u16; N] + head + len`) = 2 KB
/// = ~34 KB per flow-fair queue. Non-flow-fair queues pay the same
/// inline footprint but never touch the storage; it stays cold. At
/// 4 workers × 8 queues × 1 iface = ~1 MB, well within tolerance.
pub(super) const COS_FLOW_FAIR_BUCKETS: usize = 1024;

// Compile-time invariants for COS_FLOW_FAIR_BUCKETS — the #711 design
// depends on both and a future refactor that changes the constant
// without checking these must fail at build time, not at runtime:
//
// 1. Power of two — `cos_flow_bucket_index` masks with
//    `COS_FLOW_FAIR_BUCKETS - 1` instead of modulo, and `FlowRrRing`
//    uses mask-based wrap math on the hot push/pop path. Without
//    power-of-two sizing that math silently indexes off the end.
// 2. Fits in `u16` — `FlowRrRing` stores bucket IDs as `u16`. A
//    larger constant would silently truncate.
const _: () = assert!(COS_FLOW_FAIR_BUCKETS.is_power_of_two());
const _: () = assert!(COS_FLOW_FAIR_BUCKETS <= u16::MAX as usize);

/// Pre-computed mask for `COS_FLOW_FAIR_BUCKETS`-modulo on the hot
/// path. Using a mask (rather than `%`) gives deterministic codegen
/// independent of the optimizer proving the power-of-two property at
/// each call site.
pub(super) const COS_FLOW_FAIR_BUCKET_MASK: usize = COS_FLOW_FAIR_BUCKETS - 1;

/// #694: Fixed-capacity ring buffer holding the set of currently-active
/// flow bucket IDs, driving SFQ round-robin dequeue.
///
/// Storage is exactly `COS_FLOW_FAIR_BUCKETS` u16 slots — no heap
/// allocation. Replaces a prior `VecDeque<u8>` which paid allocator
/// cost per queue and capped bucket IDs at 256 (incompatible with the
/// #711 bucket-count grow). The ring is accessed exclusively through
/// the associated methods, which are all O(1).
///
/// Invariant: the ring contains no duplicate bucket IDs. The callers
/// in `cos_queue_push_*` / `cos_queue_pop_front` already gate on
/// "bucket transitioned empty → non-empty" before pushing and on
/// "bucket still non-empty" before re-enqueueing the RR cursor, so the
/// ring itself does not revalidate on the hot path.
#[derive(Debug)]
pub(super) struct FlowRrRing {
    buf: [u16; COS_FLOW_FAIR_BUCKETS],
    head: u16,
    len: u16,
}

impl Default for FlowRrRing {
    fn default() -> Self {
        Self {
            buf: [0; COS_FLOW_FAIR_BUCKETS],
            head: 0,
            len: 0,
        }
    }
}

impl FlowRrRing {
    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub(super) fn len(&self) -> usize {
        usize::from(self.len)
    }

    #[inline]
    pub(super) fn front(&self) -> Option<u16> {
        if self.len == 0 {
            None
        } else {
            Some(self.buf[usize::from(self.head)])
        }
    }

    /// Iterate active bucket IDs in service order (head first).
    pub(super) fn iter(&self) -> FlowRrRingIter<'_> {
        FlowRrRingIter {
            ring: self,
            offset: 0,
        }
    }

    // Hot-path invariant: the caller in `cos_queue_push_*` gates every
    // push on "bucket transitioned empty → non-empty", so a bucket ID
    // is in the ring at most once. The ring therefore never holds more
    // than `COS_FLOW_FAIR_BUCKETS` entries, and `len < CAP` is a
    // structural invariant — not a runtime bound we need to defend
    // against. `debug_assert!` enforces it in tests; release uses a
    // plain `+= 1` rather than `saturating_add` because a silent
    // saturation on a violated invariant would hide a real bug (the
    // push would succeed at the wrapped-buffer index and the ring
    // would lose either the new entry or an older one, depending on
    // head placement — very hard to triage).
    #[inline]
    pub(super) fn push_back(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        let tail = (usize::from(self.head) + usize::from(self.len)) & COS_FLOW_FAIR_BUCKET_MASK;
        self.buf[tail] = bucket;
        self.len += 1;
    }

    #[inline]
    pub(super) fn push_front(&mut self, bucket: u16) {
        debug_assert!(
            usize::from(self.len) < COS_FLOW_FAIR_BUCKETS,
            "FlowRrRing overflow: len={} cap={}",
            self.len,
            COS_FLOW_FAIR_BUCKETS
        );
        // head := (head + CAP - 1) mod CAP, with CAP a power of two
        // so this is a mask-only op. Avoids the `if head == 0` branch
        // on the hot path.
        self.head = ((usize::from(self.head) + COS_FLOW_FAIR_BUCKETS - 1)
            & COS_FLOW_FAIR_BUCKET_MASK) as u16;
        self.buf[usize::from(self.head)] = bucket;
        self.len += 1;
    }

    #[inline]
    pub(super) fn pop_front(&mut self) -> Option<u16> {
        if self.len == 0 {
            return None;
        }
        let bucket = self.buf[usize::from(self.head)];
        self.head = ((usize::from(self.head) + 1) & COS_FLOW_FAIR_BUCKET_MASK) as u16;
        self.len -= 1;
        Some(bucket)
    }
}

pub(super) struct FlowRrRingIter<'a> {
    ring: &'a FlowRrRing,
    offset: usize,
}

impl<'a> Iterator for FlowRrRingIter<'a> {
    type Item = u16;
    #[inline]
    fn next(&mut self) -> Option<u16> {
        if self.offset >= usize::from(self.ring.len) {
            return None;
        }
        let idx = (usize::from(self.ring.head) + self.offset) & COS_FLOW_FAIR_BUCKET_MASK;
        self.offset += 1;
        Some(self.ring.buf[idx])
    }
}

#[derive(Clone)]
pub(super) struct WorkerCoSQueueFastPath {
    pub(super) shared_exact: bool,
    pub(super) owner_worker_id: u32,
    pub(super) owner_live: Option<Arc<BindingLiveState>>,
    pub(super) shared_queue_lease: Option<Arc<SharedCoSQueueLease>>,
}

#[derive(Clone)]
pub(super) struct WorkerCoSInterfaceFastPath {
    pub(super) tx_ifindex: i32,
    pub(super) default_queue_index: usize,
    pub(super) queue_index_by_id: [u16; 256],
    pub(super) tx_owner_live: Option<Arc<BindingLiveState>>,
    pub(super) shared_root_lease: Option<Arc<SharedCoSRootLease>>,
    pub(super) queue_fast_path: Vec<WorkerCoSQueueFastPath>,
}

impl WorkerCoSInterfaceFastPath {
    #[inline]
    pub(super) fn effective_queue_index(&self, requested_queue_id: Option<u8>) -> Option<usize> {
        if let Some(queue_id) = requested_queue_id {
            let idx = self.queue_index_by_id[usize::from(queue_id)];
            if idx != COS_FAST_QUEUE_INDEX_MISS {
                return Some(idx as usize);
            }
            return None;
        }
        (!self.queue_fast_path.is_empty()).then_some(
            self.default_queue_index
                .min(self.queue_fast_path.len().saturating_sub(1)),
        )
    }

    #[inline]
    pub(super) fn queue_fast_path(
        &self,
        requested_queue_id: Option<u8>,
    ) -> Option<&WorkerCoSQueueFastPath> {
        self.effective_queue_index(requested_queue_id)
            .and_then(|idx| self.queue_fast_path.get(idx))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SessionFlow {
    pub(super) src_ip: IpAddr,
    pub(super) dst_ip: IpAddr,
    pub(super) forward_key: SessionKey,
}

impl SessionFlow {
    pub(super) fn with_destination(&self, dst_ip: IpAddr) -> Self {
        let mut forward_key = self.forward_key.clone();
        forward_key.dst_ip = dst_ip;
        Self {
            src_ip: self.src_ip,
            dst_ip,
            forward_key,
        }
    }

    pub(super) fn reverse_key_with_nat(&self, nat: NatDecision) -> SessionKey {
        reverse_session_key(&self.forward_key, nat)
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ResolutionDebug {
    pub(super) ingress_ifindex: i32,
    pub(super) src_ip: Option<IpAddr>,
    pub(super) dst_ip: Option<IpAddr>,
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) from_zone: Option<Arc<str>>,
    pub(super) to_zone: Option<Arc<str>>,
}

impl ResolutionDebug {
    pub(super) fn from_flow(ingress_ifindex: i32, flow: &SessionFlow) -> Self {
        Self {
            ingress_ifindex,
            src_ip: Some(flow.src_ip),
            dst_ip: Some(flow.dst_ip),
            src_port: flow.forward_key.src_port,
            dst_port: flow.forward_key.dst_port,
            from_zone: None,
            to_zone: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct TxRequest {
    pub(super) bytes: Vec<u8>,
    #[allow(dead_code)]
    pub(super) expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    pub(super) expected_addr_family: u8,
    #[allow(dead_code)]
    pub(super) expected_protocol: u8,
    pub(super) flow_key: Option<SessionKey>,
    pub(super) egress_ifindex: i32,
    pub(super) cos_queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
}

pub(super) enum PendingForwardFrame {
    Live,
    Owned(Vec<u8>),
    Prebuilt(Vec<u8>),
}

impl Default for PendingForwardFrame {
    fn default() -> Self {
        Self::Live
    }
}

pub(super) struct PendingForwardRequest {
    pub(super) target_ifindex: i32,
    pub(super) target_binding_index: Option<usize>,
    pub(super) ingress_queue_id: u32,
    pub(super) desc: XdpDesc,
    pub(super) frame: PendingForwardFrame,
    pub(super) meta: ForwardPacketMeta,
    pub(super) decision: SessionDecision,
    pub(super) apply_nat_on_fabric: bool,
    pub(super) expected_ports: Option<(u16, u16)>,
    pub(super) flow_key: Option<SessionKey>,
    pub(super) nat64_reverse: Option<Nat64ReverseInfo>,
    pub(super) cos_queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
}

pub(super) struct PreparedTxRequest {
    pub(super) offset: u64,
    pub(super) len: u32,
    pub(super) recycle: PreparedTxRecycle,
    #[allow(dead_code)]
    pub(super) expected_ports: Option<(u16, u16)>,
    #[allow(dead_code)]
    pub(super) expected_addr_family: u8,
    #[allow(dead_code)]
    pub(super) expected_protocol: u8,
    pub(super) flow_key: Option<SessionKey>,
    pub(super) egress_ifindex: i32,
    pub(super) cos_queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExactLocalScratchTxRequest {
    pub(super) offset: u64,
    pub(super) len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExactPreparedScratchTxRequest {
    pub(super) offset: u64,
    pub(super) len: u32,
}

pub(super) struct CoSInterfaceRuntime {
    pub(super) shaping_rate_bytes: u64,
    pub(super) burst_bytes: u64,
    pub(super) tokens: u64,
    pub(super) default_queue: u8,
    pub(super) nonempty_queues: usize,
    pub(super) runnable_queues: usize,
    // Round-robin cursors for the two guarantee service classes. Exact and
    // non-exact guarantee queues rotate independently — the scheduler gives
    // exact queues strict priority over non-exact guarantee service (the
    // exact path runs first in `drain_shaped_tx`; non-exact only runs when
    // the exact path returns None), and within each class RR ordering is
    // preserved across calls without coupling to the other class's service
    // events. Prior to #689 both passes shared a single `guarantee_rr`
    // cursor; that had neither pure unified-RR semantics (because the exact
    // path always wins at a shared rr position) nor clean class-independent
    // semantics (because service events in one class advanced the cursor
    // seen by the other), and in pathological backlog mixes could produce
    // non-obvious skips in the non-exact rotation.
    pub(super) exact_guarantee_rr: usize,
    pub(super) nonexact_guarantee_rr: usize,
    // Unified-walk cursor used only by the test-only legacy selector
    // `select_cos_guarantee_batch_with_fast_path`. Gated on `cfg(test)`
    // so non-test builds of the hot CoS fast-path runtime do not pay
    // field footprint or init churn for compatibility scaffolding.
    // Separate from the production cursors above so test harnesses that
    // exercise the legacy walk do not disturb production rotation state
    // and vice versa — see the
    // `legacy_guarantee_rr_does_not_advance_class_cursors` regression
    // that pins that isolation contract.
    #[cfg(test)]
    pub(super) legacy_guarantee_rr: usize,
    pub(super) queues: Vec<CoSQueueRuntime>,
    pub(super) queue_indices_by_priority: [Vec<usize>; COS_PRIORITY_LEVELS],
    pub(super) rr_index_by_priority: [usize; COS_PRIORITY_LEVELS],
    pub(super) timer_wheel: CoSTimerWheelRuntime,
}

pub(super) struct CoSQueueRuntime {
    pub(super) queue_id: u8,
    pub(super) priority: u8,
    pub(super) transmit_rate_bytes: u64,
    pub(super) exact: bool,
    pub(super) flow_fair: bool,
    /// #785: cached shadow of `WorkerCoSQueueFastPath.shared_exact`
    /// populated by `promote_cos_queue_flow_fair`. Under the current
    /// promotion policy (`flow_fair = queue.exact && !shared_exact`),
    /// shared_exact queues are NOT on the flow-fair path — they stay
    /// on the single-FIFO-per-worker drain with no SFQ DRR ordering.
    /// The shadow exists so future cross-worker fairness work
    /// (tracked in issue #786) can branch on it.
    ///
    /// Keeping the field on the queue runtime makes the policy bit
    /// available to hot-path helpers directly from
    /// `&CoSQueueRuntime`, so current and future branching does not
    /// have to thread extra interface state through admission-path
    /// call sites or add an iface_fast lookup there.
    pub(super) shared_exact: bool,
    // Per-queue hash salt mixed into `exact_cos_flow_bucket()` so the SFQ
    // bucket mapping is not an externally-probeable pure function of the
    // 5-tuple. Drawn from getrandom(2) exactly when a queue is promoted
    // onto the flow-fair path (see `ensure_cos_interface_runtime`), never
    // rotated for the lifetime of this runtime — within one instance the
    // mapping stays deterministic (required for correct enqueue/dequeue
    // bucket accounting), but is unpredictable across restarts and nodes.
    // Non-flow-fair queues keep `flow_hash_seed: 0`; the field is not read
    // on that path and the zero value preserves byte-identical legacy
    // hashing for any caller that reuses the function.
    pub(super) flow_hash_seed: u64,
    pub(super) surplus_weight: u32,
    pub(super) surplus_deficit: u64,
    pub(super) buffer_bytes: u64,
    pub(super) dscp_rewrite: Option<u8>,
    pub(super) tokens: u64,
    pub(super) last_refill_ns: u64,
    pub(super) queued_bytes: u64,
    pub(super) active_flow_buckets: u16,
    /// #784 diagnostic: runtime-lifetime peak of
    /// `active_flow_buckets` on this queue. Monotonically
    /// non-decreasing; resets only on daemon restart (queue
    /// runtime re-creation). Lets operators detect SFQ hash-
    /// collision regressions empirically — at steady state an
    /// iperf3 -P N workload should show
    /// `active_flow_buckets_peak >= N` if the hash is spreading
    /// correctly. Owner-only writes; the snapshot reader reads
    /// without resetting (Codex review: do NOT reset on
    /// snapshot, the doc here is the contract).
    pub(super) active_flow_buckets_peak: u16,
    /// #785 slice 2: windowed peak of `active_flow_buckets` on this
    /// worker used as the LOCAL input to the cross-worker fair-share
    /// rate calculation. Kept SEPARATE from
    /// `active_flow_buckets_peak` above because that field has a
    /// "never reset during daemon lifetime" contract from #784
    /// (operators inspect it to detect SFQ hash collisions).
    /// Perturbing that semantics by adding a reset for the scheduler
    /// would regress the diagnostic.
    ///
    /// Bumped on bucket 0→>0 transitions in lockstep with
    /// `active_flow_buckets_peak`, so it captures the maximum live
    /// flow count within the current window. Reset to the live
    /// instantaneous `active_flow_buckets` value every
    /// `COS_FAIR_SHARE_PEAK_WINDOW_NS` (currently 500 ms) in
    /// `maybe_top_up_local_fair_share`. The reset is the decay
    /// mechanism: on flow churn (HTTP short-lived TCP, L7LB
    /// terminations) the peak stops pinning the rate gate's
    /// denominator at a stale high-water mark, which would
    /// progressively starve the worker as flows leave.
    pub(super) local_fair_share_peak: u16,
    /// Wall-time deadline for the next peak-reset. Absolute monotonic
    /// nanoseconds. Compared against `now_ns` in
    /// `maybe_top_up_local_fair_share`; when exceeded the peak snaps
    /// to the live `active_flow_buckets` and the deadline advances
    /// by another window.
    pub(super) local_fair_share_peak_deadline_ns: u64,
    /// #785 cross-worker DRR: per-worker local token bucket that
    /// enforces `fair_share_rate_bytes = lease.rate_bytes()
    /// × (local_fair_share_peak / lease.active_flow_count_peak())` on
    /// the shared_exact service path. Refilled on every drain
    /// attempt using `local_drain_rate_bytes` (cached fair-share
    /// rate) and the time elapsed since `local_drain_last_refill_ns`.
    ///
    /// These fields are meaningful only on flow-fair shared_exact
    /// queues. On owner-local-exact queues the shared lease's
    /// `active_flow_count` stays 0 and the fields are inert.
    pub(super) local_drain_tokens: u64,
    pub(super) local_drain_last_refill_ns: u64,
    pub(super) local_drain_rate_bytes: u64,
    /// #785 cross-worker DRR: cached shared-queue lease Arc so the
    /// enqueue/dequeue accounting hooks can atomically bump
    /// `active_flow_count` on the shared counter without walking
    /// through `iface_fast.queue_fast_path[idx].shared_queue_lease`
    /// on every packet. `Some` only on flow-fair shared_exact
    /// queues; `None` on owner-local-exact and non-exact queues.
    /// Populated by `promote_cos_queue_flow_fair`; the Arc cloned
    /// from `WorkerCoSQueueFastPath.shared_queue_lease`, which
    /// itself is populated from the coordinator-owned shared
    /// `BTreeMap<(i32, u8), Arc<SharedCoSQueueLease>>`.
    pub(super) shared_lease: Option<Arc<SharedCoSQueueLease>>,
    pub(super) flow_bucket_bytes: [u64; COS_FLOW_FAIR_BUCKETS],
    pub(super) flow_rr_buckets: FlowRrRing,
    pub(super) flow_bucket_items: [VecDeque<CoSPendingTxItem>; COS_FLOW_FAIR_BUCKETS],
    pub(super) runnable: bool,
    pub(super) parked: bool,
    pub(super) next_wakeup_tick: u64,
    pub(super) wheel_level: u8,
    pub(super) wheel_slot: usize,
    pub(super) items: VecDeque<CoSPendingTxItem>,
    /// #774 optimization: cached count of `Local` items currently
    /// resident in `items` + `flow_bucket_items`. Incremented /
    /// decremented at every `cos_queue_push_*` and
    /// `cos_queue_pop_front` site. Replaces an O(n) scan in
    /// `cos_queue_accepts_prepared` that profiled at 3.25% CPU on
    /// the hot path at line rate. Owner-only writes; no atomic
    /// needed (same discipline as `queued_bytes`).
    pub(super) local_item_count: u32,
    // #710: per-queue drop-reason counters. Single-writer (the owner
    // worker is the only code path that mutates this queue's runtime),
    // so plain `u64` is sufficient — no atomics needed on the hot path.
    // Snapshot reads happen through the `build_worker_cos_statuses`
    // path which copies the whole runtime into a status struct published
    // via `ArcSwap`, so reads are consistent without ordering discipline
    // here.
    pub(super) drop_counters: CoSQueueDropCounters,
    // #751: per-queue owner-side drain telemetry. Lives inline on the
    // queue runtime so each queue's drain_latency + drain_invocations
    // are genuinely per-queue rather than a binding-wide rollup
    // surfaced under every queue row (#732). Single-writer on the
    // owner worker thread; atomic because the snapshot path reads
    // from a different thread.
    //
    // Cross-core ping-pong: this lives on the owner worker's hot
    // data, so it shares cache lines with the surrounding queue
    // state (tokens, queued_bytes, etc.). Owner-only writes to all
    // of them, so false-sharing risk is internal to the worker and
    // already accepted by the design. The #709 cache-pad isolation
    // on BindingLiveState was specifically for owner/peer split;
    // here both are owner-side so no separate pad is needed.
    pub(super) owner_profile: CoSQueueOwnerProfile,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CoSQueueDropCounters {
    /// Flow-share admission cap exceeded; packet tail-dropped at
    /// `enqueue_cos_item`. Indicates SFQ bucket collision or a single
    /// flow attempting to occupy more than its fair share of the
    /// buffer. See #705, #711.
    pub(super) admission_flow_share_drops: u64,
    /// Physical queue buffer exceeded; packet tail-dropped at
    /// `enqueue_cos_item`. Indicates buffer undersizing relative to
    /// the offered-load × RTT product. See #707.
    pub(super) admission_buffer_drops: u64,
    /// Packet ECN CE-marked at admission (not dropped). Incremented
    /// when queue depth crosses the ECN threshold derived from
    /// `buffer_limit` AND the packet was already ECT(0) or ECT(1).
    /// Non-ECT packets above the threshold fall through to the drop
    /// path and are counted under the respective drop-reason field.
    /// See #718.
    pub(super) admission_ecn_marked: u64,
    /// Queue parked because the interface shaping-rate token bucket is
    /// empty. Not a drop — the queue will be woken on timer-wheel tick.
    /// High count relative to serviced-batches indicates the root
    /// shaper is the limiter.
    pub(super) root_token_starvation_parks: u64,
    /// Queue parked because the per-queue (exact) token bucket is
    /// empty. Not a drop — the queue will be woken when its own tokens
    /// refill. High count indicates the per-queue rate cap is the
    /// limiter for this queue.
    pub(super) queue_token_starvation_parks: u64,
    /// Counts `writer.insert` returning zero on the exact-drain path —
    /// i.e. the TX ring refused the batch. NOT a packet-loss event on
    /// the exact path: FIFO variants leave items in `queue.items` and
    /// flow-fair variants explicitly restore them via
    /// `restore_exact_*_scratch_to_queue_head_flow_fair`. Frames copied
    /// into UMEM are released back to `free_tx_frames` by the caller;
    /// the packets themselves are retried on the next drain cycle.
    /// Elevated values indicate TX ring / completion reap pressure, not
    /// packet loss. See #706 / #709 for the downstream causes operators
    /// typically chase when this fires.
    pub(super) tx_ring_full_submit_stalls: u64,
}

pub(super) struct CoSTimerWheelRuntime {
    pub(super) current_tick: u64,
    pub(super) level0: [Vec<usize>; COS_TIMER_WHEEL_L0_SLOTS],
    pub(super) level1: [Vec<usize>; COS_TIMER_WHEEL_L1_SLOTS],
}

/// #751: per-queue owner-side drain telemetry. Written by the owner
/// worker when a drain cycle services this specific queue (see
/// `drain_shaped_tx`'s per-queue return signal in tx.rs); read via
/// the snapshot path published through ArcSwap to Prometheus and to
/// `show class-of-service interface`.
///
/// Buckets sum to `drain_invocations` modulo the reader's scrape
/// window, pinned in
/// `queue_owner_profile_buckets_sum_to_drain_invocations`.
///
/// Single-writer. Relaxed is sufficient:
///   - The snapshot reader tolerates monotonic counter tearing
///     across the bucket array (same tolerance the BindingLiveState
///     owner_profile_owner already assumed).
///   - Prometheus scrape semantics are "best effort at scrape time".
///   - No happens-before requirement between the buckets themselves
///     or between `drain_latency_hist` and `drain_invocations` —
///     readers compute percentiles independently and a brief skew
///     just rounds the p50/p99 into an adjacent bucket.
pub(super) struct CoSQueueOwnerProfile {
    pub(super) drain_latency_hist: [AtomicU64; super::umem::DRAIN_HIST_BUCKETS],
    pub(super) drain_invocations: AtomicU64,
    /// #760 instrumentation. Bytes the shaped drain actually
    /// submitted on behalf of this queue. Divide by a scrape window
    /// to get an observed drain rate and compare against
    /// `queue.transmit_rate_bytes`. Writer = owner worker on the
    /// single site that also decrements `queue.tokens` after a send
    /// (apply_direct_exact_send_result for exact-owner-local,
    /// apply_cos_send_result for the non-exact / shared-exact paths).
    pub(super) drain_sent_bytes: AtomicU64,
    /// #760 instrumentation. Count of drain iterations where the
    /// root token gate fired (root.tokens < head_len) and the queue
    /// got parked waiting for the interface shaper to refill.
    pub(super) drain_park_root_tokens: AtomicU64,
    /// #760 instrumentation. Count of drain iterations where the
    /// per-queue token gate fired (queue.tokens < head_len) and the
    /// queue got parked waiting for its own refill. A queue that
    /// sustains throughput above its configured rate with this near
    /// zero is a direct signal the gate never fired.
    pub(super) drain_park_queue_tokens: AtomicU64,
}

impl CoSQueueOwnerProfile {
    pub(super) fn new() -> Self {
        Self {
            drain_latency_hist: std::array::from_fn(|_| AtomicU64::new(0)),
            drain_invocations: AtomicU64::new(0),
            drain_sent_bytes: AtomicU64::new(0),
            drain_park_root_tokens: AtomicU64::new(0),
            drain_park_queue_tokens: AtomicU64::new(0),
        }
    }
}

impl Default for CoSQueueOwnerProfile {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) struct SharedCoSQueueLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
    /// #785 cross-worker DRR: atomically-tracked total flow count
    /// across all workers servicing this shared_exact queue. Each
    /// worker uses this to compute its local fair-share drain rate
    /// (`queue_rate × local_flow_count / total_flow_count`), which
    /// it enforces via a per-worker local token bucket. This
    /// breaks the positive-feedback loop where workers with
    /// higher-cwnd flows grab disproportionately more of the
    /// shared lease.
    ///
    /// Updated on per-worker SFQ bucket transitions 0↔>0. Kept at
    /// the `Relaxed` ordering — the value is advisory input to the
    /// local rate calculation, recomputed on every per-worker
    /// bucket transition, so brief staleness between workers just
    /// delays convergence by one packet-scale interval.
    active_flow_count: AtomicU32,
    /// #785 slice 2: monotonically non-decreasing peak of
    /// `active_flow_count` observed by any worker. Used by the
    /// per-worker fair-share rate gate to stabilise the division
    /// denominator — `active_flow_count` oscillates rapidly in
    /// steady state because SFQ bucket transitions fire on every
    /// `bucket_bytes == 0` moment (between packets), producing
    /// transient dips in the count that would over-rate individual
    /// workers. Reading the peak instead gives an upper bound on
    /// the true flow count that converges within ~1 ms of a new
    /// flow arriving.
    ///
    /// Trade-off: on dynamic workloads where flows come and go, the
    /// peak never decays, so a worker's fair share stays under-rated
    /// after flows leave. Acceptable for the steady-state throughput
    /// tests that motivate #785; a follow-up slice can add a slow
    /// decay (e.g. reset to current count on a 1 s timer) if
    /// dynamic workloads become important.
    active_flow_count_peak: AtomicU32,
}

pub(super) struct SharedCoSRootLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SharedCoSLeaseConfig {
    rate_bytes: u64,
    burst_bytes: u64,
    lease_bytes: u64,
    max_total_leased: u64,
    active_shards: usize,
}

#[repr(align(64))]
#[derive(Debug)]
struct SharedCoSLeaseState {
    credits: AtomicU64,
    last_refill_ns: AtomicU64,
}

const COS_ROOT_LEASE_TARGET_US: u64 = 200;
const COS_ROOT_LEASE_MIN_BYTES: u64 = 1500;
const COS_ROOT_LEASE_MAX_BYTES: u64 = 512 * 1024;

fn compute_shared_cos_lease_config(
    rate_bytes: u64,
    burst_bytes: u64,
    active_shards: usize,
) -> SharedCoSLeaseConfig {
    let burst_bytes = burst_bytes
        .max(COS_ROOT_LEASE_MIN_BYTES)
        .min(u32::MAX as u64);
    let active_shards = active_shards.max(1);
    let target_lease_bytes =
        ((rate_bytes as u128) * (COS_ROOT_LEASE_TARGET_US as u128) / 1_000_000u128) as u64;
    let lease_ceiling = burst_bytes
        .saturating_div(8)
        .min(COS_ROOT_LEASE_MAX_BYTES)
        .max(COS_ROOT_LEASE_MIN_BYTES);
    let lease_bytes = target_lease_bytes
        .max(COS_ROOT_LEASE_MIN_BYTES)
        .min(lease_ceiling);
    let max_frame_lease_bytes = lease_bytes.max(tx_frame_capacity() as u64);
    let max_total_leased = burst_bytes
        .saturating_div(4)
        .min(max_frame_lease_bytes.saturating_mul(active_shards as u64));
    debug_assert!(max_total_leased <= u32::MAX as u64);
    SharedCoSLeaseConfig {
        rate_bytes,
        burst_bytes,
        lease_bytes,
        max_total_leased,
        active_shards,
    }
}

#[inline(always)]
fn pack_shared_cos_lease_credits(available_tokens: u64, outstanding_leased_tokens: u64) -> u64 {
    debug_assert!(available_tokens <= u32::MAX as u64);
    debug_assert!(outstanding_leased_tokens <= u32::MAX as u64);
    (available_tokens << 32) | outstanding_leased_tokens
}

#[inline(always)]
fn unpack_shared_cos_lease_credits(credits: u64) -> (u64, u64) {
    ((credits >> 32) as u64, (credits as u32) as u64)
}

fn shared_cos_lease_acquire(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 {
        return 0;
    }
    refill_shared_cos_lease_state(config, state, now_ns);
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let lease_headroom = config
            .max_total_leased
            .saturating_sub(outstanding_leased_tokens);
        let granted = requested.min(available_tokens).min(lease_headroom);
        if granted == 0 {
            return 0;
        }
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens.saturating_sub(granted),
            outstanding_leased_tokens.saturating_add(granted),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return granted;
        }
    }
}

fn shared_cos_lease_consume(state: &SharedCoSLeaseState, bytes: u64) {
    if bytes == 0 {
        return;
    }
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens,
            outstanding_leased_tokens.saturating_sub(bytes),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

#[inline(always)]
fn shared_cos_lease_available_cap(
    config: SharedCoSLeaseConfig,
    outstanding_leased_tokens: u64,
) -> u64 {
    config.burst_bytes.saturating_sub(outstanding_leased_tokens)
}

fn shared_cos_lease_release_unused(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    bytes: u64,
) {
    if bytes == 0 {
        return;
    }
    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let new_outstanding = outstanding_leased_tokens.saturating_sub(bytes);
        let new_available = available_tokens
            .saturating_add(bytes)
            .min(shared_cos_lease_available_cap(config, new_outstanding));
        let new_credits = pack_shared_cos_lease_credits(new_available, new_outstanding);
        if state
            .credits
            .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

fn refill_shared_cos_lease_state(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    now_ns: u64,
) {
    if config.burst_bytes == 0 {
        return;
    }
    loop {
        let last_refill_ns = state.last_refill_ns.load(Ordering::Acquire);
        if last_refill_ns == 0 {
            if state
                .last_refill_ns
                .compare_exchange(0, now_ns, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
            continue;
        }
        if now_ns <= last_refill_ns || config.rate_bytes == 0 {
            return;
        }
        let elapsed_ns = now_ns - last_refill_ns;
        let added = ((elapsed_ns as u128) * (config.rate_bytes as u128) / 1_000_000_000u128) as u64;
        if added == 0 {
            return;
        }
        if state
            .last_refill_ns
            .compare_exchange(last_refill_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        loop {
            let credits = state.credits.load(Ordering::Acquire);
            let (available_tokens, outstanding_leased_tokens) =
                unpack_shared_cos_lease_credits(credits);
            let new_available =
                available_tokens
                    .saturating_add(added)
                    .min(shared_cos_lease_available_cap(
                        config,
                        outstanding_leased_tokens,
                    ));
            let new_credits =
                pack_shared_cos_lease_credits(new_available, outstanding_leased_tokens);
            if state
                .credits
                .compare_exchange_weak(credits, new_credits, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }
}

impl SharedCoSQueueLease {
    pub(super) fn new(rate_bytes: u64, burst_bytes: u64, active_shards: usize) -> Self {
        let config = compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards);
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
            active_flow_count: AtomicU32::new(0),
            active_flow_count_peak: AtomicU32::new(0),
        }
    }

    pub(super) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
    }

    pub(super) fn rate_bytes(&self) -> u64 {
        self.config.rate_bytes
    }

    pub(super) fn matches_config(
        &self,
        rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> bool {
        self.config == compute_shared_cos_lease_config(rate_bytes, burst_bytes, active_shards)
    }

    pub(super) fn acquire(&self, now_ns: u64, requested: u64) -> u64 {
        shared_cos_lease_acquire(self.config, &self.state, now_ns, requested)
    }

    pub(super) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(super) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }

    /// #785 cross-worker DRR: total active flow count across all
    /// workers servicing this queue. Clamped to `>=1` at the use
    /// site (`fair_share_rate_bytes`) so divisions are safe even
    /// during the brief window where a worker has enqueued its
    /// first packet but has not yet incremented the counter.
    #[inline]
    pub(super) fn active_flow_count(&self) -> u32 {
        self.active_flow_count.load(Ordering::Relaxed)
    }

    /// Called by a worker when a locally-tracked flow transitions
    /// from idle (0 bytes queued in its SFQ bucket) to active
    /// (>0 bytes). Relaxed ordering is fine: the counter is
    /// advisory input to `fair_share_rate_bytes`, not a
    /// synchronisation point.
    ///
    /// Bumps `active_flow_count_peak` via a compare-and-swap loop
    /// so the peak monotonically tracks the live maximum — used by
    /// the rate gate to stabilise the division denominator against
    /// SFQ bucket-churn.
    #[inline]
    pub(super) fn add_active_flow(&self) {
        let new = self.active_flow_count.fetch_add(1, Ordering::Relaxed) + 1;
        let mut peak = self.active_flow_count_peak.load(Ordering::Relaxed);
        while new > peak {
            match self.active_flow_count_peak.compare_exchange_weak(
                peak,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => peak = observed,
            }
        }
    }

    /// Read the peak of observed `active_flow_count` within the
    /// current decay window. Bumped on every `add_active_flow` via
    /// the CAS loop, snapped down to the live instantaneous
    /// `active_flow_count` by any worker that calls
    /// `snap_peak_to_current` at a window boundary. Stable enough
    /// to use as the rate-gate denominator on steady state; bounded
    /// to the last-window max on flow churn.
    #[inline]
    pub(super) fn active_flow_count_peak(&self) -> u32 {
        self.active_flow_count_peak.load(Ordering::Relaxed)
    }

    /// Snap `active_flow_count_peak` down to the live
    /// `active_flow_count`. Called by each worker at the boundary
    /// of its own peak-decay window (one per
    /// `COS_FAIR_SHARE_PEAK_WINDOW_NS`, currently 500 ms). Multiple
    /// workers can snap concurrently; the store is lossy but the
    /// next `add_active_flow` CAS-walks the peak back up to the
    /// true max if it under-shot.
    ///
    /// Must NOT be called from any path that needs peak to be
    /// monotonic across the daemon's lifetime — this is solely the
    /// rate-gate's decay hook. The #784 per-worker diagnostic peak
    /// `CoSQueueRuntime.active_flow_buckets_peak` has its own
    /// "never reset" contract and a separate field.
    #[inline]
    pub(super) fn snap_peak_to_current(&self) {
        let current = self.active_flow_count.load(Ordering::Relaxed);
        self.active_flow_count_peak.store(current, Ordering::Relaxed);
    }

    /// Reverse of `add_active_flow`. Uses `saturating_sub` via
    /// compare-and-swap to avoid underflow if counter drift ever
    /// occurs — defensive because an underflow would mint an
    /// enormous `active_flow_count` and collapse every worker's
    /// fair-share rate to zero.
    #[inline]
    pub(super) fn remove_active_flow(&self) {
        let mut cur = self.active_flow_count.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return;
            }
            match self.active_flow_count.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

impl SharedCoSRootLease {
    pub(super) fn new(shaping_rate_bytes: u64, burst_bytes: u64, active_shards: usize) -> Self {
        let config =
            compute_shared_cos_lease_config(shaping_rate_bytes, burst_bytes, active_shards);
        Self {
            config,
            state: SharedCoSLeaseState {
                credits: AtomicU64::new(pack_shared_cos_lease_credits(config.burst_bytes, 0)),
                last_refill_ns: AtomicU64::new(0),
            },
        }
    }

    pub(super) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
    }

    pub(super) fn matches_config(
        &self,
        shaping_rate_bytes: u64,
        burst_bytes: u64,
        active_shards: usize,
    ) -> bool {
        self.config
            == compute_shared_cos_lease_config(shaping_rate_bytes, burst_bytes, active_shards)
    }

    pub(super) fn acquire(&self, now_ns: u64, requested: u64) -> u64 {
        shared_cos_lease_acquire(self.config, &self.state, now_ns, requested)
    }

    pub(super) fn consume(&self, bytes: u64) {
        shared_cos_lease_consume(&self.state, bytes);
    }

    pub(super) fn release_unused(&self, bytes: u64) {
        shared_cos_lease_release_unused(self.config, &self.state, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::align_of;

    // #694 / #711: `FlowRrRing` invariant pins.
    //
    // The ring is the SFQ round-robin cursor storage. Every bug class
    // that can break it is pinned here so a future refactor that
    // changes the indexing math, the wrap condition, or the head/len
    // update order fails loudly in CI instead of during live
    // validation.

    #[test]
    fn flow_rr_ring_push_pop_round_robin_order() {
        let mut ring = FlowRrRing::default();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.front(), None);

        ring.push_back(7);
        ring.push_back(11);
        ring.push_back(13);
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.front(), Some(7));

        // FIFO dequeue preserves push order.
        assert_eq!(ring.pop_front(), Some(7));
        assert_eq!(ring.pop_front(), Some(11));
        assert_eq!(ring.pop_front(), Some(13));
        assert_eq!(ring.pop_front(), None);
        assert!(ring.is_empty());
    }

    #[test]
    fn flow_rr_ring_push_front_places_at_head() {
        let mut ring = FlowRrRing::default();
        ring.push_back(5);
        ring.push_back(9);
        ring.push_front(3); // restore at head
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop_front(), Some(3));
        assert_eq!(ring.pop_front(), Some(5));
        assert_eq!(ring.pop_front(), Some(9));
    }

    #[test]
    fn flow_rr_ring_wraps_around_buffer_end_correctly() {
        // Drive the head past the backing-array end and back around.
        // A naive implementation that uses `head + len` without mod
        // breaks exactly here.
        let mut ring = FlowRrRing::default();
        // Fill to 3/4 of capacity, drain half, then fill by another
        // half-capacity worth — the tail write crosses the backing-
        // array end and wraps. Total in-flight stays within capacity.
        let first = COS_FLOW_FAIR_BUCKETS * 3 / 4;
        let second = COS_FLOW_FAIR_BUCKETS / 2;
        for i in 0..first {
            ring.push_back(i as u16);
        }
        for _ in 0..(first / 2) {
            ring.pop_front();
        }
        for i in 0..second {
            ring.push_back((i + 10_000) as u16);
        }
        let mut drained = Vec::with_capacity(ring.len());
        while let Some(b) = ring.pop_front() {
            drained.push(b);
        }
        let mut expected: Vec<u16> = ((first / 2)..first).map(|i| i as u16).collect();
        expected.extend((0..second).map(|i| (i + 10_000) as u16));
        assert_eq!(drained, expected);
    }

    #[test]
    fn flow_rr_ring_iter_yields_same_order_as_pop() {
        let mut ring = FlowRrRing::default();
        for v in [17u16, 3, 11, 29, 7] {
            ring.push_back(v);
        }
        let iter_snapshot: Vec<u16> = ring.iter().collect();
        let mut pop_snapshot = Vec::new();
        while let Some(b) = ring.pop_front() {
            pop_snapshot.push(b);
        }
        assert_eq!(iter_snapshot, pop_snapshot);
    }

    #[test]
    fn flow_rr_ring_accepts_full_cap_minus_one_without_wraparound_bug() {
        // Exactly-at-capacity-minus-one fills: common off-by-one site
        // for ring buffers where the "full" condition is tested.
        let mut ring = FlowRrRing::default();
        let cap = COS_FLOW_FAIR_BUCKETS as u16;
        for i in 0..(cap - 1) {
            ring.push_back(i);
        }
        assert_eq!(ring.len(), usize::from(cap - 1));
        // Drain and re-fill to force internal head advancement past
        // 3/4 of the buffer.
        for _ in 0..((cap - 1) / 2) {
            ring.pop_front();
        }
        // Push enough to wrap past the buffer end.
        for i in 0..((cap - 1) / 2) {
            ring.push_back(i + 10_000);
        }
        // Drain and assert no duplicate IDs and no spurious values.
        let mut seen = std::collections::BTreeSet::new();
        while let Some(b) = ring.pop_front() {
            assert!(seen.insert(b), "ring produced duplicate bucket id: {b}");
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn flow_rr_ring_holds_full_bucket_count_without_panic() {
        // The ring's own capacity is `COS_FLOW_FAIR_BUCKETS`. The
        // caller guards against duplicate pushes, so in practice the
        // ring holds at most `COS_FLOW_FAIR_BUCKETS` entries. Verify
        // that exactly-at-capacity is well-defined (no push_back
        // panic in release, no wrong head index) and that the ring
        // empties correctly.
        let mut ring = FlowRrRing::default();
        for i in 0..COS_FLOW_FAIR_BUCKETS {
            ring.push_back(i as u16);
        }
        assert_eq!(ring.len(), COS_FLOW_FAIR_BUCKETS);
        // Front is 0, tail write would wrap — but we're not over-
        // filling, so this is the well-defined "exactly at capacity"
        // case.
        assert_eq!(ring.front(), Some(0));
        // Drain and verify every ID came back exactly once.
        let mut count = 0usize;
        while let Some(b) = ring.pop_front() {
            assert_eq!(b, count as u16);
            count += 1;
        }
        assert_eq!(count, COS_FLOW_FAIR_BUCKETS);
    }

    #[test]
    fn flow_rr_ring_memory_footprint_fits_expected_budget() {
        // Sanity pin: `FlowRrRing` should be ~2 KB at the chosen
        // bucket count (1024 u16 entries + two u16 indices +
        // padding). A future refactor that accidentally widens the
        // entry type to u32 would double this without a loud signal;
        // this bound catches it.
        let size = std::mem::size_of::<FlowRrRing>();
        assert!(
            size <= 2 * 1024 + 64,
            "FlowRrRing unexpectedly large: {size} bytes"
        );
    }

    fn shared_cos_lease_snapshot(lease: &SharedCoSRootLease) -> (u64, u64, u64) {
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(lease.state.credits.load(Ordering::Relaxed));
        let last_refill_ns = lease.state.last_refill_ns.load(Ordering::Relaxed);
        (available_tokens, outstanding_leased_tokens, last_refill_ns)
    }

    #[test]
    fn shared_cos_root_lease_refill_respects_outstanding_burst_credit() {
        let lease = SharedCoSRootLease::new(10_000_000, 16_000, 1);
        lease
            .state
            .credits
            .store(pack_shared_cos_lease_credits(0, 4_000), Ordering::Relaxed);
        lease.state.last_refill_ns.store(1, Ordering::Relaxed);

        refill_shared_cos_lease_state(lease.config, &lease.state, 1_000_000_001);

        let (available_tokens, outstanding_leased_tokens, _) = shared_cos_lease_snapshot(&lease);
        assert_eq!(
            available_tokens,
            lease.config.burst_bytes - outstanding_leased_tokens
        );
    }

    #[test]
    fn shared_cos_root_lease_release_unused_preserves_total_burst_bound() {
        let lease = SharedCoSRootLease::new(10_000_000, 16_000, 1);
        lease.state.credits.store(
            pack_shared_cos_lease_credits(lease.config.burst_bytes, 4_000),
            Ordering::Relaxed,
        );

        lease.release_unused(1_500);

        let (available_tokens, outstanding_leased_tokens, _) = shared_cos_lease_snapshot(&lease);
        assert_eq!(
            available_tokens + outstanding_leased_tokens,
            lease.config.burst_bytes
        );
    }

    #[test]
    fn shared_cos_lease_state_is_cacheline_aligned() {
        assert_eq!(align_of::<SharedCoSLeaseState>(), 64);
    }

    #[test]
    fn shared_cos_lease_config_clamps_burst_to_packed_range() {
        let lease = SharedCoSRootLease::new(10_000_000, u64::MAX, 1);
        assert_eq!(lease.config.burst_bytes, u32::MAX as u64);
    }
}

pub(super) enum CoSPendingTxItem {
    Local(TxRequest),
    Prepared(PreparedTxRequest),
}

pub(super) const COS_PRIORITY_LEVELS: usize = 6;
pub(super) const COS_TIMER_WHEEL_L0_SLOTS: usize = 256;
pub(super) const COS_TIMER_WHEEL_L1_SLOTS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreparedTxRecycle {
    FreeTxFrame,
    FillOnSlot(u32),
}

#[derive(Debug)]
pub(super) struct LocalTunnelTxPlan {
    pub(super) tx_ifindex: i32,
    pub(super) tx_request: TxRequest,
    pub(super) session_entry: SyncedSessionEntry,
    pub(super) reverse_session_entry: Option<SyncedSessionEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LearnedNeighborKey {
    pub(super) ingress_ifindex: i32,
    pub(super) ingress_vlan_id: u16,
    pub(super) src_ip: IpAddr,
    pub(super) src_mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(super) enum WorkerCommand {
    UpsertSynced(SyncedSessionEntry),
    UpsertLocal(SyncedSessionEntry),
    DeleteSynced(SessionKey),
    DemoteOwnerRGS { owner_rgs: Vec<i32> },
    RefreshOwnerRGS { owner_rgs: Vec<i32> },
    ExportOwnerRGSessions { sequence: u64, owner_rgs: Vec<i32> },
    EnqueueShapedLocal(TxRequest),
}

#[derive(Default)]
pub(super) struct DebugPollCounters {
    pub(super) rx: u64,
    #[allow(dead_code)]
    pub(super) tx: u64,
    pub(super) forward: u64,
    #[allow(dead_code)]
    pub(super) local: u64,
    #[allow(dead_code)]
    pub(super) session_hit: u64,
    #[allow(dead_code)]
    pub(super) session_miss: u64,
    #[allow(dead_code)]
    pub(super) session_create: u64,
    #[allow(dead_code)]
    pub(super) no_route: u64,
    #[allow(dead_code)]
    pub(super) missing_neigh: u64,
    #[allow(dead_code)]
    pub(super) policy_deny: u64,
    #[allow(dead_code)]
    pub(super) ha_inactive: u64,
    #[allow(dead_code)]
    pub(super) no_egress_binding: u64,
    #[allow(dead_code)]
    pub(super) build_fail: u64,
    #[allow(dead_code)]
    pub(super) tx_err: u64,
    #[allow(dead_code)]
    pub(super) metadata_err: u64,
    pub(super) disposition_other: u64,
    pub(super) enqueue_ok: u64,
    pub(super) enqueue_inplace: u64,
    pub(super) enqueue_direct: u64,
    pub(super) enqueue_copy: u64,
    pub(super) rx_from_trust: u64,
    pub(super) rx_from_wan: u64,
    pub(super) fwd_trust_to_wan: u64,
    pub(super) fwd_wan_to_trust: u64,
    pub(super) nat_applied_snat: u64,
    pub(super) nat_applied_dnat: u64,
    pub(super) nat_applied_none: u64,
    #[allow(dead_code)]
    pub(super) frame_build_none: u64,
    pub(super) rx_tcp_rst: u64,
    #[allow(dead_code)]
    pub(super) tx_tcp_rst: u64,
    pub(super) rx_bytes_total: u64,
    pub(super) tx_bytes_total: u64,
    pub(super) rx_oversized: u64,
    pub(super) rx_max_frame: u32,
    pub(super) tx_max_frame: u32,
    pub(super) seg_needed_but_none: u64,
    pub(super) wan_return_hits: u64,
    #[allow(dead_code)]
    pub(super) wan_return_misses: u64,
    pub(super) rx_tcp_fin: u64,
    pub(super) rx_tcp_synack: u64,
    pub(super) rx_tcp_zero_window: u64,
    pub(super) fwd_tcp_fin: u64,
    pub(super) fwd_tcp_rst: u64,
    pub(super) fwd_tcp_zero_window: u64,
}
