use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

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

pub(super) struct CoSInterfaceRuntime {
    pub(super) shaping_rate_bytes: u64,
    pub(super) burst_bytes: u64,
    pub(super) tokens: u64,
    pub(super) default_queue: u8,
    pub(super) nonempty_queues: usize,
    pub(super) runnable_queues: usize,
    pub(super) guarantee_rr: usize,
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
    pub(super) surplus_weight: u32,
    pub(super) surplus_deficit: u64,
    pub(super) buffer_bytes: u64,
    pub(super) dscp_rewrite: Option<u8>,
    pub(super) tokens: u64,
    pub(super) last_refill_ns: u64,
    pub(super) queued_bytes: u64,
    pub(super) runnable: bool,
    pub(super) parked: bool,
    pub(super) next_wakeup_tick: u64,
    pub(super) wheel_level: u8,
    pub(super) wheel_slot: usize,
    pub(super) items: VecDeque<CoSPendingTxItem>,
}

pub(super) struct CoSTimerWheelRuntime {
    pub(super) current_tick: u64,
    pub(super) level0: [Vec<usize>; COS_TIMER_WHEEL_L0_SLOTS],
    pub(super) level1: [Vec<usize>; COS_TIMER_WHEEL_L1_SLOTS],
}

#[repr(align(64))]
pub(super) struct SharedCoSQueueLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
}

#[repr(align(64))]
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
    let burst_bytes = burst_bytes.max(COS_ROOT_LEASE_MIN_BYTES);
    assert!(
        burst_bytes <= u32::MAX as u64,
        "shared CoS burst exceeds packed lease range: {}",
        burst_bytes
    );
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
        }
    }

    pub(super) fn lease_bytes(&self) -> u64 {
        self.config.lease_bytes
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
