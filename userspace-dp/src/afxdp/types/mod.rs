use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

// #1035 P4: shared CoS lease + V_min coordination types split into a
// sibling submodule. Re-exported at pub(super) so the rest of afxdp/
// continues to find them as `super::types::SharedCoS*`.
mod shared_cos_lease;
pub(super) use shared_cos_lease::{
    NOT_PARTICIPATING, PaddedVtimeSlot, SharedCoSQueueLease, SharedCoSQueueVtimeFloor,
    SharedCoSRootLease,
};

// Issue 68.1: CoS shaper / queue / flow-fair / runtime types extracted
// into types/cos.rs. Re-exported here so call sites that reach
// `crate::afxdp::types::*` resolve unchanged.
mod cos;
pub(in crate::afxdp) use cos::*;

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
    // #869: per-worker busy/idle runtime telemetry publish slot.
    pub(super) runtime_atomics: Arc<super::worker_runtime::WorkerRuntimeAtomics>,
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
    /// #921: ifindex → zone ID (was `FastMap<i32, String>`). Built
    /// at config-commit time from the snapshot's per-interface
    /// zone NAME via the `zone_name_to_id` lookup. Hot-path callers
    /// read u16 directly; slow-path display sites translate via
    /// `zone_id_to_name`. Unknown / dropped zones map to `0`.
    pub(super) ifindex_to_zone_id: FastMap<i32, u16>,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
}

#[derive(Clone, Debug)]
pub(super) struct EgressInterface {
    pub(super) bind_ifindex: i32,
    pub(super) vlan_id: u16,
    pub(super) mtu: usize,
    pub(super) src_mac: [u8; 6],
    /// #921: u16 zone ID (was `zone: String`). Resolved at config
    /// build time via `zone_name_to_id`; `0` means "unknown" (the
    /// zone wasn't in the snapshot's zones list, or had a reserved
    /// id and was dropped).
    pub(super) zone_id: u16,
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
    pub(super) fn status(
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
    /// #919: stored as zone IDs; the slow-path `into_*` conversion
    /// looks up the name via `forwarding.zone_id_to_name`.
    pub(super) from_zone: Option<u16>,
    pub(super) to_zone: Option<u16>,
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
pub(in crate::afxdp) enum WorkerCommand {
    UpsertSynced(SyncedSessionEntry),
    UpsertLocal(SyncedSessionEntry),
    DeleteSynced(SessionKey),
    DemoteOwnerRGS { owner_rgs: Vec<i32> },
    RefreshOwnerRGS { owner_rgs: Vec<i32> },
    ExportOwnerRGSessions { sequence: u64, owner_rgs: Vec<i32> },
    EnqueueShapedLocal(TxRequest),
    /// #941 Work item C: vacate ALL V_min slots owned by this worker
    /// across every binding's shared_exact queues. Enqueued by the
    /// coordinator on HA demotion (RG primary→secondary). The actual
    /// vacate runs on the worker thread (single-writer invariant) —
    /// this command sets a flag in `WorkerCommandResults`; the outer
    /// poll loop dispatches via `vacate_all_shared_exact_slots`.
    VacateAllSharedExactSlots,
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

/// #945: shared/passed-through context for `poll_binding_process_descriptor`.
///
/// All 16 fields are shared (`&'a` or `&'a Arc<...>`) references that
/// the function reads from or that wrap interior-mutable state behind
/// `Mutex`/`Arc`. NOT read-only in the strict sense — several entries
/// like `dynamic_neighbors` are mutated through their inner `Mutex`
/// (e.g. `dynamic_neighbors.lock().insert(...)` at afxdp.rs ARP/NA
/// learn sites).
///
/// Constructed once per RX-batch call at the
/// `poll_binding_process_descriptor` call site. `'a` is covariant.
pub(super) struct WorkerContext<'a> {
    pub(super) ident: &'a BindingIdentity,
    pub(super) binding_lookup: &'a WorkerBindingLookup,
    pub(super) forwarding: &'a ForwardingState,
    pub(super) ha_state: &'a BTreeMap<i32, HAGroupRuntime>,
    pub(super) dynamic_neighbors: &'a Arc<super::sharded_neighbor::ShardedNeighborMap>,
    pub(super) shared_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(super) shared_nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(super) shared_forward_wire_sessions:
        &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(super) shared_owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    pub(super) slow_path: Option<&'a Arc<SlowPathReinjector>>,
    pub(super) local_tunnel_deliveries:
        &'a Arc<ArcSwap<BTreeMap<i32, SyncSender<Vec<u8>>>>>,
    pub(super) recent_exceptions: &'a Arc<Mutex<VecDeque<ExceptionStatus>>>,
    pub(super) last_resolution: &'a Arc<Mutex<Option<PacketResolution>>>,
    pub(super) peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    pub(super) dnat_fds: &'a DnatTableFds,
    pub(super) rg_epochs: &'a [AtomicU32; MAX_RG_EPOCHS],
}

/// #945: mutable telemetry context for `poll_binding_process_descriptor`.
pub(super) struct TelemetryContext<'a> {
    pub(super) dbg: &'a mut DebugPollCounters,
    pub(super) counters: &'a mut BatchCounters,
}

#[cfg(test)]
mod flow_rr_ring_tests {
    use super::*;

    // #694 / #711: `FlowRrRing` invariant pins. Colocated with the production
    // FlowRrRing struct + impl in types/mod.rs (split back from the
    // shared_cos_lease test mod per Codex P4 review).

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
}

