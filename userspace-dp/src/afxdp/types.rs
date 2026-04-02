use super::*;
use std::sync::atomic::AtomicU32;

pub(super) type FastMap<K, V> = FxHashMap<K, V>;
pub(super) type FastSet<T> = FxHashSet<T>;

const FLOW_CACHE_SIZE: usize = 4096;
const FLOW_CACHE_MASK: usize = FLOW_CACHE_SIZE - 1;

/// Maximum number of redundancy groups for epoch-based cache invalidation.
pub(super) const MAX_RG_EPOCHS: usize = 16;

/// Precomputed rewrite descriptor for an established flow.
/// All fields are constant for the lifetime of the session.
/// Per-packet cost: write MACs + TTL-- + apply precomputed csum deltas.
#[derive(Clone, Copy, Debug)]
pub(super) struct RewriteDescriptor {
    pub(super) dst_mac: [u8; 6],
    pub(super) src_mac: [u8; 6],
    pub(super) tx_vlan_id: u16,
    pub(super) ether_type: u16,
    pub(super) rewrite_src_ip: Option<std::net::IpAddr>,
    pub(super) rewrite_dst_ip: Option<std::net::IpAddr>,
    pub(super) rewrite_src_port: Option<u16>,
    pub(super) rewrite_dst_port: Option<u16>,
    pub(super) ip_csum_delta: u16,
    pub(super) l4_csum_delta: u16,
    pub(super) egress_ifindex: i32,
    pub(super) tx_ifindex: i32,
    pub(super) target_binding_index: Option<usize>,
    pub(super) nat64: bool,
    pub(super) nptv6: bool,
    pub(super) apply_nat_on_fabric: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FlowCacheStamp {
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) owner_rg_id: i32,
    pub(super) owner_rg_epoch: u32,
}

impl FlowCacheStamp {
    #[inline]
    pub(super) fn capture(
        config_generation: u64,
        fib_generation: u32,
        owner_rg_id: i32,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Self {
        Self {
            config_generation,
            fib_generation,
            owner_rg_id,
            owner_rg_epoch: if owner_rg_id > 0 && (owner_rg_id as usize) < MAX_RG_EPOCHS {
                rg_epochs[owner_rg_id as usize].load(Ordering::Relaxed)
            } else {
                0
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FlowCacheLookup {
    pub(super) ingress_ifindex: i32,
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
}

impl FlowCacheLookup {
    #[inline]
    pub(super) fn for_packet(meta: UserspaceDpMeta, validation: ValidationState) -> Self {
        Self {
            ingress_ifindex: meta.ingress_ifindex as i32,
            config_generation: validation.config_generation,
            fib_generation: validation.fib_generation,
        }
    }
}

/// Per-flow cache entry with key validation.
#[derive(Clone)]
pub(super) struct FlowCacheEntry {
    pub(super) key: crate::session::SessionKey,
    pub(super) ingress_ifindex: i32,
    pub(super) descriptor: RewriteDescriptor,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    /// Validation stamp captured at insert time. Stale entries are treated as
    /// misses without requiring per-entry scans at RG transition.
    pub(super) stamp: FlowCacheStamp,
}

impl FlowCacheEntry {
    #[inline]
    pub(super) fn packet_eligible(meta: UserspaceDpMeta) -> bool {
        (meta.protocol == PROTO_TCP && (meta.tcp_flags & 0x17) == 0x10)
            || meta.protocol == PROTO_UDP
    }

    #[inline]
    pub(super) fn should_cache(meta: UserspaceDpMeta, decision: SessionDecision) -> bool {
        matches!(meta.protocol, PROTO_TCP | PROTO_UDP)
            && !decision.nat.nat64
            && !decision.nat.nptv6
            && decision.resolution.disposition == ForwardingDisposition::ForwardCandidate
    }

    pub(super) fn from_forward_decision(
        flow: &SessionFlow,
        meta: UserspaceDpMeta,
        validation: ValidationState,
        decision: SessionDecision,
        ingress_zone: Option<Arc<str>>,
        forwarding: &ForwardingState,
        apply_nat_on_fabric: bool,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Option<Self> {
        if !Self::should_cache(meta, decision) {
            return None;
        }
        let owner_rg_id = owner_rg_for_resolution(forwarding, decision.resolution);
        Some(Self {
            key: flow.forward_key.clone(),
            ingress_ifindex: meta.ingress_ifindex as i32,
            descriptor: RewriteDescriptor {
                dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
                src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
                tx_vlan_id: decision.resolution.tx_vlan_id,
                ether_type: if meta.addr_family as i32 == libc::AF_INET {
                    0x0800
                } else {
                    0x86dd
                },
                rewrite_src_ip: decision.nat.rewrite_src,
                rewrite_dst_ip: decision.nat.rewrite_dst,
                rewrite_src_port: decision.nat.rewrite_src_port,
                rewrite_dst_port: decision.nat.rewrite_dst_port,
                ip_csum_delta: compute_ip_csum_delta(flow, &decision.nat),
                l4_csum_delta: compute_l4_csum_delta(flow, &decision.nat),
                egress_ifindex: decision.resolution.egress_ifindex,
                tx_ifindex: decision.resolution.tx_ifindex,
                target_binding_index: None,
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric,
            },
            decision,
            metadata: SessionMetadata {
                ingress_zone: ingress_zone.unwrap_or_else(|| Arc::from("")),
                egress_zone: Arc::from(""),
                owner_rg_id,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
            stamp: FlowCacheStamp::capture(
                validation.config_generation,
                validation.fib_generation,
                owner_rg_id,
                rg_epochs,
            ),
        })
    }
}

/// Per-worker flow cache. Direct-mapped, indexed by hash of 5-tuple.
pub(super) struct FlowCache {
    pub(super) entries: Vec<Option<FlowCacheEntry>>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) evictions: u64,
}

impl FlowCache {
    pub(super) fn new() -> Self {
        Self {
            entries: (0..FLOW_CACHE_SIZE).map(|_| None).collect(),
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    #[inline]
    pub(super) fn slot(key: &crate::session::SessionKey, ingress_ifindex: i32) -> usize {
        use std::hash::{Hash, Hasher};

        let mut hasher = rustc_hash::FxHasher::default();
        key.hash(&mut hasher);
        (ingress_ifindex as u32).hash(&mut hasher);
        hasher.finish() as usize & FLOW_CACHE_MASK
    }

    #[inline]
    pub(super) fn lookup(
        &mut self,
        key: &crate::session::SessionKey,
        lookup: FlowCacheLookup,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Option<&FlowCacheEntry> {
        let idx = Self::slot(key, lookup.ingress_ifindex);
        if let Some(entry) = &self.entries[idx] {
            if entry.key == *key
                && entry.ingress_ifindex == lookup.ingress_ifindex
                && entry.stamp.config_generation == lookup.config_generation
                && entry.stamp.fib_generation == lookup.fib_generation
            {
                // Epoch-based RG invalidation: if the owner RG's epoch has
                // advanced since this entry was inserted, treat as a miss.
                let owner = entry.stamp.owner_rg_id;
                if owner > 0 && (owner as usize) < MAX_RG_EPOCHS {
                    let current_epoch = rg_epochs[owner as usize].load(Ordering::Relaxed);
                    if current_epoch != entry.stamp.owner_rg_epoch {
                        self.misses += 1;
                        // Evict stale entry.
                        self.entries[idx] = None;
                        self.evictions += 1;
                        return None;
                    }
                }
                self.hits += 1;
                return self.entries[idx].as_ref();
            }
        }
        self.misses += 1;
        None
    }

    pub(super) fn insert(&mut self, entry: FlowCacheEntry) {
        let idx = Self::slot(&entry.key, entry.ingress_ifindex);
        if self.entries[idx].is_some() {
            self.evictions += 1;
        }
        self.entries[idx] = Some(entry);
    }

    /// Nuclear invalidation — clears every entry. Reserved for rare events
    /// like link-cycle or full config reload where epoch-based invalidation
    /// is insufficient (e.g. routing table rebuild, interface renumbering).
    #[allow(dead_code)]
    pub(super) fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
    }

    pub(super) fn invalidate_slot(
        &mut self,
        key: &crate::session::SessionKey,
        ingress_ifindex: i32,
    ) {
        let idx = Self::slot(key, ingress_ifindex);
        self.entries[idx] = None;
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

#[repr(C)]
pub(super) struct XdpOptions {
    pub(super) flags: u32,
}

pub(super) struct WorkerHandle {
    pub(super) stop: Arc<AtomicBool>,
    pub(super) heartbeat: Arc<AtomicU64>,
    pub(super) commands: Arc<Mutex<VecDeque<WorkerCommand>>>,
    pub(super) demotion_prepare_ack: Arc<AtomicU64>,
    pub(super) refresh_owner_rgs_ack: Arc<AtomicU64>,
    pub(super) session_export_ack: Arc<AtomicU64>,
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
    pub(super) ifindex_to_zone: FastMap<i32, String>,
    pub(super) zone_name_to_id: FastMap<String, u16>,
    pub(super) zone_id_to_name: FastMap<u16, String>,
    pub(super) egress: FastMap<i32, EgressInterface>,
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
    #[allow(dead_code)]
    pub(super) gre_acceleration: bool,
    pub(super) flow_export_config: Option<crate::flowexport::FlowExportConfig>,
    pub(super) tcp_mss_all_tcp: u16,
    pub(super) tcp_mss_ipsec_vpn: u16,
    pub(super) tcp_mss_gre_in: u16,
    pub(super) tcp_mss_gre_out: u16,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct HAGroupRuntime {
    pub(super) active: bool,
    pub(super) watchdog_timestamp: u64,
    pub(super) demoting: bool,
    pub(super) demoting_until_secs: u64,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SessionFlow {
    pub(super) src_ip: IpAddr,
    pub(super) dst_ip: IpAddr,
    pub(super) forward_key: SessionKey,
}

impl SessionFlow {
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
}

pub(super) struct PendingForwardRequest {
    pub(super) target_ifindex: i32,
    pub(super) target_binding_index: Option<usize>,
    pub(super) ingress_queue_id: u32,
    pub(super) source_offset: u64,
    pub(super) desc: XdpDesc,
    pub(super) source_frame: Option<Vec<u8>>,
    pub(super) meta: UserspaceDpMeta,
    pub(super) decision: SessionDecision,
    pub(super) apply_nat_on_fabric: bool,
    pub(super) expected_ports: Option<(u16, u16)>,
    pub(super) flow_key: Option<SessionKey>,
    pub(super) nat64_reverse: Option<Nat64ReverseInfo>,
    pub(super) prebuilt_frame: Option<Vec<u8>>,
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
pub(super) enum WorkerCommand {
    UpsertSynced(SyncedSessionEntry),
    UpsertLocal(SyncedSessionEntry),
    DeleteSynced(SessionKey),
    ExportOwnerRGSessions { sequence: u64, owner_rgs: Vec<i32> },
    PrepareDemoteOwnerRGs { sequence: u64, owner_rgs: Vec<i32> },
    DemoteOwnerRG(i32),
    RefreshOwnerRGs { owner_rgs: Vec<i32>, sequence: u64 },
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
