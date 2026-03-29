use super::*;

pub(super) type FastMap<K, V> = FxHashMap<K, V>;
pub(super) type FastSet<T> = FxHashSet<T>;

const FLOW_CACHE_SIZE: usize = 4096;
const FLOW_CACHE_MASK: usize = FLOW_CACHE_SIZE - 1;

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
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) owner_rg_id: i32,
    pub(super) nat64: bool,
    pub(super) nptv6: bool,
    pub(super) apply_nat_on_fabric: bool,
}

/// Per-flow cache entry with key validation.
#[derive(Clone)]
pub(super) struct FlowCacheEntry {
    pub(super) key: crate::session::SessionKey,
    pub(super) ingress_ifindex: i32,
    pub(super) descriptor: RewriteDescriptor,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
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
        ingress_ifindex: i32,
        config_generation: u64,
        fib_generation: u32,
    ) -> Option<&FlowCacheEntry> {
        let idx = Self::slot(key, ingress_ifindex);
        if let Some(entry) = &self.entries[idx] {
            if entry.key == *key
                && entry.ingress_ifindex == ingress_ifindex
                && entry.descriptor.config_generation == config_generation
                && entry.descriptor.fib_generation == fib_generation
            {
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

    pub(super) fn invalidate_owner_rg(&mut self, owner_rg_id: i32) {
        if owner_rg_id <= 0 {
            return;
        }
        for entry in &mut self.entries {
            let Some(cached) = entry.as_ref() else {
                continue;
            };
            if cached.metadata.owner_rg_id == owner_rg_id
                || cached.descriptor.owner_rg_id == owner_rg_id
            {
                *entry = None;
                self.evictions += 1;
            }
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
    RefreshOwnerRGs(Vec<i32>),
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
