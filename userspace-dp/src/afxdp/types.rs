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
