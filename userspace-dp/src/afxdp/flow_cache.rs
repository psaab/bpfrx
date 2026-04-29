use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

const FLOW_CACHE_SIZE: usize = 4096;
// #918: 4-way set-associative layout. Total entry count stays
// at 4096 (1024 sets × 4 ways) so memory footprint is unchanged
// in the entries array; the new `lru: [u8; 4]` per set adds 4 KB
// of bookkeeping. Per-set scan touches ~6 cache lines (4 × ~96 B
// + 4 B lru) which is prefetcher-friendly. Compare to the old
// 1-way direct-mapped layout where any 2 flows that hashed to the
// same slot evicted each other on every packet.
const FLOW_CACHE_WAYS: usize = 4;
const FLOW_CACHE_SETS: usize = FLOW_CACHE_SIZE / FLOW_CACHE_WAYS;
const FLOW_CACHE_SET_MASK: usize = FLOW_CACHE_SETS - 1;
const _: () = assert!(FLOW_CACHE_SETS.is_power_of_two());
const _: () = assert!(FLOW_CACHE_WAYS == 4);
const _: () = assert!(FLOW_CACHE_SETS * FLOW_CACHE_WAYS == FLOW_CACHE_SIZE);

/// Maximum number of redundancy groups for epoch-based cache invalidation.
pub(super) const MAX_RG_EPOCHS: usize = 16;

#[derive(Clone, Debug, Default)]
pub(super) struct CachedTxSelectionDescriptor {
    pub(super) queue_id: Option<u8>,
    pub(super) dscp_rewrite: Option<u8>,
    pub(super) filter_counter: Option<Arc<crate::filter::FilterTermCounter>>,
}

/// Precomputed rewrite descriptor for an established flow.
/// All fields are constant for the lifetime of the session.
/// Per-packet cost: write MACs + TTL-- + apply precomputed csum deltas.
#[derive(Clone, Debug)]
pub(super) struct RewriteDescriptor {
    pub(super) dst_mac: [u8; 6],
    pub(super) src_mac: [u8; 6],
    pub(super) fabric_redirect: bool,
    pub(super) tx_vlan_id: u16,
    pub(super) ether_type: u16,
    pub(super) rewrite_src_ip: Option<std::net::IpAddr>,
    pub(super) rewrite_dst_ip: Option<std::net::IpAddr>,
    pub(super) rewrite_src_port: Option<u16>,
    pub(super) rewrite_dst_port: Option<u16>,
    pub(super) ip_csum_delta: u16,
    pub(super) l4_csum_delta: u16,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) egress_ifindex: i32,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) tx_ifindex: i32,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) target_binding_index: Option<usize>,
    pub(super) tx_selection: CachedTxSelectionDescriptor,
    pub(super) nat64: bool,
    pub(super) nptv6: bool,
    #[allow(dead_code)] // populated for future flow-cache fast-path TX
    pub(super) apply_nat_on_fabric: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FlowCacheStamp {
    pub(super) config_generation: u64,
    pub(super) fib_generation: u32,
    pub(super) owner_rg_id: i32,
    pub(super) owner_rg_epoch: u32,
    pub(super) owner_rg_lease_until: u64,
}

impl FlowCacheStamp {
    #[inline]
    pub(super) fn capture(
        config_generation: u64,
        fib_generation: u32,
        owner_rg_id: i32,
        ha_state: &BTreeMap<i32, HAGroupRuntime>,
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
            owner_rg_lease_until: ha_state
                .get(&owner_rg_id)
                .map(|group| match group.lease {
                    HAForwardingLease::ActiveUntil(until) if group.active => until,
                    _ => 0,
                })
                .unwrap_or(0),
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
            && decision.resolution.disposition.is_cacheable()
    }

    pub(super) fn from_forward_decision(
        flow: &SessionFlow,
        meta: UserspaceDpMeta,
        validation: ValidationState,
        decision: SessionDecision,
        flow_owner_rg_id: i32,
        ingress_zone: Option<u16>,
        target_binding_index: Option<usize>,
        forwarding: &ForwardingState,
        ha_state: &BTreeMap<i32, HAGroupRuntime>,
        apply_nat_on_fabric: bool,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Option<Self> {
        if !Self::should_cache(meta, decision) {
            return None;
        }
        // Keep cache invalidation tied to the flow owner RG, not the current
        // fabric parent ifindex. During split-RG operation a live flow can
        // temporarily resolve to FabricRedirect, but failback must still evict
        // that cached redirect as soon as the owning RG flips locally.
        let owner_rg_id = if flow_owner_rg_id > 0 {
            flow_owner_rg_id
        } else {
            owner_rg_for_resolution(forwarding, decision.resolution)
        };
        Some(Self {
            key: flow.forward_key.clone(),
            ingress_ifindex: meta.ingress_ifindex as i32,
            descriptor: RewriteDescriptor {
                dst_mac: decision.resolution.neighbor_mac.unwrap_or([0; 6]),
                src_mac: decision.resolution.src_mac.unwrap_or([0; 6]),
                fabric_redirect: decision.resolution.disposition
                    == ForwardingDisposition::FabricRedirect,
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
                target_binding_index,
                tx_selection: resolve_cached_cos_tx_selection(
                    forwarding,
                    decision.resolution.egress_ifindex,
                    meta,
                    Some(&flow.forward_key),
                ),
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric,
            },
            decision,
            metadata: SessionMetadata {
                ingress_zone: ingress_zone.unwrap_or(0),
                egress_zone: 0,
                owner_rg_id,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
            },
            stamp: FlowCacheStamp::capture(
                validation.config_generation,
                validation.fib_generation,
                owner_rg_id,
                ha_state,
                rg_epochs,
            ),
        })
    }
}

/// Per-worker flow cache. 4-way set-associative with LRU eviction
/// within each set (#918). Layout: `FLOW_CACHE_SETS = 1024` sets,
/// each holding `FLOW_CACHE_WAYS = 4` ways. The `entries` vec
/// is stored row-major: set `s` occupies indices
/// `[s * WAYS, s * WAYS + WAYS)`. Per set, `lru[s]` is a
/// permutation of `[0, 1, 2, 3]` where index 0 is MRU and
/// index 3 is LRU.
pub(super) struct FlowCache {
    pub(super) entries: Vec<Option<FlowCacheEntry>>,
    /// Per-set LRU permutation. `lru[s][0]` = MRU way, `lru[s][3]` = LRU way.
    /// Initialized to `[0, 1, 2, 3]` for every set so eviction order on a
    /// fresh set is deterministic.
    pub(super) lru: Vec<[u8; FLOW_CACHE_WAYS]>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) evictions: u64,
    /// Collision evictions = inserts that displaced a different-key entry
    /// (i.e. the set was full and we kicked out the LRU way). Tracked
    /// separately from `evictions` (which also counts stale-on-lookup
    /// evictions) for hot-set diagnosis.
    pub(super) collision_evictions: u64,
}

impl FlowCache {
    pub(super) fn new() -> Self {
        Self {
            entries: (0..FLOW_CACHE_SIZE).map(|_| None).collect(),
            lru: vec![[0u8, 1, 2, 3]; FLOW_CACHE_SETS],
            hits: 0,
            misses: 0,
            evictions: 0,
            collision_evictions: 0,
        }
    }

    /// Set index = low bits of the FxHasher-produced flow hash.
    /// Same hash function as the prior 1-way layout to preserve
    /// behavior for non-collision keys.
    #[inline]
    pub(super) fn set_index(key: &crate::session::SessionKey, ingress_ifindex: i32) -> usize {
        use std::hash::{Hash, Hasher};

        let mut hasher = rustc_hash::FxHasher::default();
        key.hash(&mut hasher);
        (ingress_ifindex as u32).hash(&mut hasher);
        hasher.finish() as usize & FLOW_CACHE_SET_MASK
    }

    /// Promote `way` to the MRU position in `lru[set]`, shifting the
    /// preceding entries down by one. Branchless 3-element shuffle.
    #[inline]
    fn promote_lru(&mut self, set: usize, way: u8) {
        let row = &mut self.lru[set];
        // Find current position of `way`.
        let mut pos = 0usize;
        for i in 0..FLOW_CACHE_WAYS {
            if row[i] == way {
                pos = i;
                break;
            }
        }
        if pos == 0 {
            return; // already MRU
        }
        // Shift row[0..pos] down by one, write `way` at row[0].
        for i in (1..=pos).rev() {
            row[i] = row[i - 1];
        }
        row[0] = way;
    }

    /// Demote `way` to the LRU position in `lru[set]`, shifting the
    /// following entries up by one.
    #[inline]
    fn demote_lru(&mut self, set: usize, way: u8) {
        let row = &mut self.lru[set];
        let mut pos = 0usize;
        for i in 0..FLOW_CACHE_WAYS {
            if row[i] == way {
                pos = i;
                break;
            }
        }
        if pos == FLOW_CACHE_WAYS - 1 {
            return; // already LRU
        }
        for i in pos..(FLOW_CACHE_WAYS - 1) {
            row[i] = row[i + 1];
        }
        row[FLOW_CACHE_WAYS - 1] = way;
    }

    #[inline]
    pub(super) fn lookup(
        &mut self,
        key: &crate::session::SessionKey,
        lookup: FlowCacheLookup,
        now_secs: u64,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> Option<&FlowCacheEntry> {
        let set = Self::set_index(key, lookup.ingress_ifindex);
        let base = set * FLOW_CACHE_WAYS;
        // Key-first, generation-second: scan the set for a key match.
        // A key-match with stale generation is a guaranteed-bad cache
        // entry under the §3.4.2 dedup invariant (at most one way per
        // set holds a given key), so it's safe to evict immediately
        // and return MISS.
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if let Some(entry) = &self.entries[entry_idx] {
                if entry.key != *key || entry.ingress_ifindex != lookup.ingress_ifindex {
                    continue;
                }
                // Key match. Validate generation/epoch/lease.
                if entry.stamp.config_generation != lookup.config_generation
                    || entry.stamp.fib_generation != lookup.fib_generation
                {
                    self.entries[entry_idx] = None;
                    self.evictions += 1;
                    self.demote_lru(set, way as u8);
                    self.misses += 1;
                    return None;
                }
                let owner = entry.stamp.owner_rg_id;
                if owner > 0 && (owner as usize) < MAX_RG_EPOCHS {
                    let current_epoch = rg_epochs[owner as usize].load(Ordering::Relaxed);
                    if current_epoch != entry.stamp.owner_rg_epoch {
                        self.entries[entry_idx] = None;
                        self.evictions += 1;
                        self.demote_lru(set, way as u8);
                        self.misses += 1;
                        return None;
                    }
                }
                if entry.stamp.owner_rg_lease_until != 0
                    && now_secs > entry.stamp.owner_rg_lease_until
                {
                    self.entries[entry_idx] = None;
                    self.evictions += 1;
                    self.demote_lru(set, way as u8);
                    self.misses += 1;
                    return None;
                }
                // Fresh hit.
                self.promote_lru(set, way as u8);
                self.hits += 1;
                return self.entries[entry_idx].as_ref();
            }
        }
        self.misses += 1;
        None
    }

    pub(super) fn insert(&mut self, entry: FlowCacheEntry) {
        let set = Self::set_index(&entry.key, entry.ingress_ifindex);
        let base = set * FLOW_CACHE_WAYS;
        // Dedup-on-insert: if this set already holds the same key
        // (e.g. a stale entry that the caller is about to overwrite
        // with a fresh decision), find-and-replace that way rather
        // than allocating a new way. Preserves the "at most one way
        // per set holds a given key" invariant the lookup path relies
        // on.
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if let Some(existing) = &self.entries[entry_idx] {
                if existing.key == entry.key
                    && existing.ingress_ifindex == entry.ingress_ifindex
                {
                    self.entries[entry_idx] = Some(entry);
                    self.promote_lru(set, way as u8);
                    return;
                }
            }
        }
        // No matching key: prefer an empty way; otherwise evict LRU.
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if self.entries[entry_idx].is_none() {
                self.entries[entry_idx] = Some(entry);
                self.promote_lru(set, way as u8);
                return;
            }
        }
        // Set is full — evict the LRU way.
        let lru_way = self.lru[set][FLOW_CACHE_WAYS - 1];
        let entry_idx = base + (lru_way as usize);
        self.entries[entry_idx] = Some(entry);
        self.evictions += 1;
        self.collision_evictions += 1;
        self.promote_lru(set, lru_way);
    }

    /// Nuclear invalidation — clears every entry. Reserved for rare events
    /// like link-cycle or full config reload where epoch-based invalidation
    /// is insufficient (e.g. routing table rebuild, interface renumbering).
    #[allow(dead_code)]
    pub(super) fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            *entry = None;
        }
        // LRU permutations are reset to canonical order; eviction
        // order on the next inserts to a cleared set is deterministic.
        for row in &mut self.lru {
            *row = [0, 1, 2, 3];
        }
    }

    pub(super) fn invalidate_slot(
        &mut self,
        key: &crate::session::SessionKey,
        ingress_ifindex: i32,
    ) {
        let set = Self::set_index(key, ingress_ifindex);
        let base = set * FLOW_CACHE_WAYS;
        for way in 0..FLOW_CACHE_WAYS {
            let entry_idx = base + way;
            if let Some(existing) = &self.entries[entry_idx] {
                if existing.key == *key && existing.ingress_ifindex == ingress_ifindex {
                    self.entries[entry_idx] = None;
                    self.demote_lru(set, way as u8);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU32;

    const PROTO_TCP: u8 = 6;
    const PROTO_UDP: u8 = 17;

    fn make_key() -> crate::session::SessionKey {
        crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
            src_port: 45678,
            dst_port: 443,
        }
    }

    fn make_descriptor() -> RewriteDescriptor {
        RewriteDescriptor {
            dst_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            target_binding_index: None,
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        }
    }

    fn make_resolution(disposition: ForwardingDisposition) -> ForwardingResolution {
        ForwardingResolution {
            disposition,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
            tx_vlan_id: 0,
        }
    }

    fn make_decision(disposition: ForwardingDisposition) -> SessionDecision {
        SessionDecision {
            resolution: make_resolution(disposition),
            nat: NatDecision::default(),
        }
    }

    fn make_metadata(owner_rg_id: i32) -> SessionMetadata {
        SessionMetadata {
            ingress_zone: Arc::<str>::from("trust"),
            egress_zone: Arc::<str>::from("untrust"),
            owner_rg_id,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        }
    }

    fn make_meta(protocol: u8) -> UserspaceDpMeta {
        UserspaceDpMeta {
            protocol,
            addr_family: libc::AF_INET as u8,
            ingress_ifindex: 7,
            tcp_flags: 0x10, // ACK only
            ..Default::default()
        }
    }

    fn make_entry(
        key: crate::session::SessionKey,
        stamp: FlowCacheStamp,
        owner_rg_id: i32,
    ) -> FlowCacheEntry {
        FlowCacheEntry {
            key,
            ingress_ifindex: 7,
            descriptor: make_descriptor(),
            decision: make_decision(ForwardingDisposition::ForwardCandidate),
            metadata: make_metadata(owner_rg_id),
            stamp,
        }
    }

    fn default_rg_epochs() -> [AtomicU32; MAX_RG_EPOCHS] {
        std::array::from_fn(|_| AtomicU32::new(0))
    }

    // ----------------------------------------------------------------
    // (a) Cache hit — same binding, matching stamp
    // ----------------------------------------------------------------
    #[test]
    fn cache_hit_with_matching_stamp() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 5,
            fib_generation: 3,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        cache.insert(make_entry(key.clone(), stamp, 1));

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 5,
            fib_generation: 3,
        };
        let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
        assert!(hit.is_some(), "expected cache hit with matching stamp");
        assert_eq!(cache.hits, 1);
        assert_eq!(cache.misses, 0);
    }

    // ----------------------------------------------------------------
    // (b) Stale config generation → miss
    // ----------------------------------------------------------------
    #[test]
    fn stale_config_generation_causes_miss() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        cache.insert(make_entry(key.clone(), stamp, 0));

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 2, // newer than entry's 1
            fib_generation: 1,
        };
        let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
        assert!(hit.is_none(), "expected miss on stale config_generation");
        assert_eq!(cache.misses, 1);
    }

    // ----------------------------------------------------------------
    // (c) Stale FIB generation → miss
    // ----------------------------------------------------------------
    #[test]
    fn stale_fib_generation_causes_miss() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 5,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        cache.insert(make_entry(key.clone(), stamp, 0));

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 6, // newer than entry's 5
        };
        let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
        assert!(hit.is_none(), "expected miss on stale fib_generation");
        assert_eq!(cache.misses, 1);
    }

    // ----------------------------------------------------------------
    // (d) Stale RG epoch → miss
    // ----------------------------------------------------------------
    #[test]
    fn stale_rg_epoch_causes_miss() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 3,
            owner_rg_lease_until: 0,
        };
        // Set current epoch to match so the insert is "valid" at that moment.
        rg_epochs[1].store(3, Ordering::Relaxed);
        cache.insert(make_entry(key.clone(), stamp, 1));

        // Bump RG 1 epoch to 4 — simulates failover/demotion.
        rg_epochs[1].store(4, Ordering::Relaxed);

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
        assert!(hit.is_none(), "expected miss on stale RG epoch");
        assert_eq!(cache.misses, 1);
        // Stale RG epoch also triggers eviction of the entry.
        assert_eq!(cache.evictions, 1);
    }

    // ----------------------------------------------------------------
    // (e) Unrelated RG epoch bump does not cause miss
    // ----------------------------------------------------------------
    #[test]
    fn unrelated_rg_epoch_bump_still_hits() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        cache.insert(make_entry(key.clone(), stamp, 1));

        // Bump RG 2 — unrelated to the entry's owner RG 1.
        rg_epochs[2].store(99, Ordering::Relaxed);

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        let hit = cache.lookup(&key, lookup, 0, &rg_epochs);
        assert!(hit.is_some(), "expected hit — only unrelated RG was bumped");
        assert_eq!(cache.hits, 1);
        assert_eq!(cache.misses, 0);
    }

    #[test]
    fn expired_owner_rg_lease_causes_miss_without_epoch_bump() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 7,
            owner_rg_lease_until: 50,
        };
        rg_epochs[1].store(7, Ordering::Relaxed);
        cache.insert(make_entry(key.clone(), stamp, 1));

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        let hit = cache.lookup(&key, lookup, 51, &rg_epochs);
        assert!(hit.is_none(), "expected miss after HA lease expiry");
        assert_eq!(cache.evictions, 1);
    }

    #[test]
    fn expired_owner_rg_lease_causes_miss_for_out_of_range_rg() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: MAX_RG_EPOCHS as i32 + 4,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 50,
        };
        cache.insert(make_entry(key.clone(), stamp, stamp.owner_rg_id));

        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        let hit = cache.lookup(&key, lookup, 51, &rg_epochs);
        assert!(
            hit.is_none(),
            "expected miss after HA lease expiry even for out-of-range owner RG"
        );
        assert_eq!(cache.evictions, 1);
    }

    // ----------------------------------------------------------------
    // (f) Non-cacheable dispositions rejected by should_cache
    // ----------------------------------------------------------------
    #[test]
    fn non_cacheable_dispositions_rejected() {
        let meta = make_meta(PROTO_TCP);
        let non_cacheable = [
            ForwardingDisposition::NoRoute,
            ForwardingDisposition::MissingNeighbor,
            ForwardingDisposition::HAInactive,
            ForwardingDisposition::PolicyDenied,
            ForwardingDisposition::LocalDelivery,
        ];
        for disposition in non_cacheable {
            let decision = make_decision(disposition);
            assert!(
                !FlowCacheEntry::should_cache(meta, decision),
                "expected should_cache=false for {:?}",
                disposition,
            );
        }
    }

    // ----------------------------------------------------------------
    // (g) ForwardCandidate is cacheable
    // ----------------------------------------------------------------
    #[test]
    fn forward_candidate_is_cacheable() {
        let meta_tcp = make_meta(PROTO_TCP);
        let meta_udp = make_meta(PROTO_UDP);
        let decision = make_decision(ForwardingDisposition::ForwardCandidate);

        assert!(
            FlowCacheEntry::should_cache(meta_tcp, decision),
            "TCP ForwardCandidate should be cacheable",
        );
        assert!(
            FlowCacheEntry::should_cache(meta_udp, decision),
            "UDP ForwardCandidate should be cacheable",
        );
    }

    // ----------------------------------------------------------------
    // (g-extra) NAT64 and NPTv6 decisions are not cacheable
    // ----------------------------------------------------------------
    #[test]
    fn nat64_and_nptv6_not_cacheable() {
        let meta = make_meta(PROTO_TCP);

        let mut nat64_decision = make_decision(ForwardingDisposition::ForwardCandidate);
        nat64_decision.nat.nat64 = true;
        assert!(
            !FlowCacheEntry::should_cache(meta, nat64_decision),
            "NAT64 should not be cacheable",
        );

        let mut nptv6_decision = make_decision(ForwardingDisposition::ForwardCandidate);
        nptv6_decision.nat.nptv6 = true;
        assert!(
            !FlowCacheEntry::should_cache(meta, nptv6_decision),
            "NPTv6 should not be cacheable",
        );
    }

    // ----------------------------------------------------------------
    // (h) from_forward_decision round-trip
    // ----------------------------------------------------------------
    #[test]
    fn from_forward_decision_round_trip() {
        let rg_epochs = default_rg_epochs();
        let key = make_key();
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let meta = UserspaceDpMeta {
            protocol: PROTO_TCP,
            addr_family: libc::AF_INET as u8,
            ingress_ifindex: 7,
            tcp_flags: 0x10,
            config_generation: 10,
            fib_generation: 3,
            ..Default::default()
        };
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 10,
            fib_generation: 3,
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))),
                neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]),
                tx_vlan_id: 50,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
                rewrite_dst: None,
                rewrite_src_port: Some(1024),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        };
        let ingress_zone = Some(Arc::<str>::from("trust"));

        // ForwardingState needs egress entry so owner_rg_for_resolution can
        // look up the redundancy_group for egress_ifindex=6.
        let mut forwarding = ForwardingState::default();
        forwarding.egress.insert(
            6,
            EgressInterface {
                bind_ifindex: 6,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01],
                zone: "trust".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(10, 0, 1, 1)),
                primary_v6: None,
            },
        );

        let entry = FlowCacheEntry::from_forward_decision(
            &flow,
            meta,
            validation,
            decision,
            1,
            ingress_zone.clone(),
            Some(7),
            &forwarding,
            &BTreeMap::from([(
                1,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 95,
                    lease: HAForwardingLease::ActiveUntil(100),
                },
            )]),
            false,
            &rg_epochs,
        );
        let entry = entry.expect("should produce a cache entry for ForwardCandidate");

        // Key and ingress match input.
        assert_eq!(entry.key, key);
        assert_eq!(entry.ingress_ifindex, 7);

        // Decision round-trips exactly.
        assert_eq!(entry.decision, decision);

        // Descriptor carries the resolution's MAC/VLAN/ifindex data.
        assert_eq!(
            entry.descriptor.dst_mac,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(
            entry.descriptor.src_mac,
            [0x02, 0xbf, 0x72, 0x00, 0x01, 0x01]
        );
        assert_eq!(entry.descriptor.tx_vlan_id, 50);
        assert_eq!(entry.descriptor.egress_ifindex, 6);
        assert_eq!(entry.descriptor.tx_ifindex, 6);
        assert_eq!(entry.descriptor.target_binding_index, Some(7));
        assert_eq!(entry.descriptor.ether_type, 0x0800);
        assert_eq!(
            entry.descriptor.fabric_redirect,
            decision.resolution.disposition == ForwardingDisposition::FabricRedirect
        );

        // NAT rewrite fields propagated.
        assert_eq!(
            entry.descriptor.rewrite_src_ip,
            Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
        );
        assert_eq!(entry.descriptor.rewrite_dst_ip, None);
        assert_eq!(entry.descriptor.rewrite_src_port, Some(1024));
        assert_eq!(entry.descriptor.rewrite_dst_port, None);
        assert!(!entry.descriptor.nat64);
        assert!(!entry.descriptor.nptv6);
        assert!(!entry.descriptor.apply_nat_on_fabric);

        // Stamp matches validation + RG epoch.
        assert_eq!(entry.stamp.config_generation, 10);
        assert_eq!(entry.stamp.fib_generation, 3);
        assert_eq!(entry.stamp.owner_rg_id, 1); // from egress RG
        assert_eq!(entry.stamp.owner_rg_epoch, 0); // rg_epochs all start at 0
        assert_eq!(entry.stamp.owner_rg_lease_until, 100);

        // Metadata carries ingress zone and owner RG.
        assert_eq!(&*entry.metadata.ingress_zone, "trust");
        assert_eq!(entry.metadata.owner_rg_id, 1);
        assert!(!entry.metadata.fabric_ingress);
    }

    // ----------------------------------------------------------------
    // (h-extra) from_forward_decision returns None for non-cacheable
    // ----------------------------------------------------------------
    #[test]
    fn from_forward_decision_returns_none_for_non_cacheable() {
        let rg_epochs = default_rg_epochs();
        let key = make_key();
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key,
        };
        let meta = make_meta(PROTO_TCP);
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 1,
            fib_generation: 1,
        };
        // NoRoute is not cacheable.
        let decision = make_decision(ForwardingDisposition::NoRoute);
        let forwarding = ForwardingState::default();

        let entry = FlowCacheEntry::from_forward_decision(
            &flow,
            meta,
            validation,
            decision,
            0,
            None,
            None,
            &forwarding,
            &BTreeMap::new(),
            false,
            &rg_epochs,
        );
        assert!(entry.is_none(), "NoRoute should not produce a cache entry");
    }

    #[test]
    fn fabric_redirect_cache_entry_uses_flow_owner_rg_for_epoch_invalidation() {
        let rg_epochs = default_rg_epochs();
        let key = make_key();
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let meta = make_meta(PROTO_TCP);
        let validation = ValidationState {
            snapshot_installed: true,
            config_generation: 1,
            fib_generation: 1,
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let mut forwarding = ForwardingState::default();
        forwarding.fabrics.push(FabricLink {
            parent_ifindex: 21,
            overlay_ifindex: 101,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        forwarding.egress.insert(
            6,
            EgressInterface {
                bind_ifindex: 6,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone: "trust".to_string(),
                redundancy_group: 2,
                primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );

        let entry = FlowCacheEntry::from_forward_decision(
            &flow,
            meta,
            validation,
            decision,
            2,
            Some(Arc::<str>::from("trust")),
            Some(3),
            &forwarding,
            &BTreeMap::from([(
                2,
                HAGroupRuntime {
                    active: true,
                    watchdog_timestamp: 10,
                    lease: HAForwardingLease::ActiveUntil(20),
                },
            )]),
            true,
            &rg_epochs,
        )
        .expect("fabric redirect entry");

        assert_eq!(entry.stamp.owner_rg_id, 2);
        assert_eq!(entry.metadata.owner_rg_id, 2);
        assert!(entry.descriptor.fabric_redirect);
        assert_eq!(entry.descriptor.target_binding_index, Some(3));
    }

    // ----------------------------------------------------------------
    // #918: 4-way set-associative LRU tests
    // ----------------------------------------------------------------

    /// Synthesize a key whose `set_index()` matches `target_set` so
    /// tests can exercise the full set-collision pipeline rather than
    /// rely on harness chance.
    fn key_in_set(target_set: usize, salt: u16) -> crate::session::SessionKey {
        // Iterate src_port until we land in `target_set`. FxHasher is
        // deterministic, so this terminates in O(SETS) on average.
        // Inclusive range covers the full 16-bit port space.
        for port in salt..=u16::MAX {
            let key = crate::session::SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 100)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 50, 200)),
                src_port: port,
                dst_port: 443,
            };
            if FlowCache::set_index(&key, 7) == target_set {
                return key;
            }
        }
        panic!("could not find key in set {target_set}");
    }

    #[test]
    fn flow_cache_4way_no_eviction_under_4_distinct_keys_in_same_set() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        let target_set = 42;
        let mut keys = Vec::new();
        let mut salt = 0u16;
        while keys.len() < 4 {
            let key = key_in_set(target_set, salt);
            salt = key.src_port + 1;
            if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
                keys.push(key);
            }
        }
        for key in &keys {
            cache.insert(make_entry(key.clone(), stamp, 0));
        }
        assert_eq!(
            cache.collision_evictions, 0,
            "4 distinct keys in same set must not collision-evict"
        );
        // All 4 lookups should hit.
        for key in &keys {
            let lookup = FlowCacheLookup {
                ingress_ifindex: 7,
                config_generation: 1,
                fib_generation: 1,
            };
            assert!(cache.lookup(key, lookup, 0, &rg_epochs).is_some());
        }
    }

    #[test]
    fn flow_cache_4way_lru_evicts_oldest_on_5th_insert() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        let target_set = 99;
        let mut keys = Vec::new();
        let mut salt = 0u16;
        while keys.len() < 5 {
            let key = key_in_set(target_set, salt);
            salt = key.src_port + 1;
            if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
                keys.push(key);
            }
        }
        // Insert 4 keys (set fills).
        for key in &keys[..4] {
            cache.insert(make_entry(key.clone(), stamp, 0));
        }
        assert_eq!(cache.collision_evictions, 0);
        // Insert 5th: must collision-evict the LRU (= keys[0], inserted first).
        cache.insert(make_entry(keys[4].clone(), stamp, 0));
        assert_eq!(cache.collision_evictions, 1);
        // keys[0] must be gone, keys[1..=4] present.
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        assert!(
            cache.lookup(&keys[0], lookup, 0, &rg_epochs).is_none(),
            "LRU way (keys[0]) must have been evicted"
        );
        for key in &keys[1..=4] {
            assert!(
                cache.lookup(key, lookup, 0, &rg_epochs).is_some(),
                "remaining 4 keys must still hit"
            );
        }
    }

    #[test]
    fn flow_cache_4way_lookup_promotes_to_mru() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        let target_set = 200;
        let mut keys = Vec::new();
        let mut salt = 0u16;
        while keys.len() < 5 {
            let key = key_in_set(target_set, salt);
            salt = key.src_port + 1;
            if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
                keys.push(key);
            }
        }
        // Insert 4 keys (now LRU-order: keys[0] = LRU, keys[3] = MRU).
        for key in &keys[..4] {
            cache.insert(make_entry(key.clone(), stamp, 0));
        }
        // Look up keys[0] — should promote it to MRU.
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        assert!(cache.lookup(&keys[0], lookup, 0, &rg_epochs).is_some());
        // Insert 5th: now keys[1] is LRU (since keys[0] was promoted).
        cache.insert(make_entry(keys[4].clone(), stamp, 0));
        assert_eq!(cache.collision_evictions, 1);
        assert!(
            cache.lookup(&keys[0], lookup, 0, &rg_epochs).is_some(),
            "keys[0] was promoted, must still be in cache"
        );
        assert!(
            cache.lookup(&keys[1], lookup, 0, &rg_epochs).is_none(),
            "keys[1] became LRU after the promotion, must have been evicted"
        );
    }

    #[test]
    fn flow_cache_4way_invalidate_clears_only_matching_way() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        let target_set = 300;
        let mut keys = Vec::new();
        let mut salt = 0u16;
        while keys.len() < 4 {
            let key = key_in_set(target_set, salt);
            salt = key.src_port + 1;
            if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
                keys.push(key);
            }
        }
        for key in &keys {
            cache.insert(make_entry(key.clone(), stamp, 0));
        }
        cache.invalidate_slot(&keys[1], 7);
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        assert!(
            cache.lookup(&keys[1], lookup, 0, &rg_epochs).is_none(),
            "invalidated key must miss"
        );
        for (i, key) in keys.iter().enumerate() {
            if i == 1 {
                continue;
            }
            assert!(
                cache.lookup(key, lookup, 0, &rg_epochs).is_some(),
                "non-invalidated keys must still hit"
            );
        }
    }

    /// Codex+Gemini R2 follow-up: explicitly exercise the §3.4.2
    /// dedup-on-insert path. Insert stale-generation entry, then
    /// fresh-generation entry with the same key — the existing way
    /// must be replaced and promoted to MRU rather than allocating
    /// a new way.
    #[test]
    fn flow_cache_4way_dedup_replaces_existing_and_promotes() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let key = make_key();
        let stale_stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        let fresh_stamp = FlowCacheStamp {
            config_generation: 2, // bumped
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        cache.insert(make_entry(key.clone(), stale_stamp, 0));
        // Re-insert with fresh stamp via insert(): dedup path replaces
        // the existing way, no eviction counted.
        let evictions_before = cache.evictions;
        cache.insert(make_entry(key.clone(), fresh_stamp, 0));
        assert_eq!(
            cache.evictions, evictions_before,
            "dedup-replace must not increment evictions counter"
        );
        // Lookup at fresh generation must hit (proves the entry was
        // overwritten with fresh data, not the stale entry that would
        // have been evicted on lookup).
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 2,
            fib_generation: 1,
        };
        assert!(
            cache.lookup(&key, lookup, 0, &rg_epochs).is_some(),
            "fresh-stamp lookup must hit after dedup-replace"
        );
    }

    /// Codex+Gemini R2 follow-up: verify the LRU permutation is
    /// always a permutation of [0,1,2,3] across any sequence of
    /// inserts/lookups/invalidates. Catches off-by-one shift errors.
    #[test]
    fn flow_cache_4way_lru_permutation_invariant_holds() {
        let rg_epochs = default_rg_epochs();
        let mut cache = FlowCache::new();
        let stamp = FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 0,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        };
        let target_set = 500;
        let mut keys = Vec::new();
        let mut salt = 0u16;
        while keys.len() < 6 {
            let key = key_in_set(target_set, salt);
            salt = key.src_port + 1;
            if !keys.iter().any(|k: &crate::session::SessionKey| k == &key) {
                keys.push(key);
            }
        }
        let lookup = FlowCacheLookup {
            ingress_ifindex: 7,
            config_generation: 1,
            fib_generation: 1,
        };
        // Hammer the set with mixed inserts/lookups/invalidates.
        for (i, key) in keys.iter().enumerate() {
            cache.insert(make_entry(key.clone(), stamp, 0));
            if i % 2 == 0 {
                let _ = cache.lookup(key, lookup, 0, &rg_epochs);
            }
            if i == 4 {
                cache.invalidate_slot(&keys[0], 7);
            }
        }
        // Verify lru[target_set] is a permutation of [0,1,2,3].
        let row = cache.lru[target_set];
        let mut sorted = row;
        sorted.sort();
        assert_eq!(
            sorted,
            [0u8, 1, 2, 3],
            "lru row must be a permutation of [0,1,2,3], got {row:?}"
        );
    }
}
