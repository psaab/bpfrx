// Tests for afxdp/flow_cache.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep flow_cache.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from mod.rs.

use super::*;
use crate::test_zone_ids::*;
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
        ingress_zone: TEST_TRUST_ZONE_ID,
        egress_zone: TEST_UNTRUST_ZONE_ID,
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
    let ingress_zone = Some(3);

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
            zone_id: TEST_TRUST_ZONE_ID,
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
    assert_eq!(entry.metadata.ingress_zone, TEST_TRUST_ZONE_ID);
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
            zone_id: TEST_TRUST_ZONE_ID,
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
        Some(3),
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
