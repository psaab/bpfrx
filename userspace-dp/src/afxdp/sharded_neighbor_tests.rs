// Tests for afxdp/sharded_neighbor.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep sharded_neighbor.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "sharded_neighbor_tests.rs"]` from sharded_neighbor.rs.

use super::*;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

fn entry(mac_byte: u8) -> NeighborEntry {
    NeighborEntry { mac: [mac_byte; 6] }
}

fn key_v4(ifindex: i32, last_octet: u8) -> (i32, IpAddr) {
    (ifindex, IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)))
}

#[test]
fn get_returns_inserted_value() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert_eq!(map.get(&k), Some(entry(0xAB)));
}

#[test]
fn get_returns_none_for_missing_key() {
    let map = ShardedNeighborMap::new();
    assert_eq!(map.get(&key_v4(7, 99)), None);
}

#[test]
fn remove_clears_entry() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    map.remove(&k);
    assert_eq!(map.get(&k), None);
}

#[test]
fn remove_if_present_returns_true_when_existing_false_when_absent() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(map.remove_if_present(&k));
    assert!(!map.remove_if_present(&k));
}

#[test]
fn insert_if_changed_returns_true_on_first_insert() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    assert!(map.insert_if_changed(k, entry(0xAB)));
}

#[test]
fn insert_if_changed_returns_false_on_same_mac() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(!map.insert_if_changed(k, entry(0xAB)));
}

#[test]
fn insert_if_changed_returns_true_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert!(map.insert_if_changed(k, entry(0xCD)));
    assert_eq!(map.get(&k), Some(entry(0xCD)));
}

#[test]
fn len_sums_across_shards() {
    let map = ShardedNeighborMap::new();
    for i in 0..200u8 {
        map.insert(key_v4(7, i), entry(i));
    }
    assert_eq!(map.len(), 200);
}

#[test]
fn with_all_shards_clear_via_each_shard_mut() {
    let map = ShardedNeighborMap::new();
    for i in 0..50u8 {
        map.insert(key_v4(7, i), entry(i));
    }
    map.with_all_shards(|bulk| {
        for shard in bulk.each_shard_mut() {
            shard.clear();
        }
    });
    assert_eq!(map.len(), 0);
}

#[test]
fn with_all_shards_atomic_replace() {
    let map = ShardedNeighborMap::new();
    // Pre-populate with 5 keys.
    let old_keys: Vec<_> = (0..5u8).map(|i| key_v4(7, i)).collect();
    for &k in &old_keys {
        map.insert(k, entry(0x11));
    }
    // Atomic replace: remove old keys, insert new ones with different
    // MAC. All under one with_all_shards call.
    let new_pairs: Vec<_> = (10..15u8).map(|i| (key_v4(7, i), entry(0x22))).collect();
    map.with_all_shards(|bulk| {
        for &k in &old_keys {
            bulk.remove(&k);
        }
        for (k, v) in &new_pairs {
            bulk.insert(*k, *v);
        }
    });
    for &k in &old_keys {
        assert_eq!(map.get(&k), None);
    }
    for (k, v) in &new_pairs {
        assert_eq!(map.get(k), Some(*v));
    }
}

#[test]
fn padded_shard_align_at_least_64() {
    assert!(std::mem::align_of::<PaddedShard>() >= 64);
}

/// Distribution test: /24 LAN with constant ifindex. Real-world
/// pattern that previously could collide if shard hash were
/// correlated with FastMap inner hash.
///
/// With N=256 keys and K=64 shards, ideal = 4 keys/shard. Even a
/// perfect uniform-random hash gives a maximum bin around 9-11
/// with high probability (max-of-binomial); we accept ≤ 3× ideal
/// (12) to filter only obviously-correlated hashes.
#[test]
fn shard_distribution_ipv4_24_constant_ifindex() {
    let mut counts = [0usize; NUM_SHARDS];
    for last in 0..=255u8 {
        counts[shard_idx(&key_v4(7, last))] += 1;
    }
    let max = *counts.iter().max().unwrap();
    assert!(
        max <= 12,
        "shard distribution too skewed: {:?} (max {})",
        counts,
        max
    );
}

/// Distribution test: /16 LAN, varying second-to-last octet.
#[test]
fn shard_distribution_ipv4_16() {
    let mut counts = [0usize; NUM_SHARDS];
    for second_last in 0..=255u16 {
        for last in 0..=15u16 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, second_last as u8, last as u8));
            counts[shard_idx(&(7, ip))] += 1;
        }
    }
    // 4096 keys, 64 shards → ideal 64/shard. Acceptance: max ≤ 2× ideal.
    let max = *counts.iter().max().unwrap();
    assert!(
        max <= 128,
        "shard distribution too skewed: max {} (ideal 64)",
        max
    );
}

/// Distribution test: IPv6 SLAAC-like pattern (varying last 8 bytes).
#[test]
fn shard_distribution_ipv6_slaac() {
    let mut counts = [0usize; NUM_SHARDS];
    for i in 0..256u32 {
        for j in 0..16u32 {
            let ip = IpAddr::V6(Ipv6Addr::new(
                0xfe80,
                0,
                0,
                0,
                0xabcd,
                0xef01,
                (i & 0xFFFF) as u16,
                (j & 0xFFFF) as u16,
            ));
            counts[shard_idx(&(7, ip))] += 1;
        }
    }
    // 4096 keys, 64 shards → ideal 64/shard. Acceptance: max ≤ 2× ideal.
    let max = *counts.iter().max().unwrap();
    assert!(
        max <= 128,
        "ipv6 shard distribution too skewed: max {} (ideal 64)",
        max
    );
}

/// Poison policy: a thread that panics while holding the shard
/// lock leaves it poisoned. The next caller must continue working
/// (`into_inner` recovery) rather than propagate a poison panic.
#[test]
fn poison_recovered_via_into_inner() {
    use std::sync::Arc;
    use std::thread;

    let map = Arc::new(ShardedNeighborMap::new());
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));

    // Force a poison: spawn a thread that locks the shard then panics.
    let map_clone = Arc::clone(&map);
    let _ = thread::spawn(move || {
        let _g = map_clone.shards[shard_idx(&k)].0.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    // After the thread panicked, the shard is poisoned. Our get()
    // must NOT propagate the poison — it must use into_inner and
    // return the existing entry.
    assert_eq!(map.get(&k), Some(entry(0xAB)));
}

/// Concurrency stress: 8 worker threads each doing 1000 per-key
/// insert/get/remove ops on disjoint key ranges, while one
/// "replace" thread periodically calls `with_all_shards` to do an
/// atomic bulk replace. Verifies no deadlock under interleaving
/// (the deadlock-freedom invariant: bulk locks shards 0..63 in
/// order; per-key holds at most one shard at a time, so no cycle).
#[test]
fn concurrent_per_key_with_bulk_replace_no_deadlock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let map = Arc::new(ShardedNeighborMap::new());
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // 8 per-key worker threads on disjoint ifindex ranges.
    for tid in 0..8u8 {
        let map = Arc::clone(&map);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut iter = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let key = (
                    (tid as i32) * 1000 + (iter % 100) as i32,
                    IpAddr::V4(Ipv4Addr::new(10, tid, (iter / 256) as u8, iter as u8)),
                );
                let _ = map.insert_if_changed(key, entry(tid));
                let _ = map.get(&key);
                if iter & 7 == 0 {
                    let _ = map.remove_if_present(&key);
                }
                iter = iter.wrapping_add(1);
            }
        }));
    }

    // One bulk thread doing atomic bulk replaces. If a deadlock
    // existed, this thread would block forever waiting for a
    // per-key shard lock that another thread blocks on.
    let map_bulk = Arc::clone(&map);
    let stop_bulk = Arc::clone(&stop);
    handles.push(thread::spawn(move || {
        while !stop_bulk.load(Ordering::Relaxed) {
            map_bulk.with_all_shards(|bulk| {
                for i in 0..16u8 {
                    bulk.insert(
                        (9999, IpAddr::V4(Ipv4Addr::new(10, 99, 99, i))),
                        entry(0xFF),
                    );
                }
            });
            thread::sleep(Duration::from_micros(100));
        }
    }));

    // Run for ~200 ms.
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("worker panicked");
    }
    // Map remains usable.
    assert!(map.len() > 0);
}

// ── #3048: neighbor MAC-change epoch ─────────────────────────────────
// The worker flow cache stamps `mac_change_epoch()` into each cached
// forwarding descriptor and re-reads it on every fast-path hit. The
// epoch MUST advance only on a genuine MAC CHANGE so a stale cached
// dst_mac is evicted; it MUST NOT advance on a first insert or a
// same-MAC refresh, or steady-state traffic would re-miss the cache on
// every neighbor refresh. Reverting any `mac_change_epoch.fetch_add`
// makes the corresponding "change bumps" assertion fail (RED), so these
// are the fail-on-revert guards for the #3048 invalidation.

#[test]
fn mac_change_epoch_starts_at_zero() {
    let map = ShardedNeighborMap::new();
    assert_eq!(map.mac_change_epoch(), 0);
}

#[test]
fn mac_change_epoch_not_bumped_on_first_insert() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    // A brand-new neighbor: no cached flow can reference a MAC that did
    // not previously exist, so the epoch must stay put.
    assert!(map.insert_if_changed(k, entry(0xAB)));
    assert_eq!(map.mac_change_epoch(), 0);
}

#[test]
fn mac_change_epoch_not_bumped_on_same_mac_refresh() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    assert!(map.insert_if_changed(k, entry(0xAB)));
    // The common case: a periodic ARP/NDP refresh re-learning the SAME
    // MAC must not bump the epoch (else the whole flow cache flushes on
    // every neighbor refresh and the fast-path hit rate collapses).
    assert!(!map.insert_if_changed(k, entry(0xAB)));
    assert_eq!(map.mac_change_epoch(), 0);
}

#[test]
fn mac_change_epoch_bumped_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    assert!(map.insert_if_changed(k, entry(0xAB)));
    assert_eq!(map.mac_change_epoch(), 0);
    // Genuine MAC change (gateway VRRP failover / NIC swap): the epoch
    // MUST advance so the worker fast path evicts cached descriptors
    // holding the old dst_mac. Fail-on-revert guard for insert_if_changed.
    assert!(map.insert_if_changed(k, entry(0xCD)));
    assert_eq!(map.mac_change_epoch(), 1);
    // A subsequent same-MAC refresh does not advance it further.
    assert!(!map.insert_if_changed(k, entry(0xCD)));
    assert_eq!(map.mac_change_epoch(), 1);
    // Another distinct change bumps again.
    assert!(map.insert_if_changed(k, entry(0xEF)));
    assert_eq!(map.mac_change_epoch(), 2);
}

#[test]
fn mac_change_epoch_per_key_independent_changes_accumulate() {
    let map = ShardedNeighborMap::new();
    let k1 = key_v4(7, 1);
    let k2 = key_v4(7, 2);
    map.insert_if_changed(k1, entry(0x11));
    map.insert_if_changed(k2, entry(0x22));
    assert_eq!(map.mac_change_epoch(), 0);
    // A MAC change on either key bumps the single global epoch (the
    // flow cache is keyed by flow 5-tuple, not next-hop, so #3048 uses a
    // coarse global epoch — documented tradeoff).
    map.insert_if_changed(k1, entry(0x99));
    assert_eq!(map.mac_change_epoch(), 1);
    map.insert_if_changed(k2, entry(0x88));
    assert_eq!(map.mac_change_epoch(), 2);
}

#[test]
fn mac_change_epoch_confirmed_resolver_first_insert_no_bump() {
    use std::sync::atomic::AtomicU64;
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    let generation = AtomicU64::new(5);
    // Resolver servicing a missing next-hop: prior == None, no bump.
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xAB), &generation, 5));
    assert_eq!(map.mac_change_epoch(), 0);
}

#[test]
fn mac_change_epoch_confirmed_resolver_bumps_on_change() {
    use std::sync::atomic::AtomicU64;
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    let generation = AtomicU64::new(5);
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xAB), &generation, 5));
    assert_eq!(map.mac_change_epoch(), 0);
    // A confirmed re-resolution observing a different MAC must bump,
    // matching the monitor path. Fail-on-revert guard for the resolver.
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xCD), &generation, 5));
    assert_eq!(map.mac_change_epoch(), 1);
    // Same MAC re-confirm does not bump.
    assert!(map.insert_confirmed_if_unchanged(k, entry(0xCD), &generation, 5));
    assert_eq!(map.mac_change_epoch(), 1);
}

#[test]
fn mac_change_epoch_bulk_replace_bumps_on_mac_change() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    // Seed an existing neighbor (e.g. the gateway) at MAC 0xAB.
    map.insert(k, entry(0xAB));
    assert_eq!(map.mac_change_epoch(), 0);
    // The Go control-plane snapshot push (apply_manager_neighbors with
    // NeighborReplace: true) removes the old key and re-inserts the same
    // key with a DIFFERENT MAC — the VRRP-failover gateway MAC change
    // that overflowed the in-process monitor. The bulk path snapshots
    // the prior MAC BEFORE the remove, detects the change, and bumps.
    // Fail-on-revert guard for bulk_replace_neighbors: neutralizing its
    // fetch_add makes this assertion go RED.
    let remove = [k];
    let insert = [(7, k.1, entry(0xCD))];
    map.bulk_replace_neighbors(&remove, &insert);
    assert_eq!(map.get(&k), Some(entry(0xCD)));
    assert_eq!(map.mac_change_epoch(), 1);
}

#[test]
fn mac_change_epoch_bulk_replace_no_bump_on_same_mac() {
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    map.insert(k, entry(0xAB));
    assert_eq!(map.mac_change_epoch(), 0);
    // A pure refresh: the snapshot re-learns the SAME MAC for every key.
    // Even though replace removes then re-inserts, the prior-MAC snapshot
    // (taken before the remove) equals the incoming MAC, so the epoch
    // must NOT advance — otherwise steady-state Go snapshot pushes would
    // flush the whole flow cache. This case must stay GREEN when the
    // bump is neutralized.
    let remove = [k];
    let insert = [(7, k.1, entry(0xAB))];
    map.bulk_replace_neighbors(&remove, &insert);
    assert_eq!(map.get(&k), Some(entry(0xAB)));
    assert_eq!(map.mac_change_epoch(), 0);
}

#[test]
fn mac_change_epoch_bulk_replace_no_bump_on_brand_new_keys() {
    let map = ShardedNeighborMap::new();
    // A snapshot that only ADDS neighbors with no prior entry: no cached
    // flow can hold a stale MAC for a neighbor that did not exist, so the
    // epoch stays put even though the set membership changed.
    let insert: Vec<_> = (0..5u8).map(|i| (7, key_v4(7, i).1, entry(0x22))).collect();
    map.bulk_replace_neighbors(&[], &insert);
    assert_eq!(map.len(), 5);
    assert_eq!(map.mac_change_epoch(), 0);
}

#[test]
fn mac_change_epoch_bulk_replace_single_bump_for_batch() {
    let map = ShardedNeighborMap::new();
    let k1 = key_v4(7, 1);
    let k2 = key_v4(7, 2);
    map.insert(k1, entry(0x11));
    map.insert(k2, entry(0x22));
    // Two keys change MAC in one snapshot push. The flow-cache flush is
    // a coarse global epoch, so the whole batch bumps the epoch exactly
    // ONCE (not once per changed key).
    let remove = [k1, k2];
    let insert = [(7, k1.1, entry(0x99)), (7, k2.1, entry(0x88))];
    map.bulk_replace_neighbors(&remove, &insert);
    assert_eq!(map.mac_change_epoch(), 1);
}

#[test]
fn mac_change_epoch_confirmed_resolver_epoch_reject_no_bump() {
    use std::sync::atomic::AtomicU64;
    let map = ShardedNeighborMap::new();
    let k = key_v4(7, 42);
    let generation = AtomicU64::new(5);
    map.insert_confirmed_if_unchanged(k, entry(0xAB), &generation, 5);
    // A monitor event advanced the generation between the resolver's GET
    // and its insert: the insert is rejected entirely, so no MAC is
    // written and the epoch must not move.
    generation.store(6, std::sync::atomic::Ordering::Release);
    assert!(!map.insert_confirmed_if_unchanged(k, entry(0xCD), &generation, 5));
    assert_eq!(map.mac_change_epoch(), 0);
    assert_eq!(map.get(&k), Some(entry(0xAB)));
}
