//! #949 PR1: sharded mutex for the dynamic neighbor cache.
//!
//! Replaces the single `Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>`
//! with `Arc<ShardedNeighborMap>` — 64 cache-line-padded shards. Reduces
//! cache-line bouncing on the hot path: every flow-cache miss does a
//! neighbor lookup that previously contended on one mutex.
//!
//! ## Design
//!
//! - 64 shards (`NUM_SHARDS = 64`). Standard choice; matches `dashmap`.
//! - Shard hash mixes FxHash output with a Knuth multiplier so the
//!   shard index is decorrelated from `hashbrown`'s internal bucket
//!   selection (which uses high hash bits).
//! - Cache-line padding via `#[repr(align(64))]` ensures adjacent
//!   shards do not share cache lines (false-sharing prevention).
//! - Bulk operations via `BulkShardGuard`: locks all 64 shards in
//!   shard-index order. Deadlock-free as long as every other caller
//!   that wants more than one shard also locks in ascending order.
//! - Poison policy: `lock().unwrap_or_else(|e| e.into_inner())`.
//!   Workers have no `catch_unwind` supervisor today (#925 deferred);
//!   panic-then-thread-death is operationally worse than a stale MAC.
//!   `NeighborEntry` is plain `[u8; 6]` with no invariants to corrupt.

use super::types::{FastMap, NeighborEntry};
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};

pub(super) const NUM_SHARDS: usize = 64;
const SHARD_MASK: usize = NUM_SHARDS - 1;

/// One mutex-guarded shard, padded to 64 bytes so adjacent shards do
/// not share cache lines.
#[repr(align(64))]
pub(super) struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);

impl PaddedShard {
    fn new() -> Self {
        Self(Mutex::new(FastMap::default()))
    }
}

/// 64-shard mutex map for the dynamic neighbor cache.
pub(crate) struct ShardedNeighborMap {
    shards: [PaddedShard; NUM_SHARDS],
}

/// Shard index for a key. The Knuth multiplier `0x9E3779B97F4A7C15`
/// (the 64-bit golden ratio) spreads entropy into the HIGH bits of
/// the product, so we extract the top `log2(NUM_SHARDS) = 6` bits
/// rather than the low bits. This decorrelates shard selection from
/// `hashbrown`'s internal SwissTable bucket selection (which also
/// uses high hash bits) by feeding it a freshly-rotated hash, and it
/// produces a uniform distribution for adversarial input patterns
/// like `/24` LANs (constant ifindex + sequential last octet).
const SHARD_BITS: u32 = NUM_SHARDS.trailing_zeros();

fn shard_idx(key: &(i32, IpAddr)) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    let h = hasher.finish();
    let mixed = h.wrapping_mul(0x9E3779B97F4A7C15);
    (mixed >> (64 - SHARD_BITS)) as usize
}

impl ShardedNeighborMap {
    pub(crate) fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| PaddedShard::new()),
        }
    }

    fn lock_shard(
        &self,
        idx: usize,
    ) -> MutexGuard<'_, FastMap<(i32, IpAddr), NeighborEntry>> {
        match self.shards[idx].0.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Get a copy of the entry for `key`, if present.
    pub(crate) fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        self.lock_shard(shard_idx(key)).get(key).copied()
    }

    /// Insert (or overwrite) `key → val`. Unit-returning.
    pub(crate) fn insert(&self, key: (i32, IpAddr), val: NeighborEntry) {
        self.lock_shard(shard_idx(&key)).insert(key, val);
    }

    /// Remove `key` if present. Unit-returning.
    pub(crate) fn remove(&self, key: &(i32, IpAddr)) {
        self.lock_shard(shard_idx(key)).remove(key);
    }

    /// Insert `key → val` and return whether the cache changed.
    /// Returns `false` if the key already existed with the same MAC.
    /// Mirrors `neighbor::update_dynamic_neighbor` semantics.
    pub(crate) fn insert_if_changed(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
    ) -> bool {
        let mut shard = self.lock_shard(shard_idx(&key));
        if shard.get(&key).map(|existing| existing.mac) == Some(val.mac) {
            return false;
        }
        shard.insert(key, val);
        true
    }

    /// Remove `key` if present and return whether it was actually
    /// removed. Mirrors `neighbor::remove_dynamic_neighbor` semantics.
    pub(crate) fn remove_if_present(&self, key: &(i32, IpAddr)) -> bool {
        self.lock_shard(shard_idx(key)).remove(key).is_some()
    }

    /// Lock every shard in shard-index order and run the closure with
    /// access to all of them. Used for atomic-vs-readers bulk
    /// operations: replace, clear, multi-key insert.
    ///
    /// Deadlock-free as long as every other caller that wants more
    /// than one shard locks in ascending shard-index order.
    pub(crate) fn with_all_shards<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut BulkShardGuard<'_>) -> R,
    {
        // Lock all 64 shards in ascending order. Use a Vec then convert
        // to a fixed-size array because MutexGuard doesn't impl Default,
        // ruling out `array::from_fn`.
        let mut guards: Vec<MutexGuard<'_, FastMap<(i32, IpAddr), NeighborEntry>>> =
            Vec::with_capacity(NUM_SHARDS);
        for i in 0..NUM_SHARDS {
            guards.push(self.lock_shard(i));
        }
        let mut bulk = BulkShardGuard {
            guards: guards.try_into().ok().expect("exactly NUM_SHARDS guards pushed"),
        };
        f(&mut bulk)
    }

    /// Total entry count summed across shards. Locks all shards in
    /// order. Used by `coordinator::dynamic_neighbor_status`.
    pub(crate) fn len(&self) -> usize {
        self.with_all_shards(|bulk| bulk.total_len())
    }

    /// True iff the map has zero entries across all shards.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True iff `key` is present in its shard.
    pub(crate) fn contains_key(&self, key: &(i32, IpAddr)) -> bool {
        self.lock_shard(shard_idx(key)).contains_key(key)
    }
}

impl Default for ShardedNeighborMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds all 64 shard `MutexGuard`s so a bulk closure can mutate
/// across shards safely. Provides key-routed `insert`/`remove` plus
/// raw shard iteration for `clear` and friends.
pub(crate) struct BulkShardGuard<'a> {
    guards: [MutexGuard<'a, FastMap<(i32, IpAddr), NeighborEntry>>; NUM_SHARDS],
}

impl<'a> BulkShardGuard<'a> {
    /// Insert `key → val` into the appropriate shard.
    pub(crate) fn insert(&mut self, key: (i32, IpAddr), val: NeighborEntry) {
        let i = shard_idx(&key);
        self.guards[i].insert(key, val);
    }

    /// Remove `key` from the appropriate shard.
    pub(crate) fn remove(&mut self, key: &(i32, IpAddr)) {
        let i = shard_idx(key);
        self.guards[i].remove(key);
    }

    /// Iterate every shard's underlying map mutably. Used for
    /// shard-wide operations like `clear`.
    pub(crate) fn each_shard_mut(
        &mut self,
    ) -> impl Iterator<Item = &mut FastMap<(i32, IpAddr), NeighborEntry>> {
        self.guards.iter_mut().map(|g| &mut **g)
    }

    /// Sum of `len()` across all shards.
    pub(crate) fn total_len(&self) -> usize {
        self.guards.iter().map(|g| g.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    fn entry(mac_byte: u8) -> NeighborEntry {
        NeighborEntry {
            mac: [mac_byte; 6],
        }
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
        let new_pairs: Vec<_> = (10..15u8)
            .map(|i| (key_v4(7, i), entry(0x22)))
            .collect();
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
                let ip = IpAddr::V4(Ipv4Addr::new(
                    10,
                    0,
                    second_last as u8,
                    last as u8,
                ));
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
}
