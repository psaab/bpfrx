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
//!   Workers DO have a `catch_unwind` supervisor as of #925 Phase 1
//!   (`spawn_supervised_worker` in `coordinator/supervisor.rs`), and #925
//!   Phase 2 surfaces panics on Prometheus
//!   (`xpf_userspace_worker_dead`). But a poisoned `Mutex` here is
//!   operationally worse than a stale MAC for the *surviving* threads:
//!   `NeighborEntry` is plain `[u8; 6]` with no invariants to corrupt,
//!   so the safer choice is to recover-from-poison and keep forwarding.

use super::types::{FastMap, NeighborEntry};
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

pub(super) const NUM_SHARDS: usize = 64;

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
    /// #3048: monotonic epoch bumped ONLY when a kernel ARP/NDP update
    /// REPLACES an existing neighbor's hwaddr with a different MAC
    /// (gateway VRRP failover, host NIC swap, upstream MAC change). The
    /// worker flow cache stamps this counter into each cached forwarding
    /// descriptor and re-reads it on every fast-path hit; a mismatch
    /// means the descriptor's `dst_mac` may be stale, so the entry is
    /// evicted and the next packet re-resolves the current MAC.
    ///
    /// It is deliberately NOT bumped on:
    ///   * a first insert of a brand-new neighbor (no cached flow can
    ///     reference a neighbor that did not previously exist), nor
    ///   * a periodic ARP/NDP REFRESH that re-learns the SAME MAC (the
    ///     overwhelmingly common case) — bumping there would flush the
    ///     whole flow cache on every neighbor refresh and collapse the
    ///     fast-path hit rate.
    /// `insert_if_changed` distinguishes these because it reads the prior
    /// entry under the shard lock before overwriting.
    mac_change_epoch: AtomicU32,
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
            mac_change_epoch: AtomicU32::new(0),
        }
    }

    /// #3048: current neighbor-MAC-change epoch. Read by the worker flow
    /// cache at descriptor insert (stamp) and on every fast-path hit
    /// (re-validate). A single relaxed atomic load — mirrors the
    /// `rg_epochs` lazy-invalidation pattern in `flow_cache.rs`.
    #[inline]
    pub(crate) fn mac_change_epoch(&self) -> u32 {
        self.mac_change_epoch.load(Ordering::Relaxed)
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

    /// #1769: race-safe confirmed insert for the on-demand resolver.
    ///
    /// Locks the key's shard and, **while holding the lock**, re-reads
    /// `generation`. If it still equals `expected_generation` (no monitor
    /// event has begun since the resolver snapshotted the epoch before
    /// its GET), inserts `key → val` and returns `true`. Otherwise makes
    /// no change and returns `false`.
    ///
    /// This is the AGY-F1 / Codex epoch-guard fix: the monitor bumps the
    /// generation **before** it mutates the map (bump-first ordering in
    /// `neigh_monitor_thread`), so any concurrent RTM_{NEW,DEL}NEIGH that
    /// could invalidate the GET-derived MAC is observable as a generation
    /// advance *under this same shard lock*. The previous lock-free
    /// load-then-insert could resurrect a stale MAC when a monitor
    /// removal landed between the post-GET load and the insert (and
    /// missed entirely when a DELNEIGH for an already-absent key did not
    /// bump at all). Reading the generation inside the lock plus
    /// bump-first closes both.
    pub(crate) fn insert_confirmed_if_unchanged(
        &self,
        key: (i32, IpAddr),
        val: NeighborEntry,
        generation: &std::sync::atomic::AtomicU64,
        expected_generation: u64,
    ) -> bool {
        let mut shard = self.lock_shard(shard_idx(&key));
        if generation.load(std::sync::atomic::Ordering::Acquire) != expected_generation {
            return false;
        }
        // #3048: if the confirmed GETNEIGH result REPLACES an existing
        // neighbor's MAC, that is a genuine MAC change — advance the
        // mac_change_epoch so cached forwarding descriptors holding the
        // old dst_mac are evicted on their next fast-path hit. The
        // resolver normally services a missing next-hop (prior == None,
        // first insert, no bump), but a re-resolution that observes a new
        // MAC must invalidate just like the monitor path. A re-confirm of
        // the SAME MAC does not bump.
        if let Some(prior) = shard.get(&key)
            && prior.mac != val.mac
        {
            self.mac_change_epoch.fetch_add(1, Ordering::Relaxed);
        }
        shard.insert(key, val);
        true
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
        let prior_mac = shard.get(&key).map(|existing| existing.mac);
        if prior_mac == Some(val.mac) {
            return false;
        }
        // #3048: a genuine MAC CHANGE (an existing entry whose hwaddr is
        // being replaced by a different one) invalidates any flow-cache
        // forwarding descriptor that captured the old MAC. Advance the
        // epoch so the worker fast path evicts those entries on their next
        // hit. A FIRST insert (`prior_mac == None`) does NOT advance it:
        // no cached flow can hold a stale MAC for a neighbor that did not
        // exist. The same-MAC refresh case already returned above.
        if let Some(old_mac) = prior_mac {
            debug_assert_ne!(old_mac, val.mac, "same-MAC case must have returned early");
            self.mac_change_epoch.fetch_add(1, Ordering::Relaxed);
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
    ///
    /// **Non-reentrant**: the closure MUST NOT call any other method
    /// on the same `ShardedNeighborMap` (or any of its `Arc` clones) —
    /// every shard is already locked, so a per-key call would
    /// self-deadlock waiting on a shard the same thread holds.
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

    /// #1782: iterate every shard's underlying map immutably. Used by
    /// `Coordinator::dynamic_neighbor_keys` to dump the present key set
    /// for the cold-start capture harness without needing mutable
    /// access.
    pub(crate) fn each_shard_ref(
        &self,
    ) -> impl Iterator<Item = &FastMap<(i32, IpAddr), NeighborEntry>> {
        self.guards.iter().map(|g| &**g)
    }

    /// Sum of `len()` across all shards.
    pub(crate) fn total_len(&self) -> usize {
        self.guards.iter().map(|g| g.len()).sum()
    }
}

#[cfg(test)]
#[path = "sharded_neighbor_tests.rs"]
mod tests;

