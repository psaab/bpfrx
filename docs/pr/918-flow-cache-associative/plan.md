# Plan: #918 — FlowCache 4-way set-associative

Issue: #918
Umbrella: #911 (validates against #929 same-class harness)

## 1. Problem

`FlowCache` (`userspace-dp/src/afxdp/flow_cache.rs:210`) is a 1-way
direct-mapped cache: `entries: Vec<Option<FlowCacheEntry>>` with
`FLOW_CACHE_SIZE = 4096` slots, indexed by
`FxHash(5-tuple, ingress_ifindex) % 4096`.

Under 100E100M (100 elephants + 100 mice = 200 active flows in a
single binding), the Birthday-paradox collision probability is
high: the expected number of collisions is roughly
`(N choose 2) / 4096 ≈ 200×199/2 / 4096 ≈ 4.9` flow pairs sharing
a slot. When a mouse and an elephant share a slot, EVERY packet
from one evicts the other, forcing both flows to take the slow-path
session lookup. The elephant's higher packet rate ensures the
mouse stays evicted indefinitely — fairness is destroyed at the
flow-cache layer regardless of MQFQ's correctness.

## 2. Goal

Replace the 1-way direct-mapped cache with a 4-way set-associative
design (LRU eviction within set). Keep the same total entry count
(4096 entries = 1024 sets × 4 ways). Memory footprint grows
modestly: the new `lru: [u8; 4]` per set adds 1024 × 4 = **4 KB**
of bookkeeping to the existing entries array (Codex R3: prior
"unchanged" claim was wrong). The change is contained to
`flow_cache.rs`; callers (`afxdp.rs:1102` lookup, `:2738` insert,
`:1118` invalidate_slot, `:531` direct-write) keep their existing
API surface.

Expected impact: per §7 Poisson math at λ ≈ 1.07, ~0.5% of sets
are overfull (have ≥5 flows hashing to them) under the
100-elephant + ~1000-session load. **Overfull-set probability is
NOT the same as eviction-collision rate** (Codex R3): a set with
j flows where j > 4 evicts 1/j of accesses on average under LRU,
and only the LRU way thrashes. Empirical hit-rate is the right
measure, not Poisson tails. Worst-case mouse hit-rate goes from
"effectively zero on direct-map slot collision" to "tracked by
LRU within the 4-way set" — the §6.3 cluster validation measures
this directly via `mouse_latency` p99.

## 3. Approach

### 3.1 Set-associative structure

Replace:

```rust
pub(super) struct FlowCache {
    pub(super) entries: Vec<Option<FlowCacheEntry>>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) evictions: u64,
}
```

with:

```rust
const FLOW_CACHE_WAYS: usize = 4;
const FLOW_CACHE_SETS: usize = 1024;
const FLOW_CACHE_SIZE: usize = FLOW_CACHE_SETS * FLOW_CACHE_WAYS;
const FLOW_CACHE_SET_MASK: usize = FLOW_CACHE_SETS - 1;

pub(super) struct FlowCache {
    /// Sets × ways. Index = set_idx * FLOW_CACHE_WAYS + way_idx.
    entries: Box<[Option<FlowCacheEntry>; FLOW_CACHE_SIZE]>,
    /// LRU tracking: for each set, a recency-ordered list of way
    /// indices. `lru[set_idx * WAYS + 0]` is most-recently-used,
    /// `lru[set_idx * WAYS + WAYS-1]` is LRU.
    lru: Box<[u8; FLOW_CACHE_SIZE]>,
    pub(super) hits: u64,
    pub(super) misses: u64,
    pub(super) evictions: u64,
    /// New: collisions where a slot was evicted vs. inserted into
    /// an empty way. Useful for tuning ways count empirically.
    pub(super) collision_evictions: u64,
}
```

`Box<[T; N]>` instead of `Vec<T>` to give the compiler a constant
length (better bounds-check elimination) and avoid the dynamic
len/cap metadata. (R2 correction: `Vec<T>` does NOT add a second
heap indirection per element access; the upside is fixed-length
codegen, not a missing pointer-chase.) `[u8; N]` for the LRU
table is 4 KB total at 4096 entries. Keep on per-binding
allocation so it lives on the worker's local NUMA node (per
#913 R8 Gemini scoping — this PR doesn't introduce cross-NUMA
risk).

### 3.2 Slot computation

The current `slot()` returns one global index in `[0, 4096)`.
Split into `(set_idx, way_idx_for_lookup)`:

```rust
#[inline]
pub(super) fn set_index(key: &SessionKey, ingress_ifindex: i32) -> usize {
    let mut hasher = rustc_hash::FxHasher::default();
    key.hash(&mut hasher);
    (ingress_ifindex as u32).hash(&mut hasher);
    hasher.finish() as usize & FLOW_CACHE_SET_MASK
}
```

Removes the `Self::slot` API in favor of `Self::set_index`.
Callers that previously did `entries[Self::slot(...)] = None`
(e.g., `afxdp.rs:531-532`) need to switch to a new helper
`invalidate_set_entry(key, ingress_ifindex)` that searches the
set for a match and clears that one way.

### 3.3 Lookup with LRU promotion

```rust
pub(super) fn lookup(...) -> Option<&FlowCacheEntry> {
    let set = Self::set_index(key, lookup.ingress_ifindex);
    let base = set * FLOW_CACHE_WAYS;
    for way in 0..FLOW_CACHE_WAYS {
        if let Some(entry) = &self.entries[base + way] {
            if entry.key != *key
                || entry.ingress_ifindex != lookup.ingress_ifindex
            {
                continue;  // different flow in this way; skip
            }
            // Key match. Now validate generation/epoch/lease.
            if entry.stamp.config_generation != lookup.config_generation
                || entry.stamp.fib_generation != lookup.fib_generation
                || /* epoch / lease checks fail */
            {
                // Stale entry for OUR key — evict and demote (per §3.5).
                self.entries[base + way] = None;
                self.evictions += 1;
                self.demote_lru(set, way);
                self.misses += 1;
                return None;
            }
            // Fresh hit.
            self.promote_lru(set, way);
            self.hits += 1;
            return self.entries[base + way].as_ref();
        }
    }
    self.misses += 1;
    None
}
```

**Key-first, generation-second** (Codex R3): the prior version
gated the entire match on key + generation simultaneously, which
made §3.5's "stale-on-lookup eviction" unreachable — non-matching
entries fell through silently. The corrected order matches by
key first, then validates generation. A key-match with stale
generation is a guaranteed-bad cache entry for THIS key (per the
§3.4.2 dedup invariant: at most one way per set holds a given
key), so it's safe to evict immediately and return MISS.

`promote_lru` moves `way` to MRU position in `lru[base..base+WAYS]`
and shifts the rest down one. With WAYS=4, this is a 3-element
copy (~3 ns).

### 3.4 Insert with LRU eviction

```rust
pub(super) fn insert(&mut self, entry: FlowCacheEntry) {
    let set = Self::set_index(&entry.key, entry.ingress_ifindex);
    let base = set * FLOW_CACHE_WAYS;
    // 1. Search for an existing entry with the SAME key+ingress_ifindex
    //    (could be a stale config_generation/fib_generation entry that
    //    needs to be replaced). Codex R1: without this dedup, a flow
    //    that re-enters after a config reload creates duplicate ways
    //    in the same set, and `invalidate_slot` may clear the wrong
    //    one while the actually-stale entry stays.
    for way in 0..FLOW_CACHE_WAYS {
        if let Some(existing) = &self.entries[base + way] {
            if existing.key == entry.key
                && existing.ingress_ifindex == entry.ingress_ifindex
            {
                self.entries[base + way] = Some(entry);
                self.promote_lru(set, way);
                return;
            }
        }
    }
    // 2. No same-key entry; find an empty way.
    for way in 0..FLOW_CACHE_WAYS {
        if self.entries[base + way].is_none() {
            self.entries[base + way] = Some(entry);
            self.promote_lru(set, way);
            return;
        }
    }
    // 3. No empty way; evict LRU.
    let lru_way = self.lru[base + FLOW_CACHE_WAYS - 1] as usize;
    self.entries[base + lru_way] = Some(entry);
    self.evictions += 1;
    self.collision_evictions += 1;
    self.promote_lru(set, lru_way);
}
```

### 3.4.1 LRU init invariant (Codex R1)

`new()` must initialize `lru` so each set is a permutation
`[0, 1, 2, 3]` (most-recently-used → least-recently-used).
Helpers must preserve "exactly one copy of each way 0..WAYS in
the set's lru slice":

```rust
pub(super) fn new() -> Self {
    let mut lru = Box::new([0u8; FLOW_CACHE_SIZE]);
    for set in 0..FLOW_CACHE_SETS {
        let base = set * FLOW_CACHE_WAYS;
        for way in 0..FLOW_CACHE_WAYS {
            lru[base + way] = way as u8;
        }
    }
    Self {
        entries: Box::new([const { None }; FLOW_CACHE_SIZE]),
        lru,
        hits: 0, misses: 0, evictions: 0, collision_evictions: 0,
    }
}

#[inline]
fn promote_lru(&mut self, set: usize, way: usize) {
    let base = set * FLOW_CACHE_WAYS;
    let way_u8 = way as u8;
    // Find current position of `way` in the slice.
    let pos = (0..FLOW_CACHE_WAYS)
        .find(|i| self.lru[base + i] == way_u8)
        .expect("way must be present in lru permutation");
    // Shift everything from [base..base+pos] right by one,
    // then place `way` at base.
    for i in (1..=pos).rev() {
        self.lru[base + i] = self.lru[base + i - 1];
    }
    self.lru[base] = way_u8;
}

#[inline]
fn demote_lru(&mut self, set: usize, way: usize) {
    let base = set * FLOW_CACHE_WAYS;
    let way_u8 = way as u8;
    let pos = (0..FLOW_CACHE_WAYS)
        .find(|i| self.lru[base + i] == way_u8)
        .expect("way must be present in lru permutation");
    // Shift left from [pos+1..WAYS] by one, then place `way` at WAYS-1.
    for i in pos..FLOW_CACHE_WAYS - 1 {
        self.lru[base + i] = self.lru[base + i + 1];
    }
    self.lru[base + FLOW_CACHE_WAYS - 1] = way_u8;
}
```

Both helpers maintain the permutation invariant. The new test
`flow_cache_lru_permutation_invariant_holds_across_operations`
asserts that after any sequence of insert/lookup/invalidate the
`lru[base..base+WAYS]` slice contains exactly `{0, 1, 2, 3}`.

### 3.5 Invalidation

The existing `invalidate_slot(&key, ingress_ifindex)` clears
**all matching ways** in the set (not just the first match), to
defend against the duplicate-entry case if dedup ever leaks. With
§3.4 dedup-on-insert in place, duplicates are believed unreachable;
the all-matching loop is purely defensive (and cheap — at most 4
comparisons per call).

```rust
pub(super) fn invalidate_slot(&mut self, key: &SessionKey, ifindex: i32) {
    let set = Self::set_index(key, ifindex);
    let base = set * FLOW_CACHE_WAYS;
    for way in 0..FLOW_CACHE_WAYS {
        if let Some(entry) = &self.entries[base + way] {
            if entry.key == *key && entry.ingress_ifindex == ifindex {
                self.entries[base + way] = None;
                // Demote to LRU position so this empty way is
                // ranked LRU. The empty-way scan in §3.4
                // iterates physical way order, so demoting
                // doesn't directly steer the next insert — but
                // keeping invalidated ways cold in LRU order
                // means subsequent collision-evictions correctly
                // prefer the longest-empty way.
                self.demote_lru(set, way);
                // Don't return — keep scanning for any duplicates.
            }
        }
    }
}
```

Stale-on-lookup eviction (config_generation / fib_generation /
epoch / lease check failure) is implemented inline in the §3.3
lookup body — see the "Key match. Now validate generation/
epoch/lease." block. The eviction fires when key + ingress_ifindex
match but the stamp is stale; that path clears the way, increments
`evictions`, demotes LRU, and returns MISS. Because of the §3.4.2
dedup invariant (at most one way per set holds a given key),
the lookup safely returns after evicting that single way.

`invalidate_all` is unchanged in semantics (clear all 4096
entries); just iterates the new layout.

The direct-write site at `afxdp.rs:531-532`
(`binding.flow_cache.entries[idx] = None`) needs to become
`binding.flow_cache.invalidate_slot(&key, ifindex)` since the
caller has the key.

## 4. What this is NOT

- Not a change to `FlowCacheEntry` struct, stamps, or epoch
  semantics — only the storage container.
- Not a change to the hash function — keep FxHasher.
- Not a change to the cache size (keep 4096 total entries).
- Not multi-thread shared — still per-worker, single-writer.

## 5. Files touched

- `userspace-dp/src/afxdp/flow_cache.rs`: replace `FlowCache`
  internals; add `set_index`, `promote_lru`, `demote_lru`;
  update `lookup`, `insert`, `invalidate_slot`, `invalidate_all`;
  add `collision_evictions` counter.
- `userspace-dp/src/afxdp.rs:531-532`: replace direct
  `entries[idx] = None` write with `invalidate_slot()` call.
- New unit tests in `flow_cache.rs`:
  - `flow_cache_4way_no_eviction_under_4_distinct_keys_in_same_set`
  - `flow_cache_4way_lru_evicts_oldest_on_5th_insert`
  - `flow_cache_4way_lookup_promotes_to_mru`
  - `flow_cache_4way_invalidate_clears_only_matching_way`
  - `flow_cache_4way_dedup_replaces_existing_and_promotes` (per
    Gemini R2: explicitly exercise the §3.4.2 dedup path —
    insert stale entry, insert fresh entry with same key, verify
    slot was overwritten and promoted to MRU rather than added
    in a new way).
  - `flow_cache_4way_lru_permutation_invariant_holds` (verify
    that after any sequence of inserts/lookups/invalidates the
    `lru` array is always a permutation of `[0,1,2,3]`).
  - `flow_cache_4way_forced_collision_walks_full_set` (per
    Gemini R2: synthesize keys whose `set_index()` collides
    deterministically, exercise full insert/lookup/evict pipeline
    within a known-collision set rather than relying on harness
    chance).

## 6. Test strategy

### 6.1 Unit

`cargo build --release` clean. Unit tests above pass. Pre-existing
E0063 test-build issue still blocks `cargo test`; document.

### 6.2 Cluster validation

Required: #929 same-class harness deployed (this PR depends on
#929 landing first).

Run same-class iperf-b matrix at N=128 M=10 with WAYS=1 (rolled
back) vs WAYS=4. Compare mouse p99 in the (N=128, M=10) cell.

Expected: WAYS=4 reduces p99 by 5-10× under collision-heavy
load. Even if MQFQ ordering is broken (#911 not yet fully fixed),
the cache layer no longer thrashes mice off cache.

### 6.3 Throughput sanity

`iperf3 -P 128 -p 5203 -t 30` on iperf-c queue: expect ≥15 Gb/s
unchanged. The 4-way lookup adds a small constant cost (3 extra
compare-store per lookup miss in the worst case) but lookup is
not the throughput bottleneck.

## 7. Risks

- **L1d footprint.** Total cache size per worker is `4096 ×
  sizeof(FlowCacheEntry)` (FlowCacheEntry = SessionKey +
  i32 + RewriteDescriptor + SessionDecision + SessionMetadata +
  FlowCacheStamp; concrete size depends on nested struct layout
  and is computed at impl time via `size_of::<FlowCacheEntry>()`,
  not hardcoded here). Whatever the per-entry size, it already
  vastly exceeds L1d at 4096 entries. The structural change is
  what matters: a full 4-way scan on a hot set fetches consecutive
  cache lines (prefetcher-friendly), versus the existing 1-way
  Vec layout where consecutive accesses to keys that thrash one
  slot hit random lines. Optionally `#[repr(align(64))]` the
  entries array so set boundaries don't straddle (deferred —
  single-writer per worker means no false sharing across
  workers, so straddling only costs an extra line prefetch on
  the first access of an unaligned set).
- **LRU bookkeeping cost.** 3-element u8 copy per hit + per
  insert. At 200 Kpps per worker, that's 600 K copies/sec ≈ 2 µs
  CPU per second per worker. Negligible.
- **Hash distribution.** FxHasher is fast but not avalanche-
  perfect. For 200 flows in 1024 sets, expected sets touched ≈
  1024 × (1 − (1023/1024)^200) ≈ 178. Chi-squared on 100 random
  flow IDs in unit tests should show no obvious skew (3-sigma).
- **Working-set sizing (Gemini R2).** At target load
  (100 elephants + ~1000 sessions ≈ 1100 active flows), λ = 1100
  / 1024 ≈ 1.074. Poisson per-set occupancy gives
  `P(j ≥ 5) ≈ 0.49%` — i.e. ~5 of 1024 sets are expected to be
  overfull at any moment. **The eviction-collision RATE is
  smaller than this** (only the LRU way in those overfull sets
  thrashes, not all accesses to them), so N=1024 sets has
  ample headroom. Empirical hit-rate (validated in §6.3) is
  the load-bearing measure, not Poisson tails alone.
- **Direct-write at afxdp.rs:531.** Easy to miss; add a
  `set_index()` API but make `entries` field private to force
  callers through the helper.

## 8. Acceptance

- [ ] Plan reviewed by Codex (hostile); PLAN-READY YES.
- [ ] Plan reviewed by Gemini (HPC + CPU + cache-design
      expertise); MERGE YES.
- [ ] Implemented; `cargo build --release` clean.
- [ ] Unit tests pass (locally — pre-existing E0063 documented).
- [ ] Codex hostile code review: MERGE YES.
- [ ] Gemini adversarial code review: MERGE YES.
- [ ] Cluster smoke + same-class p99 measurement.
- [ ] PR opened, Copilot review addressed.
- [ ] Merged.
