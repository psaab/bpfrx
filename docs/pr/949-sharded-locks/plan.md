# #949 PR1: Sharded mutex for `dynamic_neighbors`

Plan v3 — 2026-04-28. Addresses Codex re-review (task-moiwejlv-xpf4w1).

## Issue scope correction

#949 originally proposed BOTH RCU/ArcSwap AND sharded mutex. ArcSwap
is **already done** in current code (`coordinator.rs:15-31`). Honest
framing for this PR: **NOT RCU and NOT immutable-state**. It is
"reduce mutex contention for the dynamic neighbor cache via
sharding." The PR title and commit message reflect this.

## Why dynamic_neighbors first (and only in PR 1)

- Smallest blast radius. Fewer call sites than session maps.
- Cleanest pattern. `(key, NeighborEntry)` lookup/insert with
  `NeighborEntry: Copy` (`userspace-dp/src/afxdp/types.rs:382`).
- Reads always lock → get → copy MAC → release. No held references.
- Real contention: every flow-cache miss does a neighbor lookup.

Session maps (`shared_sessions` × 3) and `OwnerRgSessionIndex` are
deeply coupled — PR 2 needs a composite abstraction with explicit
lock ordering, not a simple mechanical shard. PR 2 has its own plan.

## Honest production effect of poison policy

The v2 plan claimed `#925` worker supervisor would respawn on panic.
**This is wrong**: workers are plain `thread::spawn(move || worker_loop(...))`
at `coordinator.rs:709` with no `catch_unwind`, and #925 is not yet
implemented. A panic on poisoned mutex would terminate the worker
thread and leave the binding dead until daemon restart.

Decision: use **`.lock().unwrap_or_else(|e| e.into_inner())`** —
ignore poison. Rationale:

- `NeighborEntry` is plain `[u8; 6]` (no invariants to corrupt).
- The shard `FastMap` may have a half-applied insert/remove — at
  worst, one key's MAC is wrong or stale. The next ARP/NA learn or
  netlink update overwrites it.
- A panic-then-thread-death is operationally worse than a stale MAC.
- This is also what `parking_lot::Mutex` would do natively (no
  poisoning at all).

When #925 lands with `catch_unwind` + respawn, the policy can
revisit fail-loud as a follow-up. Documented in code comments.

## Affected files (corrected per Codex Q6 round 2)

| File | `.lock()` runtime sites | Type-occurrence sites |
|---|---|---|
| `coordinator.rs` | 5 | 5 |
| `worker.rs` | 0 | 1 (param sig at L446) |
| `neighbor.rs` | 4 | 4 |
| `forwarding.rs` | 2 | 2 |
| `afxdp.rs` | 3 | ~6 |
| `shared_ops.rs` | 0 | 4 (passed-through) |
| `session_glue.rs` | 0 | ~3 (passed-through) |
| `tunnel.rs` | 0 | ~2 |
| `ha.rs` | 0 | ~2 |
| `icmp.rs`, `icmp_embed.rs` | 0 | ~4 |
| `frame.rs` | 0 | 1 (test constructor at L3722) |
| **Test constructors** (across all `*_test.rs` and inline tests) | 0 | **~49** |
| **Production runtime total** | **~14** | **~50** |

Realistic edit volume: 200-250 line-level changes including all 49
test constructors. Bigger than v2's "100-150" estimate.

## Existing single-lock batch semantics

The single mutex is held across multi-key sequences at four sites
that must be preserved as atomic-vs-readers:

1. **`apply_manager_neighbors`** at `coordinator.rs:177-186` — under
   one lock: removes old manager keys, inserts new entries. Readers
   see pre-replace or post-replace, never a half-replaced set.
2. **`reset_dynamic_neighbors`** at `coordinator.rs:295` (clear).
3. **Bulk-remove of stale manager keys** at `coordinator.rs:1029`.
4. **Multi-ifindex insert** at `afxdp.rs:3379-3383` — same `(src_ip,
   src_mac)` inserted under both physical and logical ifindexes
   (corrected from v2's mis-classification of this as "clear").

The sharded API exposes both per-key methods AND a `with_all_shards`
escape hatch for true atomic-across-keys writes:

```rust
impl ShardedNeighborMap {
    /// Per-key fast path (sub-microsecond).
    pub fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry>;
    pub fn insert(&self, key: (i32, IpAddr), val: NeighborEntry);
    pub fn remove(&self, key: &(i32, IpAddr));

    /// Returns true if the cache changed (new key OR different MAC).
    /// Maps to current `update_dynamic_neighbor` semantics at
    /// `neighbor.rs:189`.
    pub fn insert_if_changed(&self, key: (i32, IpAddr), val: NeighborEntry) -> bool;

    /// Returns true if the key was present before removal.
    /// Maps to current `remove_dynamic_neighbor` semantics at
    /// `neighbor.rs:206`.
    pub fn remove_if_present(&self, key: &(i32, IpAddr)) -> bool;

    /// Lock all shards in shard-index order (ascending) and run the
    /// closure. Used by replace/clear/multi-key-insert sites.
    /// Deadlock-free as long as ALL bulk operations also lock in
    /// ascending shard-index order.
    pub fn with_all_shards<R, F>(&self, f: F) -> R
    where F: FnOnce(&mut [FastMap<(i32, IpAddr), NeighborEntry>; NUM_SHARDS]) -> R;

    /// Sum of len() across all shards. Used by
    /// `dynamic_neighbor_status` at `coordinator.rs:208`.
    /// Locks all shards in order.
    pub fn len(&self) -> usize;
}
```

`apply_manager_neighbors` becomes:

```rust
self.dynamic_neighbors.with_all_shards(|shards| {
    if replace {
        for key in &old_manager_keys {
            shards[shard_idx(key)].remove(key);
        }
    }
    for (ifindex, ip, entry) in neighbors {
        shards[shard_idx(&(*ifindex, *ip))].insert((*ifindex, *ip), *entry);
    }
});
```

`afxdp.rs:3379` (multi-ifindex insert for one IP) becomes:

```rust
dynamic_neighbors.with_all_shards(|shards| {
    for ifindex in ifindexes {
        shards[shard_idx(&(ifindex, src_ip))]
            .insert((ifindex, src_ip), NeighborEntry { mac: src_mac });
    }
});
```

(Two ifindexes likely hash to different shards. Locking all 64 for
two keys is wasteful per-call but the call site is rare; correctness
trumps micro-perf here. Alternative: a `with_keys_locked(&[k1, k2],
f)` API that locks only the affected shards in shard-index order.
Defer optimization.)

## Design

### Shard hash independent of FastMap inner hash

Use rotated/mixed FxHash for shard selection to break correlation
with the inner `FastMap` bucket-selection hash:

```rust
fn shard_idx(key: &(i32, IpAddr)) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    let h = hasher.finish();
    let mixed = h.wrapping_mul(0x9E3779B97F4A7C15) ^ (h >> 32);
    (mixed as usize) & (NUM_SHARDS - 1)
}
```

### Cache-line padded shards

```rust
#[repr(align(64))]
struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);
```

Verified via `mem::align_of::<PaddedShard>() >= 64` in a unit test
(corrected from v2's `mem::size_of` per Codex).

### Final type

```rust
pub(crate) const NUM_SHARDS: usize = 64;

pub(crate) struct ShardedNeighborMap {
    shards: [PaddedShard; NUM_SHARDS],
}

#[repr(align(64))]
struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);
```

## Audit of all production callers (extended)

| Site | Operation | Replacement |
|---|---|---|
| `afxdp.rs:928` | insert (ARP learn) | `.insert(...)` |
| `afxdp.rs:996` | insert (NA learn) | `.insert(...)` |
| `afxdp.rs:3115` | get + retry pending | `.get(&key)` |
| `afxdp.rs:3379` | multi-ifindex insert | `.with_all_shards(\|s\| ...)` |
| `coordinator.rs:177-186` | replace (remove + insert) | `.with_all_shards(\|s\| ...)` |
| `coordinator.rs:208` | `len()` for status | `.len()` |
| `coordinator.rs:295` | clear | `.with_all_shards(\|s\| s.iter_mut().for_each(\|m\| m.clear()))` |
| `coordinator.rs:1029` | bulk-remove stale | `.with_all_shards(\|s\| ...)` |
| `forwarding.rs:216` | get | `.get(&key)` |
| `forwarding.rs:1509` | get | `.get(&key)` |
| `neighbor.rs:189` | `update_dynamic_neighbor` (returns bool) | `.insert_if_changed(...)` |
| `neighbor.rs:206` | `remove_dynamic_neighbor` (returns bool) | `.remove_if_present(...)` |
| `neighbor.rs:217-380` | `parse_neighbor_msg` (delegates to update/remove) | unchanged |

Zero callers iterate the map (no `.iter()` / `.values()` / `.keys()`).

## Implementation steps

1. **Add `ShardedNeighborMap`** in
   `userspace-dp/src/afxdp/sharded_neighbor.rs` (~200 lines + tests).
2. **Unit tests in same file**:
   - `get_returns_inserted_value`
   - `remove_if_present_returns_true_when_existing_false_when_absent`
   - `insert_if_changed_returns_true_on_first_insert_false_on_same_mac`
   - `insert_if_changed_returns_true_on_mac_change`
   - `len_sums_across_shards`
   - `with_all_shards_observes_atomic_replace`
     (concurrent reader sees pre-replace or post-replace, never partial)
   - `padded_shard_align_at_least_64` (`mem::align_of`)
   - `shard_distribution_ipv4_24` (max-shard ≤ 2× ideal)
   - `shard_distribution_ipv4_16`
   - `shard_distribution_ipv6_slaac`
   - `shard_distribution_constant_ifindex`
   - `poison_ignored_via_into_inner`
3. **Swap type alias** at `coordinator.rs:32` and `worker.rs:446`.
4. **Update field type and constructor** at `coordinator.rs:32`.
5. **Update all 14 runtime `.lock()` sites** to method calls per the
   audit table above.
6. **Update all ~50 type-occurrence sites** (param signatures, struct
   fields).
7. **Update all ~49 test constructors** (`Arc::new(Mutex::new(FastMap::default()))` →
   `Arc::new(ShardedNeighborMap::new())`).
8. **Run `cargo test --release`** — must pass with new tests.

## Test plan

- **`cargo test --release`** (existing 800 tests + ~12 new) must pass.
- **Cluster smoke** (HARD gate):
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 within ±5% of 27.77 ms
- **Contention measurement (HARD gate)**: `perf c2c record` on a 60s
  iperf3-P=128 run before/after. Acceptance: cache-line bouncing on
  the dynamic_neighbors mutex line drops by ≥ 50%. PR closes without
  merge if not met.

## Risk

**High.**

- ~14 production sites + ~50 type sigs + ~49 test constructors —
  large surface area.
- Single-lock batch semantics (replace, clear, bulk-remove,
  multi-ifindex insert) preserved via `with_all_shards`. Deadlock-free
  invariant: all bulk operations lock in ascending shard-index order.
- Shard hash distribution must be empirically validated; bad
  distribution undercuts the entire premise.
- False-sharing risk mitigated via `#[repr(align(64))]`.
- Poison policy is `into_inner()` — silent, but the only honest
  choice given no supervisor today.

## Out of scope (PR 2 follow-up)

- Sharding the three shared session maps + `OwnerRgSessionIndex`.
  Requires composite abstraction with explicit lock ordering.
- Worker command queues. Acceptable as full mutex.
- Control-plane mutexes. Not on the fast path.
- `with_keys_locked(&[k], f)` optimization for the multi-ifindex
  insert site (locks only affected shards). PR 1 uses
  `with_all_shards` for simplicity.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` (~812 tests) pass.
3. Cluster smoke: all four gates green.
4. Contention measurement: cache-line bouncing drops ≥ 50%.
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.
