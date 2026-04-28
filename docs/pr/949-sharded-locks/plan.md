# #949 PR1: Sharded mutex for `dynamic_neighbors`

Plan v2 — 2026-04-28. Addresses Codex hostile review (task-moivkugr-o7whtp,
verdict NEEDS-MAJOR).

## Issue scope correction

#949 originally proposed BOTH RCU/ArcSwap (for routing/config/FIB) AND
sharded mutex (for sessions/neighbors). Codex investigation
(task-moivbi68-p0r5vx) found the ArcSwap part is **already done**:

- `shared_forwarding`, `shared_validation`, `ha_state`, fabrics, CoS
  maps are already `ArcSwap` (`coordinator.rs:15-31`,
  `worker.rs:716-773,796`).
- TX inbox is already lock-free (`mpsc_inbox.rs`).
- Telemetry is already atomics.

**Honest framing**: this PR is **NOT RCU and NOT immutable-state**.
It is "reduce mutex contention for the dynamic neighbor cache via
sharding." The plan title and any commit / PR description must reflect
this (per Codex Q2). The original issue title's "RCU / Immutable State
Pattern" framing is incorrect for the remaining work.

## Why dynamic_neighbors first (and only in PR 1)

- Smallest blast radius. Fewer call sites than session maps.
- Cleanest pattern. `(key, NeighborEntry)` lookup/insert with
  `NeighborEntry: Copy` (verified at `userspace-dp/src/afxdp/types.rs:382`,
  Codex Q4 AGREE).
- Established read pattern. Reads always lock → get → copy MAC →
  release. No held references across syscalls.
- Real contention. Every flow-cache miss performs a neighbor lookup
  on this mutex.

Session maps (`shared_sessions` × 3) and the `OwnerRgSessionIndex` are
**deeply coupled** — Codex Q8 confirms PR 2 needs a composite
abstraction with explicit lock ordering, not a simple mechanical
shard. PR 2 has its own plan.

## Affected files (corrected per Codex Q6)

The v1 estimate "~30 line-level edits across 5-6 files" was wrong.
Actual scope:

| File | `.lock()` sites | Type-occurrence sites |
|---|---|---|
| `coordinator.rs` | 4 | 5 |
| `neighbor.rs` | 4 | 4 (param sigs) |
| `forwarding.rs` | 2 | 2 |
| `afxdp.rs` | 2 | ~6 |
| `shared_ops.rs` | 0 | 4 (passed-through) |
| `session_glue.rs` | 0 | ~3 (passed-through, tests) |
| `tunnel.rs` | 0 | ~2 |
| `ha.rs` | 0 | ~2 |
| `icmp.rs`, `icmp_embed.rs` | 0 | ~4 (passed-through) |
| **Test constructors** | 0 | ~10 (test-only) |
| **Production runtime** | **12** | **~44** |

Total: ~12 runtime `.lock()` sites + ~44 type-occurrence rewrites.
Realistic edit volume: 100-150 line-level changes including tests.

Affected files explicitly: `coordinator.rs`, `neighbor.rs`,
`forwarding.rs`, `afxdp.rs`, `shared_ops.rs`, `session_glue.rs`,
`tunnel.rs`, `ha.rs`, `icmp.rs`, `icmp_embed.rs`, plus test files.
This is more than the v1 plan claimed.

## Existing single-lock batch semantics (Codex Q3 — DISAGREE on prior)

The v1 plan missed three production sites that hold the single lock
across multiple operations and depend on atomicity-vs-readers:

1. **Manager replace** at `coordinator.rs:177-185` — removes/inserts
   multiple manager-owned entries under a single lock. Readers see
   either pre-replace or post-replace state, never a half-replaced
   set.
2. **Map clear** at `coordinator.rs:295` — single-lock clear.
3. **Bulk-remove of stale manager keys** at `coordinator.rs:1029` —
   removes a set of entries under a single lock.

Sharded per-key calls would make these partial across shards. The
sharded API must therefore include **bulk operations with deterministic
shard lock ordering**:

```rust
impl ShardedNeighborMap {
    /// Replace all manager entries atomically across shards.
    /// Locks all shards in shard-index order, applies the change, releases.
    pub fn replace_manager_entries(
        &self,
        new_entries: impl IntoIterator<Item = ((i32, IpAddr), NeighborEntry)>,
        is_manager_owned: impl Fn(&NeighborEntry) -> bool,
    );

    /// Clear the map across all shards. Lock-all-then-clear.
    pub fn clear(&self);

    /// Remove a set of keys atomically across shards.
    pub fn remove_many<I>(&self, keys: I) where I: IntoIterator<Item = (i32, IpAddr)>;
}
```

Lock-all-in-shard-order avoids deadlock with any future caller that
locks individual shards (deadlock-free as long as everyone uses
ascending shard order). Documented invariant in the type.

## Design

### Shard hash independent of FastMap inner hash (Codex Q1 — DISAGREE on prior)

The v1 plan used FxHash for shard selection AND the inner FastMap.
Both `hashbrown`/`FastMap` and `FxHasher` use low hash bits for bucket
selection. Using the same hash means keys in shard `i` all share the
same low 6 bits → can poison the inner FastMap distribution.

Fix: use **rotated/mixed FxHash** for shard selection:

```rust
fn shard_idx(&self, key: &(i32, IpAddr)) -> usize {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    let h = hasher.finish();
    // Mix high bits into low to break correlation with FastMap's inner
    // bucket-selection hash.
    let mixed = h.wrapping_mul(0x9E3779B97F4A7C15) ^ (h >> 32);
    (mixed as usize) & (NUM_SHARDS - 1)
}
```

Test plan covers `/24`, `/16`, IPv6 SLAAC-like, and constant-ifindex
key distributions. Acceptance: max-shard load within 2× ideal
(64-shard ideal = 1/64; max ≤ 2/64).

### Cache-line padded shards (Codex High issue)

`Mutex<FastMap<...>>` is small. Adjacent shards share cache lines, so
contention on shard `i+1` causes false-sharing on shard `i`.

Fix: cache-line padding (64 B on x86_64):

```rust
#[repr(align(64))]
struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);
```

Verified via `mem::size_of::<PaddedShard>()` ≥ 64 in a unit test.

### Poison policy (Codex High issue)

A poisoned `Mutex` shard silently blackholes that key range if every
caller uses `.lock().ok()`. Three policies considered:

| Policy | Pros | Cons |
|---|---|---|
| `into_inner()` recovery + log | Self-healing | Hides bugs; non-deterministic |
| Fail-loud (panic on poison) | Loud, debuggable | Worker death on rare bug |
| Re-init the shard on poison | Self-healing, deterministic | Adds complexity |

**Decision**: fail-loud. Match existing project style — workers
already panic on programmer errors; supervisor (#925) will respawn.
Implementation:

```rust
fn shard_lock(&self, key: &(i32, IpAddr)) -> MutexGuard<'_, FastMap<...>> {
    self.shards[self.shard_idx(key)].0.lock()
        .unwrap_or_else(|e| {
            log::error!("dynamic_neighbors shard mutex poisoned: {:?}", e);
            panic!("poisoned mutex on dynamic_neighbors fast path");
        })
}
```

Worker supervisor will respawn the worker; the shard re-initializes
on the next epoch.

### Audit of all production callers (Codex Q5 — DISAGREE on prior)

Explicit list of every production `.lock()` on `dynamic_neighbors`:

| Site | Operation | Pattern after refactor |
|---|---|---|
| `afxdp.rs:928` | insert (ARP learn) | `.insert(key, val)` |
| `afxdp.rs:996` | insert (NA learn) | `.insert(key, val)` |
| `afxdp.rs:3115` | get + retry pending | `.get(&key)` |
| `afxdp.rs:3379` | clear (reset epoch) | `.clear()` (bulk) |
| `coordinator.rs:177` | replace manager entries | `.replace_manager_entries(...)` (bulk) |
| `coordinator.rs:295` | clear | `.clear()` (bulk) |
| `coordinator.rs:1029` | bulk-remove stale | `.remove_many(...)` (bulk) |
| `forwarding.rs:216` | get | `.get(&key)` |
| `forwarding.rs:1509` | get | `.get(&key)` |
| `neighbor.rs:189-214` | netlink read+write | mixed get/insert |

Zero callers iterate the map (`.iter()` / `.values()` / `.keys()`).
Confirmed by Codex.

### Final type

```rust
pub(crate) struct ShardedNeighborMap {
    shards: [PaddedShard; NUM_SHARDS],  // NUM_SHARDS = 64
}

#[repr(align(64))]
struct PaddedShard(Mutex<FastMap<(i32, IpAddr), NeighborEntry>>);

impl ShardedNeighborMap {
    pub fn new() -> Self { /* default-init 64 padded shards */ }
    pub fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> { /* ... */ }
    pub fn insert(&self, key: (i32, IpAddr), val: NeighborEntry) { /* ... */ }
    pub fn remove(&self, key: &(i32, IpAddr)) { /* ... */ }
    pub fn clear(&self) { /* lock-all-in-order, clear all */ }
    pub fn remove_many<I>(&self, keys: I) where I: IntoIterator<Item = (i32, IpAddr)> { /* ... */ }
    pub fn replace_manager_entries<E, F>(&self, new: E, is_manager: F)
    where E: IntoIterator<Item = ((i32, IpAddr), NeighborEntry)>,
          F: Fn(&NeighborEntry) -> bool { /* ... */ }
}
```

No `for_each` API in PR 1 (no caller needs it).

## Implementation steps

1. **Add `ShardedNeighborMap`** in
   `userspace-dp/src/afxdp/sharded_neighbor.rs` (new file ~150 lines).
2. **Unit tests** in same file:
   - `get_returns_inserted_value`
   - `remove_clears_entry`
   - `clear_removes_all`
   - `remove_many_atomic` (mid-call concurrent reader sees pre-or-post,
     never partial)
   - `replace_manager_entries_atomic`
   - `shard_distribution_ipv4_24` (insert /24, max shard ≤ 2× ideal)
   - `shard_distribution_ipv6_slaac` (insert SLAAC-pattern v6 keys,
     max shard ≤ 2× ideal)
   - `shard_distribution_constant_ifindex` (real test-env pattern)
   - `padded_shard_is_cache_aligned` (`mem::size_of` check)
   - `poison_panics_loudly` (verify the poison policy fires)
3. **Swap type alias** at `coordinator.rs:32`.
4. **Update field type and constructor** at `coordinator.rs:32`.
5. **Update all 12 runtime `.lock()` sites** to method calls.
6. **Update all ~44 type-occurrence sites** (param signatures).
7. **Update test constructors** (~10 sites).
8. **Run `cargo test --release`** — must pass with new tests.

## Test plan

- **`cargo test --release`** (existing 800 tests + new ~10) must pass.
- **Cluster smoke** (HARD gate):
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 within ±5% of 27.77 ms
- **Contention measurement (HARD gate per Codex Q7)**: `perf c2c
  record` on a 60s iperf3-P=128 run before/after. Acceptance:
  cache-line bouncing on the dynamic_neighbors mutex line drops by
  ≥ 50%. If contention does NOT drop measurably, the refactor's
  premise is unproven and the PR should be closed without merge.

## Risk

**High.** (Corrected from v1's "Medium" per Codex Q9.)

- 12 production sites + ~44 type sigs + bulk-API correctness
  invariants — large surface area.
- Single-lock batch semantics (replace, clear, bulk-remove) must be
  preserved via bulk APIs. Getting deterministic lock ordering wrong
  could deadlock under concurrent bulk + key ops.
- Shard hash distribution must be empirically validated; bad
  distribution undercuts the entire premise.
- False-sharing risk (mitigated via `#[repr(align(64))]`).
- Poison policy: fail-loud is project-consistent but a real
  supervisor-respawn event under bug conditions.

## Out of scope (PR 2 follow-up)

- Sharding the three shared session maps (`shared_sessions`,
  `shared_nat_sessions`, `shared_forward_wire_sessions`). Per
  Codex Q8: requires a composite abstraction with `OwnerRgSessionIndex`
  redesign and explicit lock ordering. High risk; separate plan.
- Worker command queues. Acceptable as full mutex.
- Control-plane mutexes (`ServerState`, `recent_exceptions`). Not on
  the fast path.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` (~810 tests) pass.
3. Cluster smoke: all four gates green.
4. **Contention measurement: cache-line bouncing on the
   dynamic_neighbors mutex line drops ≥ 50%** (HARD gate; closes PR
   if not met).
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.
