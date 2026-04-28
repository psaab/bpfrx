# #949: Sharded mutex for fast-path session/neighbor maps

Plan v1 — 2026-04-28.

## Issue scope correction

#949 originally proposed BOTH RCU/ArcSwap (for routing/config/FIB) AND
sharded mutex (for sessions/neighbors). Codex investigation
(task-moivbi68-p0r5vx) found that the ArcSwap part is **already done**:

- `shared_forwarding`, `shared_validation`, `ha_state`, fabrics, CoS
  maps are already `ArcSwap` (`coordinator.rs:15-31`,
  `worker.rs:716-773,796`).
- TX inbox is already lock-free (`mpsc_inbox.rs`).
- Telemetry is already atomics.

So #949 collapses to: **shard the remaining `Arc<Mutex<FastMap<...>>>`
on the fast path.** Four candidates exist — this plan addresses
**`dynamic_neighbors` only** as PR 1, and defers session-map sharding
to PR 2.

## Why dynamic_neighbors first

- **Smallest blast radius.** ~3 read sites and ~5 write sites. Bounded
  surface area.
- **Cleanest pattern.** Pure `(key, [u8;6])` lookup/insert. No
  cross-map invariants, no index coupling.
- **Established read pattern.** Reads always lock → get → copy MAC →
  release. No held references across syscalls (`forwarding.rs:1497-
  1517`, `afxdp.rs:3108-3119,928-944,996-1005`).
- **Real contention.** Every packet that misses the flow cache and
  triggers neighbor lookup contends on this mutex.

Session maps (`shared_sessions`, `shared_nat_sessions`,
`shared_forward_wire_sessions`) and the `OwnerRgSessionIndex` are
coupled — sharding any one without the others creates inconsistency
windows. They land together in PR 2.

## Design

### `ShardedNeighborMap`

```rust
pub(crate) struct ShardedNeighborMap {
    shards: [Mutex<FastMap<(i32, IpAddr), NeighborEntry>>; 64],
}

impl ShardedNeighborMap {
    pub fn new() -> Self { /* default-init 64 shards */ }

    fn shard_for(&self, key: &(i32, IpAddr)) -> &Mutex<FastMap<(i32, IpAddr), NeighborEntry>> {
        // Hash with FxHash for consistency with the underlying FastMap.
        let mut hasher = FxHasher::default();
        key.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) & 63]
    }

    pub fn get(&self, key: &(i32, IpAddr)) -> Option<NeighborEntry> {
        self.shard_for(key).lock().ok()?.get(key).copied()
    }

    pub fn insert(&self, key: (i32, IpAddr), val: NeighborEntry) {
        if let Ok(mut shard) = self.shard_for(&key).lock() {
            shard.insert(key, val);
        }
    }

    pub fn remove(&self, key: &(i32, IpAddr)) {
        if let Ok(mut shard) = self.shard_for(key).lock() {
            shard.remove(key);
        }
    }

    /// For full-map iteration (rare — netlink reconcile, GC).
    pub fn for_each<F>(&self, mut f: F) where F: FnMut(&(i32, IpAddr), &NeighborEntry) {
        for shard in &self.shards {
            if let Ok(g) = shard.lock() {
                for (k, v) in g.iter() { f(k, v); }
            }
        }
    }
}
```

64 shards is the standard choice (matches `dashmap` default). On a
single-socket 6-core test box, 64 shards give a ~10× reduction in
collision probability vs single mutex; on bigger SMP machines the
benefit grows.

### Replacement strategy

The existing type is `Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>`,
threaded through ~7 functions as `&Arc<...>`.

Replace with `Arc<ShardedNeighborMap>`. Threading stays identical:
`&Arc<ShardedNeighborMap>`.

All call sites use one of: `.get()`, `.insert()`, `.remove()`,
`.for_each()`. Direct `.lock()` calls disappear.

## Implementation steps

1. **Add `ShardedNeighborMap`** in
   `userspace-dp/src/afxdp/sharded_neighbor.rs` (new file). Unit tests
   in the same file.
2. **Swap the type alias** at `coordinator.rs:32`,
   `worker.rs:446`, and the function-arg sites in `neighbor.rs`,
   `shared_ops.rs`, and `afxdp.rs`.
3. **Replace `.lock()` patterns** site-by-site:
   - Read: `lock + get + copy + release` → `.get()`.
   - Insert: `lock + insert + release` → `.insert()`.
   - Remove: `lock + remove + release` → `.remove()`.
   - Iterate (rare): → `.for_each()`.
4. **Coordinator init** at `coordinator.rs:32` switches from
   `Arc::new(Mutex::new(FastMap::default()))` to
   `Arc::new(ShardedNeighborMap::new())`.

## Affected files (estimated)

| File | Sites | Pattern |
|---|---|---|
| `coordinator.rs` | 2 | type alias + init |
| `worker.rs` | 1 | type alias |
| `neighbor.rs` | ~6 | type alias + lock→method |
| `shared_ops.rs` | ~3 | type alias only (passed through) |
| `afxdp.rs` | ~5 | type alias + lock→method at call sites |
| `forwarding.rs` | ~2 | lock→method (read sites) |
| `sharded_neighbor.rs` | NEW | ~80 lines |

Total: ~30 line-level edits + 1 new file.

## Test plan

- **New unit tests** for `ShardedNeighborMap`:
  - `get_returns_inserted_value`
  - `remove_clears_entry`
  - `concurrent_inserts_to_different_keys_dont_block` (loom or
    mpsc-driven thread test)
  - `for_each_visits_all_shards`
- **Existing tests** must pass unchanged: `forwarding.rs:3518,3559`
  exercise neighbor lookup paths.
- **`cargo test --release`** full suite: 800 → 804 tests.
- **Cluster smoke** (required because hot path):
  - iperf-c P=12 ≥ 22 Gb/s
  - iperf-c P=1 ≥ 6 Gb/s
  - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
  - mouse p99 within ±5% of 27.77 ms
- **Contention measurement** (nice-to-have, not gate):
  `perf c2c record` before/after on a long iperf3 run to confirm
  cache-line bouncing on the neighbor mutex actually drops.

## Risk

**Medium.**

- The type alias swap is mechanical and compile-enforced.
- The risk is **subtle behavioral drift**:
  - Iteration order across shards is non-deterministic. If any current
    code depends on iteration order, it breaks. Codex's investigation
    found no such dependency, but the audit must be explicit.
  - A `for_each` that mutates state across shards is now non-atomic.
    Currently no caller does this; must verify.
- Throughput should stay flat or improve. Latency under contention
  should improve. A regression would indicate a bug.

## Out of scope (PR 2 follow-up)

- Sharding `shared_sessions`, `shared_nat_sessions`,
  `shared_forward_wire_sessions`. These three plus `OwnerRgSessionIndex`
  are coupled — they must shard atomically, which is a much larger
  surgery (~150 line edits, plus `OwnerRgSessionIndex` redesign). High
  risk; defer to a focused PR with its own plan + smoke.
- Worker command queues (`WorkerCommand`). Codex flagged these as
  acceptable as full mutexes — sharding would be premature.
- Control-plane mutexes (`ServerState`, `recent_exceptions`). Not on
  the fast path.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` 804/804 pass (800 existing + 4 new).
3. Cluster smoke: all gates green.
4. Codex hostile review: AGREE-TO-MERGE.
5. Gemini adversarial review: AGREE-TO-MERGE.
