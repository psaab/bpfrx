# AGY adversarial plan-review r5 — #1648 (on plan v5, `2f0b60bf39a5`)

Task ID: `adversarial-review-mpr237k0-7t384z`

**Verdict: PLAN-READY.**

Rigorous, hostile, code-verified review of v5 against the active codebase.
Complete technical convergence confirmed; all six focus areas verified to the
exact line; no new blockers.

---

## 1. Concurrency Correctness of the Double-Buffered Atomic Swap — CORRECT
- No lookup-miss window or deadlock hazard.
- The swap locks all 64 shards under `with_all_shards` (`sharded_neighbor.rs:135`).
  A concurrent worker lookup `dynamic_neighbors.get(&(ifindex, target))`
  (`sharded_neighbor.rs:88`) acquires the single shard lock via
  `self.lock_shard(shard_idx(key))` (`sharded_neighbor.rs:89`).
- Because `with_all_shards` holds the `MutexGuard` for all 64 shards, worker
  lookups during the swap block synchronously and unblock only after the
  clear+copy completes → workers always see the complete pre-swap OR complete
  post-swap state, never a half-replaced/empty intermediate.
- Identical to (and no worse than) the existing manager-key replacement path
  (`coordinator/mod.rs:169-178`).
- **No lock bypass:** `shards` (`sharded_neighbor.rs:49`) and `PaddedShard`
  (`:39`) are private to `sharded_neighbor.rs`; every neighbor op goes through the
  public methods (`get`/`insert`/`remove`/`insert_if_changed`/`remove_if_present`/
  `contains_key`), all of which enforce Mutex acquisition.

## 2. Key-Collapsed Staging Map & Tombstone Semantics — SOUND
- Order-independent final-state replay is last-writer-correct.
- Events consumed from the socket `recv()` queue in order; the staging map
  collapses per `(ifindex, IP)`.
- DEL-then-NEW: staged `Tombstone` → `Present(MAC)`; replay inserts `Present`. ✓
- NEW-then-DEL: staged `Present(MAC)` → `Tombstone`; replay removes the key. ✓
- Memory bounded by unique kernel neighbor IP count (`gc_thresh*`).

## 3. Resolution of the Stale-Entry Cache Leak (H-E) — CONFIRMED & FIXED
- Leak verified: `teardown.rs:28` → `stop_inner(false)` (`coordinator/mod.rs:198`)
  tears down stop-flags/queues (`:199-208`) but **never clears
  `self.neighbors.dynamic`**.
- Respawned dump runs against the dirty map (`bringup.rs:339`); the dump path
  (`neighbor.rs:445-451`) only upserts (`update_dynamic_neighbor`
  `neighbor.rs:280`) / removes-if-present (`remove_dynamic_neighbor` `:289`) — a
  kernel-deleted neighbor absent from the dump stream **remains forever**.
- Resolution: build the local map offline + full-shard clear+copy under
  `with_all_shards` purges any entry not present in the fresh dump.

## 4. Stale-Entry-Leak Capture in §3 H-E & §5.A.2 — FAITHFUL
- §3 H-E + §5.A.2 accurately characterize the `dynamic_neighbors` lifetime, the
  `stop_inner` gap, and the L2 blackhole/leak consequence. Dual-duty (H-0 + H-E in
  one swap) correctly justified. Nothing understated.

## 5. R3 Matrix Integrity — CLEAN
- Stale "ship-any-fix" wording purged. Failover scope → strict PLAN-KILL when
  fast-path/pre-learn warm; clean-failover ENOBUFS==0 → explicit "do NOT ship;
  escalate" row. Every outcome maps to one isolated justified fix (5.A.2 vs 5.E vs
  investigate recycle).

## 6. No New Blockers
- **No 4th window:** monitor spawned only under `if monitor_stop.is_none()`
  (`bringup.rs:330`); `monitor_stop` cleared to None only in `stop_inner`
  (`coordinator/mod.rs:199`). Only the three windows exist.
- **No swap deadlock:** `with_all_shards` (`sharded_neighbor.rs:135`) always
  acquires shard locks in ascending index order (`0..64`); all other ops take a
  single shard lock or `with_all_shards` (e.g. passive learn
  `neighbor_dispatch.rs:340`) → no circular wait.
- **No republish-staleness:** workers do NOT read dynamic neighbors from the
  `ForwardingState` ArcSwap. The worker loop (`worker/loop_body/mod.rs:14`) holds a
  cloned `Arc<ShardedNeighborMap>` (`:20`) passed as `&dynamic_neighbors` to
  resolution. Mutating that same map's shards is instantly visible to worker
  lookups — no ForwardingState pointer swap / republish needed. (This resolves
  SMR r5's open /engineer question affirmatively.)

---

## Summary
Plan is rigorous, accurate, and aligned with the codebase. Ready to transition to
/engineer once Gate-R confirms the latency metrics.
