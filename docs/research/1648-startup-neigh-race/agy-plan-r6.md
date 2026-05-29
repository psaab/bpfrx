# AGY adversarial plan-review r6 — #1648 (on plan v6, `8ca9a0dc5105`)

Task ID: `adversarial-review-mpr2w010-96oqpb`

**Verdict: PLAN-READY.** Technical convergence fully achieved across Codex, AGY,
and Claude SMR. The v6 shift to a staged-replay into the live, un-cleared map
resolves the v5 blockers without regressions.

### 1. Re-read of `coordinator/mod.rs:198-268` & H-E Retraction
Re-read in full. `stop_inner` **does** clear `self.neighbors.dynamic` atomically
under a bulk lock at `coordinator/mod.rs:263-267`:
```
263:  self.neighbors.dynamic.with_all_shards(|bulk| {
264:      for shard in bulk.each_shard_mut() { shard.clear(); }
267:  });
```
This clear runs *after* `self.workers.stop_and_clear` (`coordinator/mod.rs:220`),
so the bringup map starts completely empty. **AGY's r4/r5 stale-entry-leak (H-E)
claim — based on reading only the initial lines of `stop_inner` — was incorrect.
The v6 retraction is fully correct and verified.**

### 2. Preservation of Worker-Learned Entries in v6 Staged-Replay
Workers spawn at `bringup.rs:233` before the `neigh-monitor` at `bringup.rs:338`.
During the dump window workers write `dynamic_neighbors` directly: ARP
(`poll_stages.rs:80`), NDP NA (`poll_stages.rs:103`), L3 source-learning
(`poll_stages.rs:183` → `neighbor_dispatch.rs:340`). Under v6 staged-replay (dump
rows upserted into the live empty map; worker writes via single-shard locks
`sharded_neighbor.rs:94`; staged seq=0 replayed via per-key insert/remove), there
is no blanket `.clear()`, so any worker-learned entry for an untouched key remains
intact. Avoids the v5 full-clear erasure regression.

### 3. Last-Writer-Wins & Staged-DEL-vs-Worker-Write
Key-collapsed staging (`Tombstone`/`Present(MAC)`) is order-independent at replay:
DEL→NEW collapses to `Present` → insert → **present** ✓; NEW→DEL collapses to
`Tombstone` → remove → **removed** ✓. A staged DEL removing a worker-just-learned
entry is **transient, not permanent**: the next packet to X triggers
`MissingNeighbor` → `trigger_kernel_arp_probe` (~5ms re-learn), and the kernel's
resolved state emits a steady-state RTM_NEWNEIGH processed by the (now-post-dump)
monitor loop. Bounded ~5ms, identical to steady-state races on master,
self-healing.

### 4. §5.E Per-Key-Diff Resync (ENOBUFS-gated)
Correct, avoids the blanket-clear hazard: runs on a populated live map during
active traffic, so it accumulates a fresh kernel dump + staged deltas and calls
`remove(key)` only for keys in the live map but absent from the fresh dump.
`NeighborEntry` is only `pub mac: [u8;6]` (`types/forwarding.rs:127`) — no
worker-owned tag — but a transiently-removed worker entry re-learns in ~5ms;
acceptable for a rare ENOBUFS-gated resync. Socket recreation (not reuse) is
correct (avoids a continuous ENOBUFS loop).

### 5. Exhaustive Check for Remaining Risks
- **No 4th window:** `monitor_stop` cleared only in `stop_inner`
  (`coordinator/mod.rs:199`), checked before spawn (`bringup.rs:330`). Three
  windows (Restart, VRRP Failover, BINDING Reconcile) exhaustive.
- **No deadlock:** dump/replay are per-key single-shard ops
  (`sharded_neighbor.rs:81`); the only multi-shard op `with_all_shards` acquires
  in ascending shard-index order (`sharded_neighbor.rs:144`) → deadlock-free.
- **No republish-staleness:** workers hold the `Arc<ShardedNeighborMap>` directly
  (`worker/loop_body/mod.rs:20`); shard mutations are immediately visible, no
  pointer swap / ForwardingState update needed.

### Next Steps (/engineer recommendations, non-blocking)
1. Process queued steady-state netlink messages in chronological order
   immediately after the staged replay.
2. Persistent-error hardening: inspect netlink errno in the steady-state loop;
   apply 5.E socket-recreation on persistent non-WouldBlock errors (avoid 100% CPU
   on bad fds).
3. Honor the quantitative kill bar + programmatic target-B absence on fw1 before
   triggering VRRP promotion in R2.
