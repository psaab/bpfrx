# AGY adversarial plan-review r4 — #1648 (on plan v4, `b66991feb`)

Task ID: `adversarial-review-mpr1hhma-hbycu7`

**Verdict: PLAN-NEEDS-REVISION** (due to a major hidden design flaw in Window-3
config-reloads that leads to permanent cache leaks, and a correctness hole in the
staging-overflow fallback).

Rigorous code-verified review of v4 (`b66991feb`) against the active codebase.
While the plan is thorough and addresses Round 3 feedback, AGY identified a new
critical design bug, structural refinements for the staging/overflow contracts,
and exact mitigations for the testing kill-bars.

---

## 1. Window Exhaustion Verification (Question 1)
Verified every caller of `bring_up_workers`, every write to `monitor_stop`, and
every spawn of `neigh_monitor_thread`.

- `bring_up_workers` called **only** in `Coordinator::reconcile` at
  `reconcile/mod.rs:112`.
- `monitor_stop.take()` called **only** in `stop_inner` at
  `coordinator/mod.rs:199`.
- `stop_inner` has exactly three production entry points:
  1. `teardown::tear_down` at `reconcile/teardown.rs:28` (config-reload / W3, runs
     unconditionally).
  2. `Coordinator::stop` at `coordinator/mod.rs:97` (daemon shutdown).
  3. `Coordinator::stop_with_event_stream` at `coordinator/mod.rs:106` (process
     exit / W1).
- `neigh_monitor_thread` spawned **only** in `bring_up_workers` at
  `reconcile/bringup.rs:338`.

**Conclusion: no fourth window.** The three v4 windows are exhaustive for the
lifecycle of `initial_neighbor_dump`.

---

## 2. CRITICAL NEW BUG: Window-3 Config-Reload Stale-Entry Cache Leak
1. `dynamic_neighbors` (`ShardedNeighborMap`) is a long-lived structure owned by
   `Coordinator` and shared with workers.
2. During a config-reload (W3), `teardown::tear_down` stops workers and the
   monitor thread but **never clears or resets `dynamic_neighbors`**.
3. When `bring_up_workers` respawns the monitor, `initial_neighbor_dump` runs
   against the **same, dirty map** (`bringup.rs:339`).
4. Because `initial_neighbor_dump` only **upserts** from the kernel cache
   (`neighbor.rs:446`), any neighbor deleted in the kernel during the
   reload/teardown window **remains in `dynamic_neighbors` permanently**.

This is a severe **L2 stale-entry leak** that survives across config-reloads,
risking traffic leakage to stale MAC addresses if IP allocations change.

### The Solution: Double-Buffered Atomic Swap
Clearing `dynamic_neighbors` in-place at the start of the dump is dangerous
(worker threads would suffer total cache misses during the dump). Instead:
1. `initial_neighbor_dump` builds a thread-local, empty temporary
   `FastMap<(i32, IpAddr), NeighborEntry>`.
2. Populate it with the GETNEIGH dump rows.
3. Stage all `seq == 0` multicast deltas in a local staging buffer.
4. Replay the staged deltas onto the local map once `NLMSG_DONE` is received.
5. Lock the active `dynamic_neighbors` via `with_all_shards`
   (`sharded_neighbor.rs:135`), clear every shard, copy the local map in under
   the lock.

Guarantees: no stale L2 leakage across config-reloads (W3) or resyncs (5.E);
atomic updates with zero lookup downtime / packet drops for active workers.

---

## 3. Staging-Replay Design & Ordering (Question 2)
Agree with SMR NIT-1 that FIFO replay is the gating contract; a raw unordered
`HashMap` Vec is broken because arbitrary iteration order resolves same-key
DEL/NEW wrong. A better design:
- **Key-Collapsed Staging Map** keyed by `(ifindex, IP)` storing only the
  **latest state** per key:
  - Memory bounded by number of unique active neighbor IPs (no OOM under churn).
  - Each key has exactly one final entry → iteration order irrelevant on replay
    → last-writer-wins preserved naturally.

---

## 4. Staging-Overflow Fallback (Question 3)
SMR NIT-2 ("stop staging, finish dump, let steady-state catch up — no re-dump")
has a correctness flaw. To parse dump rows to completion we must `recv()`; any
`seq == 0` multicast read during that time is consumed from the socket queue. If
we "stop staging" them on overflow, those messages are **permanently discarded**
from userspace — they will NOT be seen by the steady-state loop → **permanent map
desync** for those IPs.

### The Correct Fallback
1. With the Key-Collapsed Staging Map, the buffer is naturally bounded by unique
   neighbor entries (already capped by system limits).
2. If a defensive cap is still wanted (e.g. 8192 unique IPs), the only safe
   fallback is: **on overflow, mark the dump dirty and schedule exactly one async
   retried dump after a 1-second delay.** Avoids infinite livelock under churn
   while guaranteeing eventual consistency.

---

## 5. Clean-Failover ENOBUFS & Thread Supervision (Question 4)
`neighbor.rs:528` simply `continue`s on `recv <= 0` with no errno logging or
socket recreation. ENOBUFS is a real risk on a long-running standby during HA
transitions (multicast bursts). Gating 5.E on Gate-R confirming ENOBUFS is
honest, but the plan must include **supervision hardening**:
- **Supervision Blocker:** `neigh_monitor_thread` is spawned via
  `spawn_supervised_aux` (`bringup.rs:338`) which has **no respawn policy on
  thread panic**. A malformed netlink frame or persistent OS error that panics
  the thread kills the monitor permanently, **freezing the neighbor cache**. The
  plan should mandate thread recreation/restart on panic/death.

---

## 6. Quantitative Kill-Bar Precision (Questions 5 & 6)
- **Preventing False-Negatives:** background unsolicited multicast (RA, IPv6 DAD)
  can warm target B before failover. *Gating contract:* programmatically verify
  target B absent from BOTH the kernel cache (`ip neigh show`) AND
  `dynamic_neighbors` immediately before triggering promotion.
- **Preventing False-Positives:** normal packet loss can mimic the RTO signature
  (two SYNs ~1s apart). *Gating contract:* do NOT decide "World 1" on client-side
  SYN delay alone — require **both** the RTO signature AND the daemon's throwaway
  counters (MissingNeighbor buffer timeout / seq-mismatch drop) to have
  incremented.

---

## Summary
1. Refuted the 4th window (existing 3 are exhaustive).
2. Discovered a critical stale-entry leak bug in W3 config-reloads → proposed the
   Double-Buffered Atomic Swap fix.
3. Optimized the staging contract via Key-Collapsed Staging Map (last-writer-wins
   + natural memory bound).
4. Corrected the staging-overflow fallback to prevent permanent desync.
5. Tightened the Gate-R kill bar (both false-positive and false-negative).

Recommend revising the plan to incorporate the Double-Buffered Atomic Swap and
Key-Collapsed Staging models before engineering.
