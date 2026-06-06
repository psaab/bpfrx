# #1771 — Per-Key Neighbor Resolver State Machine

Research and implementation plan for the full §10a redesign, building on
top of the #1769 threaded resolver already in master.

**Status:** DRAFT v3 — round-2 3-way review converged on **Path B**
(Codex PLAN-NEEDS-MAJOR, AGY PLAN-NEEDS-MAJOR→Path B, Claude SMR
NEEDS-MINOR). v3 locks Path B as the plan, simplifies §2.5 to upsert-only
(removes the kernel-ownership defect), corrects §2.3, and hardens the
gated §2.1. See §0.1. Pending round-3 review of Phases 1–3.
**Branch:** `research/1771-per-key-resolver`
**Issue:** #1771
**Follows:** #1769 (merged), #1770 (merged), #1772 (merged), #1773 (merged)

---

## 0. What round-1 review found (and how v2 answers it)

Round-1 (PR #1775 @ `6fa2d15cc`) drew PLAN-NEEDS-MAJOR from all three
reviewers. The eight convergent findings and their v2 disposition:

| # | Round-1 finding | v2 disposition |
|---|-----------------|----------------|
| 1 | §2.1 per-key epoch **reopens the absent-key-DELNEIGH stale-MAC race** (#1769's fix): a separate epoch map with `get→0 if absent` + `remove(key) on DELNEIGH` lets a confirmed GET that snapshotted `0` read `0` again and cache a stale MAC. | **§2.1 redesigned to a co-located epoch** (epoch lives in the *same shard slot* as the neighbor entry). DELNEIGH-of-absent creates a tombstone slot `{entry: None, epoch += 1}`. No reset-to-0. |
| 2 | The in-lock epoch read on the confirmed-insert path is unspecified (TOCTOU if epoch is read before the shard lock). | Co-location makes the epoch read **automatic under the one `dynamic_neighbors` shard lock** — same critical section as `insert_confirmed_if_unchanged` today. No second map, no second lock. |
| 3 | Epoch map unbounded / no tombstone GC. | Tombstones (`entry: None`) are GC'd by the existing `with_all_shards` sweep after `TOMBSTONE_TTL_NS`; §2.1 + §4 specify the bound. |
| 4 | Separate epoch map needs a defined lock order vs `ShardedNeighborMap` (deadlock risk). | **Dissolved** — there is no separate map, so no cross-map lock order exists. |
| 5 | §2.2 per-key pending bound: AGY's UMEM-starvation trace + per-poll scan cost; Claude's "globally" wording + dropped #1772 accounting. | §2.2 rewritten: pending holds **UMEM frames** bounded by the existing **2 s `PENDING_NEIGH_TIMEOUT`** (the round-1 "5 min GC" was a wording bug — that 5 min is the `last_resolved` key→ts GC, which holds no frames). Per-key bound *reduces* frame pinning. #1772 dwell/depth/timeout accounting preserved. "globally"→per-worker. |
| 6 | §2.3 double backoff clock (dispatch `probe_attempts` vs resolver `attempts`); `u8` overflow; no scheduler to wake Negative keys. | §2.3 names the **two distinct clocks** and their owners (they are NOT duplicates — one drives kernel ARP solicitation, one drives userspace GET); only the resolver clock is extended; saturating math; a due-key wake is specified. |
| 7 | §2.5 ENOBUFS unsound: plain upsert dump won't evict stale; monitor has no channel to worker-private `pending_neigh`/resolver-private `last_resolved`; unbounded GET fan-out. | §2.5 specifies **replacement-style re-dump** (reconcile + evict), a bounded monitor→resolver hot-key channel, and a cap on targeted GETs per ENOBUFS event (or drop GETs entirely — re-dump alone repopulates). |
| 8 | §6 validation too generic — no named differential/property tests, no churn injection in the live gate. | §6 names the differential harness, the absent-key-DELNEIGH property test, the per-phase independent-correctness assertion, and the live churn-injection step. |

§2.4 ("Negative is a state") was flagged (Claude F6) as a conceptual rename
with no acceptance criterion; v2 gives it a concrete behavioral criterion
or demotes it to docs (§2.4).

---

## 0.1 Round-2 disposition (v3 changes)

All three reviewers converged on **Path B**: ship §2.2 (pending bound),
§2.5 (ENOBUFS re-dump), §2.6 (counters) now; **gate §2.1 on the measured
`epoch_rejects` rate** and treat it as a risky optimization, not a
correctness fix. v3 makes that the plan. Round-2 findings and disposition:

| r2 finding (reviewer) | v3 disposition |
|---|---|
| **§2.5 wrongly treats `dynamic_neighbors` as kernel-owned** — it is also RX-learned (`neighbor_dispatch.rs:315`) and manager-populated (`coordinator/mod.rs:151`); a replacement/evicting dump deletes valid non-kernel entries (Codex 1). | **§2.5 simplified to UPSERT-ONLY re-dump.** The documented D4 desync (#1771 body) is a *lost RTM_NEWNEIGH* = a **missing** good entry — re-adding what the kernel currently has fixes it with no eviction. Stale-entry eviction (lost-DELNEIGH) is **deferred** (needs per-slot source-tagging) — its own scope. This also dissolves the §2.5 TOCTOU (Claude SMR) and the `with_all_shards` I/O-under-lock risk (AGY E): upsert uses the normal per-key sharded insert with bump-first ordering, no all-shard lock. |
| **§2.3 "two clocks never drive the same syscall" is FALSE** — the resolver itself calls `trigger_kernel_arp_probe()` on stale/failed/no-reply (`neighbor_resolver.rs:700`) (Codex 4). | §2.3 corrected below: both paths can drive kernel probes; extending resolver backoff *intentionally reduces* aggregate kernel-probe cadence for permanently-dead keys. Due-key state must retain `iface_name` (Codex 4). |
| **No existing GC sweep on the neighbor map** (my "existing `with_all_shards` sweep" was fictional) and `with_all_shards` is stop-the-world (AGY C). | §2.1 (gated) now specifies an **incremental, one-shard-at-a-time** tombstone GC — never `with_all_shards`. |
| **§2.1 tombstone-GC stale-MAC resurrection** — queue depth 4096 × 200 ms recv = up to 13.6 min GET latency vs 60 s TTL; a GC'd tombstone lets `epoch_before==0` match a fresh absent slot (AGY B; Claude SMR MAJOR; Codex 5 "GC must not erase a tombstone that can still invalidate"). | §2.1 (gated) folds **both** fixes: (a) epochs drawn from a **process-global monotonic counter** (never reused post-GC) + **reject confirmed-insert on an absent slot**; (b) `ResolveItem` carries `enqueued_ns` and the resolver **discards an item older than `TTL − 2 s`** before issuing the confirm. Either alone closes it; both = belt-and-suspenders. |
| **§2.1 value-type surgery under-specified across APIs** — `get/contains_key/len/is_empty/with_all_shards/total_len` all assume "present ⇒ live"; tombstones must be invisible (Codex 2). | §2.1 (gated) adds an explicit API-audit checklist: every accessor filters `entry.is_some()`; status counts, manager replace, Go-facing status, and tests must not see tombstones. |
| **§2.3 due-key scan starves under load** — only firing in the `recv_timeout` Timeout arm misses wakeups during continuous traffic (AGY D). | §2.3 corrected: the due-key check runs on **every loop iteration** gated by a monotonic `now − last_check ≥ 500 ms`, not only on the timeout arm. |
| **Tests not convincingly runnable** — no proptest dep, no injectable recv/dump seam, failover script has no churn option (Codex 7). | §6 updated: add a hand-rolled differential harness (no new dep) OR add `proptest` dev-dep; introduce an injectable `recv`/`dump` seam trait for ENOBUFS tests; add a `--neigh-churn` option to `userspace-ha-failover-validation.sh`. |
| **§2.1 closes the round-1 absent-key race** with tombstones retained; GET timeout is 200 ms not ~1 s (Codex 5). | Confirmed; §2.1 states the invariant precisely (TTL > max send-to-confirm latency; GC must not erase a still-invalidating tombstone — satisfied by the global-monotonic-epoch + age-discard). |
| §2.2 UMEM claim verified correct (Codex 6, AGY). | No change. |

**Net:** Phases 1–3 (§2.2/§2.5-upsert/§2.6/§2.4) are the shippable plan and
are now PLAN-READY-candidate. §2.1 (Phase 4) stays **gated on
`epoch_rejects`** and, if built, must satisfy the hardened spec below.

---

## 1. Current State (#1769 as shipped)

The live resolver in `userspace-dp/src/afxdp/neighbor_resolver.rs`
(1,194 lines) implements the §9 immediate fix:

**Architecture:**
- One shared resolver thread with a persistent netlink socket.
- Per-binding `pending_neigh: VecDeque<PendingNeighPacket>` (cap
  `MAX_PENDING_NEIGH` = 4096). Each entry **pins a UMEM frame**
  (`pkt.addr`/`pkt.desc.addr`); the frame is recycled to
  `tx_pipeline.pending_fill_frames` on resolve, timeout, or drop.
- Per-binding `neg_neigh_cache: FastMap<(i32, IpAddr), u64>` (3 s TTL).
- **Global** `neighbor_generation: Arc<AtomicU64>` bumped **bump-first,
  once per RTMGRP_NEIGH batch** in `neighbor.rs:644`
  (`fetch_add(1, Release)` *before* mutating `dynamic_neighbors`).
- The confirmed-insert path re-reads the generation **inside the
  `dynamic_neighbors` shard lock** via
  `sharded_neighbor.rs:insert_confirmed_if_unchanged` — this is the
  #1769 race fix and the correctness property v2 must preserve.
- Per-key 1 s rate limit in the resolver thread (`last_resolved` map).
- Dispatch-side kernel-ARP probe schedule
  `PROBE_SCHEDULE_NS = [10 ms, 60 ms, 260 ms]` with per-packet
  `probe_attempts` (`neighbor_dispatch.rs:33`, `probe_due()` at :41).
- #1772 latency accounting on the `NeighborResolver` handle:
  `pending_dwell_hist`, `pending_timeout_drops`, `pending_max_depth`,
  `record_pending_dwell`, `observe_pending_depth`.

**Limitations (why #1771 exists):**
- Global epoch conservatively rejects a confirmed insert when *any*
  unrelated neighbor changes during the GET round-trip. **This is a
  retry, not a correctness failure** — the resolver re-probes and
  re-GETs. The cost is extra GETs under churn, surfaced by the
  already-exported `epoch_rejects` counter (#1772).
- Per-binding 4096 queue admits every packet (no per-key bound), so a
  SYN flood to one dead next-hop can pin up to 4096 UMEM frames for the
  timeout window.
- No ENOBUFS detection (monitor swallows `recv() <= 0`); a dropped
  RTM_NEWNEIGH after a transient remove is silent until the next per-key
  event (D4 desync).

---

## 2. Target Architecture (§10a)

### 2.1 Co-located Per-Key Epoch

**Why this is the hardest part — and why it is optional.** The global
epoch is **already correct** (the #1769 in-lock re-read closes the race).
A per-key epoch buys exactly one thing: it stops rejecting a confirmed
insert when an *unrelated* key churns during the GET. That is a
GET-retry-rate optimization, not a bug fix. **The `epoch_rejects`
counter already measures this** — so the decision to build §2.1 should be
gated on observed reject rate (see Path Options, §2a). If reviewers judge
the co-located-epoch complexity unjustified by the measured reject rate,
**PLAN-KILL of §2.1 alone is an acceptable outcome** and §2.2/§2.5/§2.6
still ship.

**Round-1 killed the separate-map design.** A standalone
`ShardedEpochMap` with `get → 0 if absent` and `remove(key) on DELNEIGH`
re-opens the exact #1769 race: a GET in flight snapshots epoch `0`, the
monitor bumps (NEWNEIGH) then bumps-and-removes (DELNEIGH) resetting the
lookup to `0`, the resolver reads `epoch_after == 0 == epoch_before` and
caches the now-stale MAC. It also needs a defined lock order against
`dynamic_neighbors` and an unbounded tombstone story.

**v2 design: the epoch lives in the neighbor map's shard slot.** Change
the `ShardedNeighborMap` value from `NeighborEntry` to:

```rust
struct NeighborSlot {
    entry: Option<NeighborEntry>, // None == tombstone (deleted but epoch retained)
    epoch: u64,                   // per-key generation, monotonic
    last_change_ns: u64,          // for tombstone GC
}
```

**Monitor (`neighbor.rs:neigh_monitor_thread`), per event, under the key's
shard lock:**
- `RTM_NEWNEIGH(K)`: `slot = shard.entry(K).or_insert(empty); slot.epoch += 1; slot.entry = Some(neigh); slot.last_change_ns = now;`
- `RTM_DELNEIGH(K)`: `slot = shard.entry(K).or_insert(empty); slot.epoch += 1; slot.entry = None; slot.last_change_ns = now;`
  — **note the `or_insert`: a DELNEIGH for an absent key still creates a
  slot and bumps the epoch.** This is the absent-key case #1769 fixed,
  preserved per-key. No reset-to-`0` is possible because the slot (and its
  monotonic epoch) survives deletion as a tombstone.

**Resolver (`neighbor_resolver.rs`):**
- `enqueue()` snapshots `epoch_before = shard.get(K).map(|s| s.epoch).unwrap_or(0)`.
  An absent key reads `0`; the FIRST DELNEIGH then bumps to `≥1`, so any
  later confirmed insert that snapshotted `0` is rejected — the race is
  closed by monotonicity + slot retention, not by the snapshot value.
- Confirmed insert becomes `insert_confirmed_if_unchanged(K, val, epoch_before)`:
  locks the shard, reads `slot.epoch` **under that same lock**, inserts
  `entry = Some(val)` only if `slot.epoch == epoch_before` (creating the
  slot if absent with `epoch = epoch_before`). One lock, one critical
  section — structurally identical to today's global guard, just reading a
  per-slot field instead of the global atomic.

**Cardinality bound + GC-resurrection fix (v3 — supersedes v2; round-2
AGY B/C, Codex 5, Claude SMR MAJOR).** v2 reaped tombstones via "the
existing `with_all_shards` GC sweep" — but (AGY C) **there is no existing
GC sweep on the neighbor map**, and `with_all_shards` is stop-the-world (it
locks all 64 shards → dataplane latency spike). And (AGY B / Claude SMR) a
per-key epoch that *resets to 0* on GC can resurrect a stale MAC: a GET
delayed in the resolver queue (depth 4096 × 200 ms recv → up to ~13.6 min
worst case) snapshots `epoch_before = 0`, the slot becomes a tombstone then
is GC'd at 60 s, and the late confirmed insert sees an absent slot with
`0 == 0` → inserts the stale MAC. v3 closes both:

1. **Epochs are drawn from a process-global monotonic `AtomicU64`**, not a
   per-key `0,1,2…`. Every bump (NEWNEIGH/DELNEIGH) does
   `slot.epoch = GLOBAL_NEIGH_EPOCH.fetch_add(1, Release)`. A snapshot of
   value `N` can never equal any *future* slot's epoch, so GC-then-recreate
   cannot collide with an old snapshot.
2. **Confirmed-insert REJECTS on an absent slot** — drop the "create if
   absent with `epoch = epoch_before`" branch entirely for the confirm
   path. You cannot prove a MAC unchanged against a slot that no longer
   exists. (An absent slot at confirm time ⇒ the key was never seen, or was
   GC'd ⇒ re-resolve, don't trust the snapshot.)
3. **`ResolveItem` carries `enqueued_ns`**; the resolver discards an item
   older than `TOMBSTONE_TTL_NS − 2 s` before issuing the confirm (AGY B
   mitigation). Belt-and-suspenders with (1)/(2).
4. **Tombstone GC is incremental** — one shard at a time on a timer (reuse
   the `last_resolved` 5 min GC cadence), **never `with_all_shards`** (AGY
   C). Reap `entry.is_none() && now - last_change_ns > TOMBSTONE_TTL_NS`
   (60 s). With (1)/(2) the TTL is now only a *cardinality* device, not a
   correctness device — safe at any value.

**API-audit checklist (Codex 2).** Changing the shard value to
`NeighborSlot` means every accessor must treat `entry: None` as absent:
`get` (return `None` for tombstone), `contains_key`, `len`, `is_empty`,
`with_all_shards`/`BulkShardGuard::total_len`, the coordinator/Go-facing
status counts, manager `replace`, and all existing tests. Each is listed as
a Phase-4 sub-task; a tombstone must be invisible to forwarding and status.

**No new lock and no lock-ordering rule** (finding #4 dissolved): the
epoch shares the `dynamic_neighbors` shard mutex it is stored in.

### 2.2 Per-Key Pending Bound

**Current:** per-binding `VecDeque<PendingNeighPacket>` cap 4096, admits
every packet. Each entry pins a UMEM frame; frames are recycled on
resolve/timeout/drop and the buffer is bounded by
`PENDING_NEIGH_TIMEOUT_NS` (**2000 ms**, or 800 ms fast path via #1636
option D) — **not** by any 5-minute GC (the round-1 "5 min max age"
wording was wrong; that 5 min is the `last_resolved` key→timestamp GC,
which holds no frames).

**Target:** one representative packet per `(egress_ifindex, next_hop)`:

```rust
// BindingWorker:
pub(crate) pending_neigh: FastMap<(i32, IpAddr), PendingNeighPacket>,
```

**Admission (`poll_descriptor/mod.rs`):**
- `if pending_neigh.contains_key(&key) { drop+recycle frame; record fast-fail; }`
  else `if pending_neigh.len() < MAX_PENDING_NEIGH { insert(key, pkt) }`
  else `{ drop+recycle frame; record overflow }`.
- A duplicate for an in-flight key drops the **newer** packet and keeps
  the **oldest** (the one whose `queued_ns` is driving the probe
  schedule). This is intentional: it preserves the probe/dwell clock for
  that key. Stated explicitly so an implementer does not "freshen" the
  entry.

**Retry (`neighbor_dispatch.rs:retry_pending_neigh`):**
- Iterate the map; on resolve/timeout remove the key and recycle its
  frame. No VecDeque rotation. The scan is now **O(distinct unresolved
  next-hops)**, not O(4096) — under a SYN flood to dead hosts the map
  holds one entry per dead next-hop, so the per-poll scan cost AGY flagged
  collapses to the real next-hop fan-out.
- **#1772 accounting preserved**: keep `observe_pending_depth(len)`,
  `record_pending_dwell(now - queued_ns)` on resolve, and
  `record_pending_timeout_drop()` on timeout. `pending_max_depth` now
  tracks distinct next-hops (a more meaningful number); note the semantic
  change in the metric help text.

**UMEM-frame impact (finding #5, AGY):** frames are pinned only for the
2 s timeout window and now capped at *distinct next-hop* count rather than
4096 raw packets, so this design **reduces** peak frame pinning under the
SYN-flood scenario AGY raised. The plan asserts the UMEM fill budget is
unchanged and that worst-case pinned frames per worker ≤ MAX_PENDING_NEIGH
(unchanged cap), held ≤ 2 s (unchanged timeout). No new starvation surface
is introduced; the existing one is tightened.

### 2.3 Cross-Sweep Backoff — two distinct clocks, one owner each

Round-1 read §2.3 as proposing a duplicate of the dispatch-side schedule.
It is not a duplicate; there are **two clocks with different jobs**, and
v2 keeps them separate:

1. **Dispatch-side kernel-ARP probe clock** (per *pending packet*):
   `PROBE_SCHEDULE_NS = [10, 60, 260] ms` + per-packet `probe_attempts`,
   in `neighbor_dispatch.rs`. Drives `trigger_kernel_arp_probe()` — i.e.
   asks the *kernel* to solicit. **Unchanged by #1771.** Owner: dispatch.
2. **Resolver-side userspace-GET clock** (per *key*): today a flat 1 s
   `last_resolved` rate limit. #1771 extends *only this* to exponential
   backoff so a permanently-dead key coalesces to one in-flight
   `RTM_GETNEIGH` on a widening interval. Owner: resolver.

```rust
// resolver per-key state (in last_resolved, renamed for clarity):
struct KeyBackoff { last_get_ns: u64, get_attempts: u8 }
// schedule: 1s, 2s, 4s, 8s, capped at GET_BACKOFF_CAP_NS (e.g. 8s);
// get_attempts uses saturating_add (finding #6 — no u8 overflow/probe storm).
```

**Correction (v3, Codex 4):** the two clocks are NOT disjoint — the
resolver *also* calls `trigger_kernel_arp_probe()` on stale/failed/no-reply
(`neighbor_resolver.rs:700`). Extending the resolver GET backoff therefore
*does* change a key's aggregate kernel-probe cadence — but **in the desired
direction**: a permanently-dead key gets fewer GETs and fewer
resolver-driven kernel probes as the backoff widens (1→2→4→8 s), which is
the §2.4 goal. The dispatch-side per-packet `PROBE_SCHEDULE_NS` (kernel
solicitation for *buffered* packets) is unchanged. §2.3's only change is
replacing the resolver's flat 1 s window with the saturating exponential.
**Negative keys keep getting GETs on this backoff** (§2.4 property).

**Waking due Negative keys (finding #6 + AGY D):** the due-key check must
run on **every loop iteration**, gated by a monotonic
`now − last_check ≥ 500 ms` — NOT only inside the `recv_timeout` Timeout
arm. Under continuous traffic `recv_timeout` returns `Ok(item)` immediately
and the Timeout arm never fires, so a timeout-arm-only scan starves
negative-key re-probing (AGY D). The due-key state must also retain
`iface_name` (current `last_resolved` stores only key→timestamp) so the
re-issued GET can be addressed.

### 2.4 Negative Policy — concrete criterion (finding #8/F6)

§2.4 is **behavior already present** (resolver keeps probing on the
negative fast-fail) made into an explicit, *tested* invariant rather than
a new code structure. v2 does **not** add a `ResolverKeyState` enum (that
was the largest unjustified new surface). Instead it adds one property
test as the deliverable:

> **Invariant N1:** while a key is negatively cached
> (`neg_neigh_gate` true), the resolver continues to issue GET/backoff
> probes for that key; only *duplicate buffered packets* are dropped, not
> resolution. Test: arm the negative cache for key K, then advance the
> backoff clock and assert `get_attempts` for K increments (GET fired)
> while `pending_neigh` admits at most one packet for K.

If that invariant already holds on master unchanged, §2.4 reduces to a
docs note in `docs/userspace-dataplane-architecture.md` + the regression
test, and ships no runtime change.

### 2.5 ENOBUFS Detection + Throttled Replacement Re-dump

**Current:** `neigh_monitor_thread` swallows `recv() <= 0`. No ENOBUFS
detection; full dump only at startup.

**Target:** detect ENOBUFS, count it, and trigger a **throttled
upsert-only family re-dump** (v3 — was "replacement-style" in v2; see the
upsert-only rationale below).

```rust
let n = libc::recv(...);
if n < 0 {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOBUFS) => { enobufs_total += 1; maybe_redump(); continue; }
        Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK) => continue, // SO_RCVTIMEO steady state
        _ => continue, // debug-count, never fall through to parse
    }
}
if n == 0 { continue; } // EOF shouldn't happen on netlink
```

**Upsert-only semantics (v3 — supersedes the v2 "replacement" design).**
Round-2 (Codex 1) established that `dynamic_neighbors` is **not
kernel-owned**: it is also populated by RX-side learning
(`neighbor_dispatch.rs:315`) and manager snapshots (`coordinator/mod.rs:151`).
An evicting/replacement dump that removes every key absent from the fresh
kernel dump would delete valid dataplane-learned and manager entries.

The defect #1771 actually targets (D4) is a **lost RTM_NEWNEIGH** — a
*missing* good entry — so the re-dump only needs to **re-add what the
kernel currently has**. v3 therefore specifies an **upsert-only** family
re-dump: walk the fresh dump, `dynamic_neighbors.insert_if_changed(K, …)`
per entry using the **normal per-key sharded insert** (bump-first epoch
ordering), **no `with_all_shards`, no eviction**. This fixes the documented
desync, avoids the kernel-ownership bug, dissolves the TOCTOU (Claude SMR
§2.5) and the I/O-under-all-shards-lock latency spike (AGY E), and needs no
per-slot source tag.

**Stale-entry eviction (lost-DELNEIGH self-heal) is OUT OF SCOPE for
§2.5** and deferred to a follow-up that first adds per-slot source-tagging
(`{Monitor, RxLearned, Manager}`) so only Monitor-sourced entries can be
reconciled away. Lost-DELNEIGH is rarer than lost-NEWNEIGH and the per-key
revocation path (FAILED/DELNEIGH on the next real event) still covers the
common case.

**Throttle:** `AtomicU64` last-redump timestamp, gate at 5 s
(`now - last > 5_000_000_000`) to avoid the RTNL contention AGY F2 raised.
The single-key GET path is explicitly **not** the dump path.

**Targeted hot-key GETs — bounded or dropped (finding #7).** The monitor
cannot see worker-private `pending_neigh` or resolver-private
`last_resolved`. Two options, plan recommends the simpler:
- **Chosen (v3):** drop targeted GETs entirely on ENOBUFS. The throttled
  upsert-only re-dump already repopulates `dynamic_neighbors`; per-key GETs
  after it are redundant, and dropping them avoids the monitor→resolver
  thread-boundary plumbing (AGY E agrees this is structurally sound).

### 2.6 Prometheus Counters

**Current (#1772):** `queue_depth, enqueue_drops, disconnected,
get_attempts, get_resolved, probe_on_stale, get_failures, epoch_rejects`,
plus the latency histograms (`pending_dwell`, `get_rtt`) and
`pending_timeout_drops`, `pending_max_depth`.

**Target additions:**
- `resolver_pending_keys` (gauge — distinct unresolved next-hops, replaces
  raw pending depth meaning)
- `resolver_keys_negative` (gauge)
- `resolver_get_backoff_attempts` (histogram or counter — backoff depth)
- `netlink_enobufs_total` (counter)
- `netlink_redumps_total` (counter)
- `netlink_redump_upserts_total` (counter — entries re-added by an
  upsert-only re-dump; proves the re-dump repopulated missing keys).
  (v2's `redump_evictions_total` is dropped — no eviction in v3.)

**Wiring path (unchanged from v1):** `ResolverCounters` →
`NeighborResolverCounters` snapshot → `server/helpers.rs` status →
`protocol/control.rs` JSON → Go `protocol.go` → `metrics_descriptors.go`
→ `metrics_userspace.go` → `metrics_neighbor_latency_test.go`.

---

## 2a. Path Options

The design space has a real fork on §2.1. v2 surfaces it explicitly per
research-skill guidance.

**Path A — Full §10a (all of §2.1–2.6 in one campaign).** Highest
completeness; highest risk concentrated in the §2.1 co-located-epoch map
(touches the hottest shared structure). Justified only if the
`epoch_rejects` rate is materially high.

**Path B — Value-first, measurement-gated (RECOMMENDED).**
1. Ship §2.2 (per-key pending bound — clear SYN-flood frame-pinning win),
   §2.5 (ENOBUFS upsert-only re-dump — closes the D4 lost-NEWNEIGH gap),
   §2.6 counters, and §2.4 (test/doc only). These need **no** change to
   the epoch machinery and carry the lowest risk.
2. **Gate §2.1 on data:** read `epoch_rejects` / `get_attempts` from the
   loss cluster under realistic churn. If the false-reject rate is
   negligible (expected — churn windows are sub-ms vs ~1 s GETs), **defer
   §2.1** and fold §2.3's backoff change in standalone. If it is material,
   build §2.1 as specified above with the absent-key property test gating
   merge.

Path B converts the riskiest, lowest-evidence item into a measured
decision and ships the two clear wins first. **Recommendation: Path B.**

---

## 3. Implementation Plan (Path B ordering)

Each phase is an independent merge to master and **must be correct and
smoke-clean on its own** (finding #8) — no phase may leave a half-wired
epoch on master.

### Phase 1: Per-Key Pending Bound (§2.2)
- [ ] `BindingWorker.pending_neigh` → `FastMap<(i32, IpAddr), PendingNeighPacket>`
- [ ] Admission `contains_key` guard + frame recycle on duplicate/overflow
- [ ] `retry_pending_neigh` map iteration; preserve #1772 dwell/depth/timeout
- [ ] Update metric help text (`pending_max_depth` now = distinct next-hops)
- [ ] Tests incl. SYN-flood-to-dead-host = 1 slot; #1772 dwell assertions intact

### Phase 2: ENOBUFS Replacement Re-dump (§2.5)
- [ ] ENOBUFS/EAGAIN/EOF match in `neigh_monitor_thread`
- [ ] Throttled (5 s) **upsert-only** family re-dump via per-key sharded
      insert (bump-first) — NOT `with_all_shards`, no eviction
- [ ] `netlink_enobufs_total`/`redumps_total`/`redump_upserts_total`
- [ ] Synthetic ENOBUFS injection test (injectable recv/dump seam) proving a
      lost RTM_NEWNEIGH is re-learned by the re-dump
- [ ] No targeted GETs (re-dump repopulates); stale-entry eviction deferred

### Phase 3: Counters + Negative invariant (§2.6, §2.4)
- [ ] New gauges/counters wired Rust→Go; metrics test
- [ ] Invariant N1 property test; docs note

### Phase 4 (GATED on §2a measurement): Per-Key Co-located Epoch (§2.1, §2.3)
- [ ] Read `epoch_rejects` under churn on loss cluster; record the number
- [ ] If material: `NeighborSlot` value type; monitor `or_insert`+bump-first;
      `insert_confirmed_if_unchanged` reads per-slot epoch under shard lock;
      tombstone GC; resolver exponential GET backoff (saturating) + due-key wake
- [ ] Differential + property tests (§6)
- [ ] If negligible: close §2.1 with the measured rationale; land §2.3
      backoff standalone

### Phase 5: Validation (§6)

---

## 4. Risks and Mitigations

**Per-key epoch reopens the #1769 race (round-1 #1/#2).** Mitigated by
co-location (epoch in the neighbor shard slot, read under the same lock as
the insert) + `or_insert` bump on absent-key DELNEIGH + monotonic
tombstone retention. Gated behind a named property test reproducing the
exact race (§6).

**Tombstone growth (round-1 #3).** `TOMBSTONE_TTL_NS` (60 s) GC in the
existing `with_all_shards` sweep; bound documented; TTL ≫ GET timeout so
GC cannot race an in-flight confirm.

**UMEM frame starvation (round-1 #5, AGY).** Pending holds frames only for
the existing 2 s timeout; per-key bound *reduces* peak pinning vs the
4096-packet status quo. No 5 min hold exists (round-1 wording bug fixed).

**Backoff double-clock / overflow (round-1 #6).** Two clocks documented as
distinct owners; only the resolver clock changes; `saturating_add`.

**ENOBUFS RTNL contention / unbounded GETs (round-1 #7).** 5 s re-dump
throttle; targeted GETs dropped (recommended) or capped via bounded
channel.

**Per-phase half-wiring (round-1 #8).** Path B orders the epoch change
last and gates it; Phases 1–3 are independent and don't touch epoch state.

---

## 5. Out of Scope

- Changing the single-key GET mechanism itself (optimal per #1769)
- Changing the netlink multicast subscription model
- Changing the resolver thread architecture (already shared, off hot path)
- L7 application identification

---

## 6. Success Criteria

- [ ] **Phase 1:** SYN flood to one dead next-hop pins ≤ 1 pending slot
      (test); #1772 dwell/depth/timeout metrics unchanged in meaning where
      noted, values asserted; cargo test green.
- [ ] **Phase 2:** synthetic ENOBUFS injection followed by a lost-NEWNEIGH
      scenario re-learns the missing `dynamic_neighbors` entry within one
      throttled upsert re-dump (`redump_upserts_total` increments); EAGAIN
      steady-state path unaffected.
- [ ] **Phase 3:** all new counters export and scrape; Invariant N1 holds
      (negative key keeps issuing GETs; ≤1 buffered packet/key).
- [ ] **Phase 4 (if built):** **Differential test** — old global-epoch
      path vs new per-key path produce identical cache state under a
      workload of concurrent confirms + *unrelated-key* churn, except that
      the per-key path has strictly fewer `epoch_rejects`. **Property
      test** — the absent-key-DELNEIGH race: GET snapshots key K's epoch,
      a NEWNEIGH then DELNEIGH(K) land, the confirmed insert is REJECTED
      (no stale-MAC resurrection) — the #1769/#1774 defect.
- [ ] **Live gate:** deploy to loss cluster; run
      `userspace-ha-failover-validation.sh` **with neighbor-churn
      injection** (`ip neigh flush` / add-delete loops on a non-target
      next-hop during failover) — connectivity must not blackhole and the
      `-P 12 -p 5208` hang-repro must connect promptly (the #1769
      symptom). v4 + v6.
- [ ] `cargo test`, `make test` pass.
- [ ] No regression on `userspace-perf-compare.sh`.
