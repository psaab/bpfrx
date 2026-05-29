# Plan — #1651 Path B3: dead-host negative cache

- **Status:** DRAFT v1 — pending adversarial plan review (B3 already
  design-blessed in the research plan; this is the IMPLEMENTATION plan).
- **Branch:** `pr/1651-b3-negcache`
- **Base:** origin/master @ `a107e7489`
- **Issue:** #1651 (reopened) — Path B3 ONLY. Path A (active resolution)
  is KILLED. Path C (do-nothing on resolve latency) is the disposition
  for the *latency* question; B3 is the one shippable code change.
- **Research plan (design authority):**
  `docs/research/1651-cold-resolve-latency/plan.md` v4 @ `c148d04ae`
  (Codex r3 + AGY r2 + Claude SMR converged PLAN-READY).

---

## §1. Issue framing

The reopened-#1651 research established (measured on `loss:xpf-userspace-
fw0/fw1`): live-host empty-cache cold connect is already 1–9 ms across all
four cells (on-link v4/v6, routed v4/v6, post-failover). The 800 ms
`PENDING_NEIGH_TIMEOUT_FAST_NS` drop fires ONLY for dead / non-responding
destinations. The genuine hazard AGY-r1 surfaced is an **availability**
one, not a latency one:

> `pending_neigh` is capped at `MAX_PENDING_NEIGH = 4096` and each entry is
> held for 800 ms. A sustained dead-host SYN storm (port scan, a subnet of
> down hosts, a failover storm) keeps that bounded queue saturated. New
> packets hit the full-queue gate at `poll_descriptor/mod.rs:2644` and are
> dropped without buffering — **starving LIVE cold connects** that would
> otherwise resolve in 1–9 ms.

Path B3 adds a short-TTL **negative cache** so repeated cold packets to a
non-responding destination fast-fail immediately (no 800 ms buffer, no
queue slot consumed) instead of each re-occupying a `pending_neigh` slot.
This both (a) frees the queue for live cold connects and (b) removes the
per-attempt 800 ms penalty an operator perceives as "new connections are
slow when caches are empty" when their targets are intermittently
unreachable.

## §2. Honest scope / value framing

- **Win:** under a dead-host SYN storm, live cold connects continue to
  resolve in single-digit ms instead of being dropped at the full-queue
  gate. Steady-state (no dead hosts) behavior is byte-identical — the
  negative cache is empty and adds one O(1) hashmap lookup on the
  MissingNeighbor cold path only (NOT the established-flow hot path).
- **Cost:** one `FastMap<(i32, IpAddr), u64>` per binding (bounded at 256
  entries), one O(1) lookup on the MissingNeighbor slow path, one O(1)
  insert at the drop-at-timeout site. No per-packet (established-flow)
  cost. No allocation on the hot path after first-grow.
- *If reviewers conclude the perf/availability gain is too small to
  justify the churn, PLAN-KILL is an acceptable verdict.* (It is not
  expected here — AGY-r1 rated the starvation hazard HIGH and the research
  triple-review elevated B3 from "optional" to "recommended shippable".)

## §3. What already exists / composes with

- `pending_neigh: VecDeque<PendingNeighPacket>` per binding
  (`worker/mod.rs:126`), cap `MAX_PENDING_NEIGH = 4096` (`mod.rs:342`).
- Buffer/probe-fire site: `poll_descriptor/mod.rs:2379` (MissingNeighbor
  handler) → push into `pending_neigh` at `:2644` gated by the cap.
  Initial `trigger_kernel_arp_probe` at `:2413-2432`.
- Re-probe schedule + drop-at-timeout: `neighbor_dispatch.rs`
  `retry_pending_neigh` (`:47`), `PROBE_SCHEDULE_NS` (`:33`, 10/60/260 ms),
  drop site at `:110` (`now - queued > pending_neigh_timeout_ns`).
- `pending_neigh_timeout_ns`: 800 ms fast (`PENDING_NEIGH_TIMEOUT_FAST_NS`,
  `forwarding_build/mod.rs`) when kernel retrans confirmed, else 2 s
  (`PENDING_NEIGH_TIMEOUT_NS`, `mod.rs:329`).
- Resolution learn path: shared `neigh_monitor_thread` →
  `parse_neighbor_msg` (`neighbor.rs:297`) → `update_dynamic_neighbor`
  (`:280`) → `ShardedNeighborMap::insert_if_changed` populates the shared
  `Arc<ShardedNeighborMap> dynamic_neighbors`. RTM_DELNEIGH / NUD_FAILED →
  `remove_dynamic_neighbor`.
- Neighbor lookup order (must mirror): static/Go-push `forwarding.neighbors`
  FIRST, then `dynamic_neighbors` (`neighbor_dispatch.rs:117-126`,
  `forwarding/mod.rs:1529`).

## §4. Concrete design

### 4.1 Constants (`afxdp/mod.rs`, next to `MAX_PENDING_NEIGH`)

```rust
/// #1651 B3: short TTL for the dead-host negative neighbor cache. A dst
/// that exhausted all PROBE_SCHEDULE_NS re-probes and hit the
/// pending_neigh drop is suppressed for this long so a dead-host SYN
/// storm cannot re-occupy pending_neigh slots and starve live cold
/// connects. 3 s is: (a) > the 800 ms fast drop, so each storm packet is
/// suppressed across many connection attempts; (b) short enough that a
/// recovered host is penalized at most one TTL window — and recovery is
/// usually faster because RTM_NEWNEIGH eviction (below) is immediate.
const NEG_NEIGH_TTL_NS: u64 = 3_000_000_000;

/// #1651 B3: bound on the per-binding negative cache. A /24 scan touches
/// 254 dsts; 256 covers a full subnet sweep without unbounded growth.
/// On overflow the map is cleared wholesale (best-effort optimization —
/// losing suppression for a few dsts only costs one more 800 ms drop,
/// never correctness). clear() retains capacity → no realloc churn.
const MAX_NEG_NEIGH_CACHE: usize = 256;
```

### 4.2 Per-binding field (`worker/mod.rs` BindingWorker, all 3 ctors)

```rust
/// #1651 B3: dead-host negative neighbor cache. Key
/// (egress_ifindex, next_hop); value = insertion now_ns. A dst is
/// inserted when it exhausts all re-probes and hits the pending_neigh
/// drop; while present + un-expired + still-unresolved, new
/// MissingNeighbor packets to it fast-fail (recycle) instead of buffering
/// for another 800 ms. Per-binding (mirrors pending_neigh) — the
/// per-queue AF_XDP model keeps this thread-local, no cross-core sync.
pub(crate) neg_neigh_cache: FastMap<(i32, IpAddr), u64>,
```

Constructed `FastMap::default()` in all three ctors (lazy-grow, like
`pending_neigh`).

### 4.3 Helper module (`afxdp/neg_neigh.rs`, new file, per modularity rules)

Small, pure-as-possible, fully unit-tested. Two functions plus the lookup
that the hot site calls:

```rust
use super::*;

/// Returns true if `key` is currently negatively cached (present AND
/// un-expired). Expired entries are evicted on access (lazy TTL). Does
/// NOT consult the neighbor maps — the caller does that first so a
/// resolved dst wins (RTM_NEWNEIGH eviction, §4.5).
pub(super) fn neg_neigh_active(
    cache: &mut FastMap<(i32, IpAddr), u64>,
    key: &(i32, IpAddr),
    now_ns: u64,
) -> bool {
    match cache.get(key) {
        Some(&inserted) if now_ns.saturating_sub(inserted) < NEG_NEIGH_TTL_NS => true,
        Some(_) => { cache.remove(key); false }   // expired — evict
        None => false,
    }
}

/// Record a dead-host drop. Bounded: on overflow, clear (retains cap).
pub(super) fn neg_neigh_record(
    cache: &mut FastMap<(i32, IpAddr), u64>,
    key: (i32, IpAddr),
    now_ns: u64,
) {
    if cache.len() >= MAX_NEG_NEIGH_CACHE && !cache.contains_key(&key) {
        cache.clear();
    }
    cache.insert(key, now_ns);
}

/// Explicit eviction (resolved-neighbor-wins, §4.5). Idempotent.
pub(super) fn neg_neigh_evict(
    cache: &mut FastMap<(i32, IpAddr), u64>,
    key: &(i32, IpAddr),
) { cache.remove(key); }
```

### 4.4 Fast-fail at the MissingNeighbor site (`poll_descriptor/mod.rs`)

Inside `ForwardingDisposition::MissingNeighbor`, immediately after
`if let Some(next_hop) = decision.resolution.next_hop` is known and BEFORE
the `trigger_kernel_arp_probe` / session-seed / buffer work, insert the
fast-fail gate. It only fires when there IS a next_hop (no next_hop already
cannot probe):

```rust
if let Some(next_hop) = decision.resolution.next_hop {
    let neg_key = (decision.resolution.egress_ifindex, next_hop);
    // Resolved-neighbor-wins (RTM_NEWNEIGH eviction): if the dst is now
    // resolved (static or dynamic), drop any stale negative entry and
    // fall through to normal forwarding. Mirrors the lookup order in
    // retry_pending_neigh / lookup_neighbor_entry.
    let resolved = worker_ctx.forwarding.neighbors.contains_key(&neg_key)
        || worker_ctx.dynamic_neighbors.get(&neg_key).is_some();
    if resolved {
        neg_neigh_evict(&mut binding.neg_neigh_cache, &neg_key);
    } else if neg_neigh_active(&mut binding.neg_neigh_cache, &neg_key, now_ns) {
        // Dead-host fast-fail: recycle the frame, do NOT buffer, do NOT
        // probe, do NOT consume a pending_neigh slot. This is what frees
        // the queue for live cold connects under a dead-host storm.
        telemetry.dbg.<new_counter> += 1;   // see §4.6
        binding.scratch.scratch_recycle.push(desc.addr);
        recycle_now = false;                 // we recycled explicitly
        continue;                            // skip buffer + session-seed
    }
}
```

NOTE: the gate must run BEFORE the session-seed block (which installs the
MissingNeighborSeed session + publishes shared/BPF entries). Fast-failing
a dead host must NOT create a session. Placement: the very top of the
`MissingNeighbor` arm.

Concern to verify in review: the existing `MissingNeighbor` arm computes
`from_zone`/`to_zone` then conditionally seeds a session and buffers. The
`continue` must land us at the descriptor-loop boundary cleanly (same as
the existing `continue`s at `:2533`/`:2563`). Confirm `scratch_recycle` is
the correct recycle channel here (the source-NAT-failure path uses exactly
`binding.scratch.scratch_recycle.push(desc.addr); continue;`).

### 4.5 Record at the drop-at-timeout site (`neighbor_dispatch.rs:110`)

```rust
if now_ns.saturating_sub(pkt.queued_ns) > pending_neigh_timeout_ns {
    // #1651 B3: this dst exhausted all re-probes and never resolved —
    // negatively cache it so subsequent cold packets fast-fail instead
    // of re-buffering for another 800 ms.
    if let Some(hop) = pkt.decision.resolution.next_hop {
        neg_neigh_record(
            &mut binding.neg_neigh_cache,
            (pkt.decision.resolution.egress_ifindex, hop),
            now_ns,
        );
    }
    binding.tx_pipeline.pending_fill_frames.push_back(pkt.addr);
    continue;
}
```

### 4.6 Invalidation summary (mandatory RTM_NEWNEIGH + TTL)

- **RTM_NEWNEIGH (host came back):** the shared monitor thread populates
  `dynamic_neighbors` (existing, unchanged). The per-binding fast-fail
  gate (§4.4) checks `forwarding.neighbors` + `dynamic_neighbors` BEFORE
  honoring a negative entry; on a resolved hit it calls `neg_neigh_evict`
  and falls through to normal forwarding. So a recovered host connects on
  the very next packet — invalidation is immediate, not TTL-bounded.
  Rationale for lazy (not monitor-thread-driven) eviction: the negative
  cache is per-binding (per-queue AF_XDP model) and the monitor thread has
  no per-binding handle; coupling them would need a shared structure +
  cross-core sync on the resolve path. Lazy resolved-wins is allocation-
  free, O(1), and strictly correct (a resolved dst can never be wrongly
  fast-failed).
- **TTL:** `neg_neigh_active` evicts on access once
  `now - inserted >= NEG_NEIGH_TTL_NS` (3 s). Covers the case where a dst
  recovers but no traffic flowed for it (entry just ages out) and bounds
  worst-case suppression of a recovered-but-silent host.

### 4.7 Telemetry

Add `neg_neigh_fast_fail: u64` to `WorkerTelemetry.dbg` (debug counter
cluster) bumped at the fast-fail site. Cheap, matches the existing
`missing_neigh` / `no_route` debug counters. (No new Prometheus surface in
this PR — keep scope narrow; a follow-up can export it if ops wants it.)

## §5. Public API preservation

No public API change. New items are `pub(super)` / `pub(crate)` field on
an internal struct. `retry_pending_neigh` and the MissingNeighbor handler
keep their signatures (both already take `&mut BindingWorker`). No protocol
/ wire / config / CLI surface touched.

## §6. Hidden invariants to preserve

- **Lookup order:** negative-cache resolved-wins check uses
  `forwarding.neighbors` THEN `dynamic_neighbors` — identical to
  `retry_pending_neigh:117-126` and `lookup_neighbor_entry`. A negative
  entry must never shadow a resolved neighbor.
- **No session for a dead host:** the fast-fail `continue` runs before the
  session-seed block. A fast-failed packet creates no session, publishes
  no shared/BPF entry, allocates no NAT binding.
- **Recycle correctness:** fast-fail uses `scratch.scratch_recycle` +
  `recycle_now = false` (the established pattern at the source-NAT-failure
  paths). The frame is returned exactly once.
- **Per-queue thread-locality:** `neg_neigh_cache` is touched ONLY by the
  owning worker thread (poll_descriptor + retry both run on it). No Arc,
  no Mutex, no cross-core sharing — consistent with `pending_neigh`.
- **Allocation:** `FastMap` grows lazily; `clear()` on overflow retains
  capacity. No per-packet allocation. Established-flow hot path untouched.
- **Drop-newest policy:** unchanged for `pending_neigh`. The negative
  cache itself uses clear-on-overflow (documented best-effort).
- **HA portability:** negative cache is pure local optimization, NOT
  synced. A failover peer rebuilds it naturally (first dead-host drop
  re-populates). No HA-sync change.

## §7. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Empty cache ⇒ byte-identical to today. Only new behavior: dead-host repeat packets recycle instead of buffer. Resolved-wins guard prevents shadowing a live host. |
| Lifetime / borrow-checker | LOW | `&mut binding.neg_neigh_cache` borrows disjoint from `worker_ctx.forwarding`/`dynamic_neighbors` (different objects). Helper takes `&mut FastMap` + plain key. |
| Performance regression | LOW | One O(1) lookup on the MissingNeighbor *cold* path only. Zero cost on established-flow hot path and on the empty-cache common case (a `contains_key` miss). |
| Architectural mismatch | LOW | Mirrors `pending_neigh` placement exactly; no new shared map, no monitor-thread coupling. Design blessed by the research triple-review. |

## §8. Test plan

- `cargo build --release` clean after each change.
- New `mod tests` in `neg_neigh.rs`: TTL active/expire edges; record +
  bounded-clear-on-overflow; evict idempotence; resolved-wins (a key in
  `dynamic_neighbors` is never fast-failed); a dead key is fast-failed,
  then after `insert_if_changed` into `dynamic_neighbors` the same key is
  NOT fast-failed (RTM_NEWNEIGH-evict simulation).
- A `retry_pending_neigh` test: a never-resolving pkt that crosses the
  timeout records its key in `neg_neigh_cache`.
- Full `cargo test --release`.
- 5/5 flake on the most-affected named test (`retry_pending_*` /
  `neg_neigh_*`).
- Go suite (`go test ./...`).
- DEPLOY + FULL SMOKE MATRIX on `loss:xpf-userspace-fw0/fw1`
  (v4+v6 × push+`-R` × CoS-off+CoS-on, per-class 5201-5211).
- **Dead-host-starvation proof (added):** hammer cold SYNs at a batch of
  unused on-link IPs (172.16.80.120-139) WHILE running a live cold connect
  to a real host; prove the live connect still completes in single-digit
  ms and the dead-host attempts fast-fail after the first 800 ms drop.
  fail-before/pass-after: run the same storm against the origin/master
  binary (live connect starves) vs this branch (live connect survives).
- `make test-failover` (touches the worker/binding path).

## §9. Out of scope (explicitly)

- Path A (active dataplane ARP/NDP resolution) — KILLED.
- Path B1 (netlink fd in worker poll set) — optional ≤1 ms polish,
  separate change.
- Prometheus export of the fast-fail counter — follow-up.
- The two spin-off cache-correctness bugs (dynamic-neighbor leak on
  `update_neighbors` replace; monitor socket `SO_RCVBUF`) — separate
  issues per research §7.
- Lowering `PENDING_NEIGH_TIMEOUT_FAST_NS` — bounded by the <1 s TCP-RTO
  design constraint; not touched.

## §10. Open questions for adversarial review

1. **Placement of the gate (§4.4):** is the very top of the
   `MissingNeighbor` arm correct, and is `scratch.scratch_recycle` +
   `recycle_now = false` + `continue` the right recycle channel there
   (vs `pending_fill_frames`)? The frame here is a fresh RX descriptor,
   not a previously-buffered pending frame — so `scratch_recycle` (the
   RX-recycle channel) is what the source-NAT-failure path uses. Confirm.
2. **Resolved-wins races:** can a key be in `dynamic_neighbors` AND
   negatively cached simultaneously in a way that wrongly fast-fails a
   live host? (Claim: no — the resolved check runs first and evicts.)
   Conversely, can a dst resolve *between* the resolved-check and the
   buffer, causing a needless 800 ms wait? (Claim: same as today — the
   retry loop re-drives within ≤1 ms once `dynamic_neighbors` updates.)
3. **TTL value (3 s):** too long (penalizes a recovered-but-silent host)
   or too short (storm leaks through more often)? Given RTM_NEWNEIGH
   eviction is immediate for any host that *receives traffic*, the TTL
   only governs recovered-but-silent hosts. Is 3 s defensible?
4. **Overflow policy (clear-on-full):** is wholesale `clear()` acceptable
   vs LRU/random eviction? (Claim: yes — losing suppression for a few
   dsts costs at most one extra 800 ms drop, never correctness; clear is
   O(1)-amortized and allocation-free. A /24 scan = 254 dsts < 256 cap so
   clear is rare even under a full-subnet sweep.)
5. **Key correctness:** `(egress_ifindex, next_hop)` — is `egress_ifindex`
   the logical (VLAN) ifindex consistently between the record site
   (`pkt.decision.resolution.egress_ifindex`) and the fast-fail site
   (`decision.resolution.egress_ifindex`)? Gate-M' showed `egress_if=14` =
   logical VLAN ifindex at both. Confirm no physical/logical mismatch.
6. **Does the gate starve a live-but-SLOW host** that legitimately takes
   >800 ms to ARP-reply once, then is negatively cached for 3 s? (Claim:
   such a host, once it replies, lands in `dynamic_neighbors` and is
   evicted by resolved-wins on its next packet. The only loss is the
   in-flight 3 s window for a host whose reply was dropped AND who sends
   no further packets — degenerate.)
