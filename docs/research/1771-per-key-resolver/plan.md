# #1771 — Per-Key Neighbor Resolver State Machine

Research and implementation plan for the full §10a redesign, building on top of the #1769 threaded resolver already in master.

**Status:** PLAN-READY for adversarial review  
**Branch:** `research/1771-per-key-resolver`  
**Issue:** #1771  
**Follows:** #1769 (merged), #1770 (merged), #1772 (merged), #1773 (merged)

---

## 1. Current State (#1769 as shipped)

The live resolver in `userspace-dp/src/afxdp/neighbor_resolver.rs` (1,194 lines) implements the §9 immediate fix:

**Architecture:**
- One shared resolver thread with persistent netlink socket
- Per-binding `pending_neigh: VecDeque<PendingNeighPacket>` (cap 4096, admits every packet)
- Per-binding `neg_neigh_cache: FastMap<(i32, IpAddr), u64>` (3s TTL)
- Global `neighbor_generation: Arc<AtomicU64>` bumped on every netlink event batch
- Per-key rate limiting in resolver thread (1s window via `last_resolved` map)
- Per-binding enqueue throttle (100ms window to avoid `String` alloc storm)

**Flow:**
1. Worker hits `MissingNeighbor` → checks `neg_neigh_gate()` → fast-fails if negatively cached
2. On fast-fail, enqueues to shared resolver via non-blocking `try_send()`
3. Resolver thread dequeues, rate-limits per key, issues `RTM_GETNEIGH`
4. On `REACHABLE`/`PERMANENT` with unchanged global epoch → cache to `dynamic_neighbors`
5. On `STALE`/`DELAY`/`PROBE` → probe only, don't cache
6. On `FAILED` → revoke + probe
7. On timeout/error → probe only, don't revoke

**Limitations (why #1771 exists):**
- Global epoch causes false rejects under unrelated neighbor churn
- Per-binding 4096 queue admits every packet (no per-key bound)
- Probe dedup only within single sweep, not across sweeps
- No ENOBUFS detection (monitor swallows `recv()<=0`)
- Incomplete Prometheus counters

---

## 2. Target Architecture (§10a)

### 2.1 Per-Key Epoch

**Current:** Single `Arc<AtomicU64>` bumped on every `RTM_NEWNEIGH`/`RTM_DELNEIGH` batch in `neighbor.rs:656`.

**Target:** Per-key epoch map, bumped only for the specific key that changed.

**Implementation:**
```rust
// In neighbor.rs, replace:
// pub(crate) neighbor_generation: Arc<AtomicU64>,
// With:
pub(crate) neighbor_epochs: Arc<ShardedEpochMap>, // new type, similar to ShardedNeighborMap

// ShardedEpochMap provides:
// - get(key) -> u64 (current epoch for key, 0 if absent)
// - bump(key) -> u64 (increment and return new epoch)
// - remove(key) (on DELNEIGH)
```

**Netlink monitor changes (`neighbor.rs:neigh_monitor_thread`):**
- On `RTM_NEWNEIGH` for key K: `neighbor_epochs.bump(K)` then `dynamic_neighbors.insert(K, ...)`
- On `RTM_DELNEIGH` for key K: `neighbor_epochs.bump(K)` then `dynamic_neighbors.remove(K)`
- Order matters: bump FIRST, then mutate map (same as current global epoch ordering)

**Resolver changes (`neighbor_resolver.rs`):**
- `ResolveItem` carries `per_key_epoch: u64` instead of global epoch
- `enqueue()` snapshots `neighbor_epochs.get(key)` at enqueue time
- `decide_action()` compares per-key epoch before/after GET
- False reject rate drops from "any neighbor churn" to "churn on this specific key"

### 2.2 Per-Key Pending Bound

**Current:** Per-binding `VecDeque<PendingNeighPacket>` with cap 4096, admits every packet up to cap.

**Target:** One representative packet per `(egress_ifindex, next_hop)` key under fair global cap.

**Implementation:**
```rust
// In worker/mod.rs, replace:
// pub(crate) pending_neigh: VecDeque<PendingNeighPacket>,
// With:
pub(crate) pending_neigh: FastMap<(i32, IpAddr), PendingNeighPacket>,
// Key is (egress_ifindex, next_hop) — same as neg_neigh_cache key
```

**Admission logic change (`poll_descriptor/mod.rs`):**
- Current: `if binding.pending_neigh.len() < MAX_PENDING_NEIGH { push_back() }`
- Target: `if !pending_neigh.contains_key(&key) && pending_neigh.len() < MAX_PENDING_NEIGH { insert(key, packet) }`
- Duplicate packets for same key are dropped at admission (fast-fail), not buffered

**Retry logic change (`neighbor_dispatch.rs:retry_pending_neigh`):**
- Current: iterates VecDeque, pops front, pushes back if still pending
- Target: iterate map, remove key on resolve/timeout, no rotation needed (no FIFO ordering to preserve — one packet per key)

**Implication:** The 4096 cap now bounds distinct unresolved next-hops globally per worker, not total packets. A SYN flood to one dead host consumes 1 slot, not 4096.

### 2.3 Cross-Sweep Backoff Coalescing

**Current:** Probe dedup via `BTreeSet` within single `retry_pending_neigh` sweep (`neighbor_dispatch.rs:92`). Next sweep can re-probe same key.

**Target:** Backoff state persists across sweeps in the per-key resolver state.

**Implementation:** Already partly implemented in #1769's resolver thread via `last_resolved` map with 1s rate limit. For #1771, extend to full backoff schedule:

```rust
// In neighbor_resolver.rs, extend per-key state:
struct PerKeyState {
    last_probe_ns: u64,
    attempts: u8,  // for exponential backoff
    // ... existing fields
}

// Backoff schedule (already defined in neighbor_dispatch.rs as PROBE_SCHEDULE_NS):
// [10ms, 60ms, 260ms, 1s] then exponential to 5s cap
```

The resolver thread already has per-key rate limiting; #1771 extends it to track attempt count for proper exponential backoff across sweeps, not just a fixed 1s window.

### 2.4 Negative Policy Structural Model

**Current:** `neg_neigh_gate()` fast-fails at packet admission, but resolver is only enqueued on fast-fail. The resolver runs, but the structure doesn't make the "resolver keeps running" property obvious.

**Target:** Make it structural — the per-key state machine explicitly tracks Negative state with ongoing backoff.

**Implementation:** The per-key state in the resolver thread already handles this via the rate-limit map. For #1771, make it explicit in the state model:

```rust
enum ResolverKeyState {
    Idle,
    Resolving { attempts: u8, last_probe_ns: u64 },
    Negative { since_ns: u64, attempts: u8 }, // still probes on backoff
    Resolved { confirmed_ns: u64 },
}
```

The key change is conceptual: Negative is a state in the resolver's state machine, not just a cache entry checked at admission. The resolver continues to schedule probes for Negative keys on backoff.

### 2.5 ENOBUFS Detection + Throttled Re-dump

**Current:** `neigh_monitor_thread` swallows `recv() <= 0` (`neighbor.rs:630-632`). No ENOBUFS detection. Full dump only at startup.

**Target:** Detect ENOBUFS, count it, trigger throttled family re-dump plus targeted single-key GET for hot keys.

**Implementation (`neighbor.rs`):**
```rust
// In neigh_monitor_thread recv loop:
let n = libc::recv(...);
if n < 0 {
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOBUFS) {
        // Increment counter
        // Check throttle (e.g., at most once per 5s)
        // If allowed: trigger re-dump for both families
        // Also signal hot-key targeted GETs (see below)
        continue;
    }
    if matches!(
        err.raw_os_error(),
        Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
    ) {
        // SO_RCVTIMEO steady-state timeout; never fall through to parsing.
        continue;
    }
    // Other recv() errors: log/debug-count as needed, then continue.
    continue;
}
if n == 0 {
    // EOF on netlink shouldn't happen, but treat as error and continue.
    continue;
}
```

**Throttle:** Use `AtomicU64` timestamp for last re-dump, check `now - last > 5_000_000_000` (5s) before dumping. This prevents RTNL contention (AGY F2).

**Hot keys:** `last_resolved` is currently resolver-thread local, so the monitor cannot directly iterate it. #1771 therefore needs an explicit monitor→resolver signal path (for example a small shared hot-key set or dedicated control channel) if ENOBUFS recovery should trigger targeted single-key GETs for recently active keys.

### 2.6 Prometheus Counters

**Current (#1772):** Exports via `NeighborResolverCounters`:
- queue_depth, enqueue_drops, disconnected
- get_attempts, get_resolved, probe_on_stale, get_failures, epoch_rejects

**Target (#1771):** Extend for per-key state machine:
- `resolver_keys_resolving` (gauge)
- `resolver_keys_negative` (gauge)
- `resolver_keys_resolved` (gauge)
- `resolver_pending_packets` (gauge, replaces per-binding pending depth)
- `resolver_fast_fail_drops` (counter, already exists as debug-only)
- `netlink_enobufs_total` (counter)
- `netlink_redumps_total` (counter)

**Implementation path:**
1. Extend `ResolverCounters` struct in `neighbor_resolver.rs`
2. Extend `NeighborResolverCounters` snapshot struct
3. Update `server/helpers.rs` to include new fields in status
4. Update `protocol/control.rs` for JSON serialization
5. Update Go `protocol.go` structs
6. Add descriptors in `metrics_descriptors.go`
7. Add collection in `metrics_userspace.go`
8. Add tests in `metrics_neighbor_latency_test.go`

---

## 3. Implementation Plan

### Phase 1: Per-Key Epoch Infrastructure
- [ ] Create `ShardedEpochMap` type (similar to `ShardedNeighborMap`)
- [ ] Update `neighbor.rs` monitor to bump per-key epochs
- [ ] Update `neighbor_resolver.rs` to use per-key epochs in `ResolveItem` and `decide_action()`
- [ ] Update `coordinator/mod.rs` to create and pass per-key epoch map
- [ ] Tests for per-key epoch behavior

### Phase 2: Per-Key Pending Bound
- [ ] Change `BindingWorker.pending_neigh` from `VecDeque` to `FastMap<(i32, IpAddr), PendingNeighPacket>`
- [ ] Update admission logic in `poll_descriptor/mod.rs` to check `contains_key` before insert
- [ ] Update `retry_pending_neigh` in `neighbor_dispatch.rs` to iterate map instead of rotating VecDeque
- [ ] Update tests that construct `PendingNeighPacket` directly

### Phase 3: Cross-Sweep Backoff
- [ ] Extend resolver's `last_resolved` map to track attempt count
- [ ] Implement exponential backoff schedule in resolver thread
- [ ] Ensure backoff persists across sweeps (already partly done via map retention)

### Phase 4: ENOBUFS Handling
- [ ] Add ENOBUFS detection in `neigh_monitor_thread`
- [ ] Preserve the existing `recv() <= 0 { continue; }` safety on timeout/error paths (`EAGAIN`/`EWOULDBLOCK` must never fall through to parsing)
- [ ] Add throttle mechanism (5s window)
- [ ] Implement throttled family re-dump
- [ ] Add monitor→resolver signaling for hot-key targeted GETs on ENOBUFS (or explicitly defer targeted GETs if re-dump alone is sufficient)

### Phase 5: Prometheus Metrics
- [ ] Extend Rust counters
- [ ] Wire through Go stack
- [ ] Add tests

### Phase 6: Validation
- [ ] `cargo test` (356 tests)
- [ ] `make test` (1020+ Go tests)
- [ ] Deploy to loss cluster
- [ ] Run `userspace-ha-validation.sh`
- [ ] Run `userspace-ha-failover-validation.sh` with failover cycles
- [ ] Verify metrics export

---

## 4. Risks and Mitigations

**Risk: Per-key epoch map contention**
- Mitigation: Use same sharding strategy as `ShardedNeighborMap` (64 shards, cache-line padded)

**Risk: Per-key pending map grows unbounded**
- Mitigation: Same GC as existing `last_resolved` map (60s interval, 5min max age)

**Risk: ENOBUFS re-dump causes RTNL contention**
- Mitigation: 5s throttle, and re-dump is rare (only on actual overflow)

**Risk: Breaking existing behavior**
- Mitigation: Property tests comparing old vs new behavior on key scenarios; differential tests; live validation

---

## 5. Out of Scope

- Changing the single-key GET mechanism itself (already optimal per #1769)
- Changing the netlink monitor's multicast subscription model
- Changing the resolver thread architecture (already shared, already off hot path)
- L7 application identification (separate feature area)

---

## 6. Success Criteria

- [ ] Per-key epochs eliminate false rejects under unrelated neighbor churn (verified via test with concurrent churn on different keys)
- [ ] Per-key pending bound limits SYN flood to 1 slot per dead host (verified via test)
- [ ] Backoff coalesces probes across sweeps (verified via counter assertions)
- [ ] ENOBUFS triggers throttled re-dump (verified via synthetic ENOBUFS injection test)
- [ ] All Prometheus counters export correctly
- [ ] `cargo test` passes
- [ ] `make test` passes
- [ ] Loss cluster validation passes (HA failover with neighbor churn)
- [ ] No performance regression on `userspace-perf-compare.sh`
