# #965: bucketed timer-wheel session GC (replace O(N) scan)

Plan v2 — 2026-04-29. Addresses Codex round-1 (task-mojzeozp-8bzfr7):
8 blocking findings — cursor init, per-tick cap drainage,
deferred-tail semantics, exact-256s correctness trap, alias
lookup, hot-path allocation claim, duplicate-wheel-entry bound,
expiry boundary off-by-1ns.

## Investigation findings (Claude, on commit 08ff1838)

`SessionTable.expire_stale_entries` at `userspace-dp/src/session.rs:279-340`
runs once per `SESSION_GC_INTERVAL_NS = 1s`. Inside that gate it does:

```rust
let stale = self.sessions.iter()
    .filter_map(|(key, entry)| {
        if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
            Some(key.clone())
        } else { None }
    })
    .collect::<Vec<_>>();
// then iterate stale and remove each
```

This is O(N) over the entire `FxHashMap<SessionKey, SessionEntry>`
every tick. At 1M concurrent sessions (a realistic 100G workload):

- Hash-map iter + entry-tuple copy ≈ 100 ns/entry → ~100 ms per tick.
- Two `Vec` allocations per tick (`stale`, `expired_entries`).
- The hot worker thread BLOCKS for those 100 ms — every queue
  starves, mouse-latency p99 jumps to >100 ms, and the XSK RX rings
  back-pressure into the kernel.

This is the "stop the world" GC pause #965 calls out.

### Where last_seen / expires_after are written

- `install_with_protocol` (L484) — initial insert.
- `upsert_synced` (L554) — HA peer sync insert.
- `update_session` (L612) — protocol-specific update.
- `lookup_with_origin` (L390) — every read also touches last_seen
  (this is the most frequent path; ~per session-miss-cached-hit).
- `touch` (L274) — flow-cache amortized keepalive.
- `refresh_local` / `refresh_for_ha_activation` /
  `refresh_for_ha_transition` — HA state-machine paths.

Any change to expiration management has to thread these write sites.

## Approach

Add a **bucketed timer wheel** that mirrors the `sessions` HashMap.
On insert / touch / refresh, push the key into the bucket whose
index = `(last_seen_ns + expires_after_ns) / TICK_NS` modulo the
wheel size. On GC tick, pop one bucket and walk only those keys.

The wheel is purely an *index*; the authoritative state still lives
in `sessions: FxHashMap<SessionKey, SessionEntry>`. We do NOT
require #964's slab + integer handle refactor for #965 to land.

### Wheel shape

```rust
const WHEEL_TICK_NS: u64 = 1_000_000_000;        // 1 s
const WHEEL_BUCKETS: usize = 256;                // 256 s window
const WHEEL_MASK: u64 = (WHEEL_BUCKETS as u64) - 1; // 0xFF

pub(crate) struct SessionWheel {
    /// 256 buckets indexed by `expiration_tick & WHEEL_MASK`.
    /// Each bucket holds keys whose computed `expiration_tick`
    /// (= `(last_seen_ns + expires_after_ns) / WHEEL_TICK_NS`)
    /// modulo 256 equals the bucket index.
    buckets: Box<[VecDeque<SessionKey>; WHEEL_BUCKETS]>,
    /// Tick that bucket index 0 represents on the *current*
    /// wheel revolution. Advanced lazily as `cursor_tick`
    /// crosses bucket boundaries.
    base_tick: u64,
    /// Most-recent processed tick. Strictly < the live `now_tick`
    /// once initialized. Initialized lazily on the first
    /// insert/touch/expire that observes a `now_ns`.
    cursor_tick: u64,
    /// `false` until the first observation of `now_ns`. Until then
    /// every wheel mutation resets cursor/base from `now_ns`. This
    /// avoids the catastrophe of `cursor_tick = 0` being many
    /// years behind `now_tick = uptime_secs` on the first GC call.
    initialized: bool,
}
```

### Cursor / base initialization (Codex finding #1)

`SessionTable::new()` does not have a `now_ns`. The wheel must be
created in an "uninitialized" state and lazily initialize on the
first observation of `now_ns` from any of the touch/insert/expire
paths:

```rust
fn wheel_observe(&mut self, now_ns: u64) {
    if !self.wheel.initialized {
        let now_tick = now_ns / WHEEL_TICK_NS;
        self.wheel.base_tick = now_tick;
        self.wheel.cursor_tick = now_tick;
        self.wheel.initialized = true;
    }
}
```

Every public method that takes `now_ns` calls `wheel_observe(now_ns)`
before any wheel push or pop. Test:
`first_gc_with_large_monotonic_now_doesnt_walk_billions_of_buckets`.

### Bucket-index calculation (Codex finding #4 — exact-256s trap)

```rust
const FAR_FUTURE_OFFSET: u64 = WHEEL_BUCKETS as u64 - 1;

fn bucket_for_expiration(&self, expiration_ns: u64, now_ns: u64) -> usize {
    let now_tick = now_ns / WHEEL_TICK_NS;
    let expiration_tick = expiration_ns / WHEEL_TICK_NS;
    let delta = expiration_tick.saturating_sub(now_tick);
    // Cap at WHEEL_BUCKETS - 1 to make the "far future" bucket
    // unambiguously distinct from the current bucket. An entry
    // with delta >= WHEEL_BUCKETS lands in the far-future bucket
    // and gets re-bucketed on pop. An entry with delta < WHEEL_BUCKETS
    // lands at its precise position.
    let offset = delta.min(FAR_FUTURE_OFFSET);
    ((self.wheel.cursor_tick + offset) & WHEEL_MASK) as usize
}
```

Use `>= WHEEL_BUCKETS` (i.e., `delta` clamped to FAR_FUTURE_OFFSET)
not `> WHEEL_TIMEOUT_CAP_NS`. The clamping makes "exactly 256s"
land at FAR_FUTURE_OFFSET ahead — distinct from the current bucket
and correctly delayed. Test: `wheel_handles_exact_256s_timeout`.

### Coverage of long-lived TCP

`TCP_ESTABLISHED_TIMEOUT_NS` ≈ 7200 s exceeds the 256-s window.
Such an entry lands in the far-future bucket. When that bucket is
popped (256 s after insertion), `wheel_pop_one_bucket` re-checks
the entry's actual `last_seen + expires_after` against `now_ns`,
finds it still in the future, and re-buckets via the same logic.
Cost: one HashMap lookup + one push per long session per 256 s.

### Lazy delete on touch (Codex finding #7 — duplicate bound)

When `touch` / `lookup_with_origin` / `update_session` updates
`last_seen_ns`, the old bucket entry becomes stale. We use **lazy
delete**: leave the stale entry, push a new one, re-check on pop.

The bound on duplicates per session matters because
`lookup_with_origin` is called per session-cache-touch on the hot
path. Without throttling, a session that's touched 1000 times
during its lifetime would have 1000 stale wheel entries — that's
240 KB of `SessionKey` (240 B each) per long session. At 1M
sessions × 1000 touches that's 240 GB of stale wheel garbage.

**Per-tick throttle**: only re-push to the wheel if the new
expiration tick differs from the previously-recorded one. Embed a
`wheel_tick: u64` field on SessionEntry (16 B added). On
touch/lookup_with_origin/update_session/refresh_*:

```rust
let new_expiration_tick = (entry.last_seen_ns + entry.expires_after_ns)
    / WHEEL_TICK_NS;
if new_expiration_tick != entry.wheel_tick {
    entry.wheel_tick = new_expiration_tick;
    self.wheel.push(key.clone(), new_expiration_tick);
}
// Same-tick touches: no wheel push.
```

This bounds duplicates per session to:
`(session_lifetime_secs / WHEEL_TICK_NS_secs) ≈ session_lifetime_secs`.

For a 30-second session: max 30 wheel duplicates. For a 7200-s TCP
session: max 7200 entries (one per second the session is touched).
At 1M long sessions × 7200 entries = 7.2B entries × 240 B/entry =
1.7 TB worst case. That's still bad.

**Tighter bound**: bucket the wheel at *touch granularity*, not
expiration granularity. The wheel only cares about
"approximately when this key SHOULD be checked again". Push at
`expiration_tick` only when the key's next expiration is more
than 1 tick away from its previously-recorded one. The 1-tick
granularity is fine because GC pops one bucket = 1 tick of wall
time anyway.

This is the same algorithm as above, but the bound is now:
`(session_lifetime_secs / 1 sec) = session_lifetime_secs`.

For typical session lifetimes (≤300 s) and ≤1M sessions, that's
1M × 300 = 300M entries × 240 B = 72 GB. Still bad for pathological
workloads but realistic deployments stay well under.

**Decision**: ship with the per-tick throttle. Document the
"pathological worst case" honestly. The ultimate fix is the #964
slab: SlotHandle is 8 B not 240 B (30× smaller), so 300M handles
= 2.4 GB — same workload, manageable. #964 is the right place to
solve the duplicate-storage problem; #965 ships with a usable
bound and an explicit "pathological-only" caveat.

### Per-tick GC work — the algorithm in full

Per Codex findings #2/#3/#5/#8: cap-vs-uncapped, deferred-tail
semantics, alias-key correctness, and the off-by-1-ns expiry
boundary all need explicit pseudocode.

Decision per Codex finding #2: **no per-tick cap**. The cap was a
flawed knob — at 5K/tick when due-rate is ≥5K/s the backlog grows
unbounded. Two options remained:

(a) Multi-level wheel — extra complexity and a follow-up.
(b) Just pay the bucket cost — ≤7 ms per tick at 1M sessions / 30s
    timeouts in the worst case, but small (sub-ms) for realistic
    loads. This still beats today's O(N) which is 100+ ms at the
    same scale.

We choose (b). The plan is honest: this is *bounded per-bucket*
work, not *fixed per-tick* work. The "Stop the World" #965 issue
goes away because per-tick work is now O(N/T) instead of O(N) —
~30× lower at typical timeout/session-count ratios.

```rust
pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
    if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
        return Vec::new();
    }
    self.last_gc_ns = now_ns;
    self.wheel_observe(now_ns);  // lazy init if first call

    let now_tick = now_ns / WHEEL_TICK_NS;
    let mut expired = Vec::new();
    // Process every bucket from cursor_tick up to (but not including)
    // now_tick. cursor_tick starts at the lazy-init now_tick, so the
    // first call after init is a no-op (loop body runs zero times).
    while self.wheel.cursor_tick < now_tick {
        let bucket_idx = (self.wheel.cursor_tick & WHEEL_MASK) as usize;
        // Take ownership of the bucket for the duration of this drain.
        // Reusing `due` after the loop returns the buffer to the wheel,
        // amortizing allocation.
        let mut due = std::mem::take(&mut self.wheel.buckets[bucket_idx]);
        for key in due.drain(..) {
            // Lookup + boundary check matches today's exact semantics
            // (Codex finding #8): `now - last_seen > expires_after`
            // (strict `>`), not `>=`.
            let Some(entry) = self.sessions.get(&key) else { continue };
            if now_ns.saturating_sub(entry.last_seen_ns) <= entry.expires_after_ns {
                // Touched after bucketing — already re-bucketed in the
                // new tick. Stale hint; drop.
                continue;
            }
            if let Some(removed) = self.remove_entry(&key) {
                // ... existing remove_entry path produces SessionDelta
                // and ExpiredSession; same logic as today's GC ...
                expired.push(...);
            }
        }
        // Return the (now-empty) VecDeque buffer back to the wheel for reuse.
        self.wheel.buckets[bucket_idx] = due;
        self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
    }
    self.wheel.base_tick = now_tick;  // for far-future bucket arithmetic
    expired
}
```

### Alias correctness in lookup_with_origin (Codex finding #5)

`lookup_with_origin` resolves NAT aliases via
`reverse_translated_index`. The wheel push must use `actual_key`
(the canonical key the entry is stored under), NOT the caller's
alias key. Otherwise the wheel push goes to the wrong shard and
the canonical entry never gets its expiration refreshed.

```rust
let actual_key = if self.sessions.contains_key(key) {
    key.clone()
} else if let Some(alias) = self.reverse_translated_index.get(key) {
    alias.clone()
} else {
    return None;
};
self.sessions.get_mut(&actual_key).map(|entry| {
    // ... last_seen_ns / expires_after_ns updates ...
    let new_expiration_tick = (entry.last_seen_ns + entry.expires_after_ns)
        / WHEEL_TICK_NS;
    if new_expiration_tick != entry.wheel_tick {
        entry.wheel_tick = new_expiration_tick;
        // PUSH actual_key, not the alias `key`.
        let bucket = self.wheel.bucket_for_tick(new_expiration_tick);
        self.wheel.buckets[bucket].push_back(actual_key.clone());
    }
    // ... return SessionLookup ...
})
```

Test: `wheel_alias_lookup_refreshes_canonical_key`.

### Hot-path allocation honesty (Codex finding #6)

`Box<[VecDeque<SessionKey>; 256]>` preallocates the 256 VecDeque
*headers* (24 B each = 6 KB total). Each VecDeque allocates its
backing buffer on first `push_back`. To avoid per-tick allocation
on the hot path, we pre-reserve `max_sessions / WHEEL_BUCKETS`
slots per bucket at construction:

```rust
fn new_wheel(max_sessions: usize) -> SessionWheel {
    let initial_cap = (max_sessions / WHEEL_BUCKETS).max(64);
    let mut buckets: Vec<VecDeque<SessionKey>> = Vec::with_capacity(WHEEL_BUCKETS);
    for _ in 0..WHEEL_BUCKETS {
        buckets.push(VecDeque::with_capacity(initial_cap));
    }
    let buckets: Box<[VecDeque<SessionKey>; WHEEL_BUCKETS]> =
        buckets.into_boxed_slice().try_into().expect("right size");
    SessionWheel { buckets, base_tick: 0, cursor_tick: 0, initialized: false }
}
```

For default `max_sessions = 1M`, that's 256 × 4096 SessionKeys =
~250 MB of preallocated buffers. Drop to `max_sessions = 256K` for
typical deployments and it's 64 MB. The `initial_cap` calc errs on
the side of "no growth needed at steady state" — explicit
`with_capacity` calls so the claim "no allocations on the hot path"
is true at steady state, with a documented warm-up cost.

Fallback: when bucket spikes past initial_cap (rare but possible
if a config change creates many sessions with the same expiration
bucket), `push_back` reallocates. This is rare enough that the
"no allocations on hot path" claim is honest for the common case.

### Files touched

- `userspace-dp/src/session.rs`: add `SessionWheel` (~150 LOC),
  add wheel push at insert/touch/refresh sites, replace
  `expire_stale_entries` body with wheel pop. ~250 LOC change.
  Public API unchanged.

### Tests

- `wheel_pops_expired_entry_from_bucket`: insert one session, advance
  time past its timeout, verify expire_stale_entries returns it.
- `wheel_skips_touched_entry`: insert, touch (advances last_seen),
  advance time past original bucket but before new bucket; verify
  expire_stale_entries does NOT return it.
- `wheel_handles_long_timeout_via_far_future_bucket`: insert with
  timeout > 256s; verify entry doesn't expire prematurely; advance
  past 256s; verify entry re-buckets and expires correctly later.
- `wheel_handles_exact_256s_timeout` (Codex finding #4): insert
  with `expires_after_ns == WHEEL_BUCKETS * WHEEL_TICK_NS`. Verify
  the entry lands in the FAR_FUTURE bucket (not the current one)
  and gets re-checked after the wheel rotation.
- `wheel_alias_lookup_refreshes_canonical_key` (Codex finding #5):
  install entry under canonical key K; lookup via NAT alias key A
  (where reverse_translated_index[A] = K); verify the wheel push
  goes to K's bucket, not A's.
- `first_gc_with_large_monotonic_now_doesnt_walk_billions_of_buckets`
  (Codex finding #1): construct fresh SessionTable; call
  expire_stale_entries with `now_ns = 10^18` (wall-time-ish big);
  verify it returns immediately (no infinite loop, no panic).
- `expiry_boundary_strict_greater_than` (Codex finding #8): insert
  entry with `expires_after_ns = 1_000_000_000`; advance to
  exactly `last_seen + 1_000_000_000` (boundary); verify entry is
  NOT expired (matches today's `>` semantics, not `>=`).
- `wheel_duplicate_count_per_session_bounded` (Codex finding #7):
  insert one session; touch it 100 times within the same tick;
  count wheel entries for that key; assert ≤ 2 (the initial push
  + at most one re-push if expiration tick changed).
- `wheel_sustained_overload_drains_all_buckets`: insert 50K
  sessions all with same expiration; advance time past expiration;
  verify expire_stale_entries returns all 50K in a single call
  (no per-tick cap; one tick = one bucket = O(B) work, not capped).
- `wheel_handles_concurrent_insert_and_pop`: not relevant
  (SessionTable is not Send + Sync — owned by a single worker;
  Codex confirmed worker.rs:490 has `let mut sessions = ...`).

Plus 4 existing GC tests (lines 2138, 2142, 2162, +1 more) must
continue to pass.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ baseline (851 post-#921) + 8 new = 859.
3. Cluster smoke (HARD): no regression on the unloaded-session path.
   - iperf-c P=12 ≥ 22 Gb/s
   - iperf-c P=1 ≥ 6 Gb/s
4. **Mouse-latency gate** (the actual #965 win): when the daemon
   is loaded with ≥10K sessions and GC ticks fire under load, p99
   mouse latency stays within ±5% of the unloaded baseline. Today
   without this PR, p99 spikes correlate with GC ticks. Hard to
   reproduce in a 30s smoke run; we'll instrument the GC-tick
   wall time and assert ≤1 ms p99 under synthetic 50K-session load.
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Risk

**Medium-low.**

- Wheel is purely an index; sessions HashMap is authoritative.
- Lazy-delete is correct: we re-check actual expiration on pop.
- Long-timeout fallback (re-bucket past the wheel cap) tested.
- Per-tick cap bounds the spike.

Risk areas:
- `touch` / `lookup_with_origin` are hot — they currently just
  update `last_seen_ns` in-place. After this PR they ALSO push to
  a wheel bucket. The push is `VecDeque::push_back` on a
  preallocated Box<[VecDeque; 256]>. No allocations on the hot
  path (the VecDeques start empty and grow as needed; capacity
  hints can avoid allocations under steady-state).

## Out of scope

- #964 (slab + integer handles): keep `sessions: FxHashMap<SessionKey, SessionEntry>`.
  The wheel uses `SessionKey` as the bucket payload. After #964,
  the wheel can switch to `SlotHandle` payload (smaller, faster).
- Multi-level wheels (hashed timing wheels): single wheel + per-tick
  cap is enough for the bounds we need. Multi-level is a follow-up
  if profiling shows the cap deferral causes work pile-up.
- Per-protocol expire policy refactor: timeouts are still computed
  from `key.protocol` and `tcp_flags` at insert time.
