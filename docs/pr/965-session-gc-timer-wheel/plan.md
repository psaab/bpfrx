# #965: bucketed timer-wheel session GC (replace O(N) scan)

Plan v1 — 2026-04-29.

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
const WHEEL_BUCKETS: usize = 256;                // covers 256 s window
const WHEEL_TIMEOUT_CAP_NS: u64 =
    WHEEL_TICK_NS * (WHEEL_BUCKETS as u64);      // 256 s

pub(crate) struct SessionWheel {
    /// 256 buckets indexed by `(expiration_ns / TICK_NS) & 0xFF`.
    /// Each bucket holds the SessionKeys whose computed expiration
    /// rounded down lands in that bucket.
    buckets: Box<[VecDeque<SessionKey>; WHEEL_BUCKETS]>,
    /// Anchor: the `expiration_tick` value of bucket index 0 in the
    /// most recently rolled-over wheel cycle. Used to translate
    /// absolute time → bucket index.
    base_tick: u64,
    /// Last tick processed by `pop_due()`. Bounded by current tick.
    cursor_tick: u64,
}
```

Coverage: with `WHEEL_TICK_NS = 1s` and 256 buckets, the wheel
covers a 256-second timeout window. The longest session timeout
today is `TCP_ESTABLISHED_TIMEOUT_NS` ≈ 7200 s — that exceeds the
wheel. We handle long-timeout entries via a fallback:

- If `expires_after_ns > WHEEL_TIMEOUT_CAP_NS`, push the key into
  the bucket at `(base_tick + WHEEL_BUCKETS - 1) & WHEEL_MASK`
  (the "far future" bucket). When that bucket is popped, re-check
  the entry's actual `last_seen_ns + expires_after_ns`; if it's
  still in the future, re-bucket it.

This gives correctness for long sessions at the cost of one extra
re-bucket every 256 s for each long-lived TCP session (a few
microseconds per session — negligible at any realistic count).

### Lazy delete on touch

When `touch` / `lookup_with_origin` / `update_session` updates
`last_seen_ns`, the old bucket entry becomes stale. Two options:

A. **Eager remove + re-insert**: O(N_bucket) scan to find the old
   key in its bucket, remove it, then push to the new bucket.
   Per-touch cost: O(N_bucket) which can be thousands.

B. **Lazy delete**: leave the stale entry in the old bucket. On
   pop, re-check the entry's current `last_seen_ns + expires_after_ns`
   against `now_ns`. If still in the future, the entry was touched
   after we bucketed it; skip (don't remove from sessions, don't
   emit expired). If `Some(entry)` not found in `sessions`, also
   skip (already removed).

Option B is dramatically simpler and faster on the hot path. Cost:
the wheel can carry duplicate entries for a touched session (one
in the old stale bucket, one in the new). Each pop visit to a
stale entry is one HashMap lookup ≈ 100 ns and a comparison. For a
session that's touched 10x over its lifetime, that's 10 stale
bucket entries × 100 ns = 1 µs total over the session lifetime.

We choose **B (lazy delete)**. The wheel is a *hint* about which
keys *might* have expired, not authoritative state.

### Per-tick GC work

```rust
pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
    let now_tick = now_ns / WHEEL_TICK_NS;
    if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
        return Vec::new();
    }
    self.last_gc_ns = now_ns;
    let mut expired = Vec::new();
    while self.wheel.cursor_tick < now_tick {
        let bucket_idx = (self.wheel.cursor_tick & WHEEL_MASK) as usize;
        let mut due = std::mem::take(&mut self.wheel.buckets[bucket_idx]);
        for key in due.drain(..) {
            // Lazy-delete: re-check current expiration against now_ns.
            let Some(entry) = self.sessions.get(&key) else { continue };
            let entry_expires_at = entry.last_seen_ns.saturating_add(entry.expires_after_ns);
            if entry_expires_at > now_ns {
                // Touched since this bucket was set — already
                // re-bucketed at touch time. Drop this stale ref.
                continue;
            }
            // Genuinely expired. Remove and emit.
            if let Some(removed) = self.remove_entry(&key) {
                // ... existing remove_entry path produces SessionDelta
                // and ExpiredSession ...
                expired.push(...);
            }
        }
        self.wheel.cursor_tick += 1;
    }
    expired
}
```

Per-tick work: O(B) where B is the average bucket size = N / T.
For N=1M sessions across the 256-bucket wheel and average timeout
30s, B = 1M / 30 ≈ 33,000 entries per bucket. Each entry is one
HashMap lookup + one comparison ≈ 200 ns. Per-tick cost: ~6.6 ms.

To bound the spike further (target: ≤1 ms per tick), we cap
per-tick work to `MAX_GC_ENTRIES_PER_TICK = 5000`. If a bucket has
more, defer the rest — push them back at the wheel's tail and they
get processed next tick.

That's still O(1) amortized: the wheel's total work over a full
revolution is O(N), distributed across 256 ticks. With the cap,
worst-case spike is 5000 × 200 ns = 1 ms.

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
- `wheel_per_tick_work_capped`: insert 50,000 sessions all with
  same expiration tick; verify expire_stale_entries returns at
  most MAX_GC_ENTRIES_PER_TICK; subsequent tick returns the rest.
- `wheel_handles_concurrent_insert_and_pop`: not relevant
  (SessionTable is not Send + Sync — owned by a single worker).

Plus 4 existing GC tests (lines 2138, 2142, 2162, +1 more) must
continue to pass.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ baseline (851 post-#921) + 4 new = 855.
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
