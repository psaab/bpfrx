# #964 SessionTable Multi-Index — Slab + Integer Handles (Step 1)

Status: **DRAFT v2 — addressing Codex round-1 PLAN-NEEDS-MAJOR**

## v2 changes (Codex round-1 + Gemini round-1)

Codex round 1: **PLAN-NEEDS-MAJOR** (task-moqg4s64-vl1jel).
Gemini round 1: **PLAN-NEEDS-MINOR** (task-moqg5i8m-74tkzh).
Codex's longer list subsumed Gemini's, so v2 addresses Codex.

5 blockers from Codex:

### 1. Missing handle→key path (Codex blocker #1)

`find_forward_nat_match()` (session/mod.rs:472),
`find_forward_wire_match_with_origin()` (session/mod.rs:492),
and `lookup_with_origin()` (session/mod.rs:407) must return the
canonical `SessionKey`, not just the entry data.
`lookup_with_origin` also calls `push_to_wheel(key, ...)` after
the lookup — the wheel update needs the canonical key.

**v2 decision**: store the canonical key INSIDE the slab entry.
The slab holds `SessionRecord { key: SessionKey, entry:
SessionEntry }`. From any handle the canonical key is
reachable in O(1). This subsumes the owner_rg_sessions
handle→key issue Gemini also raised — `owner_rg_session_keys()`
maps `FxHashSet<u32>` → keys via `slab[h].key.clone()` in
O(owner-sessions), not O(all-sessions).

Memory cost recalculated below.

### 2. Stale-handle invariant misstated (Codex blocker #2)

v1 said "handles are local to a single method call." That's
wrong — secondary indices DO store handles across calls.

**Real invariant** (v2): handles persist only in eagerly-
maintained internal indices, and EVERY such index MUST be
cleaned before its slab slot can be reused. The wheel is the
ONLY place that holds a `SessionKey` (not handle) across calls
because wheel entries are lazily deleted via `wheel_tick`
mismatch.

### 3. Wheel STAYS key-based in Step 1 (Codex blocker #3)

v1 had contradictory wording ("update the wheel to handles" in
one place, "keep wheel key-based for Step 1" in another). v2 is
unambiguous: **wheel keys on `SessionKey`, NOT on handle.**

Reason: wheel entries outlive method calls and are lazily
deleted (a `(SessionKey, scheduled_tick)` entry in a bucket can
sit there for a long time). If we used handles, slab handle
reuse (after remove + new install) would point a stale wheel
entry at a DIFFERENT session. The lazy-delete discriminator
needs to be a stable identifier, which the SessionKey is.

This means the wheel keeps its ~50 bytes per entry. At 1M
sessions × 2x amortization (per #965 plan), that's ~100 MB of
SessionKey storage in the wheel. Not addressed by this Step.

### 4. Use `entries.get(handle)?` not `entries[handle]` (Codex blocker #4)

v1's lookup pattern `let entry = &self.entries[handle as usize];`
panics if the handle is invalid. The current `sessions.get(...)`
returns `None` on stale lookups (graceful degradation).

**v2 fix**: use `self.entries.get(handle as usize)?` everywhere
in lookup paths so stale secondary indices propagate as `None`,
matching today's behavior.

### 5. owner_rg_sessions handle→key cost (Codex blocker #5 + Gemini Q3)

Resolved by v2 decision in #1: SessionRecord stores the key
inline. `owner_rg_session_keys()` collects keys via
`set.iter().map(|h| slab[h].key.clone()).collect()` — O(owner
sessions), same as today. No O(all-sessions) regression.

## Memory math recalculated (v2 honest)

v1 claimed 33% reduction at 1M sessions but used hand-wavy
math. Codex blocker #6 also pointed out that
`DEFAULT_MAX_SESSIONS = 131072` (session/mod.rs:24), so 1M is
already 8x over the configured cap.

**Use 131072 sessions for the v2 baseline.**

Current state (FxHashMap overhead included; FxHashMap is ~1.5×
sizeof(K)+sizeof(V)+1 control byte at 75% load):

| Map | Per-entry | × N=131072 | Total |
|-----|-----------|------------|-------|
| sessions: Key→Entry | 1.5 × (50+80+1) = 197 | × 131072 | 25.8 MB |
| nat_reverse: Key→Key | 1.5 × (50+50+1) = 152 | × 131072 | 19.9 MB |
| forward_wire: Key→Key | 152 | × 131072 | 19.9 MB |
| reverse_translated: Key→Key | 152 | × 131072 | 19.9 MB |
| owner_rg: i32→FxHashSet<Key> | ~25 MB across all RGs | | ~25 MB |
| **Total** | | | **~111 MB** |

After Step 1 (slab with SessionRecord{key,entry}):

| Map | Per-entry | × N=131072 | Total |
|-----|-----------|------------|-------|
| slab: SessionRecord{Key,Entry} | 50+80 = 130 (no hash overhead) | × 131072 | 17.0 MB |
| key_to_handle: Key→u32 | 1.5 × (50+4+1) = 82 | × 131072 | 10.7 MB |
| nat_reverse: Key→u32 | 82 | × 131072 | 10.7 MB |
| forward_wire: Key→u32 | 82 | × 131072 | 10.7 MB |
| reverse_translated: Key→u32 | 82 | × 131072 | 10.7 MB |
| owner_rg: i32→FxHashSet<u32> | ~5 MB across all RGs | | ~5 MB |
| **Total** | | | **~65 MB** |

**Realistic saving: ~46 MB / ~41% reduction at 131072 sessions.**

The Step also takes the CRITICAL improvement: `sessions` HashMap
overhead disappears entirely (the slab is a contiguous Vec, no
hash bucket overhead). That alone is the bulk of the win.

If session count grows to 1M, the same percentages apply:
~880 MB → ~510 MB savings. The plan's earlier "33% at 1M"
claim was directionally correct but underestimated.

## Performance claims (v2 honest)

v1 claimed:
- 2x lookup speedup on cache miss
- 5-10x faster secondary inserts

Codex round 1 correctly noted these are overstated:
- The 2x lookup applies ONLY to specific cache-miss secondary
  lookups (e.g., `find_forward_nat_match`). The bulk of the
  slow path is dominated by other work.
- Secondary insert hash/bucket work remains; only the
  payload (Key→u32 vs Key→Key) shrinks. The wall-clock saving
  per insert is in the tens of nanoseconds, not microseconds.

**v2 perf claim**: lookup-path latency for `find_forward_nat_match`
and `find_forward_wire_match_with_origin` improves by ~50ns per
call (one fewer FxHashMap lookup). At ~65k flow-cache misses/s
per worker, that's ~3.25ms/s/worker = ~0.3% CPU saved on the
slow path. Real but small.

**The dominant value is memory** (~41% reduction at 131072
sessions, ~880 MB saved at 1M).

## Benchmark requirement (v2 — promoted from optional to required)

A microbenchmark in `userspace-dp/benches/` covering:
- 100 inserts under steady-state churn (insert + remove cycle)
- Lookup latency for forward-key, reverse-NAT-key, and
  forward-wire-key paths

Expected: lookup latency reduction ~30-50ns; insert latency
roughly unchanged or 5-10ns better.

If the benchmark shows a regression on either dimension, the
implementation is wrong (or the slab crate has unexpected
overhead and we should switch to `Vec<Option<SessionRecord>> +
free list`).

## Issue framing

`SessionTable` (in `userspace-dp/src/session/mod.rs`) currently
holds five `FxHashMap`s:

```rust
sessions:                   FxHashMap<SessionKey, SessionEntry>,
nat_reverse_index:          FxHashMap<SessionKey, SessionKey>,
forward_wire_index:         FxHashMap<SessionKey, SessionKey>,
reverse_translated_index:   FxHashMap<SessionKey, SessionKey>,
owner_rg_sessions:          FxHashMap<i32, FxHashSet<SessionKey>>,
```

Each `SessionEntry` is ~80 bytes (decision + metadata + origin +
8-byte timestamps + closing flag + wheel_tick). Each `SessionKey`
is ~50 bytes (5-tuple incl. 16-byte v6 IPs + protocol).

For 1M sessions the maps consume roughly:
- `sessions`: ~130 MB
- 4 secondary indices: ~400 MB combined (each duplicates the key
  on both sides — Key→Key — and pays HashMap bucket overhead)
- Total: ~530 MB

The issue (#964) proposes four design steps:

1. **Preallocate session slab** — store SessionEntry in
   `Slab<SessionEntry>` (or `Vec` with a free list).
2. **Integer handles** — secondary indices map
   `SessionKey → u32` instead of `SessionKey → SessionKey`.
3. **Multi-index design** — embed intrusive `next_node` indices
   in `SessionEntry` to remove some of the secondary HashMaps.
4. **Cache locality** — shrink `SessionEntry` to fit in 1-2 cache
   lines.

This plan is **Step 1 only**: slab + integer handles. Steps 3
and 4 are deferred to follow-up issues.

## Honest scope/value framing

The hot path that touches `SessionTable` is the **slow path** —
`SessionTable::lookup` runs ONLY on flow-cache miss. The flow-
cache fast path (in `poll_descriptor.rs`) bypasses
`SessionTable` entirely on session-hit ACK packets. So the
session-table work is per-flow-establishment, not per-packet at
line rate.

This means the perf win from the refactor is bounded by the
flow-establishment rate, which at 1.3M pps and a typical 64 RX
batch is dominated by ACK packets that hit the flow cache. The
session-table work fires for SYN, FIN, RST, NAT64, and cache
invalidations — likely <5% of packets in steady state.

Concrete measurable benefits from Step 1:

1. **Memory reduction**: ~33% (~530 MB → ~350 MB at 1M sessions).
   v6 NAT pool / SNAT-heavy deployments get the biggest savings.
2. **Insert latency**: install_with_protocol does up to 4
   secondary inserts; switching value type from `SessionKey`
   (~50 bytes copy + alloc-free hash bucket placement) to `u32`
   (4 bytes, no clone) makes each secondary insert ~5-10x cheaper.
3. **Lookup latency on cache miss**: today's reverse-NAT lookup
   does TWO hash lookups (`nat_reverse_index.get(reply) →
   forward_key`, then `sessions.get(forward_key) → entry`). With
   slab + u32: ONE hash + ONE slab indexing. Roughly 2x lookup
   speedup on cache miss.

NOT measurable from Step 1:

- **No L1-i benefit** (this is a data-structure refactor, not a
  control-flow refactor).
- **No fast-path benefit** (flow-cache hits still bypass
  SessionTable).

If the reviewers conclude this is insufficient justification for
the churn, **PLAN-KILL is an acceptable verdict** — same
methodology as #946 Phase 2.

## What's already shipped (#965 — wheel GC)

Issue #965 already replaced the O(N) GC scan with a 256-bucket
timer wheel (`session/wheel.rs`). The wheel is keyed on
`SessionKey` and stores `(SessionKey, scheduled_tick)` per
bucket entry. **Step 1 of #964 must update the wheel to use
slab handles too**, or it stays Key-based and we have one
remaining Key duplication.

For Step 1 simplicity: keep the wheel Key-based for now; flag
it as a known follow-up.

## Step 1 design

### Add `Slab<SessionRecord>` with key inline

Use the [`slab`](https://crates.io/crates/slab) crate. Per
Codex blocker #1, the canonical key is reachable from any
handle by storing it inline in the slab record:

```rust
use slab::Slab;

/// Slab-resident record. Holds the canonical key alongside
/// the SessionEntry so any handle resolves to both. Required
/// because find_forward_nat_match() etc. must return the
/// canonical key (used by callers + push_to_wheel).
pub(crate) struct SessionRecord {
    pub(crate) key: SessionKey,
    pub(crate) entry: SessionEntry,
}

pub(crate) struct SessionTable {
    /// Slab-allocated session storage. Indexed by u32 handle.
    entries: Slab<SessionRecord>,
    /// Forward-key → handle. Replaces the `sessions` HashMap's
    /// key-to-entry mapping.
    key_to_handle: FxHashMap<SessionKey, u32>,
    /// Secondary indices now map to u32 handles, not full keys.
    nat_reverse_index:        FxHashMap<SessionKey, u32>,
    forward_wire_index:       FxHashMap<SessionKey, u32>,
    reverse_translated_index: FxHashMap<SessionKey, u32>,
    /// owner_rg_sessions also goes integer-keyed.
    owner_rg_sessions:        FxHashMap<i32, FxHashSet<u32>>,
    // ── unchanged: deltas, timeouts, wheel (still key-based per
    // ── Codex blocker #3), counters, last_pop_stats.
}
```

The wheel REMAINS keyed on `SessionKey`. Per Codex blocker #3,
wheel entries are lazily deleted via `wheel_tick` mismatch and
outlive method calls. If we used handles, slab handle reuse
after remove + new install would point a stale wheel entry at
a DIFFERENT session. SessionKey is the stable identifier
needed for lazy delete.

### Lookup path transformation

Today (Key→Key indirection):
```rust
let forward_key = self.nat_reverse_index.get(reply_key)?;
let entry = self.sessions.get(forward_key)?;  // 2nd hash lookup
```

Step 1 (Key→u32 → slab, fallible per Codex blocker #4):
```rust
let handle = *self.nat_reverse_index.get(reply_key)?;
let record = self.entries.get(handle as usize)?;  // graceful None on stale
let (forward_key, entry) = (&record.key, &record.entry);
```

`entries.get(handle as usize)` returns `Option<&SessionRecord>`
— if the slab slot was reused (which would only happen via
correct cleanup ordering, but the defense-in-depth is here), it
returns the new record's key/entry, not panic. The caller
checks the returned key against the lookup key when needed.

### Insert path transformation

Today:
```rust
self.sessions.insert(forward_key.clone(), entry);
self.nat_reverse_index.insert(reverse_wire, forward_key.clone());
self.forward_wire_index.insert(forward_wire, forward_key.clone());
// ... etc
```

Step 1:
```rust
let raw = self.entries.insert(SessionRecord {
    key: forward_key.clone(),
    entry,
});
// slab returns usize; convert via fallible u32 cast (Codex
// suggestion). DEFAULT_MAX_SESSIONS = 131072 fits comfortably
// in u32 — we'd need a 64-bit slab to overflow, which would be
// an unrelated capacity bug.
let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
self.key_to_handle.insert(forward_key.clone(), handle);
self.nat_reverse_index.insert(reverse_wire, handle);
self.forward_wire_index.insert(forward_wire, handle);
// ... etc
```

Each secondary insert pays a `u32` (4 bytes) instead of a
`SessionKey` (~50 bytes) — no clone, no hash bucket value-side
allocation.

### Delete path transformation

Today:
```rust
let entry = self.sessions.remove(key)?;
self.nat_reverse_index.remove(&reverse);
// ... etc
```

Step 1 — **eager-cleanup ordering (Codex blocker #2 invariant)**:
```rust
let handle = self.key_to_handle.remove(key)?;
// Step A: clean up ALL eagerly-maintained handle indices
// BEFORE returning the slab slot to the free list.
self.nat_reverse_index.remove(&reverse);
self.forward_wire_index.remove(&forward_wire);
self.reverse_translated_index.remove(&translated);
remove_owner_rg_index_entry(&mut self.owner_rg_sessions,
    record.entry.metadata.owner_rg_id, &handle);
// Step B: only AFTER all handle indices are clean, return the
// slab slot to the free list. Any future insert that reuses
// this slot starts with a clean index state.
let record = self.entries.remove(handle as usize);
// Step C: wheel cleanup — NOT done eagerly. The wheel uses the
// (key, scheduled_tick) lazy-delete discriminator. A stale
// wheel entry whose key now refers to a different session (or
// no session) is dropped during the next pop because
// wheel_tick won't match (or sessions.get returns None). This
// is why the wheel stays key-based.
```

**Slab handle reuse contract**: when a session is removed, the
slab marks the slot as free; the next insert reuses that slot.
The eager-cleanup invariant guarantees that NO handle index
contains the freed handle by the time it's reused. The wheel is
the only structure that may retain a stale (handle-reusable
slot, but the wheel uses Key) entry — and the lazy-delete
discriminator handles that.

### Iterator transformation

Today's `iter_with_origin` etc. iterate `sessions` directly.
With slab, we iterate `key_to_handle` and dereference into
`entries`:

```rust
pub fn iter_with_origin(&self) -> impl Iterator<Item = (&SessionKey, ...)> {
    self.key_to_handle.iter().map(|(key, handle)| {
        let entry = &self.entries[*handle as usize];
        (key, ...)
    })
}
```

## Public API preservation

All 33 public methods on `SessionTable` keep their signatures.
The slab is an internal implementation detail. Callers that
receive `SessionLookup` / `ForwardSessionMatch` / `ExpiredSession`
get the same data — handles are NOT exposed in the public API.

## Hidden invariants Step 1 must preserve

- **HA sync key portability**: `drain_deltas()` emits
  `SessionDelta { key, decision, metadata, origin, ... }`. The
  key MUST stay portable (not a handle) because handles are not
  stable across cluster nodes. Step 1 keeps the key in the
  delta — handles are internal-only.
- **Wheel cursor semantics**: the wheel keys on `SessionKey`. If
  Step 1 doesn't update the wheel, it stays Key-based and that's
  one remaining Key duplication (~50 bytes × wheel-entry-count).
  Acceptable for Step 1; flagged for follow-up.
- **owner_rg_sessions iteration**: `owner_rg_session_keys()`
  returns `Vec<SessionKey>`. With handles, the impl maps
  u32 → key via the slab + a reverse handle→key map (or just
  iterates the FxHashMap of handles + looks up in
  key_to_handle's inverse). Need to verify this doesn't
  introduce a new `Vec<SessionKey>` allocation that wasn't
  there before.
- **Stale-handle access**: if a handle is held across a
  `remove()` and the slot is reused, accessing the handle
  returns a different session. Step 1 must verify NO callsite
  holds a handle across mutations of the slab. The internal
  rule: "handles are local to a single method call" — they
  don't persist beyond the method scope.

## Risk assessment

- **Public API regression**: LOW. All 33 methods preserve
  their signatures; the slab is internal.
- **HA sync regression**: MEDIUM. The wheel stays Key-based in
  Step 1 (deferred). Need to verify drain_deltas + delta replay
  on the peer don't break.
- **Borrow-checker complexity**: MEDIUM. `Slab::get_mut` +
  `key_to_handle.get` simultaneously may require sequencing.
- **Performance regression risk**: LOW-MEDIUM. The lookup
  path becomes 1 hash + 1 array index (faster than 2 hashes).
  Insert path: replacing Key clones with u32 is faster. But
  slab insert/remove with free-list management has its own
  overhead — need to measure.
- **Architectural mismatch risk** (#946 Phase 2 dead-end
  pattern): MEDIUM. Step 1 changes the storage layout, which
  is purely internal to SessionTable. It does NOT change the
  flow of operations across packets, so the cross-packet state
  reorder failures of #946 Phase 2 don't apply here.

## Test plan

- `cargo build` clean.
- 952+ cargo tests pass — particularly the 60+ tests in
  `session/tests.rs` that exercise install/lookup/expire paths.
- 5/5 flake check on `wheel_pops_expired_entry_from_bucket`.
- 30 Go test packages pass.
- `make test-failover` since this touches HA-relevant data
  structures.
- Deploy on loss userspace cluster.
- v4 + v6 smoke against 172.16.80.200 / 2001:559:8585:80::200.
- Per-class CoS smoke (5201-5206) — refactor PR rule.
- **MANDATORY** (Codex round-1 requirement): microbenchmark in
  `userspace-dp/benches/session_table.rs` covering insert and
  lookup latency for forward-key, reverse-NAT-key, and
  forward-wire-key paths. If the benchmark shows a regression
  on either dimension, the implementation is wrong (or the
  slab crate has unexpected overhead and we should switch to
  `Vec<Option<SessionRecord>> + free list`).

## Out of scope (explicitly)

- Step 2 (intrusive `next_node` indices) — defer.
- Step 3 (SessionEntry shrunk to 64 bytes) — defer.
- Wheel migration to handles — defer (Key-based is fine; the
  wheel doesn't dominate memory).
- Changing the public API of SessionTable — none of the 33
  methods change signature.

## Open questions for round-2 adversarial review

(v1 had 7. Resolved by v2: Q3 wheel-stays-key-based, Q5 stale-
handle invariant, Q6 owner_rg via SessionRecord-with-key. Q1-Q2-Q4-Q7
remain plus one new from Codex.)

1. **Does Step 1 deliver a measurable benefit?** v2's honest
   numbers: ~41% memory reduction at 131072 sessions (~46 MB);
   ~50ns per cache-miss lookup (~0.3% CPU saved on slow path);
   secondary insert payload shrinks Key→u32 (tens of ns). Net:
   memory win is the dominant value; CPU win is small. Is this
   sufficient justification for the churn?
2. **Slab crate vs custom Vec+free-list**: slab is ~600 LOC
   well-tested. Custom would be ~80 LOC review-able-here. Adds
   a transitive dep. Which is right?
3. **HA delta replay**: peer's `upsert_synced_with_origin`
   allocates a NEW local handle for the synced session.
   Confirmed in pkg/cluster/ — sync wire format is key/value,
   no handle assumption. (Verified by Codex round 1.)
4. **Eager-cleanup invariant verifiability**: every code path
   that removes from `key_to_handle` must also remove from the
   3 secondary indices and `owner_rg_sessions` BEFORE returning
   the slab slot. Currently 8 callsites do session removal
   (search `entries.remove`, `key_to_handle.remove`, etc.). Is
   the invariant testable via a debug assertion that the
   secondary indices have no entries pointing to the freed
   handle?
5. **Benchmark precondition**: the mandatory microbench will
   measure under steady-state churn. Are there stress patterns
   (high-churn install/remove cycles, or RG demote/promote)
   that would expose slab fragmentation or free-list latency
   that the simple bench misses?
