# #964 SessionTable Multi-Index — Slab + Integer Handles (Step 1)

Status: **DRAFT v1 — pending adversarial plan review (Codex + Gemini)**

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

### Add `Slab<SessionEntry>`

Use the [`slab`](https://crates.io/crates/slab) crate (already
common in async Rust). It provides:
- O(1) insert / remove / index by handle.
- Stable handles (u32 won't be reused while in use).
- Integer handle reuse on remove (no monotonic growth).

```rust
use slab::Slab;

pub(crate) struct SessionTable {
    /// Slab-allocated session storage. Indexed by u32 handle.
    entries: Slab<SessionEntry>,
    /// Forward-key → handle. Replaces the `sessions` HashMap's
    /// key-to-entry mapping.
    key_to_handle: FxHashMap<SessionKey, u32>,
    /// Secondary indices now map to u32 handles, not full keys.
    nat_reverse_index:        FxHashMap<SessionKey, u32>,
    forward_wire_index:       FxHashMap<SessionKey, u32>,
    reverse_translated_index: FxHashMap<SessionKey, u32>,
    /// owner_rg_sessions also goes integer-keyed.
    owner_rg_sessions:        FxHashMap<i32, FxHashSet<u32>>,
    // ... unchanged: deltas, timeouts, wheel, etc.
}
```

### Lookup path transformation

Today (Key→Key indirection):
```rust
let forward_key = self.nat_reverse_index.get(reply_key)?;
let entry = self.sessions.get(forward_key)?;  // 2nd hash lookup
```

Step 1 (Key→u32 → slab):
```rust
let handle = *self.nat_reverse_index.get(reply_key)?;
let entry = &self.entries[handle as usize];   // 1 array index
```

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
let handle = self.entries.insert(entry) as u32;
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

Step 1:
```rust
let handle = self.key_to_handle.remove(key)?;
let entry = self.entries.remove(handle as usize);
self.nat_reverse_index.remove(&reverse);
// ... etc
```

Slab handle reuse: when a session is removed, the slab marks
the slot as free; the next insert reuses that slot. Handle
values can repeat, but never while a holder of the handle is
alive (slab guarantees this through the free list).

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
- **Optional**: micro-benchmark of lookup latency before/after
  to confirm the 2x speedup claim is real.

## Out of scope (explicitly)

- Step 2 (intrusive `next_node` indices) — defer.
- Step 3 (SessionEntry shrunk to 64 bytes) — defer.
- Wheel migration to handles — defer (Key-based is fine; the
  wheel doesn't dominate memory).
- Changing the public API of SessionTable — none of the 33
  methods change signature.

## Open questions for adversarial review

1. **Does Step 1 deliver a measurable benefit, or is the perf
   gain too small to justify the churn?** The session-table is
   slow-path; flow-cache misses are <5% of packets. Memory win
   is real (~33% reduction at 1M sessions). Insert/lookup
   latency wins are real but on a low-fire path.
2. **Is the slab crate the right primitive, or should we roll
   our own (a `Vec<Option<SessionEntry>>` + free list)?** Slab
   has 4 bytes of overhead per slot for the next-free-link.
3. **What about the `wheel` left Key-based?** Acceptable for
   Step 1, or does the inconsistency block the refactor?
4. **HA delta replay**: when the peer replays a delta and
   inserts into its own SessionTable, does it allocate a NEW
   handle for the same forward_key? My read is yes (handles are
   per-node, not portable). Verify.
5. **Stale-handle hazard**: any callsite that takes a handle
   from one method and passes it to another method on the same
   SessionTable? The internal rule says no, but worth grepping
   to confirm.
6. **owner_rg_sessions iteration cost**: today returns
   `Vec<SessionKey>` — already an alloc. With slab, we need a
   handle→key reverse mapping. Either:
   - Use `key_to_handle.iter().filter()` — O(N) over all keys.
   - Add a parallel `handle_to_key: Slab<SessionKey>` — doubles
     the slab memory.
   - Store key inside SessionEntry — adds ~50 bytes per entry.
   
   What's the right trade-off?
7. **Should the slab use `Vec<Option<SessionEntry>>` instead of
   the slab crate** to avoid a new dependency?
