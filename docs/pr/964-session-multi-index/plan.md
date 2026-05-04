# #964 SessionTable Multi-Index — Slab + Integer Handles (Step 1)

Status: **FINAL v5 — Gemini PLAN-READY (round 4); Codex PLAN-NEEDS-MINOR (round 4) addressed below.**

## v5 changes (Codex round-4 tactical fixes)

Round 4 converged: Gemini PLAN-READY, Codex PLAN-NEEDS-MINOR
with 5 tactical findings. v5 addresses each:

1. **`remove_entry` primary-key guard**: after `key_to_handle.remove(key)`,
   verify `record.key == *key` BEFORE cleaning. Defends against
   a stale `key_to_handle` pointing at a reused slot.
   `no_index_points_at` extended to also scan `key_to_handle.values()`.
2. **Insert gates match today exactly**: `forward_wire_index`
   inserts only when `forward_wire != forward_key`
   (session/mod.rs:951); `owner_rg_sessions` only when
   `owner_rg_id > 0` (session/mod.rs:963). v4 was unconditional.
3. **Release-mode alias validation**: `lookup_with_origin`'s
   alias path now checks `metadata.is_reverse &&
   translated_session_key(&record.key, record.entry.decision.nat) == *lookup_key`
   so stale alias returns None, never a wrong reused-slot session.
4. **Memory math**: numbers are plausible but the breakdown is
   structural (size_of estimates with tuple padding rules of
   thumb). Implementation MUST replace the table with measured
   `std::mem::size_of::<SessionRecord>()` output and rounded
   bucket counts.
5. **Bench**: add alias-path lookup (via `reverse_translated_index`)
   and a churn cycle that creates+destroys NAT sessions to
   exercise both `reverse_wire` and `reverse_canonical` cleanup.

## Review history

- **v1** (round 1): Codex PLAN-NEEDS-MAJOR (5 blockers) /
  Gemini PLAN-NEEDS-MINOR (1 finding).
- **v2** (round 2): Codex PLAN-NEEDS-MAJOR (12 findings, "core
  direction salvageable") / Gemini PLAN-NEEDS-MINOR (2 small
  recommendations).
- **v3** (round 3): Codex PLAN-NEEDS-MAJOR (5 findings, mostly
  pseudocode bugs + memory-math overstatement + stale
  contradictory instructions still in body) / Gemini
  PLAN-NEEDS-MINOR (NAT alias concern, same as Codex finding 1).

v4 is a **clean rewrite** dropping the layered v1/v2/v3 patch
sections that accumulated stale wording. The design below is
the single coherent v4 design.

## Issue framing

`SessionTable` (`userspace-dp/src/session/mod.rs`) currently
holds 5 hashmaps:

```rust
sessions:                   FxHashMap<SessionKey, SessionEntry>,
nat_reverse_index:          FxHashMap<SessionKey, SessionKey>,
forward_wire_index:         FxHashMap<SessionKey, SessionKey>,
reverse_translated_index:   FxHashMap<SessionKey, SessionKey>,
owner_rg_sessions:          FxHashMap<i32, FxHashSet<SessionKey>>,
```

Each `SessionKey` is ~50 bytes (5-tuple incl. 16-byte v6 IPs).
Each `SessionEntry` is ~80 bytes (decision, metadata, origin,
8-byte timestamps, closing flag, wheel_tick).

#964 proposes 4 design steps. **Step 1** (this plan) does:

1. Replace `sessions: FxHashMap<Key, Entry>` with
   `entries: Slab<SessionRecord>` + `key_to_handle: FxHashMap<Key, u32>`,
   where `SessionRecord { key: SessionKey, entry: SessionEntry }`
   keeps the canonical key reachable from any handle.
2. Switch the 4 secondary indices from `Key→Key` /
   `Key→FxHashSet<Key>` to `Key→u32` / `Key→FxHashSet<u32>`.

Steps 2-4 (intrusive next_node, cache packing) deferred.

## Honest scope/value framing

`SessionTable` lives on the SLOW PATH — `lookup` runs only on
flow-cache miss. Flow-cache hits (per the existing fast path in
`poll_descriptor.rs`) bypass `SessionTable` entirely on
session-hit ACK packets.

Concrete benefits:

- **Memory reduction**: realistic estimate ~40% at 131072
  sessions (the configured `DEFAULT_MAX_SESSIONS`). Recomputed
  honestly in §"Memory math" below — Codex round-3 caught my
  v3 owner-RG overcount.
- **Lookup latency on cache miss**: ~50ns saved per
  reverse-NAT or forward-wire lookup (one fewer hash). At
  ~65k flow-cache misses/s/worker → ~3ms/s/worker = ~0.3% CPU.
  Real but small.
- **Insert latency**: secondary insert payload shrinks from
  ~50 bytes (Key) to 4 bytes (u32). Wall-clock saving is in
  the tens-of-ns range per insert.
- **NO L1-i benefit** (this is a data-structure refactor, not
  a control-flow refactor).
- **NO fast-path benefit** (flow-cache hits bypass).

The **dominant value is memory**. If reviewers conclude the
benefit is too small to justify the churn, **PLAN-KILL is an
acceptable verdict** (matches the methodology that killed
#946 Phase 2).

## Step 1 design

### `SessionRecord` and the slab

Per Codex round-1 finding "missing handle→key path",
`find_forward_nat_match()`, `find_forward_wire_match_with_origin()`,
and `lookup_with_origin()` all need the canonical SessionKey
reachable from a handle. v4 stores the key inline in the slab:

```rust
use slab::Slab;

pub(crate) struct SessionRecord {
    pub(crate) key: SessionKey,
    pub(crate) entry: SessionEntry,
}

pub(crate) struct SessionTable {
    /// Slab-allocated session storage. Indexed by u32 handle.
    entries: Slab<SessionRecord>,
    /// Forward-key → handle. Replaces `sessions` HashMap's
    /// key-to-entry mapping.
    key_to_handle: FxHashMap<SessionKey, u32>,
    nat_reverse_index:        FxHashMap<SessionKey, u32>,
    forward_wire_index:       FxHashMap<SessionKey, u32>,
    reverse_translated_index: FxHashMap<SessionKey, u32>,
    owner_rg_sessions:        FxHashMap<i32, FxHashSet<u32>>,
    // Unchanged: deltas, timeouts, wheel (key-based), counters,
    // last_pop_stats.
}
```

Add `slab = "0.4"` to `userspace-dp/Cargo.toml`. The crate is
~22M downloads/year and well-tested; rolling our own
`Vec<Option<Record>> + free list` would be ~80 LOC of subtle
free-list management with the same review burden.

### Wheel STAYS key-based

The wheel (`session/wheel.rs`) keeps `(SessionKey, scheduled_tick)`
per bucket entry. Lazy-delete via `wheel_tick` mismatch needs
a stable identifier; slab handle reuse after remove+insert
would point a stale wheel entry at the wrong session. `SessionKey`
is the stable identifier.

The wheel pop becomes:
```rust
// Today: self.sessions.get(&key) → entry  (1 hash)
// v4:   self.key_to_handle.get(&key) → handle, self.entries.get(handle as usize) → record  (1 hash + slab deref)
```
One extra slab indirection per pop. Acceptable.

### Lookup paths (path-specific validation)

Codex round-3 finding 1: `lookup_with_origin` needs different
key validation depending on path. Today
(session/mod.rs:413-419):

```rust
let mut entry = self.sessions.get_mut(key).or_else(|| {
    let alias = self.reverse_translated_index.get(key)?;
    self.sessions.get_mut(alias)
})?;
```

The alias lookup intentionally returns an entry whose
`record.key != *key` — the `reverse_translated_index` value
IS the canonical key. So a generic `record.key == lookup_key`
check would reject valid alias lookups.

v4's lookup_with_origin:
```rust
pub fn lookup_with_origin(&mut self, key: &SessionKey, now_ns: u64)
    -> Option<SessionLookup>
{
    // Resolve handle. Direct-primary path: validate record.key == key.
    // Alias path: trust the alias index (record.key may differ).
    let (handle, via_alias) = match self.key_to_handle.get(key) {
        Some(h) => (*h, false),
        None => (*self.reverse_translated_index.get(key)?, true),
    };

    // Mutate-then-drop the borrow before push_to_wheel.
    {
        let record = self.entries.get_mut(handle as usize)?;
        if !via_alias {
            // Direct-primary path: record.key MUST equal lookup key.
            if record.key != *key {
                return None;  // stale primary index → graceful None
            }
        } else {
            // Alias path: record.key is the canonical (forward)
            // key; lookup_key is the translated (reverse) wire
            // key. Validate that translating record.key under the
            // record's NAT decision yields lookup_key. This
            // catches stale reverse_translated_index pointing at
            // a reused slab slot in release builds (Codex
            // round-4 finding #3).
            let must_be_reverse = record.entry.metadata.is_reverse;
            let translated = translated_session_key(&record.key,
                record.entry.decision.nat);
            if !must_be_reverse || translated != *key {
                return None;  // stale alias → graceful None
            }
        }
        // (Mutation block: TCP closing, last_seen_ns,
        // expires_after_ns recomputation, etc. — same as today's
        // session/mod.rs:428-460.)
        ...
    }

    // Borrow dropped above. Now we can take &mut self for wheel.
    let canonical_key = self.entries[handle as usize].key.clone();
    self.push_to_wheel(&canonical_key, now_ns);
    Some(SessionLookup { decision, metadata, origin })
}
```

**Validation rule** (Codex round-4 finding #3 — release-mode
guard, NOT debug-only): the direct-primary path checks
`record.key == lookup_key`. The alias path verifies that
translating the canonical record key under the record's NAT
decision yields the lookup_key, AND that
`metadata.is_reverse` is set. Both checks fire in release
builds. A stale alias index returns `None` instead of a
wrong reused-slot session. The debug assertion in
`remove_entry` is an additional defense for tests, not the
sole release-mode guard.

`find_forward_nat_match` and `find_forward_wire_match_with_origin`
return owned clones today (session/mod.rs:472-510), so they're
straightforward — just resolve `handle = nat_reverse_index.get(reply_key)?`,
then `record = entries.get(handle as usize)?`, return cloned
fields. No alias-path complexity.

### Insert path

```rust
let raw = self.entries.insert(SessionRecord {
    key: forward_key.clone(),
    entry,
});
// slab returns usize. DEFAULT_MAX_SESSIONS = 131072 fits in u32.
let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
self.key_to_handle.insert(forward_key.clone(), handle);
self.nat_reverse_index.insert(reverse_wire, handle);
self.nat_reverse_index.insert(reverse_canonical, handle);  // both keys today
// Match today's session/mod.rs:951 gate exactly: only insert
// the forward-wire index when the wire key differs from the
// canonical forward key (Codex round-4 finding #2).
if forward_wire != forward_key {
    self.forward_wire_index.insert(forward_wire, handle);
}
// reverse_translated_index inserted only on NAT-translated paths.
// Match today's session/mod.rs:963 gate: only index by owner-RG
// when owner_rg_id > 0 (Codex round-4 finding #2).
if metadata.owner_rg_id > 0 {
    self.owner_rg_sessions.entry(metadata.owner_rg_id)
        .or_default()
        .insert(handle);
}
```

### Centralized remove with eager cleanup

Per Codex round-2 + round-3 findings: today
(session/mod.rs:926-1025) all session removal goes through
ONE helper, `remove_entry`, which:
1. Removes from `sessions` map.
2. **Value-guards** each secondary cleanup: only removes a
   secondary index entry if its stored value still matches
   the canonical key.
3. Cleans owner_rg_sessions, removing the empty FxHashSet
   when its last session leaves.

v4 preserves this shape:

```rust
fn remove_entry(&mut self, key: &SessionKey) -> Option<SessionEntry> {
    let handle = self.key_to_handle.remove(key)?;
    // 1. Read the record (still in slab) to learn what to clean.
    //    .get not .remove — we'll remove from slab last.
    let record = self.entries.get(handle as usize)
        .expect("handle in key_to_handle must be valid");
    // PRIMARY-KEY GUARD (Codex round-4 finding #1): if
    // key_to_handle was somehow stale (e.g. concurrent state
    // corruption — should not happen but defense in depth), the
    // resolved record might be a different session. Bail without
    // touching the slab so we don't free another session's slot.
    if record.key != *key {
        // Reinsert the (correct) primary mapping we just removed,
        // since we shouldn't have removed it. This branch should
        // NEVER fire in correct code; the assertion below is the
        // primary defense.
        debug_assert!(false, "remove_entry: stale key_to_handle for {:?}", key);
        // In release: leak rather than corrupt. We've already
        // removed from key_to_handle; restore it pointing at the
        // canonical handle of the SAME key we just looked up.
        self.key_to_handle.insert(key.clone(), handle);
        return None;
    }
    let owner_rg_id = record.entry.metadata.owner_rg_id;
    let reverse_wire = compute_reverse_wire(record);
    let reverse_canonical = compute_reverse_canonical(record);
    let forward_wire = compute_forward_wire(record);
    let translated = compute_translated(record);

    // 2. Clean every handle-valued index. Each cleanup is
    //    VALUE-GUARDED — only remove if the stored handle
    //    still equals our handle. Equivalent to today's
    //    session/mod.rs:979-999 `matches!(... existing == key)`.
    fn guarded_remove<K: Eq + Hash>(
        idx: &mut FxHashMap<K, u32>, k: &K, expected: u32,
    ) {
        if matches!(idx.get(k), Some(stored) if *stored == expected) {
            idx.remove(k);
        }
    }
    guarded_remove(&mut self.nat_reverse_index, &reverse_wire, handle);
    guarded_remove(&mut self.nat_reverse_index, &reverse_canonical, handle);
    guarded_remove(&mut self.forward_wire_index, &forward_wire, handle);
    guarded_remove(&mut self.reverse_translated_index, &translated, handle);

    // owner_rg_sessions: remove the handle from the per-RG set;
    // remove the per-RG entry if its set is now empty (matches
    // today's session/mod.rs:1025).
    if let Some(set) = self.owner_rg_sessions.get_mut(&owner_rg_id) {
        set.remove(&handle);
        if set.is_empty() {
            self.owner_rg_sessions.remove(&owner_rg_id);
        }
    }

    // 3. Mandatory debug assertion: NO handle-valued index
    //    still points at this handle. Catches eager-cleanup
    //    invariant violations before slab slot reuse.
    debug_assert!(self.no_index_points_at(handle),
        "remove_entry leaked handle {} in a secondary index", handle);

    // 4. Only AFTER all indices are clean, return slot to slab.
    let record = self.entries.remove(handle as usize);
    Some(record.entry)
}

#[cfg(debug_assertions)]
fn no_index_points_at(&self, handle: u32) -> bool {
    // Codex round-4 finding #1: also scan key_to_handle.
    !self.key_to_handle.values().any(|h| *h == handle)
        && !self.nat_reverse_index.values().any(|h| *h == handle)
        && !self.forward_wire_index.values().any(|h| *h == handle)
        && !self.reverse_translated_index.values().any(|h| *h == handle)
        && !self.owner_rg_sessions.values()
            .any(|set| set.contains(&handle))
}
```

**Centralization**: every session removal callsite goes
through `remove_entry`. Today there are no direct
`sessions.remove` calls outside `remove_entry`; v4 preserves
that.

**Codex round-3 finding 5 — `demote_owner_rg`**: that method
mutates origin in place (session/mod.rs:854) and does NOT
remove sessions. v4 leaves it unchanged at the storage level
— no routing through `remove_entry` for it.

### Iterators use fallible `entries.get()`

```rust
pub fn iter_with_origin(&self) -> impl Iterator<Item = (&SessionKey, ...)> {
    self.key_to_handle.iter().filter_map(|(key, handle)| {
        let record = self.entries.get(*handle as usize)?;
        Some((key, &record.entry, ...))
    })
}
```

`filter_map` over `entries.get()` drops any orphan
key→handle mapping defensively (none expected post-cleanup,
but defense in depth).

### owner_rg_session_keys() with handles

```rust
pub fn owner_rg_session_keys(&self, owner_rgs: &[i32]) -> Vec<SessionKey> {
    owner_rgs.iter()
        .filter_map(|id| self.owner_rg_sessions.get(id))
        .flat_map(|set| set.iter())
        .filter_map(|h| self.entries.get(*h as usize))
        .map(|r| r.key.clone())
        .collect()
}
```

O(owner-sessions) — same complexity as today.

## Memory math (recomputed v4 — Codex round-3 fix)

v3 claimed ~55% saving but assumed `10 RGs × 100K owner_rg
entries = 1M` against `131072` total sessions. Codex round 3
caught: each session is in **exactly one** owner-RG set, so
total owner-RG entries = N = 131072.

Under realistic deployment (~7 RGs, sessions distributed
roughly evenly):
- Per RG: ~131072 / 7 ≈ 19K sessions per FxHashSet.
- FxHashSet<Key>(19K): hashbrown rounds to 32K buckets at
  7/8 load. 32K × 50 bytes = ~1.6 MB per RG.
- 7 RGs × 1.6 MB = ~11 MB total owner_rg.

Recomputed totals at 131072 sessions:

| Map | Tuple padded | × 262144 buckets | Total |
|-----|--------------|------------------|-------|
| sessions: Key→Entry | (50+80→136) | 35.6 MB | ~36 MB |
| 3 × Key→Key | (50+50→104) × 3 | 81.9 MB | ~82 MB |
| owner_rg_sessions | per-RG ~1.6 MB × 7 | | ~11 MB |
| **Current total** | | | **~129 MB** |

After v4 (slab + Key→u32 indices + handle-keyed RG sets):

| Map | Tuple padded | × 262144 buckets | Total |
|-----|--------------|------------------|-------|
| entries: Slab<SessionRecord> | 50+80+8 (slab tag) ≈ 144 | × 131072 slots | ~18 MB |
| 4 × Key→u32 | (50+4→56) × 4 | 58.7 MB | ~59 MB |
| owner_rg → FxHashSet<u32> | per-RG ~0.13 MB × 7 | | ~1 MB |
| **v4 total** | | | **~78 MB** |

**Realistic saving: ~51 MB / ~40% reduction at 131072
sessions.** Better than v2's 41% claim, less than v3's
inflated 55%, but more honest. The dominant win is shrinking
the secondary indices' value side from 50-byte Keys to 4-byte
u32s.

**Caveat (Codex round-4 finding #4)**: the table above uses
size_of estimates with tuple-padding rules of thumb. The
implementation MUST replace these numbers with measured
`std::mem::size_of::<SessionRecord>()` and
`std::mem::size_of::<SessionEntry>()` output, plus rounded
hashbrown bucket counts (`capacity_to_buckets(N)` from
hashbrown source). The total ~129 MB → ~78 MB direction is
believable; the line-item attribution may shift by 5-10%.

## Public API preservation

All 33 public methods on SessionTable keep their signatures.
The slab is an internal implementation detail. Callers
receiving `SessionLookup` / `ForwardSessionMatch` /
`ExpiredSession` get the same data — handles are NOT exposed
in the public API.

## Hidden invariants

- **Eager cleanup invariant**: when `remove_entry` returns,
  NO handle-valued internal index points at the freed handle.
  Enforced by the debug assertion above. Violation can cause
  a stale secondary index to point at a reused-slot record
  (different session). The debug assertion catches it in
  tests; the lookup-path key validation catches the
  primary-index case in release.
- **HA sync portability**: `drain_deltas()` emits
  `SessionDelta { key, ... }`. The key is the
  cross-node-portable identifier. Handles are node-local;
  the peer allocates a fresh handle on its slab when it
  replays the delta.
- **Wheel keys on `SessionKey`** — required by lazy-delete
  semantics.
- **Stable record identity**: a single `entries.insert()`
  returns a stable handle until the matching
  `entries.remove()` runs. Slab guarantees the slot is not
  recycled for any insert that observes the handle as live.

## Risk assessment

- **Public API regression**: LOW. All 33 methods retain
  signatures; slab is internal.
- **HA sync regression**: LOW. Wire format keeps using
  `SessionKey`; handles are node-local.
- **Borrow-checker complexity**: LOW. The `entries.get_mut`
  + `key_to_handle.get` are disjoint borrows; the
  scoped-mutation pattern in `lookup_with_origin` matches
  today's existing pattern.
- **Performance regression risk**: LOW-MEDIUM. Lookup +
  insert paths get faster; slab insert/remove with free-list
  has its own small overhead. Microbenchmark required to
  confirm.
- **Architectural mismatch risk** (#946 Phase 2 dead-end
  pattern): LOW. Pure storage-layout change. No cross-packet
  reordering, no shared-state visibility changes.

## Test plan

- `cargo build` clean.
- 952+ cargo tests pass — particularly `session/tests.rs`
  install/lookup/expire paths.
- `wheel_pops_expired_entry_from_bucket` 5/5 flake check.
- 30 Go test packages pass.
- `make test-failover` since this touches HA-relevant data
  structures.
- Deploy on loss userspace cluster.
- v4 + v6 smoke against `172.16.80.200` /
  `2001:559:8585:80::200`.
- Per-class CoS smoke (5201-5206) — refactor PR rule.
- **MANDATORY** microbench at
  `userspace-dp/benches/session_table.rs` covering:
  - Insert (install_with_protocol shape) under steady-state
    churn.
  - Lookup for forward-key, reverse-NAT-key, forward-wire-key,
    AND **alias-path lookup via reverse_translated_index**
    (Codex round-4 finding #5 — the alias path was the source
    of multiple prior review failures).
  - **NAT churn cycle**: install/remove pairs that produce
    BOTH `reverse_wire` and `reverse_canonical` keys, so the
    bench exercises the full guarded-remove path (Codex
    round-4 finding #5).
  - GC (expire_stale_entries shape).
  - owner_rg_session_keys (HA export hot path).

  Bench reimplements the SessionTable hot-path shape because
  `SessionTable` is `pub(crate)` in a bin crate — same pattern
  as `userspace-dp/benches/tx_kick_latency.rs`. This is a
  "structural microbenchmark" (measures the same data-shape
  costs but is not the production code); divergence is caught
  by `session/tests.rs` unit tests.

  Slab fragmentation stress test (Gemini round-2 finding):
  documented as follow-up, not in v4's mandatory scope. The
  steady-state churn bench exercises insert+remove cycles but
  doesn't simulate long-duration randomized lifetimes.

  `drain_deltas` not in bench scope — Codex round 2 + 3
  noted it just drains a `VecDeque`, not refactor-affected.

## Out of scope (explicitly)

- Step 2 of #964 (intrusive `next_node` indices in
  SessionEntry) — defer to follow-up.
- Step 3 (cache-line packing of SessionEntry to ≤64 bytes) —
  defer.
- Wheel migration to handles — left key-based by design (see
  hidden invariants).
- Changing the public API of SessionTable — none of the 33
  methods change signature.
- Slab fragmentation stress test — documented follow-up.

## Open questions for round-4 review

1. **Does the v4 design now deliver a measurable benefit?**
   ~40% memory reduction at 131072 sessions; ~50ns per
   cache-miss lookup. Sufficient justification for the churn?
2. **(Resolved in v5)** Alias-path validation now fires in
   release builds: `metadata.is_reverse &&
   translated_session_key(record.key, decision.nat) == lookup_key`.
3. **Are the 4 secondary indices bench-covered for both
   `reverse_wire` and `reverse_canonical`?** Both keys are
   inserted today; `remove_entry` cleans both. The bench
   should exercise NAT cases that produce both keys.
4. **Eager-cleanup debug assertion**: O(N) per remove in
   debug mode. Acceptable for tests, or should it be
   `O(degree-of-handle)` via a reverse-index?
5. **Slab dependency**: v4 commits to `slab = "0.4"`. Adds
   ~600 LOC of transitive dependency. Acceptable, or roll our
   own?
