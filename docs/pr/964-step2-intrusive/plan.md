# #964 Step 2 — Intrusive `next_node` indices in `SessionEntry`

Status: **DRAFT v1 — pending adversarial plan review (Codex + Gemini)**

## Issue framing

#964 Step 2 (issue text §3): "embed intrusive 'next_node'
indices directly into the `SessionEntry` struct for common
lookups. This transforms 5 heap allocations into 1 slab
allocation."

The Linux kernel uses this pattern extensively (`list_head`,
`hlist_node`) — every kernel session/conntrack/socket struct
has next/prev pointers threaded through it, eliminating the
need for a separate set of nodes managed by the hash table.

## Honest scope/value framing — likely PLAN-KILL territory

**Up front**: this plan probably should be killed at v1 review.
The intrusive-`next_node` pattern is a great match for code
that has many small linked lists, but our SessionTable's
post-Step-1 layout doesn't fit that shape. A hostile read of
the available wins:

### What our secondary indices actually look like (post Step 1)

After PR #1182 (Step 1, slab + integer handles):

| Index | Shape | Cardinality |
|-------|-------|-------------|
| `key_to_handle` | `FxHashMap<Key, u32>` | 1:1 (primary lookup) |
| `nat_reverse_index` | `FxHashMap<Key, u32>` | 1:1 (each reverse-wire/canonical key → 1 forward) |
| `forward_wire_index` | `FxHashMap<Key, u32>` | 1:1 (wire key → forward) |
| `reverse_translated_index` | `FxHashMap<Key, u32>` | 1:1 (alias key → forward) |
| `owner_rg_sessions` | `FxHashMap<i32, FxHashSet<u32>>` | 1:N (one set per RG) |

**Only `owner_rg_sessions` is 1:N.** The other four are 1:1.
The intrusive-list pattern only applies to 1:N relationships
(threading a list through nodes that share a key/owner).

### What "intrusive next_node" can replace

Only `owner_rg_sessions`. Specifically:

- **Today**: `FxHashMap<i32, FxHashSet<u32>>` — per-RG hash-set
  of session handles.
- **Intrusive**: `FxHashMap<i32, u32>` (head pointer) +
  add `next_in_rg: Option<u32>`, `prev_in_rg: Option<u32>` to
  `SessionEntry`.

### Memory math — the intrusive variant is WORSE

| Component | Today (FxHashSet) | Intrusive (linked list) |
|-----------|------------------|------------------------|
| Per-session payload | u32 in FxHashSet bucket (~6 bytes effective with hashbrown ~1.4× overhead) | next + prev u32 = 8 bytes added to SessionEntry |
| Per-RG anchor | FxHashSet (1 alloc + ~128 KB per RG at 18K sessions) | head: Option<u32> (5 bytes) |
| Total at 131072 sessions, 7 RGs | ~770 KB hash-set storage + 7 hash-set allocations | ~1 MB pointer storage in slab + 7 head pointers |
| **Net** | **~770 KB** | **~1 MB (worse by ~250 KB)** |

The "5-allocations-to-1-allocation" claim from the issue
doesn't translate: we already have the slab (1 alloc post
Step 1). Replacing 7 FxHashSet allocations with intrusive
pointers saves 7 small allocations at the cost of 256 KB
extra slab storage.

### Lookup performance

- **Today**: `FxHashSet<u32>::contains/insert/remove` —
  hashbrown bucket lookup ~50ns. Iteration (for
  `owner_rg_session_keys`) walks contiguous buckets.
- **Intrusive**: insert/remove are O(1) pointer ops (~5ns).
  Iteration walks the linked list — **pointer chase through
  slab records, much WORSE cache locality** than FxHashSet's
  contiguous bucket array.

`owner_rg_session_keys` is called by:
- HA snapshot export on RG demote (rare, slow path)
- Coordinator's session_manager (rare)
- Forwarding tests

None of these are hot paths. A 2-3× slowdown on iteration
(from cache-miss linked-list walk) wouldn't move a needle.

### What would the change actually deliver?

- **Memory**: net regression of ~250 KB (negligible).
- **Insert/remove latency**: ~45ns saved per
  `install_with_protocol_with_origin` call. Slow-path,
  ~few-thousand calls/s, total CPU saved ~0.001%.
- **Iteration latency**: regresses ~2-3× on the slow
  `owner_rg_session_keys` path.
- **Code complexity**: adds intrusive-list bookkeeping to
  `index_forward_nat_key` + `remove_forward_nat_index` +
  `remove_entry`. Each list mutation must atomically update
  prev + next of neighbors. Plus head pointer update on
  empty/non-empty transitions.

### Why this matches Step 3's PLAN-KILL pattern

Step 3 (cache-line packing) was killed because:
1. Memory savings were small at typical loads.
2. CPU costs erased Step 1's wins.
3. Sentinel encoding had unsafe collisions.

Step 2 (intrusive list) has the same shape:
1. Memory is a NET REGRESSION at typical loads.
2. CPU costs are tiny but iteration regresses.
3. Bookkeeping complexity offsets the modest insert win.

**If reviewers conclude the perf gain is too small to justify
the churn, PLAN-KILL is an acceptable verdict.**

## What's already shipped

- **Step 1** (PR #1182): slab + key_to_handle + Key→u32
  secondary indices. Eager-cleanup invariant via
  `remove_entry` helper.
- **Step 3** (this plan v2 from prior session): KILLED at
  plan stage by both reviewers.

## Concrete design (if Step 2 ships anyway)

If reviewers vote PLAN-READY despite the analysis above:

```rust
pub(crate) struct SessionRecord {
    pub(crate) key: SessionKey,
    pub(crate) entry: SessionEntry,
    /// #964 Step 2: doubly-linked list of sessions in the
    /// same owner-RG. None means "head of list" (prev) or
    /// "tail of list" (next). The list head pointer lives in
    /// `SessionTable::owner_rg_heads`.
    pub(crate) prev_in_rg: Option<u32>,
    pub(crate) next_in_rg: Option<u32>,
}

pub(crate) struct SessionTable {
    entries: Slab<SessionRecord>,
    key_to_handle: FxHashMap<SessionKey, u32>,
    nat_reverse_index: FxHashMap<SessionKey, u32>,
    forward_wire_index: FxHashMap<SessionKey, u32>,
    reverse_translated_index: FxHashMap<SessionKey, u32>,
    /// Replaces owner_rg_sessions. Maps RG ID → head of the
    /// intrusive linked list of session handles.
    owner_rg_heads: FxHashMap<i32, u32>,
    // ...
}
```

Insert (in `index_forward_nat_key`):
```rust
if metadata.owner_rg_id > 0 {
    let head = self.owner_rg_heads.get(&metadata.owner_rg_id).copied();
    // Push new handle at head: new.next = old_head; old_head.prev = new.
    let record = self.entries.get_mut(handle as usize)
        .expect("just inserted");
    record.next_in_rg = head;
    record.prev_in_rg = None;
    if let Some(old_head) = head {
        self.entries.get_mut(old_head as usize)
            .expect("head must be valid")
            .prev_in_rg = Some(handle);
    }
    self.owner_rg_heads.insert(metadata.owner_rg_id, handle);
}
```

Remove (in `remove_entry`):
```rust
// Unlink from owner-RG list.
if metadata.owner_rg_id > 0 {
    let (prev, next) = {
        let r = self.entries.get(handle as usize).unwrap();
        (r.prev_in_rg, r.next_in_rg)
    };
    if let Some(p) = prev {
        self.entries.get_mut(p as usize).unwrap().next_in_rg = next;
    } else {
        // We were the head; promote next.
        match next {
            Some(n) => { self.owner_rg_heads.insert(metadata.owner_rg_id, n); }
            None => { self.owner_rg_heads.remove(&metadata.owner_rg_id); }
        }
    }
    if let Some(n) = next {
        self.entries.get_mut(n as usize).unwrap().prev_in_rg = prev;
    }
}
```

Iteration (in `owner_rg_session_keys`):
```rust
let mut handles = Vec::new();
for owner_rg_id in owner_rgs {
    let mut cur = self.owner_rg_heads.get(owner_rg_id).copied();
    while let Some(h) = cur {
        let record = &self.entries[h as usize];
        handles.push(h);
        cur = record.next_in_rg;
    }
}
// Then map handles → keys via the slab.
```

## Public API preservation

All 33 public methods retain signatures. Internal-only
storage change. owner_rg_session_keys returns
`Vec<SessionKey>` as today.

## Hidden invariants

- **List integrity under concurrent install/remove**:
  SessionTable is `&mut self` everywhere, so no concurrent
  access. But the code must NEVER leave a list in an
  inconsistent state mid-mutation (next pointing to freed
  slot, or unlinked head not in heads map).
- **Cleanup ordering for slab handle reuse**: when removing,
  must unlink from owner-RG list BEFORE returning slot to
  slab. Otherwise a freshly-inserted session would inherit
  the previous occupant's next/prev pointers.
- **Empty-list transitions**: when a list becomes empty,
  `owner_rg_heads.remove(&rg)` to keep the map small.
  Mirrors today's FxHashSet `is_empty` cleanup.
- **Stale-handle hazard re-emerges**: now we have additional
  handle-valued state (next_in_rg / prev_in_rg fields)
  that must be cleaned. The Step 1 `no_index_points_at`
  debug assertion needs extension.
- **HA sync**: owner_rg metadata is included in the
  SessionDelta — wire format unchanged.

## Risk assessment

| Risk | Level | Note |
|------|-------|------|
| Behavioral regression | MED | List bookkeeping has many edge cases (head/tail/single-element/empty transitions). |
| Lifetime / borrow-checker | MED | Multiple `&mut self.entries` accesses in insert/remove (head, prev, next, current). May need fallible `get_mut` chains. |
| Performance regression | MED | Iteration regresses (linked-list pointer chase vs FxHashSet bucket scan). On rare paths, but real. |
| Architectural mismatch (Phase-2 / #961 / Step-3 dead-end pattern) | **HIGH** | The intrusive-list pattern doesn't fit a 1:1-dominant secondary-index landscape. Same shape as Step 3 KILL. |

## Test plan

- `cargo build` clean.
- 952+ cargo tests pass — particularly `session/tests.rs`
  (install/lookup/expire) and HA sync round-trip tests.
- 5/5 `wheel_pops_expired_entry_from_bucket` flake check.
- 30 Go test packages pass.
- `make test-failover` (touches HA paths).
- Deploy on loss userspace cluster.
- v4 + v6 smoke against `172.16.80.200` /
  `2001:559:8585:80::200`.
- Per-class CoS smoke (5201-5206).
- Microbench updates: extend `userspace-dp/benches/session_table.rs`
  with insert+remove churn that exercises the
  owner-RG list, and a separate iteration bench measuring
  `owner_rg_session_keys` latency.

## Out of scope

- Replacing any 1:1 secondary index with intrusive
  structures (no improvement available — they're already at
  optimum cardinality).
- Step 3 (already KILLED).
- Wheel handle migration (out of scope for #964 entirely).

## Open questions for adversarial review

1. **Should Step 2 be killed at v1 like Step 3 was?** The
   honest analysis above shows net memory regression of
   ~250 KB, ~45ns insert win on a slow path, ~2-3×
   iteration slowdown on `owner_rg_session_keys`. The
   complexity-to-win ratio is bad.
2. **Is the intrusive-list pattern actually relevant for
   xpf's session model?** The Linux kernel uses it for
   structures with MANY small lists (per-bucket hash chains,
   per-process file descriptors, etc.) — we have ~7 large
   lists (one per RG). Different cardinality regime.
3. **Could the secondary-index landscape benefit from a
   DIFFERENT optimization** (e.g., merging two indices, or
   moving cold metadata to a side table) that's NOT
   intrusive-list-shaped?
4. **What's the test-failover risk?** owner_rg_sessions
   feeds HA failover (RG demote → session export). A bug in
   the linked-list bookkeeping could surface during failover
   only, days after merge.
5. **Realistic projection**: if Step 2 is KILLED here, what
   IS the natural Step 2 for #964? The issue's 4 stages
   are (a) slab — Step 1 ✅, (b) integer handles — Step 1 ✅,
   (c) intrusive next_node — this plan, likely KILL, (d)
   cache locality — Step 3 KILLED. **#964 may be effectively
   complete after Step 1.**
