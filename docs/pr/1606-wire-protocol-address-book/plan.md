# Plan v8: Wire protocol address-book ID + shared CIDR table (#1606)

**Revision history**
- v1: original plan; killed by Codex (HA determinism, shim
  contradiction, §7 rosy memory, forwarding_build rename blast
  radius, Vec<Arc<BookEntry>> hot-path shape, ArcSwap wording).
- v2: PLAN-NEEDS-MAJOR — wrong protocol version baseline, inverted
  parse condition, content-vs-name clash, u16-fallback, 31-bit
  math.
- v3: PLAN-NEEDS-MAJOR — book-only fail-open via PrefixSet empty,
  unknown ID should hard-fail, collision math, hash framing.
- v4: per-rule v3-shaped predicate, hard-fail unknowns, family/
  count framing. PLAN-NEEDS-MAJOR'd: book-only rule still
  fail-opens via PrefixSetV4::from_prefixes(empty)=MatchAny.
- v5: added MatchNone variant + from_v3_literals constructor.
  PLAN-NEEDS-MAJOR'd by Codex r5: (F-r5-1) v3-shaped "any" token
  produces empty prefix vec → MatchNone → fail CLOSED on a rule
  that should match all; (F-r5-2) fallible Result<PolicyState>
  propagation scope is too narrow (multiple side-effecting call
  sites between the snapshot handler and the policy build).
- v6: adds explicit "any" handling in the v3 literal parser;
  expands fallibility scope to include `build_forwarding_state*`,
  coordinator refresh, reconcile, and snapshot handler.
  PLAN-NEEDS-MINOR'd by Codex r6 for two refinements: (1) sort by
  `(hash64, canonical_bytes)` to disambiguate the impossible-in-
  practice 64-bit hash collision; (2) address-book contents
  containing "any" string need normalization (canonicalize to
  `0.0.0.0/0` + `::/0` at book-build time, or reject).
- v7 (this): Codex r6 minor fixes — bucket-by-canonical-content
  with `(hash64, canonical_bytes)` sort key; normalize "any" in
  address-book contents to `0.0.0.0/0` + `::/0` at the Go
  buildAddressBookTable level, so book contents on the wire are
  always concrete CIDR strings.

## 0. Wire-protocol context (READ FIRST)

The control-plane → dataplane wire on the userspace path is **JSON
over the local control socket**, not protobuf.

The `ConfigSnapshot` JSON has a `version: i32` field. The repo is
already at **protocol version 3**, set at
`pkg/dataplane/userspace/protocol.go:11` (`ProtocolVersion = 3`).
The Rust side STRICTLY rejects mismatched versions at
`userspace-dp/src/server/handlers/snapshot.rs:25` — there is NO
graceful field-by-field fallback once versions diverge.

**This PR DOES NOT bump the protocol version.** The new wire fields
are additive on version 3: serde `default` + `omitempty` handle the
"old binary missing the field" case naturally. Old Go binaries
emit no `address_books` / `source_book_ids` / `source_literals` and
new Rust binaries fall through to the existing legacy
`source_addresses` parse path. New Go binaries emit the additive
fields, and new Rust binaries prefer them.

A future shim-removal PR will bump version to 4 when the legacy
`source_addresses` field is finally retired.

## 1. Goal

Restructure the JSON snapshot wire surface so that:

1. Address-book contents live in a top-level `address_books` array,
   keyed by a stable `u32` ID computed at Go compile-time by
   **content-only** content-hashing (two named books with identical
   CIDR sets share the same ID and produce ONE row in
   `address_books`).
2. Each `PolicyRuleSnapshot` references books by ID
   (`source_book_ids: Vec<u32>`, `destination_book_ids: Vec<u32>`)
   AND carries a separate `source_literals: Vec<String>` /
   `destination_literals: Vec<String>` for free-form CIDRs that
   appeared inline in the rule (not via a named address-book name).
3. The existing wire field `source_addresses` / `destination_addresses`
   stays on the v3 wire for **back-compat with old Rust binaries**
   reading new-Go snapshots — it carries the FULLY EXPANDED literal
   CIDRs (union of book expansion + free-form literals), exactly as
   today. New-Rust IGNORES this field when ANY of the new fields
   (`source_book_ids` or `source_literals`) is present on the rule.
4. The Rust side stores books in a **flat dense table**
   (`Vec<BookEntry>` on `PolicyState`); rules reference books by
   small dense `u32` index. No `Arc<BookEntry>` per rule; no per-
   rule heap allocations for the common case (≤8 books per rule).
5. Memory dedup lands as soon as the Rust side is upgraded — new
   Rust no longer re-parses CIDRs from `source_addresses` when book
   IDs are present.

## 2. Non-goals

- **No gRPC / protobuf changes.** The CLI-facing `xpf.proto` is
  untouched.
- **No protocol version bump.** New fields are additive on version
  3. Version bump (to 4) is deferred to a follow-up shim-removal PR.
- **No DIR-24-8 / multibit trie / Patricia compression.** That is
  #1608 follow-up.
- **No new HA wire frames.** Snapshot bulk-sync uses the existing
  envelope; the book table travels inside.
- **No JIT / Cranelift work.**
- **No removal of legacy `source_addresses`.** Follow-up
  shim-removal PR, ≥1 release later.
- **No address-book CRUD CLI changes.**

## 3. Architecture

### 3.1 Snapshot DTO shape (Rust side, `protocol/security.rs`)

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct AddressBookSnapshot {
    /// Stable u32 ID assigned at Go compile-time by content-only
    /// content-hashing. Two address-book DECLARATIONS with the same
    /// CIDR set get the same ID and produce ONE row in the wire
    /// `address_books` array. ID 0 is reserved as "unused" and
    /// never minted for a real book.
    pub id: u32,
    /// Diagnostic-only. When multiple Junos address-book names map
    /// to the same content hash, this is the lexicographically
    /// smallest name. Lookups always go through `id`.
    #[serde(default)]
    pub name: String,
    /// Already-resolved literal CIDRs (v4). Address-set nesting and
    /// name indirection is fully expanded on the Go side.
    #[serde(rename = "prefixes_v4", default)]
    pub prefixes_v4: Vec<String>,
    #[serde(rename = "prefixes_v6", default)]
    pub prefixes_v6: Vec<String>,
}
```

`PolicyRuleSnapshot` grows FOUR new optional fields (all additive on
version 3; serde defaults handle absence):

```rust
#[serde(rename = "source_book_ids", default)]
pub source_book_ids: Vec<u32>,
#[serde(rename = "destination_book_ids", default)]
pub destination_book_ids: Vec<u32>,
#[serde(rename = "source_literals", default)]
pub source_literals: Vec<String>,
#[serde(rename = "destination_literals", default)]
pub destination_literals: Vec<String>,
```

The existing `source_addresses` / `destination_addresses` (Vec<String>
of fully-expanded CIDRs) STAYS on the wire as the back-compat
channel for old-Rust binaries reading new-Go snapshots.

`ConfigSnapshot` (`protocol/snapshot.rs`) grows:

```rust
#[serde(rename = "address_books", default)]
pub address_books: Vec<AddressBookSnapshot>,
```

The `version` field stays at 3.

### 3.2 Go control plane

`pkg/dataplane/userspace/protocol.go`:

- Add `AddressBookSnapshot` struct.
- Add `SourceBookIDs []uint32`, `DestinationBookIDs []uint32`,
  `SourceLiterals []string`, `DestinationLiterals []string` to
  `PolicyRuleSnapshot` (all `,omitempty`).
- Add `AddressBooks []AddressBookSnapshot` to the wire snapshot
  envelope (`,omitempty`).
- **Do NOT bump `ProtocolVersion`.** Stays at 3.

`pkg/dataplane/userspace/policies.go`:

- New `buildAddressBookTable(cfg) ([]AddressBookSnapshot, map[string]uint32)`:
  - Walk `cfg.Security.AddressBook.Addresses` +
    `cfg.Security.AddressBook.AddressSets` in
    **lexicographic sorted order** of the map keys. Go map iteration
    is randomized; sorting is the HA determinism gate.
  - For each declared book name, fully expand to a canonical
    `(v4 CIDRs sorted by network bytes, v6 CIDRs sorted by network
    bytes)` tuple.
  - **"any" normalization (Codex r6 refinement)**: if a resolved
    address-book entry value is `"any"`, replace it with the pair
    `{ v4: "0.0.0.0/0", v6: "::/0" }` BEFORE canonicalization.
    This way book-content wire bytes are always concrete CIDR
    strings; the Rust side never sees `"any"` inside an
    `AddressBookSnapshot.prefixes_v*`, eliminating the "any
    inside a book" semantic-ambiguity case. Test
    `TestAddressBookContainingAnyNormalizesToZeroSlash` asserts
    this.
  - **Bucket by canonical CIDR-set bytes** (NOT by hash — see §5
    for why). Compute FNV-1a 64-bit hash per bucket as metadata.
    Each unique bucket → one `AddressBookSnapshot`; its `name` is
    the lexicographically smallest of the names whose canonical
    bytes are in the bucket; its `id` is derived from the bucket's
    hash (after collision recovery; see §5).
  - Return `(books []AddressBookSnapshot, nameToID
    map[string]uint32)`. Multiple names sharing a content hash all
    map to the same ID.
- Refactor `expandUserspacePolicyAddresses` into a new variant
  `classifyUserspacePolicyAddresses(cfg, nameToID, addrs)`:
  - Returns `(bookIDs []uint32, literals []string, legacyExpanded
    []string, ok bool)`.
  - For each entry in `addrs`:
    - If it's a recognized address-book / address-set name → append
      `nameToID[name]` to `bookIDs`.
    - If it's a literal CIDR / IP → append to `literals`.
    - If it's "any" → emit "any" into `literals` (matches existing
      behaviour; PrefixSetV4::MatchAny is built from "any" via the
      Rust side's `parse_address`).
    - `legacyExpanded` is the union of `literals` + the expansion of
      every named-book reference — identical to what
      `expandUserspacePolicyAddresses` returns today.
  - Per-rule `bookIDs` are sorted + deduped before being emitted
    (so wire output is canonical regardless of input order).

`pkg/dataplane/userspace/manager.go` (and `builder.go` where the
snapshot is assembled):

- Call `buildAddressBookTable` once per snapshot build.
- Populate `AddressBooks` on the wire snapshot.
- For each policy rule, populate `SourceBookIDs` /
  `DestinationBookIDs` (from named-book references),
  `SourceLiterals` / `DestinationLiterals` (from free-form CIDRs),
  AND `SourceAddresses` / `DestinationAddresses` (full legacy
  expansion, unchanged from today, for old-Rust back-compat).

### 3.3 Rust dataplane (`userspace-dp/src/policy.rs`)

- Add `BookEntry { v4: PrefixSetV4, v6: PrefixSetV6 }` (no `Arc`,
  flat-owned).
- `PolicyState` grows:
  - `books: Vec<BookEntry>` — dense table.
  - `book_id_to_idx: FxHashMap<u32, u32>` — wire-ID → dense index.
  - `u32` index throughout (future-proof for >65K books).
- `PolicyRule`:
  - Rename `source_v4` → `source_literal_v4`. Same for
    `destination_v4` / `source_v6` / `destination_v6`.
  - Add `source_book_idxs: SmallVec<[u32; 8]>` — inline cap of 8 to
    cover Codex's "p95 may exceed 4" concern.
  - Add `destination_book_idxs: SmallVec<[u32; 8]>`.
  - Add precomputed `source_v4_match_any: bool`,
    `source_v6_match_any: bool`, `destination_v4_match_any: bool`,
    `destination_v6_match_any: bool` (true iff EITHER the literal
    set OR any cited book is `MatchAny` on that family).

- `parse_policy_state_with_counters` grows a new parameter:
  `address_books: &[AddressBookSnapshot]`.

- **Book table build (HARD-FAIL on integrity errors)**:
  - First pass: iterate `address_books`. For each row:
    - If `row.id == 0`, hard-fail (0 is the reserved sentinel).
    - If `row.id` is already in `book_id_to_idx`, hard-fail (Go-
      side dedup bug).
    - **Parse via the new MatchNone-aware constructor**: build
      `entry.v4 = PrefixSetV4::from_v3_literals(prefixes_v4)` and
      `entry.v6 = PrefixSetV6::from_v3_literals(prefixes_v6)`.
      A v4-only book (empty v6 list) gets `entry.v6 = MatchNone`,
      NOT `MatchAny`. Likewise a v6-only book.
    - Push `BookEntry` to `state.books`; insert `(row.id,
      books.len() - 1)` into `book_id_to_idx`.
  - Hard-fail = return a snapshot-apply error from
    `parse_policy_state_with_counters` up through the
    snapshot-apply handler. The control plane retains the previous
    snapshot. This matches the existing version-mismatch failure
    mode at `userspace-dp/src/server/handlers/snapshot.rs:25`.
    The implementation MUST return BEFORE mutating
    `guard.snapshot` or publishing forwarding state — i.e. the
    parse-policy-state path becomes fallible (`Result<PolicyState,
    Error>`) and the snapshot handler propagates the error before
    any side-effect.

- **Per-rule build (v3-shaped predicate, FAIL-CLOSED safe)**:
  - Define `source_is_v3_shaped =
    !snap.source_book_ids.is_empty() || !snap.source_literals.is_empty()`.
    Same for destination.
  - **CRITICAL**: the literal-field selection is per-rule-per-side
    based on this predicate, NOT a global `address_books.is_empty()`
    check.
  - If `source_is_v3_shaped`: build the literal sets via a new
    helper `parse_v3_literal_set(source_literals: &[String]) ->
    (PrefixSetV4, PrefixSetV6)`:
    - Walk `source_literals`. For each token:
      - "any" → set `any_v4 = true` AND `any_v6 = true`.
      - CIDR / IP literal → push to the appropriate prefix vec.
      - "any4" / "any6" (future-proof): force MatchAny on one
        family. Not required by today's Junos syntax but supported.
    - At end: if `any_v4` → `source_literal_v4 = MatchAny`; else
      build via `PrefixSetV4::from_v3_literals(v4_prefixes)` which
      returns `MatchNone` on empty, `MatchAny` on `/0`, else
      `Linear` / `Trie`. Symmetric for v6.
    - **CRITICAL**: this fixes Codex r5 F-r5-1 — "any" in
      `source_literals` correctly produces `MatchAny`, not
      `MatchNone`.
  - Else (non-v3-shaped — legacy emitter): parse `source_literal_v4`
    from `source_addresses` via the existing
    `PrefixSetV4::from_prefixes`. Empty `source_addresses` still
    means "match any" — that's the legacy semantics this PR
    preserves.
  - `source_book_idxs` ← for each ID in `source_book_ids`:
    - sort + dedup the input IDs first;
    - if ID is in `book_id_to_idx`, append the index;
    - if ID is unknown (no matching `address_books` row):
      **HARD-FAIL the snapshot apply**, returning a snapshot-
      integrity error to the control plane. Junos compiler already
      rejects unresolved address-book references at
      `pkg/config/compiler.go:590`+ ; a dataplane-level "log+skip"
      could silently widen policy. Bail to the previous snapshot.
  - Precompute `source_v4_match_any` = true iff the **union** of
    the literal set + cited books would match any address. That is:
    - `source_literal_v4.is_match_any() == true`, OR
    - any cited book has `v4.is_match_any() == true`.
    `MatchNone` on the literal does NOT short-circuit `match_any`.
  - Symmetric: precompute `source_v4_match_none` = true iff the
    literal is `MatchNone` AND every cited book's v4 is
    `MatchNone`. Used to short-circuit "no source v4 criteria"
    rules at parse time — they immediately fail the v4 side of the
    match (returns None from `try_match_rule`).

  This eliminates the book-only fail-open path Codex r4 identified:
  a rule citing only books has `source_literal_v4 = MatchNone`, so
  `source_literal_v4.contains(src) = false`, and the union falls
  through to the book walk. Correct.

- **`try_match_rule`** (the hot path):

```rust
fn try_match_rule(rule: &PolicyRule, state: &PolicyState, ...) -> Option<...> {
    if rule.inactive { return None; }
    if !rule.compiled_apps.matches(protocol, src_port, dst_port) { return None; }

    let src_ok = match src_ip {
        IpAddr::V4(src) => rule.source_v4_match_any
            || rule.source_literal_v4.contains(src)
            || rule.source_book_idxs.iter()
                .any(|&i| state.books[i as usize].v4.contains(src)),
        IpAddr::V6(src) => /* mirror */,
    };
    if !src_ok { return None; }

    let dst_ok = /* mirror destination */;
    if !dst_ok { return None; }

    rule.hit_counter.add(packet_len);
    Some(PolicyEvaluationResult { action: rule.action, policy_id: rule.policy_id })
}
```

All book lookups are dense-index Vec accesses. No `Arc` deref.

`userspace-dp/src/afxdp/mod.rs`:
- Pass `&snapshot.address_books` to
  `parse_policy_state_with_counters`.

`userspace-dp/src/afxdp/forwarding_build/mod.rs:309-310`:
- Replace `rule.source_v4.prefix_count()` /
  `rule.destination_v4.prefix_count()` with an aggregate over
  `source_literal_v4` + indexed books. ~10 LOC.

`userspace-dp/src/prefix_set.rs`:
- Add `MatchNone` variant to both `PrefixSetV4` and `PrefixSetV6`.
  `contains()` on `MatchNone` returns `false`. `prefix_count()`
  returns 0. `is_match_none(&self) -> bool` helper.
- Add `is_match_any(&self) -> bool` helper.
- Add new constructor `from_v3_literals(prefixes)` that returns
  `MatchNone` on empty input (distinguishes "no criteria specified"
  from "match all"). The legacy `from_prefixes` factory keeps the
  empty=MatchAny convention (for the non-v3-shaped fallback path).
- This eliminates the book-only fail-open path: a v3-shaped rule
  citing only books has `source_literal_v4 = MatchNone`, so
  `source_literal_v4.contains(src) = false`, and the match-union
  correctly falls through to the book walk.

### 3.4 Cross-version compatibility (rolling upgrade)

Because the protocol version stays at 3, this is purely a
field-presence story:

| Combo                          | source_addresses | source_book_ids | source_literals | Behaviour |
|--------------------------------|------------------|-----------------|-----------------|-----------|
| Old Go (no new fields) → Old Rust | full expansion | absent          | absent          | unchanged |
| Old Go → New Rust              | full expansion   | absent          | absent          | new Rust falls through: `source_literal_v4` built from `source_addresses` (since `source_literals` is empty). |
| New Go → Old Rust              | full expansion   | ignored         | ignored         | old Rust uses `source_addresses` (unchanged). |
| New Go → New Rust              | (ignored at parse) | dense table | inline literals | full dedup win. |

Key invariant: **`source_literals` takes precedence over
`source_addresses` IFF `source_literals` is non-empty on the rule
(or `source_book_ids` is non-empty)**. If a rule has no books cited
AND no inline literals, the rule has nothing to match — back-compat
demands we fall through to `source_addresses` as before.

The exact predicate: a rule is "v3-shaped" iff
`!source_literals.is_empty() || !source_book_ids.is_empty()`.
For v3-shaped rules, new-Rust ignores `source_addresses`. For
non-v3-shaped rules, new-Rust falls through to `source_addresses`
(legacy parse). Same logic for destination, independently.

Old Go produces NO v3-shaped rules; new Go produces all v3-shaped
rules. There's no mixed-shape rule on a single side from a single
emitter.

### 3.5 Shim-removal followup (out of scope)

Follow-up PR (≥1 release later):
1. Drop Go-side `SourceAddresses` / `DestinationAddresses`.
2. Drop Rust-side fallback path.
3. Bump JSON `version` to 4 (with the corresponding RX-side check
   updated).

## 4. HA snapshot sync portability

`pkg/cluster/configsync` ships the same `ConfigSnapshot` JSON
between HA peers. Adding new JSON fields with `omitempty` / serde
defaults is HA-safe — the established pattern.

**Determinism gates** (see §5 for the algorithm):

- `cfg.Security.AddressBook.Addresses` and `.AddressSets` keys are
  iterated in lexicographic sorted order before any ID assignment.
- Collision-resolution loop is FULLY deterministic given a sorted
  input order.
- Unit test `TestAddressBookIDDeterministicAcrossMapOrder` constructs
  the same config with map keys inserted in 5 different orders
  and asserts the emitted `AddressBookSnapshot.id` array is
  IDENTICAL across all 5 builds.

**No new lock acquisitions on the hot path.** `PolicyState::books`
is `Vec<BookEntry>`. `PolicyState` is owned by `ForwardingState`,
published via the existing `ArcSwap` discipline at
`userspace-dp/src/afxdp/worker/mod.rs:976` (`load_arc_if_changed`).
The packet worker pins `Arc<ForwardingState>` once at the top of
each tick via `loop_body/mod.rs:58` (`shared_forwarding.load_full()`)
and packet matching reads from the pinned `&forwarding` reference.
Per-packet code never touches an atomic.

## 5. Content-hash interning algorithm

**Hash input** (with explicit framing to prevent v4/v6 cross-family
collisions):

```
"V4" || u32_be(v4_count) || (for each v4 prefix:
    u8(prefix_len) || u32_be(addr_bytes))
"V6" || u32_be(v6_count) || (for each v6 prefix:
    u8(prefix_len) || u128_be(addr_bytes))
```

v4 and v6 lists are sorted by `(prefix_len, addr_bytes)` before
serialization for canonicalization. The literal "V4" / "V6" tags +
the count prefixes prevent two distinct sets from canonicalizing to
the same byte stream (e.g. a single v4 /24 and a single v6 ::/24
would otherwise share the same raw `[24, ...]` if the addresses
happen to share the prefix bytes).

**Hash function**: FNV-1a 64-bit fold.

**Pre-hash input ordering**: book NAMES are iterated in lexicographic
sort order during bucket-by-content. This is the HA determinism
gate. Multiple names hashing to the same content → all map to the
same ID; the lexicographically smallest name becomes the diagnostic
`name` field on the wire.

**ID derivation**: `id = low_32(hash)` (no high-bit reservation —
we'd lose a bit of headroom without need). Special case: if
`id == 0`, set `id = 1`. ID 0 is reserved as "unused" by convention.

**Collision recovery**: when two DISTINCT content-hashes collide on
the low-32 bits:
- Probe sequence: `id_probe = ((hash >> 32) ^ low_32(hash)) + probe_count`,
  where `probe_count` starts at 1 and increments until a free ID is
  found. Wraps at u32. If `id_probe == 0`, set to 1.
- The probe sequence is deterministic given (hash, probe_count)
  AND a deterministic visit order across distinct unique content-
  hashes. Visit order is:
  1. **Bucket by canonical CIDR-set bytes**, NOT by full 64-bit
     hash. Multiple book NAMES sharing the same canonical bytes
     all map to the same bucket. (Codex r6 refinement: this
     handles the theoretically-possible 64-bit hash collision
     where two distinct canonical-byte streams produce the same
     FNV-1a 64-bit output. Buckets are keyed on canonical bytes
     so distinct content always lives in distinct buckets.)
  2. Compute full 64-bit FNV-1a hash on each bucket's canonical
     bytes; store as bucket metadata.
  3. Sort buckets by `(hash64, canonical_bytes)` ascending before
     entering the linear-probe ID-assignment loop. The
     `canonical_bytes` tie-break disambiguates the impossible-in-
     practice case where two distinct contents share a 64-bit
     hash; even if it ever happens, ID assignment is deterministic
     because byte-comparison is total.
  4. Within a bucket: the diagnostic `name` is the
     lexicographically smallest of the names that hashed to it.
- Hard termination: if probe_count > 256, hard-fail the snapshot.
  At 1M books in a 2^32 ID space, expected collision pairs ~116;
  probe length per affected book is tiny (load factor ≈ 1/4096),
  so cap of 256 is generous and effectively never trips.

**Collision math (32-bit hash, full birthday formula)**:
- 10K books: P(any collision) = 1 − exp(−1e8 / 2^33) ≈ 1.16%.
- 100K books: P ≈ 1 − exp(−1e10 / 2^33) ≈ 68.8%.
- 1M books: effectively certain (≈ expected 116 collision pairs).

Probe scheme: at load factor << 1 (1M entries in 2^32 space ≈ 1
in 4096), clustering is not an issue. Linear-probe-from-hash
walks an average of < 2 slots even at 1M scale. Probe cap of 256
is generous.

Updated v3 from earlier-version's understated math.

**Content-only identity**: two address-book DECLARATIONS with the
same canonical CIDR content share the same ID. The wire
`address_books` array contains ONE row per unique content; the row's
`name` field is the lexicographically smallest declaring name (for
diagnostics).

**Why content-hashing**: two configuration commits that re-declare
the same address book (rollback, equivalent rename) produce the
same wire ID. Enables #1607 (per-book Arc reuse across snapshots)
without code change to the Rust side.

## 6. Memory footprint — informational only, NOT a PR gate

The acceptance gate for this PR is wire-correctness + dedup-by-
construction. Memory numbers are measured but not gated.

Math against the existing `PrefixSetV4::Trie` (24-byte node +
jemalloc 32-byte bin):

- 100 random v4 /32 → ~2.6K nodes → ~83 KB per book.
- 100 random v6 /64 → ~5.6K nodes → ~180 KB per book.
- 1K random v4 /32 → ~24K nodes → ~770 KB per book.
- 1K random v6 /64 → ~56K nodes → ~1.79 MB per book.
- 10K books × 100 CIDRs (v4+v6) → ~2.6 GB.
- 10K books × 1K CIDRs → ~25 GB.

The issue's stated 200 MB gate at 10K × 1K is structurally
unachievable with the current binary trie. We comment on the issue
explaining the rescoping when the PR lands.

The memory win is **structural deduplication**: at 100K rules each
citing on average 3 books × 10K total books, the prefix tables now
scale as `O(book_count × per_book_size)` not
`O(rule_count × per_rule_avg_size)`. That's a 10×-100× memory
reduction depending on book reuse ratio.

Informational measurements (in `userspace-dp/tests/policy_scale.rs`,
gated `#[ignore]`):

- 10K books × 10 CIDRs × 100K rules → expect ΔVmRSS ≤ 500 MB.
- 10K books × 100 CIDRs × 100K rules → expect ΔVmRSS ≤ 3 GB.
- 10K books × 1K CIDRs × 100K rules → expect ΔVmRSS ≤ 30 GB
  (vs. 255 GB without dedup).

These run on-demand, not in CI.

## 7. Detailed change list

### Go (`pkg/dataplane/userspace/`)

1. `protocol.go` (+40 LOC):
   - Add `AddressBookSnapshot`.
   - Add four new fields to `PolicyRuleSnapshot`.
   - Add `AddressBooks` to the wire snapshot envelope.
   - **Do NOT bump `ProtocolVersion`.**

2. `policies.go` (+150 LOC):
   - `buildAddressBookTable(cfg) ([]AddressBookSnapshot,
     map[string]uint32)`.
   - `classifyUserspacePolicyAddresses(cfg, nameToID, addrs)`.
   - Sort + dedup per-rule `bookIDs` before emit.
   - Updated `buildPolicySnapshotsWithSchedulerState` to use the
     new classifier.

3. `manager.go` / `builder.go` (snapshot assembler, +30 LOC):
   - Call `buildAddressBookTable`.
   - Populate new wire fields.

4. `policies_test.go` (+300 LOC):
   - `TestAddressBookIDStability` — same config emits same IDs.
   - `TestAddressBookIDDeterministicAcrossMapOrder` — 5 different
     map-key insertion orders → identical wire output.
   - `TestAddressBookContentDedup` — two names, same content → one
     row in `address_books`, same ID, diag-name is the
     lexicographically smaller.
   - `TestAddressBookCollisionRecovery` — synthetic adversarial.
   - `TestPolicyBuildEmitsBookIDsAndLiterals`.
   - `TestPolicyBuildLegacyFieldStillExpanded` — old-Rust
     back-compat channel still populated.

### Rust (`userspace-dp/src/`)

1. `protocol/security.rs` (+30 LOC):
   - `AddressBookSnapshot`.
   - Four new fields on `PolicyRuleSnapshot`.

2. `protocol/snapshot.rs` (+3 LOC):
   - `address_books` on `ConfigSnapshot`.

3. `prefix_set.rs` (+50 LOC):
   - Add `MatchNone` variant to both `PrefixSetV4` and `PrefixSetV6`.
   - Add `is_match_any(&self) -> bool` and
     `is_match_none(&self) -> bool` on both types.
   - `contains()` on `MatchNone` returns `false`.
   - New constructor `from_v3_literals(prefixes: Vec<PrefixV*>)`:
     - Empty → `MatchNone` (v3 semantic).
     - `/0` present → `MatchAny`.
     - Else `Linear` / `Trie` as today.
   - Existing `from_prefixes(empty) -> MatchAny` stays intact for
     the non-v3 legacy fallback path.
   - `prefix_count()` on `MatchNone` returns 0.

4. `policy.rs` (~+200 LOC, ~−15 LOC):
   - `BookEntry`.
   - `PolicyState::books: Vec<BookEntry>` +
     `book_id_to_idx: FxHashMap<u32, u32>`.
   - `PolicyRule` renamed fields + new SmallVec fields +
     precomputed match-any bools.
   - `parse_policy_state_with_counters` becomes **fallible**
     (returns `Result<PolicyState, SnapshotIntegrityError>`). New
     `address_books` parameter; per-rule literal-field selection
     via "v3-shaped predicate"; book index resolution with
     duplicate/unknown/zero-ID hard-fail handling per §3.3.
   - Fallibility propagation scope (Codex r5 F-r5-2):
     - `build_forwarding_state` /
       `build_forwarding_state_with_policy_counters` /
       `build_forwarding_state_with_policy_counters_and_previous`
       in `forwarding_build/mod.rs` all become fallible (return
       `Result<ForwardingState, SnapshotIntegrityError>`).
     - `Coordinator::refresh_runtime_snapshot` in
       `afxdp/coordinator/mod.rs:454` checks the Result BEFORE
       mutating neighbor manager keys, validation, and policy
       counters. On error, propagates back up; no partial state.
     - `reconcile/snapshot.rs:apply` likewise validates the
       Result BEFORE applying validation and reconciling counters.
     - `snapshot.rs::apply` in `server/handlers/`: runs a
       **preflight build**: tries `build_forwarding_state(...)`
       FIRST, in a side-effect-free path, before mutating
       `guard.status.last_snapshot_generation`,
       `guard.status.last_fib_generation`,
       `guard.status.last_snapshot_at`, `guard.status.capabilities`,
       or `guard.status.bindings`. On preflight failure, return
       `ControlResponse { ok: false, error: "snapshot integrity
       error: ..." }`. The guard's existing snapshot stays.
   - `try_match_rule` new dense-index walk; consumes the
     `state: &PolicyState` reference so books are addressable.

5. `policy_tests.rs` (+250 LOC):
   - `test_book_table_dedup_by_index`.
   - `test_match_book_union_with_literal`.
   - `test_match_any_short_circuit`.
   - `test_v3_shaped_predicate_ignores_legacy_field`.
   - `test_non_v3_shaped_falls_through_to_legacy_field`.
   - `test_unknown_book_id_hard_fails_snapshot` (changed from
     skip-not-fatal per Codex r3 F2; matches Junos
     compiler-rejects-unresolved semantics).
   - `test_duplicate_address_book_id_hard_fails_snapshot`.
   - `test_book_id_zero_hard_fails_snapshot`.
   - `test_per_rule_duplicate_book_ids_are_deduped`.
   - `test_book_only_rule_does_not_fail_open` — rule with
     non-empty `source_book_ids` + empty `source_literals` parses
     `source_literal_v4 = MatchNone` (via the new
     `from_v3_literals` constructor). Match path then ONLY matches
     IPs covered by the cited books — IPs outside the books do
     NOT match. Without `MatchNone`, the empty-literal would have
     been `MatchAny` (legacy `from_prefixes` semantics) and the
     rule would have matched ALL traffic.
   - `test_pure_any_rule_with_address_books_present` — a rule with
     ALL empty new fields (book_ids + literals) when
     `address_books.is_empty()` is false (some OTHER rule cites
     books): is correctly treated as non-v3-shaped and falls
     through to `source_addresses`. Without the per-rule
     predicate, this would fail open.
   - `test_v4_v6_canonical_framing_no_cross_family_collision` —
     constructs two distinct books (one v4-only, one v6-only)
     whose raw bytes would collide WITHOUT the V4/V6 framing
     prefix; assert their IDs differ.
   - `test_v4_only_book_does_not_match_v6_traffic` — a v4-only
     book has `entry.v6 = MatchNone`; a rule citing only this book
     must NOT match v6 packets. Closes the family-incomplete-book
     fail-open path Codex r4 identified.
   - `test_v6_only_book_does_not_match_v4_traffic` — symmetric.
   - `test_v3_shaped_any_token_matches_all_v4_and_v6` — closes
     Codex r5 F-r5-1: a v3-shaped rule with
     `source_literals=["any"]` must match all v4 AND all v6
     traffic, not fail closed via MatchNone.
   - `test_v3_shaped_any4_token_matches_all_v4_only` (future-
     proof; can be `#[ignore]` if Junos syntax doesn't support).
   - `test_snapshot_preflight_rejects_unknown_book_id` — preflight
     `build_forwarding_state` on a snapshot with unknown book ID
     returns Err; the snapshot handler does NOT mutate
     `guard.status.last_snapshot_generation` etc.
   - `test_snapshot_preflight_rejects_duplicate_book_id` —
     similar.
   - Plus signature updates for all existing tests that call
     `parse_policy_state_with_counters` / `parse_policy_state`.

6. `afxdp/mod.rs` (+5 LOC):
   - Pass `&snapshot.address_books` to
     `parse_policy_state_with_counters`.

7. `afxdp/forwarding_build/mod.rs` (~+40 LOC):
   - Make `build_forwarding_state*` family fallible
     (Result<ForwardingState, SnapshotIntegrityError>).
   - Replace `rule.source_v4.prefix_count()` at line 309-310 with
     aggregate across `source_literal_v4` + indexed books.
   - Add `SnapshotIntegrityError` type (or reuse an existing
     error type; check `src/error.rs` if it exists).

8. `afxdp/coordinator/mod.rs:454-485` (+20 LOC):
   - `refresh_runtime_snapshot` propagates the fallible
     forwarding-state build. On error, returns/logs without
     mutating coordinator state.

9. `afxdp/coordinator/reconcile/snapshot.rs` (+15 LOC):
   - `apply` does a preflight forwarding-state build before
     side-effecting mutations.

10. `server/handlers/snapshot.rs` (+25 LOC):
    - Preflight `build_forwarding_state(...)` BEFORE the existing
      `guard.status.*` mutations at lines 37-41.
    - On preflight failure, return `ControlResponse { ok: false,
      error: "snapshot integrity error: ..." }` without touching
      the guard.

8. `Cargo.toml`:
   - Add `smallvec = "1.13"` (verify not already present).

### Docs

1. `docs/userspace-jit-design.md` (Phase 3 row): note that wire
   format for book sharing landed in #1606; trie compaction
   (DIR-24-8) deferred to #1608.

2. `docs/per-rule-policy-memory.md` (new, ~80 LOC): memory math,
   content-hash ID scheme with sort-by-name gate, deduplication
   test, deferred DIR-24-8 work.

## 8. Test plan

### Unit (Rust)

- All existing 600+ policy tests pass after signature updates.
- New tests above. 5× flake loop on each new test.

### Unit (Go)

- All existing `pkg/dataplane/userspace` tests pass.
- New tests above. `TestAddressBookIDDeterministicAcrossMapOrder` is
  the HA-correctness gate.

### Synthetic memory smoke (informational, `#[ignore]`)

As §6. Run on demand; not in CI.

### Smoke (loss userspace cluster)

`make cluster-deploy` (default `loss-userspace-cluster.env`) →
`./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0` →

Pass A (CoS off):
- iperf3 to 172.16.80.200, -P 12 (push), 60s — 0 retrans.
- iperf3 to 172.16.80.200, -P 12 -R (reverse), 60s — 0 retrans.
- iperf3 to 2001:559:8585:80::200, -P 12, 60s.
- iperf3 to 2001:559:8585:80::200, -P 12 -R, 60s.

Pass B (CoS on, per-class ports 5201-5206):
- All four directions × six classes.

Gates: zero retrans, throughput within ±5% of master baseline.

### HA failover

`make test-failover` — must remain ≤ 60ms with no session loss.

## 9. Rollback

Pure code rollback is `git revert` clean — no schema migration.
Because the protocol version is unchanged (still 3), old and new
binaries can be mixed in either direction.

## 10. Followups (out of scope)

1. **Shim-removal PR** — bump version to 4, drop legacy
   `source_addresses` / `destination_addresses` fields, drop
   Rust-side fallback path. Ships ≥ 1 release after #1606.

2. **DIR-24-8 / Patricia sparse LPM (#1608)** — replace the binary
   trie. Pre-requisite for 1M-rule line-rate gate.

3. **Per-book reuse across snapshots (#1607)** — keep
   process-lifetime cache of `BookEntry` keyed on book ID for fast
   apply at 10K-book scale.
