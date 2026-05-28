# #1623 Path B narrow — PolicyRule parallel-prefix arrays

**Status:** DRAFT v2 — Claude SMR r1 self-review folded; pending Codex + AGY adversarial plan review

Revision history:
- v1: initial draft.
- v2: addresses Claude SMR r1 PLAN-NEEDS-MINOR findings F-SMR-r1-1
  (document 1M-rule replication as accepted cost), F-SMR-r1-2
  (Default impl uses `Arc::<[T]>::default()` to share global empty
  Arc), F-SMR-r1-4 (quantitative `size_of` note), F-SMR-r1-6
  (clarify book_idxs sort order).

## 1. Issue framing

Issue #1623 tracks the residual work from #1609 (multi-stage policy
decision DAG) after the v3.x architectural round hit a fourth
consecutive PLAN-NEEDS-MAJOR / PLAN-KILL on the Multi-Book LPM axis.
The full LPM / Stage 2/3/4 / PseudoBook design has been deferred
indefinitely pending #1622 empirical numbers on 10K/100K/1M-rule
cold-path latency.

User has authorized a **narrow Path B**: extend `PolicyRule` with
parallel-prefix arrays (`prefixes_v4: Arc<[PrefixV4]>` +
`prefixes_v6: Arc<[PrefixV6]>`), populated at parse-time exactly the
way #1624 (PR for #1609 Step 1) extended `BookEntry`. This is the
AGY r2 #1 simplification line item from #1623 — "parallel
`prefixes_v4/v6: Arc<[Prefix]>` on PolicyRule (same shape as
BookEntry from #1609 Step 1)".

The scope is foundational scaffolding only. The fields are populated
but consumed nowhere. A future #1623 v4 design round may consume them
when (and if) the architectural axis converges.

## 2. Honest scope / value framing

Absolute scale of the win at this PR: **zero runtime cycles, zero
bytes saved, zero retransmits avoided**. The new fields:

- Add 32 bytes per `PolicyRule` (two 16-byte `Arc<[T]>` fat pointers).
- Allocate twice per parse pass per rule (`Arc::from(slice)` for each
  family). Parse time scales O(rules × literals + rules × cited-book-prefixes).
- Are read by NO hot-path code in this PR.

The value is purely structural — it materializes the per-rule
canonical prefix list at parse time so a future LPM builder can
consume it without re-walking trie-compressed `PrefixSet` values.
This matches the exact shape `BookEntry` already carries since
#1624 (`d339b69f8`).

**If reviewers conclude that materializing dead-storage fields
without a concrete consumer is not worth the parse-time cost and
churn, PLAN-KILL is an acceptable verdict.** The #1624 BookEntry
precedent shipped clean with a 4-of-4 attestation, so the prior is
favorable, but this is still 32 bytes + two allocations per rule of
pure foundation work.

### 2.1 Accepted costs (per Claude SMR r1 F-SMR-r1-1)

- **1M-rule book-prefix replication (~80 MB at 1M cited-book-only
  rules with a 10-prefix book).** A rule that cites a book today
  references the book by dense index; with parallel arrays it
  additionally carries a *copy* of the book's prefixes. The
  alternative shape (`SmallVec<[Arc<[PrefixV4]>; 4]>` to share
  storage with `BookEntry.prefixes_v4`) diverges from the #1624
  flat-Arc contract and forces the future LPM builder to fan
  out across multiple Arc refs. Plan v2 accepts the replication
  cost as a deferred optimization to be revisited if #1622
  measurements show parse-time allocation pressure or memory
  footprint regression at 1M rules. This is foundation
  scaffolding — the simple shape wins now, and the future LPM
  builder + #1622 measurements decide the optimization later.

## 3. Precedent — #1624 BookEntry parallel arrays

PR #1624 (squash `d339b69f8`) extended `BookEntry`:

```rust
pub(crate) struct BookEntry {
    pub(crate) v4: PrefixSetV4,
    pub(crate) v6: PrefixSetV6,
    pub(crate) prefixes_v4: Arc<[PrefixV4]>,  // NEW
    pub(crate) prefixes_v6: Arc<[PrefixV6]>,  // NEW
}
```

Population at `parse_policy_state_with_counters` after the literal
parse loops, BEFORE moving the Vecs into `from_v3_literals`:

```rust
let prefixes_v4: Arc<[PrefixV4]> = Arc::from(v4.as_slice());
let prefixes_v6: Arc<[PrefixV6]> = Arc::from(v6.as_slice());
let entry = BookEntry {
    v4: PrefixSetV4::from_v3_literals(v4),
    v6: PrefixSetV6::from_v3_literals(v6),
    prefixes_v4,
    prefixes_v6,
};
```

Six unit tests in `policy_tests.rs` lines 1015-1280 covering: empty
book, v4-only, v6-only, dual-family, /0 preserved, trie-variant
(17+ prefixes), /0-plus-non-/0 preserved.

This PR mirrors that exact pattern for `PolicyRule`.

## 4. Concrete design

### 4.1 Struct extension

Add two fields to `PolicyRule` (currently `userspace-dp/src/policy.rs`
lines 122-155):

```rust
pub(crate) struct PolicyRule {
    // ... existing fields ...
    pub(crate) source_literal_v4: PrefixSetV4,
    pub(crate) source_literal_v6: PrefixSetV6,
    pub(crate) destination_literal_v4: PrefixSetV4,
    pub(crate) destination_literal_v6: PrefixSetV6,
    pub(crate) source_book_idxs: SmallVec<[u32; 8]>,
    pub(crate) destination_book_idxs: SmallVec<[u32; 8]>,

    // #1623 Path B narrow — parallel canonical prefix arrays for
    // the future Multi-Book LPM builder. NOT consumed by the
    // hot path in this PR. Populated at parse-time mirroring the
    // #1624 BookEntry precedent.
    pub(crate) source_prefixes_v4: Arc<[PrefixV4]>,
    pub(crate) source_prefixes_v6: Arc<[PrefixV6]>,
    pub(crate) destination_prefixes_v4: Arc<[PrefixV4]>,
    pub(crate) destination_prefixes_v6: Arc<[PrefixV6]>,

    // ... rest ...
}
```

`Default` and `Clone` impls extended to cover these. `Default` uses
`Arc::from(&[][..])` (empty slice) for each.

### 4.2 Semantic contract for the parallel arrays

The arrays carry the union of:

1. Literal CIDRs parsed from the rule itself
   (`snap.source_literals` / `snap.source_addresses` depending on
   shape), AND
2. The full prefix list of every cited address book
   (`state.books[i].prefixes_v4` / `prefixes_v6` for each
   `i ∈ source_book_idxs`).

A rule with `source any` (no literals, no books) gets an EMPTY
array. The existing `source_v4_match_any` / `source_v6_match_any`
boolean flags continue to signal "any" semantics; the parallel
array does NOT carry an explicit `0.0.0.0/0` synthetic entry. This
matches the #1624 BookEntry decision (parallel arrays preserve
input, do not synthesize markers).

**Why mirror the #1624 contract exactly:** synthesizing `[0.0.0.0/0]`
for the any-side case would diverge from BookEntry semantics and
require future LPM builder code to handle two conventions. Keeping
the parallel array as the union of *input* prefixes (literal +
cited-book) preserves the invariant "parallel arrays carry input
prefix shape verbatim; MatchAny is communicated via the dedicated
boolean flag". Per-rule `any` is structurally identical to
"empty literal set + zero cited books" — the future LPM builder
treats both via the MatchAny short-circuit per plan §2.1, NOT via
a synthetic /0 entry.

### 4.3 Population at parse-time

Inside `parse_policy_state_with_counters` (currently lines 477-560
of `policy.rs`), after the literal parse and book-idx resolve but
before the `PolicyRule { ... }` construction, materialize the
union arrays:

```rust
// #1623 Path B: materialize canonical per-rule prefix arrays.
// Union of (literal CIDRs parsed for this side) + (every prefix
// of every cited book on this side).
let source_prefixes_v4 = collect_rule_side_prefixes_v4(
    &snap.source_addresses,
    &snap.source_literals,
    source_is_v3_shaped,
    &source_book_idxs,
    &state.books,
);
let source_prefixes_v6 = collect_rule_side_prefixes_v6(
    &snap.source_addresses,
    &snap.source_literals,
    source_is_v3_shaped,
    &source_book_idxs,
    &state.books,
);
let destination_prefixes_v4 = collect_rule_side_prefixes_v4(
    &snap.destination_addresses,
    &snap.destination_literals,
    destination_is_v3_shaped,
    &destination_book_idxs,
    &state.books,
);
let destination_prefixes_v6 = collect_rule_side_prefixes_v6(
    &snap.destination_addresses,
    &snap.destination_literals,
    destination_is_v3_shaped,
    &destination_book_idxs,
    &state.books,
);
```

Helper signatures (private to `policy.rs`):

```rust
fn collect_rule_side_prefixes_v4(
    addresses: &[String],
    literals: &[String],
    is_v3_shaped: bool,
    book_idxs: &SmallVec<[u32; 8]>,
    books: &[BookEntry],
) -> Arc<[PrefixV4]> {
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6_scratch: Vec<PrefixV6> = Vec::new();
    if is_v3_shaped {
        for tok in literals {
            match tok.as_str() {
                // v3 "any" / "any4" / "any6" tokens do NOT contribute
                // prefixes — match-any is communicated via the
                // existing source_v{4,6}_match_any flags.
                "any" | "any4" | "any6" | "" => {}
                s => parse_literal_cidr_into(s, &mut v4, &mut v6_scratch),
            }
        }
    } else {
        for prefix in addresses {
            parse_address(prefix, &mut v4, &mut v6_scratch);
        }
    }
    for &idx in book_idxs.iter() {
        let book = &books[idx as usize];
        v4.extend_from_slice(&book.prefixes_v4);
    }
    Arc::from(v4.as_slice())
}
// Symmetric for v6 — drop v4 scratch, capture v6.
```

**Ordering note (Claude SMR r1 F-SMR-r1-6 clarified):** The arrays
are NOT sorted, NOT deduped. They carry "union of input prefixes in
the following order:
1. The rule's own literal CIDRs in `snap.source_literals` /
   `snap.source_addresses` order (whichever shape applies).
2. Each cited book's `BookEntry.prefixes_v4` (or `prefixes_v6`),
   walked in the order of `source_book_idxs` /
   `destination_book_idxs`. Note that `resolve_book_idxs()` already
   `sort_unstable() + dedup()`s the input IDs into dense-index
   ascending order, so cited-book contributions appear in
   ascending dense-index order regardless of the operator's
   declared `source_book_ids` order. This stability is asserted
   by `test_policy_rule_book_only_rule_inherits_book_prefixes`.

The future LPM builder is free to sort/dedup as needed. This PR
makes no correctness claim about ordering beyond the above — it
matches the #1624 BookEntry contract (which also does not sort).

### 4.4 Default impl (Claude SMR r1 F-SMR-r1-2: share global empty Arc)

```rust
impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            // ... existing fields ...
            source_prefixes_v4: <Arc<[PrefixV4]>>::default(),
            source_prefixes_v6: <Arc<[PrefixV6]>>::default(),
            destination_prefixes_v4: <Arc<[PrefixV4]>>::default(),
            destination_prefixes_v6: <Arc<[PrefixV6]>>::default(),
            // ...
        }
    }
}
```

`<Arc<[T]>>::default()` returns the canonical empty Arc — the
implementation in `alloc::sync` returns an Arc constructed from an
empty `Box<[T]>` (single allocation per `default()` call in
current stable Rust; std does NOT yet share a single global empty
Arc across all callers, but the allocation is a 24 B header with
no payload). Using `default()` avoids the explicit
`Arc::from(&[][..])` call site repeated four times and inherits
whatever optimization std applies in the future.

`BookEntry` derives `Default` via the field-level
`Arc<[T]>: Default` blanket impl — same result. Mirrors the
#1624 BookEntry precedent.

### 4.5 Clone impl

Add the four fields to the manual `Clone` impl (lines 187-212).
Each is a single `Arc` ref-count bump:

```rust
source_prefixes_v4: self.source_prefixes_v4.clone(),
source_prefixes_v6: self.source_prefixes_v6.clone(),
destination_prefixes_v4: self.destination_prefixes_v4.clone(),
destination_prefixes_v6: self.destination_prefixes_v6.clone(),
```

## 5. Public API preservation

`PolicyRule` is `pub(crate)`, so no public Rust API surface is
touched. The wire protocol (`PolicyRuleSnapshot` in
`protocol/security.rs`) is NOT modified — these fields are
in-memory only, populated from the existing wire fields.

`evaluate_policy()` (lines 670+) is NOT modified. The new fields
are populated and dropped; the hot path reads only the existing
`PrefixSetV{4,6}` + book table + match-any flags.

No Go-side changes. The Go control plane already serializes the
existing `source_book_ids` / `source_addresses` / `source_literals`
fields, and that wire shape is unchanged.

## 6. Hidden invariants this change must preserve

- **Hot path zero-touch.** `evaluate_policy()` and every function
  called per packet must not reference the new fields. Verify with
  `grep prefixes_v[46]` after implementation: hits only in
  `parse_policy_state_with_counters` + struct definitions + tests.
- **PolicyRule cloneability.** `PolicyState` clones rules on
  reconcile_rules; the new Arc fields are clone-cheap (ref-count
  bump) but must be in the manual `Clone` impl.
- **MatchAny semantics unchanged.** The existing
  `source_v{4,6}_match_any` / `destination_v{4,6}_match_any`
  booleans are the SOLE signal for any-side semantics. Parallel
  arrays do NOT participate in policy evaluation.
- **Default impl correctness.** `PolicyRule::default()` returns
  rules with empty parallel arrays AND `..._match_any = true`
  (existing). This is consistent — the default-constructed rule
  matches any address but carries no canonical prefix shape.
- **Parse-time allocation cost.** Each parse pass allocates 4 Arcs
  per rule (4 sides × 4 family-arrays = 4 Arc headers + payload).
  For 1K rules: 4K allocs at parse time, < 1MB total. Acceptable.
  Hot path: zero new allocs.
- **HA sync portability.** PolicyState is rebuilt from
  `PolicyRuleSnapshot` (wire format) on every reconcile; the new
  fields are derived from existing wire fields, so HA sync
  semantics are unchanged.

## 7. Risk assessment

| Class | Risk | Reasoning |
|-------|------|-----------|
| Behavioral regression | LOW | Hot path untouched. New fields populated but read nowhere. |
| Lifetime / borrow-checker | LOW | `Arc<[T]>` is `'static`, `Clone`, `Send + Sync`. Mirrors #1624 BookEntry. |
| Performance regression | LOW–MED | Parse-time: O(rules × prefixes) extra work + 4 Arcs/rule. Cold path. Reconcile-on-config-change only. |
| Architectural mismatch | LOW | This is foundation work the future LPM builder needs. If the builder never ships, the cost is 32B/rule + dead allocations — small. #1624 precedent already lives in master uncontested. |

The non-trivial risk is the `Default` impl breaking codepaths that
construct partial `PolicyRule { ..PolicyRule::default() }` and
rely on parallel-array fields existing — but this only matters if
something reads them, which is exactly what we're banning. Grep
post-impl confirms.

## 8. Test plan

### 8.1 New unit tests in `policy_tests.rs`

Six tests mirroring the #1624 BookEntry test suite:

1. `test_policy_rule_carries_canonical_prefix_lists_v4` — rule
   with three v4 literal CIDRs + one cited book (one v4 prefix);
   assert `source_prefixes_v4.len() == 4` and every entry
   "round-trips" through the matching `PrefixSet` (i.e.
   `source_literal_v4.contains(p.addr()) ||
    book.v4.contains(p.addr())`).
2. `test_policy_rule_carries_canonical_prefix_lists_v6` — same
   shape, v6 only.
3. `test_policy_rule_carries_canonical_prefix_lists_dual_family`
   — both v4 + v6 literals, single book contributing both.
4. `test_policy_rule_any_source_has_empty_parallel_arrays` —
   rule with `source_literals: ["any"]`, no books, no
   addresses. Assert `source_prefixes_v4.is_empty()` AND
   `source_prefixes_v6.is_empty()` AND
   `source_v4_match_any == true` AND
   `source_v6_match_any == true`. Demonstrates the
   "any communicated via flag, not synthetic /0" contract.
5. `test_policy_rule_book_only_rule_inherits_book_prefixes` —
   rule with `source_book_ids: [N]`, empty `source_literals`.
   Assert the rule's `source_prefixes_v4` equals the book's
   `prefixes_v4` in length AND content.
6. `test_policy_rule_destination_side_independent_from_source` —
   rule with different source vs destination shape (e.g. source
   is `any`, destination is two literal CIDRs). Assert source
   arrays are empty AND destination arrays carry the two
   literals.

### 8.2 Cargo gates

```bash
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release 2>&1 | tail -3
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release 2>&1 | tail -3
# 5x flake check on the broadest new test
for i in 1 2 3 4 5; do
  TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo \
    cargo test --release test_policy_rule_ 2>&1 | grep "test result" | tail -1
done
```

### 8.3 Go gates

```bash
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./... 2>&1 | grep -v "^ok\|^?" | tail
```

Expected: no Go-side changes, all Go tests pass unchanged.

### 8.4 Smoke matrix on `loss:xpf-userspace-fw0/fw1`

Per SKILL.md Step 6 Pass A (CoS off) + Pass B (CoS on): v4 + v6 ×
push + reverse × 1 + 12 streams + per-class 5201-5206. Expected:
identical numbers to master — this is a zero-hot-path-touch PR.

### 8.5 `make test-failover`

Not required — no HA-visible state touched (the parallel arrays
live in `PolicyState` which is rebuilt on every config apply on
both nodes independently from the same wire snapshot).

## 9. Out of scope (explicitly)

- **NO Multi-Book LPM.** The whole DAG / Stage 2/3/4 / DIR-24-8 /
  bounded multibit trie / galloping merge work is deferred to
  #1623 v4 (which may never happen if #1622 numbers don't
  motivate it).
- **NO PseudoBook materialization.** The plan §2.2 PseudoBook
  scheme is not implemented in this PR.
- **NO feature flag.** There's no consumer; no flag needed.
- **NO hot-path changes.** `evaluate_policy()` is byte-for-byte
  identical.
- **NO wire-protocol changes.** `PolicyRuleSnapshot` is unchanged.
- **NO `pkg/cluster/`, `pkg/policy/`, or Go-side compiler
  changes.** Pure Rust-side in-memory extension.
- **NO sort / dedup of parallel arrays.** Order matches input
  parse order (literals first, then cited-book prefixes in
  book_idxs order), no dedup. Future LPM builder owns sort/dedup.

## 10. Open questions for adversarial review

1. **Construction-order semantics.** Should the parallel arrays
   be sorted + deduped at parse-time (cheaper for the future LPM
   builder), or kept as raw input concatenation (matches #1624
   BookEntry semantics, which also does NOT sort)? Plan picks
   raw input order to match #1624 — is that the wrong call?
2. **`any` semantics.** When `source_literals: ["any"]`, should
   `source_prefixes_v4` carry an explicit `[0.0.0.0/0]` synthetic
   entry, or stay empty (with `source_v4_match_any` as the sole
   signal)? Plan picks empty + flag (matches §4.2 invariant).
   Is the synthetic-/0 approach actually preferable for an LPM
   builder that needs to route /0 through a short-circuit?
3. **Cache-line impact.** Approximate field-by-field accounting
   on x86_64 (rustc stable):
   - rule_id: 24 B (String)
   - policy_id: 4 B (u32, +4 B pad)
   - from_zone, to_zone, scheduler_name: 3 × 24 B = 72 B (Strings)
   - inactive: 1 B (+ 7 B align pad)
   - 4 × PrefixSet{V4,V6} enum: roughly 4 × ~32 B = 128 B (enum
     tag + largest variant, depends on `PrefixSetV4` shape —
     `Linear` carries Vec, `Trie` carries Box<...>, so ~24-32 B)
   - 2 × SmallVec<[u32; 8]>: 2 × ~40 B = 80 B (8 inline u32 = 32 B
     + len/cap discriminant header ~8 B)
   - 4 × bool match_any: 4 B (+ 4 B pad)
   - applications: Vec<ApplicationMatch> = 24 B
   - compiled_apps: CompiledApplications = ~56 B (bool + FxHashMap)
   - action: enum = 1 B (+ 7 B pad)
   - hit_counter: Arc<...> = 8 B

   Rough total before: ~430 B (≈ 7 cache lines on 64 B lines).

   **Post-change:** +4 × 16 B = +64 B → ~494 B (≈ 8 cache lines).
   The struct already straddles multiple cache lines today.
   `evaluate_policy()` reads (per call): action, applications +
   compiled_apps, the four PrefixSet fields, the four match-any
   bools. These are scattered across lines 1-6 today and will
   remain so post-change. The new fields land at the end of the
   struct (lines 7-8) and are NOT read by `evaluate_policy()` by
   contract. Cache-line touch count for a policy hit: UNCHANGED.

   The honest concern: a future LPM-builder consumer of these
   fields would touch lines 7-8 once at LPM build time per
   PolicyState reconcile — cold path, not packet path.
4. **Allocation pressure on large rule sets.** At 1M rules
   (#1622 target), this adds 4M Arc allocations per parse pass
   PLUS the payload bytes (1M × N prefixes × 8 B v4 / 24 B v6).
   For an all-cited-book rule with no literals and 1 cited
   `internal` book (10 prefixes), that's 1M × (10 × 8) = 80 MB
   for the v4 payload alone, replicated to every rule that
   cites the book even though the Arc COULD have shared the
   book's `prefixes_v4` directly. **Should the parallel array
   instead be a `SmallVec<[Arc<[PrefixV4]>; 4]>` of references
   to each contributing source (per-rule literals as one Arc,
   each cited book's `prefixes_v4` as one Arc by clone)?** That
   would share storage with the book table and avoid the 80 MB
   replication at 1M rules. Plan picks the simpler #1624-mirror
   shape because the future LPM builder semantics aren't pinned
   yet, but this is an honest concern; PLAN-KILL is acceptable
   on this axis.
5. **Empty-arc footprint vs `Option<Arc<[T]>>`.** Empty
   `Arc::from(&[][..])` still allocates the Arc header (24 B on
   x86_64). For all-`any` rules that's 4 × 24 = 96 B of waste
   per rule, times 1M rules = 96 MB. Should the field be
   `Option<Arc<[PrefixV4]>>` with `None` meaning "use the
   match-any flag", so the all-any rules pay zero allocations?
   #1624 BookEntry chose `Arc<[T]>` not `Option<Arc<[T]>>` —
   should this PR diverge from that precedent?

## 11. Status / decision summary

- **Author position:** Mirror #1624 BookEntry shape exactly,
  including raw-input ordering and `Arc<[T]>` (not
  `Option<Arc<[T]>>`). The #1624 precedent shipped clean
  under adversarial quad-review and any divergence here would
  fragment the parallel-arrays convention.
- **Hostile axes Q4 and Q5 are the open architectural risks**
  (1M-rule allocation pressure vs reference-shared shape;
  empty-Arc footprint vs Option). Either could justify
  PLAN-NEEDS-MAJOR; on the narrowest read of "match #1624
  exactly", neither is a structural blocker because #1622
  empirical numbers are not yet in and we cannot know whether
  any consumer of these arrays will ship.
- **PLAN-KILL pressure is low** because the change is small
  (~50 LOC + tests) and the precedent is in master. But
  PLAN-KILL is acceptable if reviewers conclude this is dead
  storage with no path to a consumer.

