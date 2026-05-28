# #1623 Path B narrow — PolicyRule parallel-prefix arrays

**Status:** DRAFT v5 — Codex r3 PLAN-NEEDS-MINOR + AGY r3 PLAN-READY + Claude SMR r4 folded; ready to implement

Revision history:
- v1: initial draft.
- v2: addresses Claude SMR r1 PLAN-NEEDS-MINOR findings.
- v3: addresses Codex r1 PLAN-NEEDS-MAJOR (F1-F7) + AGY r1 PLAN-NEEDS-MINOR (F1-F4) + Claude SMR r2.
- v5: addresses Codex r3 PLAN-NEEDS-MINOR + AGY r3 PLAN-READY + Claude SMR r4:
  - **Arc construction:** `Arc::from(lit_vec.into_boxed_slice())` → `Arc::from(lit_vec)`. Codex r3 correctly noted that `Arc<[T]>` allocates its own ref-counted allocation and moves elements out of the Vec; the `into_boxed_slice()` step adds a wasted shrink-to-fit realloc before Arc allocates. Direct `Arc::from(Vec<T>)` (impl since Rust 1.45) is correct.
  - **Add test 18 literal-/0-plus-non-/0** (Codex r3 finding 1) — rule with `source_literals: ["0.0.0.0/0", "10.0.0.0/8"]` (LITERAL both, NOT `any` token). Assert `source_prefixes_v4 = Some([/0, /8])` AND `source_v4_match_any = true` (PrefixSet collapses to MatchAny due to /0 presence).
  - **Add test 19 duplicate preservation** (Codex r3 finding 1) — rule with literal `10.0.0.0/8` AND a cited book that also contains `10.0.0.0/8`. Assert the parallel array contains the prefix TWICE (literal once + book once), confirming the "no dedup at this layer" invariant from §4.3.
  - **Fix `PrefixV4` / `PrefixV6` size accounting** (Codex r3 finding 3 + Codex r2-code 2026-05-28 self-consistency correction): `PrefixV4` is `u32 addr + u32 mask + u8 prefix_len + pad = 12 B`. `PrefixV6` is `u128 addr + u128 mask + u8 prefix_len + pad = 48 B` (16-byte alignment; NOT 24 B as v4 §2.1 originally claimed; NOT 40 B as v5/v6 transitional estimates wrongly claimed). Update accounting.
  - **`size_of` assertion implementation** (AGY r3 + Codex r3): use compile-time `const _: [(); 16] = [(); std::mem::size_of::<...>()];` pattern inside test 13 to avoid the static_assertions crate dependency.

- v4: addressed Codex r2 PLAN-NEEDS-MINOR + AGY r2 PLAN-NEEDS-MINOR + Claude SMR r3:
  - **Drop `..PolicyRule::default()` from parse constructor** (AGY r2 D + Codex r2): pre-declare `applications` + `compiled_apps` locals; constructor names every field explicitly.
  - **Arc construction via `.into()` from Vec** (Codex r2 B): `Arc::from(lit_vec)` reuses the Vec's allocation; `Arc::from(lit_vec.as_slice())` would re-copy.
  - **Honest populated-rule cost accounting** (Codex r2 D): per Arc adds 16 B (strong+weak counters) + 8 B (slice length) + 8 B (allocator overhead) on top of the 8 B payload per PrefixV4. Realistic 1M-rule footprint estimate: +250-500 MB.
  - **Consumer contract: match_any DOMINATES** (Codex r2 B): make explicit that match_any=true makes the parallel array purely diagnostic — never narrows the rule.
  - **Test expansion 11 → 17 tests** (Codex r2 C + AGY r2 F): adds any+book book-only with match_any AND Some(arr), book empty v4 non-empty v6, rule-level zero-plus-non-zero, destination book path, duplicate preservation, book /0+non-/0, empty-book yields None, size_of static assertion.
  - **Plan §10 Q6 typo fix** (Codex r2 B): `&Arc<T>` → `&Arc<[T]>`.
  - **Plan §10 Q7 unit fix** (Codex r2 B): "1 G prefix-bytes" → realistic byte-count estimate.
  - **Plan §8.4 wording soften** (Codex r2 A): "expected: identical numbers" → "expected: within noise of master".

v3 → v4 also addresses Codex r1 + AGY r1 + Claude SMR r2 (carried forward unchanged):
  - **Shape change:** `Arc<[T]>` → `Option<Arc<[T]>>` (AGY F1).
    Null-pointer optimization makes this zero-size-overhead vs
    bare `Arc<[T]>` (still 16 B fat pointer) while eliminating
    empty-Arc allocations entirely (~96 MB savings at 1M rules).
  - **Helper strategy change:** reuse existing intermediate
    `Vec<PrefixV{4,6}>` parsing rather than separate
    `collect_rule_side_prefixes` helpers that re-parse the same
    tokens (Codex F5).
  - **Explicit field init:** drop reliance on
    `..PolicyRule::default()` for the four new fields to remove
    AGY F2 silent-omission hazard.
  - **Test plan expansion:** 6 → 11 tests covering legacy
    `source_addresses` shape, `any4`/`any6`, /0-preserved,
    multiple books with dense-index ordering, duplicate
    literal/book prefixes, destination-side coverage, clone
    integrity, trie-variant, zero-plus-non-zero (Codex F7 + AGY F3).
  - **Cache-line wording tightened** to drop the
    "lands at the end" claim about rustc field placement (Codex F1).
  - **Consumer contract clarification** in §4.2: the parallel
    array is INPUT prefix shape, NOT a complete semantic match
    set; future LPM builder MUST read it together with the
    `..._match_any` flag (Codex F6).

## 1. Issue framing

Issue #1623 tracks the residual work from #1609 (multi-stage policy
decision DAG) after the v3.x architectural round hit a fourth
consecutive PLAN-NEEDS-MAJOR / PLAN-KILL on the Multi-Book LPM axis.
The full LPM / Stage 2/3/4 / PseudoBook design has been deferred
indefinitely pending #1622 empirical numbers on 10K/100K/1M-rule
cold-path latency.

User has authorized a **narrow Path B**: extend `PolicyRule` with
parallel-prefix arrays (`source_prefixes_v4`, `source_prefixes_v6`,
`destination_prefixes_v4`, `destination_prefixes_v6` — each of
type `Option<Arc<[Prefix...]>>`), populated at parse-time. This is
the AGY r2 #1 simplification line item from #1623, adjusted to
`Option<Arc<[T]>>` per AGY r1 / Codex r1 / Claude SMR r2
convergence on the empty-Arc cost issue.

The scope is foundational scaffolding only. The fields are
populated but consumed nowhere. A future #1623 v4 design round may
consume them when (and if) the architectural axis converges.

## 2. Honest scope / value framing

Absolute scale of the win at this PR: **zero runtime cycles, zero
bytes saved, zero retransmits avoided**. The new fields:

- Add 64 bytes per `PolicyRule` (four 16-byte `Option<Arc<[T]>>`
  fat-pointer fields — NPO makes `Option<Arc<[T]>>` the same size
  as `Arc<[T]>`).
- Allocate **only for non-empty sides**. A rule with `source any`
  contributes `source_prefixes_v4 = None` and
  `source_prefixes_v6 = None` — zero allocations. A rule with
  literal CIDRs or cited books allocates one Arc per family per
  side that has actual content.
- Are read by NO hot-path code in this PR.

The value is purely structural — it materializes the per-rule
canonical prefix list at parse time so a future LPM builder can
consume it without re-walking trie-compressed `PrefixSet` values.

**If reviewers conclude that materializing dead-storage fields
without a concrete consumer is not worth the parse-time cost and
+64 B/rule footprint, PLAN-KILL is an acceptable verdict.** The
#1624 BookEntry precedent shipped clean with a 4-of-4 attestation,
but Codex r1 correctly notes the cardinality difference (books
~10s vs rules ~1M) — the precedent doesn't transfer cleanly.

### 2.1 Accepted costs (Codex F2/F4 cardinality + Codex r2 D populated-rule accounting)

- **Per-rule struct growth: +64 B.** With `Option<Arc<[T]>>`, four
  fields × 16 B (NPO-collapsed) = 64 B. At 1M rules: ~430 B → ~494 B
  → ~430 MB → ~494 MB resident rule table. Within 8-16 GB VM
  budget. Codex F1 correctly notes the struct growth changes
  Vec<PolicyRule> stride; this is accepted as the foundation cost.
  Both r2 reviewers REJECTED PLAN-KILL on this axis (Codex r2 D,
  AGY r2 G), so the cardinality argument is closed.
- **Per-Arc overhead** (Codex r2 D + r3 finding 3 corrected
  accounting). Each `Some(Arc<[T]>)` carries:
  - 16 B Arc inner header (strong + weak ref counts) — the slice
    length lives in the FAT POINTER (already counted in the +64 B
    struct growth), NOT in a separate allocation field.
  - ~8-16 B allocator block overhead (depends on jemalloc / glibc
    malloc rounding).
  - Payload: 12 B per `PrefixV4` element (u32 addr + u32 mask + u8
    prefix_len + 3 B alignment pad). 48 B per `PrefixV6` element
    (u128 addr + u128 mask + u8 prefix_len + 15 B alignment pad to
    16-byte alignment — Codex r1-code 2026-05-28 corrected the
    v5 estimate of 40 B).

  So a rule with 10 PrefixV4 entries in one Arc: ~24-32 B header
  + 120 B payload = ~144-152 B per Arc. Worst-case realistic 1M
  rules × 2 populated Arcs average × ~150 B = +300 MB Arc
  allocations on top of struct growth (v4 estimate was +240 MB
  but used the wrong PrefixV4 size; corrected estimate is
  higher).
- **Book-prefix replication.** A rule that cites a 10-prefix
  book materializes those 10 prefixes into its
  `source_prefixes_v4` Arc rather than sharing the book's already-
  allocated `Arc<[PrefixV4]>`. At 1M cited-book-only rules with
  one 10-prefix book: ~80 MB of data replication PLUS the per-Arc
  overhead above. **This is an explicit deferred optimization.**
  A future shape change to
  `Option<SmallVec<[Arc<[PrefixV4]>; 4]>>` (referencing each
  contributing source's existing Arc) would eliminate the
  replication at the cost of diverging from the #1624 BookEntry
  flat-Arc contract. Decision deferred to #1623 v4 design round
  once #1622 measurements quantify whether parse-time
  allocation or memory footprint is actually the bottleneck.
- **Empty-Arc cost: ELIMINATED.** Plan v2 → v3 shape change
  (`Arc<[T]>` → `Option<Arc<[T]>>`) saves ~96 MB at 1M all-`any`
  rules. NPO ensures zero per-field size overhead vs the bare
  `Arc<[T]>` shape.

**Realistic 1M-rule total memory cost (corrected):** +64 MB
struct growth + ~300 MB Arc allocations + ~120 MB book-prefix
data replication (10 prefixes × 12 B v4 + 48 B v6 mix × 1M rules)
= **~450-600 MB total**. Within 8-16 GB VM budget. PLAN-KILL on
this axis was rejected by both r2 reviewers (and r3 Codex
explicitly approved as foundation cost); foundation work shipped
as-is is acceptable.

## 3. Precedent — #1624 BookEntry parallel arrays (and where this PR diverges)

PR #1624 (squash `d339b69f8`) extended `BookEntry`:

```rust
pub(crate) struct BookEntry {
    pub(crate) v4: PrefixSetV4,
    pub(crate) v6: PrefixSetV6,
    pub(crate) prefixes_v4: Arc<[PrefixV4]>,  // bare Arc<[T]>
    pub(crate) prefixes_v6: Arc<[PrefixV6]>,
}
```

**This PR diverges from the precedent in one specific way:**
`Option<Arc<[T]>>` instead of bare `Arc<[T]>` on PolicyRule. The
divergence is motivated by cardinality:

- BookEntry runs at ~10-100 entries; an empty-Arc footprint there
  is ~2.4 KB (100 × 24 B), trivial.
- PolicyRule runs at 1K-1M entries; an empty-Arc footprint at 1M
  is ~96 MB (1M × 4 × 24 B). Structural problem.

The future Multi-Book LPM builder reads BookEntry parallel arrays
as `book.prefixes_v4.iter()` (bare Arc); for PolicyRule it reads
`rule.source_prefixes_v4.as_deref().unwrap_or(&[]).iter()` (Option
unwrap). The semantic of "rule with no source-side input
prefixes" is communicated by `None`, equivalent to BookEntry's
empty-Arc + `v4.is_match_none()` shape but cheaper.

The future LPM builder can also wrap BookEntry's parallel arrays
into Some(book.prefixes_v4.clone()) for uniform handling if
needed — Arc clones are cheap.

## 4. Concrete design

### 4.1 Struct extension

Add four fields to `PolicyRule` (currently `userspace-dp/src/policy.rs`
lines 122-155):

```rust
pub(crate) struct PolicyRule {
    // ... existing fields through destination_book_idxs ...
    pub(crate) destination_book_idxs: SmallVec<[u32; 8]>,

    // #1623 Path B narrow — parallel canonical prefix arrays for
    // a future Multi-Book LPM builder. NOT consumed by the hot
    // path in this PR. `None` means "this side contributed no
    // input prefixes" (typically: source-any rule); the existing
    // source_v{4,6}_match_any / destination_v{4,6}_match_any
    // booleans remain the SOLE signal for any-side semantics.
    //
    // Shape: Option<Arc<[T]>> (not bare Arc<[T]>) — NPO collapses
    // this to one fat-pointer-sized field. Empty-Arc allocation
    // for all-any rules is ELIMINATED.
    pub(crate) source_prefixes_v4: Option<Arc<[PrefixV4]>>,
    pub(crate) source_prefixes_v6: Option<Arc<[PrefixV6]>>,
    pub(crate) destination_prefixes_v4: Option<Arc<[PrefixV4]>>,
    pub(crate) destination_prefixes_v6: Option<Arc<[PrefixV6]>>,

    // ... rest: match_any flags, applications, compiled_apps, action, hit_counter ...
}
```

### 4.2 Semantic contract for the parallel arrays

The arrays carry the union of:

1. Literal CIDRs parsed from the rule itself
   (`snap.source_literals` / `snap.source_addresses` depending on
   shape), AND
2. The full prefix list of every cited address book
   (`state.books[i].prefixes_v4` / `prefixes_v6` for each
   `i ∈ source_book_idxs`).

`None` means "no input prefixes contributed on this side, for this
family". This is the case for:
- `source_literals: ["any"]` rules (no per-rule literal prefixes,
  no cited books that contribute v4/v6 prefixes).
- `source_addresses: ["any"]` legacy shape.
- Rules where every cited book has an empty `prefixes_v4` for the
  v4 case (similarly v6).

`Some(arr)` with `arr.len() == 0` is NEVER produced. The parse
logic in §4.3 converts an empty union vector to `None`.

**Consumer contract (Codex r1 F6 + Codex r2 B clarifications).**
A downstream LPM builder MUST read both
`(source_prefixes_v4, source_v4_match_any)` together. The parallel
array is INPUT prefix shape — it does NOT encode any semantic
("match any") by itself. The match-any flag remains the
authoritative source of any-side semantics.

**Dominance rule (Codex r2 B):** when `..._match_any` is `true`,
the parallel array `Some(arr)` (or `None`) is purely diagnostic /
build-hint and **may not be used to narrow the rule's match set**.
The rule semantically matches all addresses of that family
regardless of `arr`'s contents. A future LPM builder may use
`arr` for diagnostics or for §2.6 short-circuit routing
optimization but MUST honor `match_any = true` as the controlling
match semantic.

When `..._match_any` is `false`, the parallel array `Some(arr)`
gives the input prefix shape; the rule matches addresses covered
by any prefix in `arr` (this matches the existing `PrefixSet`
semantics). `None` with `match_any = false` is a rule that
matches no addresses of that family — equivalent to MatchNone
under the v3-shaped factory semantics.

**Why NOT a synthetic `[0.0.0.0/0]`:** synthesizing /0 for the any
case would fragment the contract: the same value `Some([0.0.0.0/0])`
would mean two different things depending on whether the operator
actually wrote `source 0.0.0.0/0` (literal) vs `source any` (no
literal). Keeping `None == "no literal contribution"` preserves
input fidelity.

### 4.3 Population at parse-time (Codex F5: no helper re-parse)

The existing parse loop at policy.rs:485-510 already materializes
intermediate `Vec<PrefixV4>` + `Vec<PrefixV6>` for the literal
CIDR side. Refactor to CAPTURE these intermediates before they're
moved into the PrefixSet factories, then extend with cited-book
prefixes to materialize the parallel array.

The replacement structure:

```rust
// Build literal prefix sets per side, capturing the intermediate
// Vec for parallel-array reuse.
let (
    source_literal_v4,
    source_literal_v6,
    src_lit_v4_vec,
    src_lit_v6_vec,
    src_any_v4_literal,
    src_any_v6_literal,
) = if source_is_v3_shaped {
    parse_v3_literal_set_capture(&snap.source_literals)
} else {
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    for prefix in &snap.source_addresses {
        parse_address(prefix, &mut v4, &mut v6);
    }
    // Legacy shape: empty -> MatchAny (per from_prefixes semantics).
    let any_v4 = v4.is_empty();
    let any_v6 = v6.is_empty();
    (
        PrefixSetV4::from_prefixes(v4.clone()),
        PrefixSetV6::from_prefixes(v6.clone()),
        v4,
        v6,
        any_v4,
        any_v6,
    )
};
// ... same for destination ...

// Materialize the parallel arrays by extending the captured
// literal vectors with each cited book's prefixes_v{4,6}.
let source_prefixes_v4 = build_rule_side_arc(
    src_lit_v4_vec,
    &source_book_idxs,
    &state.books,
    |book| &book.prefixes_v4,
);
// ... symmetric for source_v6 / destination_v4 / destination_v6 ...
```

Where `build_rule_side_arc` is a small generic helper:

```rust
fn build_rule_side_arc<T: Clone, F>(
    mut lit_vec: Vec<T>,
    book_idxs: &SmallVec<[u32; 8]>,
    books: &[BookEntry],
    extractor: F,
) -> Option<Arc<[T]>>
where
    F: Fn(&BookEntry) -> &Arc<[T]>,
{
    for &idx in book_idxs.iter() {
        let book = &books[idx as usize];
        lit_vec.extend_from_slice(extractor(book));
    }
    if lit_vec.is_empty() {
        None
    } else {
        // Codex r3 finding 2 correction: Arc::from(Vec<T>) (impl
        // since Rust 1.45) is preferred. Arc<[T]> always
        // allocates its own ref-counted slice and moves elements
        // out of the Vec — it does NOT reuse the Vec's heap
        // allocation, because Arc needs the Arc header layout.
        // The previous .into_boxed_slice() intermediate added a
        // wasted shrink-to-fit realloc before Arc's allocation.
        // Direct Arc::from(Vec) is cleanest.
        Some(Arc::from(lit_vec))
    }
}
```

And `parse_v3_literal_set_capture` is `parse_v3_literal_set`
refactored to ALSO return the captured Vec + the any-token flags:

```rust
fn parse_v3_literal_set_capture(
    literals: &[String],
) -> (PrefixSetV4, PrefixSetV6, Vec<PrefixV4>, Vec<PrefixV6>, bool, bool) {
    let mut any_v4 = false;
    let mut any_v6 = false;
    let mut v4: Vec<PrefixV4> = Vec::new();
    let mut v6: Vec<PrefixV6> = Vec::new();
    for tok in literals {
        match tok.as_str() {
            "any" => { any_v4 = true; any_v6 = true; }
            "any4" => any_v4 = true,
            "any6" => any_v6 = true,
            "" => {}
            s => parse_literal_cidr_into(s, &mut v4, &mut v6),
        }
    }
    let v4_set = if any_v4 {
        PrefixSetV4::MatchAny
    } else {
        PrefixSetV4::from_v3_literals(v4.clone())
    };
    let v6_set = if any_v6 {
        PrefixSetV6::MatchAny
    } else {
        PrefixSetV6::from_v3_literals(v6.clone())
    };
    (v4_set, v6_set, v4, v6, any_v4, any_v6)
}
```

Note: `v4.clone()` + `v6.clone()` inside `parse_v3_literal_set_capture`
adds one Vec clone per side per rule on the parse path. This is
cold path; the alternative (passing ownership and returning the
captured Vec only when the factory is done) requires intrusive
changes to `PrefixSetV{4,6}::from_v3_literals`. For the narrow
foundation PR, the extra clone is acceptable.

**Ordering note (CORRECTED per Codex r1-code MERGE-NEEDS-MINOR
2026-05-28):** Both `lit_v4_vec` and the per-book `prefixes_v4`
arrays carry their natural input ordering. The
`source_book_idxs` SmallVec is "dense indices in ASCENDING
EXTERNAL-ID ORDER" — NOT ascending dense-index order.
`resolve_book_idxs::sort_unstable() + dedup()` sorts the INPUT
u32 external IDs first, then maps each to its dense index. When
address_books are declared in non-ID-ascending order, dense
indices DIVERGE from external IDs and the walk order follows
external IDs, not dense indices. Final union order: literals
first (in `snap.source_literals` parse order), then each cited
book's `prefixes_v4` in ASCENDING EXTERNAL-ID order. No sort,
no dedup at this layer. Exposed by test 6
(`test_policy_rule_v3_multiple_books_external_id_ascending_order`).

### 4.4 Default impl + parse constructor (AGY r2 D: drop `..default()` entirely)

`PolicyRule::default()` extended to set all four new fields to
`None`:

```rust
impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            // ... existing fields ...
            source_prefixes_v4: None,
            source_prefixes_v6: None,
            destination_prefixes_v4: None,
            destination_prefixes_v6: None,
            // ...
        }
    }
}
```

The existing `PolicyRule { ..PolicyRule::default() }` constructor
at lines 540-560 is REFACTORED to drop the `..default()` tail
entirely (AGY r2 D). Pre-declare `applications` and
`compiled_apps` as locals, then name every field in the struct
literal so the compiler enforces exhaustiveness:

```rust
// Pre-declare the post-construction-mutated fields as locals so
// they can be named in the struct literal.
let applications = parse_applications(&snap.application_terms);
let compiled_apps = CompiledApplications::from_matches(&applications);

let rule = PolicyRule {
    rule_id: rule_id.clone(),
    policy_id: snap.policy_id,
    from_zone: snap.from_zone.clone(),
    to_zone: snap.to_zone.clone(),
    scheduler_name: snap.scheduler_name.clone(),
    inactive: snap.inactive,
    source_literal_v4,
    source_literal_v6,
    destination_literal_v4,
    destination_literal_v6,
    source_book_idxs,
    destination_book_idxs,
    source_v4_match_any,
    source_v6_match_any,
    destination_v4_match_any,
    destination_v6_match_any,
    source_prefixes_v4,
    source_prefixes_v6,
    destination_prefixes_v4,
    destination_prefixes_v6,
    applications,
    compiled_apps,
    action: parse_action(&snap.action),
    hit_counter: counter_store.rule_hit_counter(&rule_id),
};
```

This is a structural hardening — adding ANY future field to
`PolicyRule` produces a compile error in
`parse_policy_state_with_counters` until the constructor is
updated, eliminating the silent-zero-default hazard AGY F2
raised. The post-construction `rule.applications = ...;
rule.compiled_apps = ...;` lines on the existing 561-562 are
DELETED — these fields are now constructed in place.

### 4.5 Clone impl

Add the four fields to the manual `Clone` impl (lines 187-212).
Each is a single `Arc` ref-count bump for `Some`, no-op for `None`:

```rust
source_prefixes_v4: self.source_prefixes_v4.clone(),
source_prefixes_v6: self.source_prefixes_v6.clone(),
destination_prefixes_v4: self.destination_prefixes_v4.clone(),
destination_prefixes_v6: self.destination_prefixes_v6.clone(),
```

`Option<Arc<[T]>>::clone()` does exactly this: `None.clone() ==
None`, `Some(arc).clone() == Some(arc.clone())` (Arc::clone is
one atomic increment).

## 5. Public API preservation

`PolicyRule` is `pub(crate)`, so no public Rust API surface is
touched. The wire protocol (`PolicyRuleSnapshot` in
`protocol/security.rs`) is NOT modified. No Go-side changes.
`evaluate_policy()` (lines 670+) is NOT modified.

## 6. Hidden invariants this change must preserve

- **Hot path zero-touch.** `evaluate_policy()` and every function
  called per packet must not reference the new fields. Verified
  post-impl via:
  `grep -nE "(source|destination)_prefixes_v[46]" userspace-dp/src/`
  — hits only in struct definition, parse loop, Default impl,
  Clone impl, and tests.
- **PolicyRule cloneability.** PolicyState clones rules on
  reconcile_rules; the new Option<Arc> fields are clone-cheap
  (None: no-op; Some: ref-count bump).
- **MatchAny semantics unchanged.** The existing
  `source_v{4,6}_match_any` / `destination_v{4,6}_match_any`
  booleans are the SOLE signal for any-side semantics. Parallel
  arrays do NOT participate in policy evaluation.
- **Default impl correctness.** `PolicyRule::default()` returns
  rules with `None` parallel arrays AND `..._match_any = true`
  (existing). Consistent with the existing default-rule
  semantics: default-constructed rule matches any address,
  carries no operator-stated input prefixes.
- **Constructor robustness.** The four new fields are EXPLICITLY
  named in the `parse_policy_state_with_counters` constructor
  (NOT relying on `..PolicyRule::default()`), so future field
  additions cannot silently zero them.
- **Parse-time allocation cost.** Each parse pass allocates at
  most 4 Arcs per rule (one per non-empty Option). For 1K rules
  where most cite a book + carry a few literals: ~4K allocs at
  parse time. For 1M all-any rules: 0 allocs (Option = None).
  Hot path: zero new allocs.
- **HA sync portability.** PolicyState is rebuilt from
  `PolicyRuleSnapshot` (wire format) on every reconcile; the new
  fields are derived from existing wire fields, so HA sync
  semantics are unchanged.

## 7. Risk assessment

| Class | Risk | Reasoning |
|-------|------|-----------|
| Behavioral regression | LOW | Hot path untouched. New fields populated but read nowhere. |
| Lifetime / borrow-checker | LOW | `Option<Arc<[T]>>` is `'static`, `Clone`, `Send + Sync`. Mirrors #1624 BookEntry up to the Option wrapper. |
| Performance regression | LOW–MED | Parse-time: O(rules × prefixes) extra work + up to 4 Arcs/rule (only for non-empty sides). Cold path. Reconcile-on-config-change only. +64 B/rule struct growth. |
| Architectural mismatch | LOW | Foundation work the future LPM builder needs. If the builder never ships, the cost is +64 B/rule + Arc allocations for populated rules — small. Codex F2 cardinality argument addressed by the Option<Arc<[T]>> shape change. |

## 8. Test plan

### 8.1 New unit tests in `policy_tests.rs` (19 tests; Codex r1 F7 + AGY r1 F3 + Codex r2 C + AGY r2 F + Codex r3 finding 1 + AGY r3 expansion)

1. `test_policy_rule_v3_carries_canonical_prefix_lists_v4` — rule
   with three v4 literal CIDRs + one cited v4-only book. Assert
   `source_prefixes_v4 = Some(arr)` with `arr.len() == 4` and
   contents include all literals + all book prefixes; assert
   `source_prefixes_v6 = None` and
   `destination_prefixes_v4 = None` (destination is `any`).
2. `test_policy_rule_v3_carries_canonical_prefix_lists_v6` — same
   shape, v6 only.
3. `test_policy_rule_v3_dual_family` — rule with v4 + v6 literals
   + a dual-family book. Assert both Some arrays populated
   independently with correct content.
4. `test_policy_rule_v3_any_source_yields_none` — rule with
   `source_literals: ["any"]`, no books, no addresses. Assert
   `source_prefixes_v4 == None` AND `source_prefixes_v6 == None`
   AND `source_v4_match_any == true` AND
   `source_v6_match_any == true`. **Critical:** demonstrates the
   "any → None + flag" contract and the empty-Arc avoidance.
5. `test_policy_rule_v3_book_only_inherits_book_prefixes` — rule
   with `source_book_ids: [N]`, empty literals. Assert
   `source_prefixes_v4` matches the cited book's `prefixes_v4`
   exactly (same length, same contents in order).
6. `test_policy_rule_v3_multiple_books_dense_index_order` — rule
   with `source_book_ids: [3, 1, 2]` resolving to dense indices
   in ascending order (assert ordering invariant from §4.3).
   Each book contributes distinct prefixes; final array order
   must reflect dense-index-ascending walk.
7. `test_policy_rule_legacy_source_addresses_path` (Codex F7) —
   non-v3-shaped rule (`source_addresses: ["10.0.0.0/8"]`, no
   `source_literals`, no books). Assert
   `source_prefixes_v4 = Some([10.0.0.0/8])` with one element.
8. `test_policy_rule_v3_any4_any6_tokens` (Codex F7) — rule with
   `source_literals: ["any4"]` (no any6). Assert
   `source_prefixes_v4 = None` AND `source_v4_match_any == true`,
   AND `source_prefixes_v6 = None` AND
   `source_v6_match_any == false` (no any6 token, no v6 input).
   Then second case `["any6"]`: symmetric.
9. `test_policy_rule_v3_literal_zero_prefix_preserved` (AGY F3
   mirror of BookEntry test 1112) — rule with
   `source_literals: ["0.0.0.0/0"]` (LITERAL /0, NOT "any").
   Assert `source_v4_match_any == true` (PrefixSet collapses /0
   to MatchAny) AND `source_prefixes_v4 = Some(arr)` with
   `arr.len() == 1` AND `arr[0].prefix_len() == 0`.
   **Critical:** demonstrates `Some([0.0.0.0/0])` ≠ `None` and
   preserves operator input fidelity for diagnostics.
10. `test_policy_rule_v3_destination_side_independent` (Codex F7)
    — rule with `source_literals: ["any"]`, `destination_literals:
    ["10.0.0.0/8", "192.168.1.0/24"]`. Assert source side is
    `None` for both families; destination_v4 is
    `Some([10.0.0.0/8, 192.168.1.0/24])`, destination_v6 is `None`.
11. `test_policy_rule_v3_trie_variant_preserves_array` (AGY F3
    mirror of BookEntry test 1170) — rule with 17 literal CIDRs
    (`10.0.{0..16}.0/24`). Assert
    `source_literal_v4 == PrefixSetV4::Trie(_)` AND
    `source_prefixes_v4 = Some(arr)` with all 17 entries
    preserved (parallel array is variant-independent).
12. `test_policy_rule_clone_preserves_arrays` (AGY r1 F3) — build
    a rule with both `Some(arr)` and `None` fields; clone it; assert
    cloned values are equal (Arc ptr-equality for Some,
    None preserved).
13. `test_policy_rule_size_of_option_arc` (Codex r2 C + r3
    finding 5 + AGY r3 recommendation) — uses zero-dependency
    compile-time `const _: [(); 16] = [(); size_of::<...>()];`
    pattern at module scope to assert
    `size_of::<Option<Arc<[PrefixV4]>>>() == 16` AND
    `size_of::<Option<Arc<[PrefixV6]>>>() == 16` AND
    `size_of::<Arc<[PrefixV4]>>() == 16`. The `const _` blocks
    fail compilation if NPO is ever broken. Wrapped in a `#[test]
    fn test_policy_rule_size_of_option_arc()` shell that does
    nothing (or runtime-asserts the same values) so it still
    appears in cargo test output. Validates the NPO claim that
    backs the memory accounting in §2.1.
14. `test_policy_rule_v3_any_plus_book_match_any_with_some_arr`
    (Codex r2 C) — rule with `source_literals: ["any"]` AND a
    cited book containing prefixes. Assert
    `source_v4_match_any == true` (any token dominates) AND
    `source_prefixes_v4 == Some(arr)` with `arr` containing the
    book's prefixes. Demonstrates the dominance rule from §4.2:
    when match_any=true, the parallel array is diagnostic only,
    not used to narrow the rule.
15. `test_policy_rule_v3_book_v6_only_yields_v4_none`
    (Codex r2 C + AGY r2 F) — rule that cites a v6-only book
    (no v4 prefixes) and has no v4 literals. Assert
    `source_prefixes_v4 == None` (not `Some([])`) AND
    `source_prefixes_v6 == Some(arr)`. Verifies the "empty union
    → None" branch in `build_rule_side_arc`.
16. `test_policy_rule_v3_destination_book_path` (Codex r2 C) —
    rule with `destination_book_ids: [N]` citing a book; empty
    `destination_literals`. Mirror test 5 but for the
    destination side; asserts symmetric handling.
17. `test_policy_rule_v3_book_zero_plus_non_zero` (AGY r2 F) —
    rule citing a book that contains both `0.0.0.0/0` AND
    `10.0.0.0/8` (book's `prefixes_v4` already carries both per
    #1624 BookEntry contract). Assert
    `source_prefixes_v4 == Some([0/0, 10.0.0.0/8])` (length 2,
    preserves both entries) AND `source_v4_match_any == true`
    (book has /0 which propagates the match-any flag at rule
    construction).
18. `test_policy_rule_v3_literal_zero_plus_non_zero` (Codex r3
    finding 1) — rule with `source_literals: ["0.0.0.0/0",
    "10.0.0.0/8"]` (LITERAL both, NOT `any` token). Assert
    `source_prefixes_v4 == Some([0/0, 10.0.0.0/8])` (length 2)
    AND `source_v4_match_any == true` (PrefixSet collapses /0 to
    MatchAny). Rule-level mirror of test 17 and of BookEntry
    test_book_entry_zero_plus_non_zero_prefixes_preserved.
19. `test_policy_rule_v3_duplicate_preservation` (Codex r3
    finding 1) — rule with `source_literals: ["10.0.0.0/8"]`
    AND citing a book whose `prefixes_v4` also contains
    `10.0.0.0/8`. Assert `source_prefixes_v4 == Some(arr)` with
    `arr.len() == 2` AND both entries equal `10.0.0.0/8`.
    Confirms the "no dedup at this layer; future LPM owns it"
    invariant from §4.3.

### 8.2 Cargo gates

```bash
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release 2>&1 | tail -3
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release 2>&1 | tail -3
# 5x flake check on the new test module
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
**within noise of master** (Codex r2 A: not "identical" — the
+64 B/rule stride change can in principle affect hot-path cache
behavior even though `evaluate_policy()` does not read the new
fields). A line-rate regression on the 12-stream `-P 12 -R`
reproducer would be a blocking failure; sub-Gbps drift on per-class
shaped cells is within expected noise.

### 8.5 `make test-failover`

Not required — no HA-visible state touched (the parallel arrays
live in `PolicyState` which is rebuilt on every config apply on
both nodes independently from the same wire snapshot).

## 9. Out of scope (explicitly)

- **NO Multi-Book LPM.** Whole DAG / Stage 2/3/4 / DIR-24-8 /
  bounded multibit trie / galloping merge — deferred to #1623 v4.
- **NO PseudoBook materialization.**
- **NO feature flag.**
- **NO hot-path changes.** `evaluate_policy()` byte-identical.
- **NO wire-protocol changes.**
- **NO `pkg/cluster/`, `pkg/policy/`, or Go-side compiler changes.**
- **NO sort / dedup of parallel arrays.**
- **NO shared-storage shape change to `Option<SmallVec<[Arc<[T]>; 4]>>`.**
  Deferred optimization per §2.1 if #1622 shows replication is a
  bottleneck.

## 10. Open questions for adversarial r2 review

### Resolved in v2 → v3 transition:

- ~~Q1 (sorted/deduped vs raw input):~~ raw input order, per §4.3 final paragraph.
- ~~Q2 (synthetic /0 vs empty + flag):~~ `None` + flag, per §4.2 contract. Literal /0 preserved as `Some([0/0])` for fidelity.
- ~~Q3 (cache-line impact):~~ +64 B accepted in §2.1 + risk table.
- ~~Q4 (1M-rule replication):~~ accepted deferred opt per §2.1 last bullet.
- ~~Q5 (empty-Arc footprint):~~ resolved by Option<Arc<[T]>> shape — empty case allocates zero bytes.

### New for r2:

Q6. **Helper signature `build_rule_side_arc`.** Generic over `T:
Clone` + `F: Fn(&BookEntry) -> &Arc<[T]>` (v4 typo fix). Two
instantiations (PrefixV4 / PrefixV6) generate two
monomorphizations. Approved by both Codex r2 + AGY r2 — keeping
the generic shape in v4.

Q7. **`parse_v3_literal_set_capture` clone cost.** The refactored
helper calls `v4.clone()` + `v6.clone()` to keep ownership for
the parallel array while still moving into `from_v3_literals`.
Per-rule: 2 extra `Vec<Prefix*>::clone()` calls on the parse
path. Cold path, but at 1M-rule snapshots this is 2M clones.
Worst case at 1K prefixes/rule × 1M rules = 1 billion prefix
copies = ~8 GB of v4 prefix bytes traversed (or ~24 GB v6) over
the parse pass (NOT resident — these are short-lived clones
freed as the parse loop walks). Approved by AGY r2 C as cold-
path acceptable; Codex r2 D accepted with the unit-fix note.
Alternative deferred: thread an `out_parallel: &mut Vec<...>`
parameter through `from_v3_literals` so the literal Vec is
consumed without clone — intrusive to `PrefixSet` factories and
out of scope for this PR.

Q8. **Constructor explicit-field shape.** RESOLVED in v4: plan §4.4
now pre-declares `applications` + `compiled_apps` as locals and
drops `..PolicyRule::default()` from the parse constructor
entirely (AGY r2 D). Every field is named in the struct literal;
adding any future field forces a compile error in
`parse_policy_state_with_counters` until the constructor is
updated. Closes the silent-omission hazard completely.

Q9. **Test count and granularity.** RESOLVED in v5: 19 tests
total. v4 added 17; Codex r3 finding 1 surfaced two more axes
explicitly: test 18 literal-/0+non-/0 (rule-level mirror of book
test 17), test 19 duplicate preservation across literal + book.
Matrix is now exhaustively populated. Future LPM consumer's
duplicate-handling and dedup behavior is tested at the OUTPUT
layer (the duplicate is preserved into the parallel array, per
"no dedup at this layer" contract).

Q10. **PolicyRule cardinality vs precedent.** RESOLVED in v3-v4
review rounds: both Codex r2 D and AGY r2 G REJECTED PLAN-KILL
on cardinality. With Option<Arc<[T]>>, +64 B struct growth at 1M
rules is within the 8-16 GB VM budget. Per-Arc overhead is real
(see §2.1 honest accounting) but bounded. Cardinality axis is
CLOSED.

## 11. Status / decision summary

- **Author position (v3):** Option<Arc<[T]>> + explicit constructor
  + capture-before-move parser refactor + 11 tests + accept the
  +64 B/rule footprint as the foundation cost. PLAN-KILL remains
  acceptable on the cardinality axis if reviewers think 64 MB at
  1M rules is too much for a no-consumer scaffolding PR.
- **Open architectural risks:** Q7 clone cost (parse-time), Q10
  cardinality footprint. Both are honest about absolute numbers.
- **Convergence path:** if Codex r2 accepts the cardinality
  argument with Option fix and AGY r2 accepts the helper /
  constructor structure, this ships. If either still PLAN-KILLs,
  scope is small enough to absorb a clean fail.

