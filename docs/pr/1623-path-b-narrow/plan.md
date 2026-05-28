# #1623 Path B narrow — PolicyRule parallel-prefix arrays

**Status:** DRAFT v3 — Codex r1 PLAN-NEEDS-MAJOR + AGY r1 PLAN-NEEDS-MINOR + Claude SMR r2 folded; pending r2 adversarial review

Revision history:
- v1: initial draft.
- v2: addresses Claude SMR r1 PLAN-NEEDS-MINOR findings.
- v3: addresses Codex r1 PLAN-NEEDS-MAJOR (F1-F7) + AGY r1 PLAN-NEEDS-MINOR (F1-F4) + Claude SMR r2:
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

### 2.1 Accepted costs (Codex F2/F4 cardinality argument + Claude SMR r2 C5)

- **Per-rule struct growth: +64 B.** With `Option<Arc<[T]>>`, four
  fields × 16 B (NPO-collapsed) = 64 B. At 1M rules: ~430 B → ~494 B
  → ~430 MB → ~494 MB resident rule table. Within 8-16 GB VM
  budget. Codex F1 correctly notes the struct growth changes
  Vec<PolicyRule> stride; this is accepted as the foundation cost.
- **Book-prefix replication.** A rule that cites a 10-prefix
  book materializes those 10 prefixes into its
  `source_prefixes_v4` Arc rather than sharing the book's already-
  allocated `Arc<[PrefixV4]>`. At 1M cited-book-only rules with
  one 10-prefix book: ~80 MB of replication. **This is an
  explicit deferred optimization.** A future shape change to
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

If reviewers still find +64 B × 1M rules prohibitive,
PLAN-KILL on the cardinality axis is acceptable.

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

**Consumer contract (Codex F6 clarification).** A downstream LPM
builder MUST read both `(source_prefixes_v4, source_v4_match_any)`
together. The parallel array is INPUT prefix shape — it does NOT
encode any semantic ("match any") by itself. The match-any flag
remains the authoritative source of any-side semantics. If
match_any is true AND the array is `Some(arr)`, the consumer is
free to use `arr` to inform LPM build (the rule still matches all
addresses, but the operator-stated CIDRs are recoverable for
diagnostics or for §2.6 short-circuit routing).

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
        Some(Arc::from(lit_vec.as_slice()))
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

**Ordering note.** Both `lit_v4_vec` and the per-book
`prefixes_v4` arrays carry their natural input ordering. The
`source_book_idxs` SmallVec is already sorted ascending by dense
index (via `resolve_book_idxs::sort_unstable() + dedup()`), so
cited-book contributions appear in ascending dense-index order
regardless of the operator's declared `source_book_ids` order.
Final union order: literals first (in `snap.source_literals`
parse order), then each cited book's `prefixes_v4` in
dense-index-ascending order. No sort, no dedup at this layer.

### 4.4 Default impl (AGY F2: explicit field assignment, no `..default()` reliance for new fields)

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
at lines 540-560 is updated to assign all four new fields
EXPLICITLY (NOT relying on the `..default()` fallback, per AGY
F2):

```rust
let mut rule = PolicyRule {
    rule_id: rule_id.clone(),
    policy_id: snap.policy_id,
    // ... other explicitly-assigned fields ...
    source_prefixes_v4,
    source_prefixes_v6,
    destination_prefixes_v4,
    destination_prefixes_v6,
    ..PolicyRule::default()
};
```

The `..PolicyRule::default()` tail remains for the
`applications: Vec::new()` + `compiled_apps: CompiledApplications { match_any: true, ... }`
fields (currently filled in after the `..default()` via mutation
on lines 561-562 — that pattern is preserved). The four new
fields are NOT in the `..default()` tail; they are explicitly
named, so adding any future field to PolicyRule cannot silently
zero them.

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

### 8.1 New unit tests in `policy_tests.rs` (11 tests, Codex F7 + AGY F3 expansion)

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
12. `test_policy_rule_clone_preserves_arrays` (AGY F3) — build a
    rule with both `Some(arr)` and `None` fields; clone it; assert
    cloned values are equal (Arc ptr-equality for Some,
    None preserved).

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
identical numbers to master — this is a zero-hot-path-touch PR.

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
Clone` + `F: Fn(&BookEntry) -> &Arc<T>`. Two instantiations
(PrefixV4 / PrefixV6) generate two monomorphizations. Is the
generic shape acceptable, or should this be two non-generic
helpers `build_rule_side_v4` / `build_rule_side_v6`?

Q7. **`parse_v3_literal_set_capture` clone cost.** The refactored
helper calls `v4.clone()` + `v6.clone()` to keep ownership for
the parallel array while still moving into `from_v3_literals`.
Per-rule: 2 extra `Vec<Prefix*>::clone()` calls on the parse
path. Cold path, but at 1M-rule snapshots this is 2M clones.
Worst case: 1K-prefix rule × 1M rules = 1 G prefix-bytes of
clone work. Is this acceptable? Alternative: thread an
`out_parallel: &mut Vec<...>` parameter through
`from_v3_literals` so the literal Vec is consumed without clone.

Q8. **Constructor explicit-field shape.** Plan §4.4 keeps
`..PolicyRule::default()` for applications/compiled_apps but
names the four new fields explicitly. Is the residual `..default()`
fallback acceptable, or should the constructor name EVERY field
explicitly (a separate cleanup, but tightens the AGY F2 hazard
fully)?

Q9. **Test count and granularity.** 11 tests covers the matrix
axes called out by Codex F7 + AGY F3. Are any axes still missing?
(e.g., book that has /0 + non-/0 contributing to the rule —
"zero-plus-non-zero" mirror in the *rule* context; rule that
cites a book whose `prefixes_v4` is empty.)

Q10. **PolicyRule cardinality vs precedent.** Codex F2's
fundamental point — BookEntry runs at 10s of entries; PolicyRule
at 1M — is partially mitigated by Option<Arc<[T]>> but not fully.
At 1M rules, the rule table grows by 64 MB just for the four new
fields. Is that 64 MB worth the foundation work? PLAN-KILL is
still on the table on this axis.

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

