# Claude SMR plan-r2 (HOSTILE self-review) — #1623 Path B narrow

**Round:** 2 (post Codex + AGY r1)
**Plan revision under review:** v2 → about to become v3
**Codex r1 verdict:** PLAN-NEEDS-MAJOR
**AGY r1 verdict:** PLAN-NEEDS-MINOR
**Convergence:** PLAN-NEEDS-MAJOR (must address Codex F1-F7 + AGY F1-F4 before READY)

## Cross-reviewer convergence

### CONVERGENT (both reviewers AND my SMR r1 hit it):

**C1. Empty-Arc footprint requires Option<Arc<[T]>>.** Codex F3 +
AGY F1 + my SMR r1 F-SMR-r1-2 all hit this. Codex frames it as a
*structural* problem (96 MB at 1M rules); AGY notes Option<Arc<[T]>>
is zero-overhead thanks to NPO (null-pointer optimization: a fat
Arc pointer's non-null payload pointer encodes `Some`, null encodes
`None`, so `size_of::<Option<Arc<[T]>>>() == size_of::<Arc<[T]>>() == 16 B`).

**Self-pass:** I missed the NPO observation in my r1 — I was correct
that empty Arc is wasteful but wrong about the fix. AGY's
Option<Arc<[T]>> is strictly better than the
`Arc::<[T]>::default()` workaround I proposed. **Accept.**

**Decision:** Plan v3 SWITCHES from `Arc<[PrefixV4]>` to
`Option<Arc<[PrefixV4]>>` (and similarly v6). This is a real
divergence from #1624 BookEntry shape, but the rule-cardinality
multiplier (1M rules vs ~10s of books) justifies it. Future
LPM-builder consumer reads `match opt { None => match_any path,
Some(arr) => walk arr }` — straightforward.

### CONVERGENT (Codex + AGY):

**C2. Test plan coverage gaps.** Codex F7 + AGY F3 list overlapping
missing tests:
- Legacy non-v3 `source_addresses`/`destination_addresses` shape
- `any4` / `any6` token semantics
- Literal `/0` preserved distinct from `any`
- Multiple cited books, dense-index ordering
- Duplicate literal/book prefixes (preserved? not?)
- Destination-side coverage
- Clone/reconcile preserving populated arrays
- Trie-variant (17+ prefixes mirroring BookEntry test 1170)
- Zero-plus-non-zero preserved (mirror BookEntry test 1198)

**Decision:** Plan v3 §8.1 expands from 6 tests to ~10-12 tests
covering all the above axes.

### CODEX-ONLY:

**C3. Helper redundancy + branch drift risk.** Codex F5: my
`collect_rule_side_prefixes_v4/v6` re-parses the same tokens that
the existing `parse_v3_literal_set` / `parse_address` calls
already parse. Two parsers risks drift.

**Hostile self-check:** This is real. The existing parser at
policy.rs:485-510 already builds Vec<PrefixV4> + Vec<PrefixV6>
intermediate vectors before passing them to PrefixSet factories.
I can capture those intermediate vectors and use them for BOTH
the PrefixSet construction AND the parallel array, instead of
re-parsing.

**Decision:** Plan v3 §4.3 changes the implementation strategy.
Instead of helper functions that re-parse, refactor the existing
parse_policy_state_with_counters loop to:
1. Parse literals once into `lit_v4: Vec<PrefixV4>`, `lit_v6: Vec<PrefixV6>`.
2. Construct PrefixSet from those vectors (passing ownership).
3. Build a NEW vector `union_v4` = `lit_v4.clone()` then
   extend_from_slice from each cited book's `prefixes_v4`.
4. Materialize `Some(Arc::from(union_v4.as_slice()))` if non-empty
   AND not match-any, else `None`.

This eliminates the re-parse drift. Pattern matches #1624
BookEntry's "capture before move" approach but extended to
include book contributions.

### AGY-ONLY:

**C4. Silent omission hazard from `..PolicyRule::default()`.**
AGY F2: the existing PolicyRule constructor at policy.rs:540-560
uses `..PolicyRule::default()` to fall back the application/compiled_apps
fields. If I add new fields and forget to assign them explicitly,
they silently default to None and the compiler emits zero warning.
Since the fields are dead-storage in this PR, that bug would
bypass all CI gates.

**Hostile self-check:** This is real and load-bearing. The fix is
either:
- (a) Drop `..PolicyRule::default()` entirely; require every
  field to be assigned explicitly. Hardens against future field
  additions too.
- (b) Add the four new fields explicitly to the constructor;
  keep `..PolicyRule::default()` for backward compat with
  applications/compiled_apps.

**Decision:** Plan v3 picks (b) — minimum change, explicitly
assigns the four new fields in the constructor. Option (a) is a
broader cleanup and out of scope.

### CODEX-ONLY (UNRESOLVED):

**C5. Cardinality argument — BookEntry precedent is NOT equivalent.**
Codex F2: "Books are low-cardinality shared objects. Rules may be
1M-cardinality hot objects. Mirroring BookEntry's shape into every
rule multiplies costs in a way the precedent does not justify."

**Hostile self-check:** This is fair. BookEntry runs at ~10-100
entries in practice; PolicyRule at 1K-1M. The pure precedent
argument doesn't carry. But:
- The Option<Arc<[T]>> shape change (C1) addresses 80%+ of the
  cost concern (empty rules pay 0, populated rules pay the
  payload only).
- The 1M-rule struct growth is +64 B per rule = 64 MB at 1M
  rules. That's real but not catastrophic for an 8-16 GB VM.
- The 80 MB book-prefix replication (C5 worst case from Codex F4)
  is still real, but it's an OPTIMIZATION axis — current code
  already replicates Vec<PolicyRule> on reconcile.

**Decision:** Plan v3 §2.1 accepted-cost section explicitly
acknowledges Codex F2/F4 — the per-rule footprint (with Option
fix) is +16 B/rule struct + Arc allocations only for populated
rules. The book-prefix replication remains an explicit deferred
optimization. If reviewers think the 1M-rule footprint is still
prohibitive after Option<Arc<[T]>> + book-prefix-as-deferred-opt,
PLAN-KILL is acceptable.

### CODEX-ONLY (PARTIALLY RESOLVED):

**C6. "Zero hot-path impact" wording.** Codex F1: PolicyRule is the
per-rule scanned object; growing it changes Vec stride and cache
residency even if evaluate_policy() doesn't read the new fields.
Plus repr(Rust) doesn't guarantee field placement.

**Hostile self-check:** Codex is technically correct but the
worst-case impact is bounded:
- Vec<PolicyRule> stride grows by 16 B (with Option<Arc<[T]>>) ×
  4 = 64 B. At 1M rules, the rule table grows from ~430 B × 1M
  ≈ 430 MB to ~494 B × 1M ≈ 494 MB. Within 8-16 GB VM budget.
- repr(Rust) DOES guarantee that fields of equal alignment are
  placed in declaration order for non-#[repr(C)] structs in
  current rustc — but this is NOT a stable language guarantee.
  The cache-line analysis should be rephrased as "current
  rustc places fields in declaration order; the new fields
  appended at the end touch later cache lines that
  evaluate_policy() does not read".

**Decision:** Plan v3 §10 Q3 rephrases — drops the "lands at the
end" claim and replaces with "fields are declared in the
constructor in canonical position (after destination_book_idxs);
current rustc places these in declaration order, which means
they fall at the tail of the struct". Notes this is current-rustc
behavior, not language-stable.

### CODEX F6 (NUANCE):

**C7. Empty-array + match-any-flag contract requires consumer to
read both.** Codex F6: the parallel arrays are "input prefix
arrays", not "complete semantic match sets". A future LPM builder
must consume `(prefixes_v4, match_any_v4)` together.

**Hostile self-check:** Yes, this is exactly the BookEntry
contract — BookEntry parallel arrays + `v4.is_match_any()` are
read together. The future LPM builder is already designed (per
#1623 issue body) to consume both. This is documentation, not a
structural fix.

**Decision:** Plan v3 §4.2 contract block expanded to make this
explicit: "Consumer contract — a downstream builder MUST read
both (`prefixes_v{4,6}`, `..._match_any`) together. The parallel
array is INPUT shape; the flag is the SEMANTIC override for any."

## Net verdict

PLAN-NEEDS-MAJOR (per Codex). Five substantive changes for v3:

1. **SHAPE CHANGE:** `Arc<[T]>` → `Option<Arc<[T]>>` per AGY F1.
2. **HELPER STRATEGY CHANGE:** Re-use existing intermediate Vec
   parsing rather than separate helpers per Codex F5.
3. **EXPLICIT FIELD INIT:** Drop reliance on `..PolicyRule::default()`
   for the four new fields per AGY F2.
4. **TEST PLAN EXPANSION:** 6 → 10-12 tests per Codex F7 + AGY F3.
5. **DOC/CONTRACT TIGHTENING:** §2.1, §4.2, §10 Q3 wording per
   Codex F1/F2/F4/F6.

All five are mechanically addressable in a single v3 revision. Net
plan still ships as ~50-100 LOC + tests. No new scope.

PLAN-KILL is still on the table after v3 if Codex's cardinality
argument (C5) is the load-bearing concern. My read is the
Option<Arc<[T]>> + deferred-book-prefix-replication-opt addresses
the practical impact, but I'll re-issue an SMR r3 after v3
dispatch + Codex/AGY r2 to verify the residual concerns.

Self-pass: PLAN-NEEDS-MAJOR is the right convergence verdict. Will
revise to plan v3 and re-dispatch.
