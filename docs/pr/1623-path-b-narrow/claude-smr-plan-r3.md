# Claude SMR plan-r3 (HOSTILE self-review) — #1623 Path B narrow

**Round:** 3 (post Codex r2 + AGY r2)
**Plan revision under review:** v3 → about to become v4
**Codex r2 verdict:** PLAN-NEEDS-MINOR
**AGY r2 verdict:** PLAN-NEEDS-MINOR
**Convergence:** PLAN-NEEDS-MINOR — both reviewers within striking distance of READY.

## Cross-reviewer convergence (r2)

### CONVERGENT (Codex r2 + AGY r2):

**CC1. Drop `..PolicyRule::default()` from the parse constructor.**
Both reviewers want this. Codex r2 accepts the current shape but
AGY r2 D pushes back hard and requires the full elimination. The
AGY refactor (pre-declare `applications` + `compiled_apps` as
local vars) is clean and structurally hardens against future
field additions.

**Decision:** Plan v4 §4.4 adopts the AGY refactor — pre-declare
locals, drop `..default()` from the constructor entirely.

**CC2. Test count expansion — overlap on book /0+non-/0 +
empty-book-yields-None.**

Codex r2 C lists 6 additional tests:
- `source_literals: ["any"]` + cited book → match_any=true AND
  Some(arr)
- Cited book with empty v4 + non-empty v6 → per-family None
  behavior with book IDs present
- Rule-level zero-plus-non-zero `["0.0.0.0/0", "10.0.0.0/8"]`
- Destination book path
- Explicit duplicate-preservation
- `size_of` static assertion test

AGY r2 F lists 2:
- Book containing /0 + non-/0 → Some([0/0, ...]) AND match_any=true
- Rule citing v6-only/empty book → None

Overlap: book /0+non-/0 (Codex 3rd ≈ AGY 1st), empty-side-yields-None
(Codex 2nd ≈ AGY 2nd). Plus Codex unique: any+book, dest book,
duplicate-preservation, size_of.

**Decision:** Plan v4 §8.1 expands from 11 to 17 tests covering
all the new axes. No risk in over-testing scaffolding.

### CODEX-ONLY:

**CC3. `Arc::from(lit_vec.into_boxed_slice())` not
`Arc::from(lit_vec.as_slice())`** (Codex r2 B). The `.as_slice()`
form clones/copies the union vector again; `.into_boxed_slice()`
or `.into()` consumes the Vec and converts the existing
allocation in place.

**Hostile self-check:** Codex is right. `Arc::from(&[T])` blanket
impl requires `T: Clone` and copies all elements into a fresh
Arc payload (Vec is dropped, all elements copied). `Arc::from(Vec<T>)`
or `Arc::from(Box<[T]>)` reuses the existing heap allocation —
no element copy. For 1K-prefix rules at 1M scale this is a
material savings on the parse path.

**Decision:** Plan v4 §4.3 `build_rule_side_arc` body uses
`Arc::from(lit_vec)` (passing Vec by value) or
`Arc::from(lit_vec.into_boxed_slice())`. Verify which is correct
for `Arc<[T]>::from(Vec<T>)` — std impl: `impl<T> From<Vec<T>> for Arc<[T]>`
exists (since Rust 1.45) — it reuses the Vec's allocation iff
capacity == len, otherwise reallocates. Safer to use
`.into_boxed_slice()` which forces shrink-to-fit then converts
without a second copy.

**CC4. Populated-rule cost accounting beyond data bytes** (Codex
r2 D). Plan v3 §2.1 says +64 B/rule + 80 MB data replication.
Codex says: each `Some(arc)` ALSO carries Arc strong/weak counters
(16 B) + allocator overhead (8-16 B per alloc) + per-rule pointer
indirection.

**Hostile self-check:** Codex is right. Per non-empty Arc:
- 16 B Arc header (strong + weak)
- 8 B slice length
- 8 B allocator block header
- payload: 8 B × prefix_v4 count

So a rule with 10 prefixes in one Arc has ~40 B overhead + 80 B
payload = 120 B/Arc. For 1M rules × 4 Arcs (worst case all 4
sides populated): +480 MB Arc overhead + +320 MB data. That's
significant.

But realistic rules don't all populate all 4 sides — many are
"source any, dest book" or vice versa. Realistic worst case: 1M
rules × 2 Arcs avg × ~120 B per Arc = +240 MB.

**Decision:** Plan v4 §2.1 expanded with honest accounting: per
Arc overhead 24-32 B (counters + length + allocator), realistic
1M-rule footprint estimate 250-500 MB. PLAN-KILL on cardinality
still available if reviewers find this prohibitive.

**CC5. Consumer contract sharper: match_any DOMINATES** (Codex
r2 B). Plan v3 §4.2 says "consumer must read both together".
Codex says: be explicit that match_any TRUE makes the parallel
array purely diagnostic — it never narrows the rule. Some([/0])
or Some([anything]) cannot override match_any=true to a more-
restrictive match.

**Decision:** Plan v4 §4.2 adds explicit dominance rule.

**CC6. Plan §10 Q6 typo** — `&Arc<T>` should be `&Arc<[T]>`.
**Decision:** Fix in v4.

**CC7. Plan §10 Q7 wrong unit** — "1 G prefix-bytes" is wrong;
should be "1 B prefix elements" or actual byte count. **Decision:**
Fix in v4.

**CC8. Plan §8.4 wording** — "identical numbers to master" is
too strong because larger PolicyRule stride can affect hot-path
cache behavior. **Decision:** Soften wording in v4.

**CC9. size_of static assertion test** (Codex r2 C). Add as test
13.

### AGY-ONLY:

**CC10. Pre-declare `applications` + `compiled_apps`** locals
(AGY r2 D). Already accepted in CC1.

## Net verdict

PLAN-NEEDS-MINOR (per both reviewers' r2). All MINOR items are
mechanically addressable in plan v4. The architecture is settled.

After v4 lands, this is ready for round 3 dispatch with high
confidence of PLAN-READY from both.

Self-pass: PLAN-NEEDS-MINOR convergence is the right call. Will
revise to v4 and re-dispatch.

## Forward-looking risk

If r3 lands MINOR-or-better from both, ship to implementation +
code review. If r3 surfaces a NEW major issue (low probability
at this point), iterate again. PLAN-KILL is still on the table
on Codex F2 cardinality axis but both reviewers explicitly
REJECTED PLAN-KILL on cardinality in r2 (Codex r2 D, AGY r2 G).
That axis is now closed.
