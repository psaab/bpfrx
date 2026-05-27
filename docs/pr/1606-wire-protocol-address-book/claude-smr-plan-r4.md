# Claude SMR plan review — round 4 (plan v4 → v5)

## Plan v4 round-4 verdict: PLAN-NEEDS-MAJOR (convergent with Codex r4)

### Convergent finding with Codex r4

**F-r4-1 [MAJOR] Book-only rule fail-opens via legacy
PrefixSet::from_prefixes(empty)=MatchAny**

V4's per-rule predicate fix correctly identified that the
literal-source-selection must be per-rule-per-side, not global. But
v4 still routes the `source_literals` parse through the existing
`PrefixSetV4::from_prefixes` factory at
`userspace-dp/src/prefix_set.rs:62`:

```rust
pub(crate) fn from_prefixes(prefixes: Vec<PrefixV4>) -> Self {
    if prefixes.is_empty() {
        return Self::MatchAny;
    }
```

This means a v3-shaped rule that cites ONLY books (empty
`source_literals`) gets `source_literal_v4 = MatchAny`. Then in
`try_match_rule`:

```rust
src_ok = rule.source_v4_match_any
    || rule.source_literal_v4.contains(src)  // <- MatchAny.contains() = true
    || ...
```

…short-circuits to true regardless of the cited books' actual CIDR
content. **Fail open.**

Codex r4 caught this with exact line cites. My v4 SMR review missed
it (I voted PLAN-READY on v4 — wrongly).

### Additional Codex r4 finding

**F-r4-2 [MAJOR] Family-incomplete books also fail-open**

A v4-only book (`prefixes_v4` populated, `prefixes_v6` empty) built
via `from_prefixes` has `entry.v6 = MatchAny`. Then a v6 packet
hitting a rule that cites this book matches the book on v6 because
of the empty=MatchAny convention. **Fail open** on v6 traffic.

V4 didn't address this. V5 must.

## Plan v5 fix

V5 introduces an explicit `MatchNone` variant on `PrefixSetV4` /
`PrefixSetV6`:

- `MatchNone.contains(_) -> false`.
- `MatchNone.prefix_count() -> 0`.
- `MatchNone.is_match_none() -> true`.
- `MatchNone.is_match_any() -> false`.

And a new constructor `from_v3_literals(prefixes)`:

- Empty input → `MatchNone` (NEW v3 semantic).
- `/0` present → `MatchAny`.
- Else `Linear` / `Trie` as today.

The existing `from_prefixes` factory keeps the empty=MatchAny
semantics so the non-v3-shaped fallback path is unaffected.

Per-rule build:
- v3-shaped side → `from_v3_literals` (MatchNone on empty).
- non-v3-shaped side → `from_prefixes` (MatchAny on empty, legacy
  back-compat for old-Go snapshots).

Book table build:
- Every book row → use `from_v3_literals` for both v4 and v6.
  A v4-only book has `entry.v6 = MatchNone`. A v6-only book has
  `entry.v4 = MatchNone`. An empty book (no v4 OR v6 — which is
  semantically malformed) has both MatchNone — the book contributes
  nothing to any match. Note: we should consider whether an empty
  book should be a hard-fail on the wire, but it's not critical
  for correctness.

## V5 verdict: PLAN-READY (pending Codex r5 confirmation)

The MatchNone variant cleanly closes:
- Book-only rule fail-open.
- Family-incomplete book fail-open.
- Without breaking non-v3-shaped legacy compatibility (those still
  use `from_prefixes` which keeps empty=MatchAny).

Codex r4's other items:
- F2 (unknown book ID hard-fail): fully addressed in v5; the
  parse-policy-state function becomes `Result<PolicyState,
  ParseError>` and the snapshot handler propagates errors before
  any side-effect.
- F3 (collision math): corrected in v4, retained in v5.
- F4 (hash framing): corrected in v4, retained in v5.

The minor "22.6%" doc artifact is fixed in v5.

## What I'd kill on

- Re-introducing `from_prefixes` on the v3-shaped path.
- Conflating "no criteria" with "match all".
- Skipping the MatchNone variant.

None of those are in v5. The plan is ready to implement.

## Test coverage check

V5 has tests for:
- book-only rule does NOT fail open (the F-r4-1 fix).
- Pure "any" rule with address_books present (the v4 predicate
  test).
- v4/v6 cross-family no-canonical-collision (F4 fix).
- unknown book ID = hard-fail snapshot (F2).
- duplicate book ID = hard-fail.
- book ID 0 = hard-fail.

Missing test (should add): v4-only book + v6 traffic packet should
NOT match on v6. The `family-incomplete book fail-open` symmetry.
Add `test_v4_only_book_does_not_match_v6_traffic` in r5.
