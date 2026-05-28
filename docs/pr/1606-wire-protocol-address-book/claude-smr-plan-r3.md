# Claude SMR plan review — round 3 (plan v3 + v4 reactions)

## Plan v3 round-3 verdict: PLAN-NEEDS-MAJOR (convergent with Codex r3)

Plan v3 fixed all five of Codex's round-2 findings but introduced one
critical fail-open path Codex correctly identified.

### Convergent findings with Codex r3

**F1 [MAJOR] Fail-open via empty PrefixSet → MatchAny**

V3 §3.3 says: "`source_literal_v4` ← parse from `source_literals` if
non-empty, ELSE parse from `source_addresses`."

Combined with `userspace-dp/src/prefix_set.rs:58`:

```rust
if prefixes.is_empty() {
    return Self::MatchAny;
}
```

…the parse-condition has a fail-open path. Walk the scenario:

1. New-Go emits a snapshot with `address_books` populated (some
   other rule cites a book).
2. A specific rule has `source_addresses=["any"]` (a legacy "match
   any source" rule, fully expanded by Go's full-expansion code).
   That rule has empty `source_literals` AND empty
   `source_book_ids`.
3. If new-Rust uses a GLOBAL gate "address_books non-empty → use
   new fields", that rule parses with empty `source_literals` →
   `PrefixSetV4::MatchAny` → matches all v4 traffic.
4. The legacy `source_addresses=["any"]` field that previously
   would have produced this same `MatchAny` is now ignored.

In this specific case the outcome is the same (MatchAny either
way), but the parse-condition is wrong because:

- A rule that legitimately has `source_addresses = ["10.0.0.0/8"]`
  (no books, no inline literals — just legacy full-expansion) and
  is in a SNAPSHOT where `address_books` is non-empty (other
  rules cite books) would be parsed with empty `source_literals`
  → `MatchAny` → match all v4 traffic. **Fail open.**

V4 fixes this by changing to a per-rule v3-shaped predicate:
`source_is_v3_shaped = !source_book_ids.is_empty() ||
!source_literals.is_empty()`.

**F2 [MAJOR] Unknown book ID should hard-fail, not log+skip**

V3 says "if ID is unknown ... log a warning and skip the ID".
Codex r3 correctly notes that Junos compiler already rejects
unresolved address-book references at
`pkg/config/compiler.go:590`+. A dataplane-level skip could:

- Silently widen policy: e.g. a rule that should match "internal-
  hosts" book but the book is missing on the wire → rule matches
  NOTHING from books, but the rule ALSO has no inline literals →
  policy applies to no flows → traffic affected by that rule is
  governed by whatever rule comes next (could be a more-open
  default).

V4 hard-fails the snapshot apply on unknown book ID, falling back
to the previous snapshot. Same failure semantics as the existing
version-mismatch reject at `snapshot.rs:25`.

**F3 [MINOR] Collision math correction**

V3 said 100K books → 0.116% collision probability. Codex r3 noted
the correct birthday formula gives ~68.8%. My round-2 review was
also imprecise (said "0.116% — collision-free in practice" which is
wrong at 100K).

V4 corrects: 10K → 1.16%, 100K → 68.8%, 1M → effectively certain.
The probe scheme still works because load factor at 1M / 2^32 is
1/4096; clustering is not an issue.

**F4 [MAJOR] Hash input needs family/count framing**

Codex r3 correctly identifies that concatenating raw `addr || len`
bytes without a family tag or count prefix can produce identical
canonical bytes for distinct v4/v6 content. E.g., a book containing
`[10.0.0.0/8]` (v4) and an empty v6 list canonicalizes to roughly
`[8, 10, 0, 0, 0]`; a book containing only `[0a00:0000::/8]` (v6
where the high byte happens to be 0x0a) would canonicalize to
`[8, 0a, 00, 00, ...]` — distinguishable only by length, but FNV-1a
of these is ambiguous on truncation/end-of-stream.

V4 adds explicit `"V4" || u32_be(count) || ...` and `"V6" || u32_be(
count) || ...` framing.

## Plan v4 verdict: PLAN-READY (pending Codex r4 confirmation)

V4 incorporates the four findings cleanly. My remaining concerns:

### Open items (NONE blocking)

- **SmallVec inline cap**: V4 keeps `SmallVec<[u32; 8]>`. Codex r3
  was silent on cap-of-4 (AGY raised it against the stashed code,
  not the plan). I think 8 is the right number; bench data from the
  implementation will tell us if it's too small/large.

- **Test coverage** for the per-rule predicate edge cases is added
  in v4's test plan. Good.

### What I'd reject in v5+

- Re-introducing any "global flag" parse predicate.
- Softening the "hard-fail" on unknown book ID.
- Removing the V4/V6 framing prefix.

## My SMR vote on v4: PLAN-READY.

The architecture is correct. The wire surface is honest. The HA
determinism story is closed. The fail-open paths are closed. The
flat-index design is the right hot-path shape. The forwarding_build
external user is in the change list.

Pending Codex round-4 confirmation, this plan is ready to implement.
