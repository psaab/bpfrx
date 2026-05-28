# Claude SMR plan-review r5 — #1609 v3 round 1 (hostile self-pass)

**Role**: domain SMR (network firewall semantics + Junos policy
order + data-structure algorithms + CPU microarchitecture + AF_XDP
ZC cold-path budgets).

**Target**: `docs/pr/1609-multistage-policy-dag/plan.md` v3 (Multi-Book
LPM + 5 fixes addressing v2 r4 convergent fatals + user-relaxed
memory budget).

**Verdict (round 5): PLAN-NEEDS-MINOR** (residual gaps; not
PLAN-READY because hostile re-read found 4 issues v3 must close in
v3.1 before declaring PLAN-READY).

The methodology has caught my soft-passes before (r3 PLAN-READY-WITH-
NITS → r4 PLAN-KILL self-correction on v2). I am explicitly going
HOSTILE on v3 — first-pass PLAN-READY would be a yellow flag.

## Convergent v2 r4 fatal resolutions — verify

| v2 r4 fatal | v3 fix location | Verified? |
|---|---|---|
| F1 Level-0 memory | §6 §Y RELAXED per user override | ✓ explicit |
| F2 Literal/any rule drop | §2.1 MatchAny side-channels + §2.2 PseudoBooks | ✓ both paths covered |
| F3 v6 FxHashMap DoS | §2.3 bounded multibit trie | ✓ DIR-(8×6) deterministic |
| F4 Global ordering | §2.5 per-(zone-pair, local_idx) + two-phase eval | ✓ explicit two-phase |
| F5 Broad /0 blow-up | §2.6 build-time short-circuit + covers_all merge | ✓ |
| F6 BookEntry not buildable | §2.4 extra prefixes_v4/v6 Arc<[Prefix]> + iter_prefixes | ✓ |

All 6 fatals have **real, named fixes** with code-level detail. v3
addresses the convergent kill axis.

But hostile re-read finds residual gaps:

## Residual issues v3 must close (PLAN-NEEDS-MINOR)

### F-r5-1 — book_id space: real-books + PseudoBooks share dense index, BUT BookCitations.per_zone_pair is sized for ALL of them (FATAL-ish)

§2.1 says PseudoBooks live at indices
`real_book_count..real_book_count + pseudo_book_count` in the same
LPM book-id space. §2.5 then defines:

```rust
struct BookCitations {
    per_zone_pair: Vec<FxHashMap<ZonePairKey, Arc<[u32]>>>,
    global: Vec<Arc<[u32]>>,
}
```

If `per_zone_pair: Vec<FxHashMap<...>>` is indexed by `book_id`,
then `per_zone_pair.len() = real_book_count + pseudo_book_count =
~1M+ entries at scale`. The outer Vec is 1M FxHashMap stubs ≈ 32 MB
of metadata. Probably fine under relaxed budget but worth noting.

**Bigger concern**: per-PseudoBook citation Arc<[u32]> is length-1
(only its owning rule). 1M PseudoBooks × Arc<[u32]> of len 1 ≈ 24 MB
Arc headers + 4 MB content. Each Stage 3 LPM hit on a PseudoBook
returns book_id → citation array of len 1. Galloping merge over
slices of len 1 is degenerate (fine, but inefficient — gallop step
is always min-jump = 1).

v3.1 should call out the PseudoBook-citation degenerate-merge case.
Not blocking but worth a sentence in §2.5.

### F-r5-2 — Galloping merge has not been spec'd at all (MAJOR)

Step 1 is "primitive + scaffold" so Stage 4 galloping merge is
explicitly out-of-scope per §4. But §2.7's `evaluate_phase` calls
`galloping_merge_evaluate` and §2.8 shows pseudocode for it. The
plan never specifies:
- How many slices in (5+ from §2.1 Stage 4 input list).
- Loser-tree vs simple-2way-merge.
- Hot-path register pressure.

v3.1 (or Step 2's plan) must define the merge shape. For Step 1 we
don't need it; just call this out as Step 2's first design item.

### F-r5-3 — PseudoBook prefix-deduplication is structurally absent (MINOR)

Two rules with `source any` produce zero PseudoBooks (handled by
MatchAny). But two rules with overlapping literal prefixes (e.g.
both have `source-address [10.0.0.0/24]`) produce TWO separate
PseudoBooks each with prefix list `[10.0.0.0/24]`. The LPM treats
them as independent book IDs.

At 1M rules with high literal-prefix overlap, PseudoBook count
could explode. Realistic: most rules either use books (no
PseudoBook) or have `source any` (no PseudoBook either) — only
rules with explicit per-rule literals get PseudoBooks. Probably
small in practice but worth a sentence.

v3.1 could add a content-hash dedup pass at construction time:
hash the prefix list, intern duplicate PseudoBooks via Arc dedup.
~10 ns per rule overhead but cuts PseudoBook count substantially
for configs with shared literals.

**Not blocking** — Step 1's tests at 1K rules don't exercise this
pathology. Step 2 may want to add it.

### F-r5-4 — §2.5 BookCitations.per_zone_pair: O(book_count × zone_pair_count) (MAJOR)

`per_zone_pair: Vec<FxHashMap<ZonePairKey, Arc<[u32]>>>` indexed by
book_id. Per-book inner map has one entry per (zone-pair that has
≥1 rule citing this book).

Worst case 10K books × 100 zone-pairs = 1M FxHashMap entries.
Realistic 1K books × 20 zone-pairs = 20K entries. Fine.

But the **lookup pattern is**: at hot path, given `book_id` (returned
from LPM), we need `book_citations[book_id].per_zone_pair.get(&zp_key)`.
That's a HashMap probe per LPM-hit book per packet — at scale, many
LPM hits per packet × HashMap probe = unbounded cost.

**Alternative design**: store the inner map as `Box<[(ZonePairKey,
Arc<[u32]>)]>` sorted by ZonePairKey, with binary search. ~20 ns
per lookup vs ~10 ns HashMap probe — both reasonable. The sorted
shape is also more cache-friendly.

v3.1 should pick one. Position: sorted Box<[...]> + binary search,
because (a) ZonePairKey set is small (~100); (b) cache-line behavior
beats HashMap hashing for small maps; (c) no DoS surface (zone-pair
keys are operator-controlled).

### Additional hostile checks

- **§2.4 iter_prefixes() — Trie walk cost**: at 1M-prefix book, the
  Trie walk is O(N) per call. Two-pass build calls iter_prefixes
  once per book per pass = O(2N) per book. Total build cost
  O(books × prefixes_per_book) = 10K × 100 ≈ 1M iter ≈ 10-100 ms.
  Acceptable.
- **§2.6 covers_all_v4 at galloping merge**: only ever appended to
  the LPM-output slice list. Hot-path cost: 1 extra slice in the
  merge. Typical len 0-2. Fine.
- **§2.5 EvalPhase::ZonePair vs Global**: how does Stage 4 know
  which BookCitations entry to use? Pass an enum tag. §2.7
  `populate_phase` takes `phase: EvalPhase`. Inside it must do
  `if phase == ZonePair { ... .per_zone_pair.get(&zp_key) } else
  { ...global }`. Single branch per lookup — fine.
- **§2.3 MultiBookLpmV6Sub depth tracking**: enum V6Node holds
  Descend(Box<MultiBookLpmV6Sub>). Each sub stores a depth field
  for runtime bounds check? Or compile-time enforced via
  `MultiBookLpmV6Sub<const DEPTH: u8>`? Plan handwaves. v3.1 must
  spec.
- **PrefixSetV4::Trie walk implementation**: how does iter_prefixes
  walk? Plan says "walk", but the existing Trie variant in
  prefix_set.rs uses uncompressed binary radix tree (per the
  comment "uncompressed binary radix tree"). Walking it gives
  longest-prefix per branch; converting back to original prefix
  list is reconstructible. Test in Step 1 must verify the
  iter_prefixes output matches the input prefix list ordering-
  agnostic.

## Verdict and recommendation

**PLAN-NEEDS-MINOR.** Not PLAN-READY because of F-r5-2 (galloping
merge unspecified — Step 2 problem, but Step 1 should at least
forward-link), F-r5-4 (per_zone_pair HashMap probe vs sorted-array
binary search — pick one before Step 1 ships citation arrays). F-r5-1
and F-r5-3 are documentation-clarity nits.

If Codex + AGY return PLAN-READY-equivalent, I'll up-vote to
PLAN-READY upon v3.1 patch addressing F-r5-2 + F-r5-4.

If Codex + AGY find additional fatals, those + my F-r5-* items roll
into v3.1.

## Why I'm being hostile

r3 (v2 round 1) called PLAN-READY-WITH-NITS and missed 6 fatals
that Codex + AGY caught. The methodology corrected my soft-pass via
r4. v3 deserves the same hostility — first-pass PLAN-READY would be
suspicious. PLAN-NEEDS-MINOR with 4 named residual issues forces
v3.1 to close gaps before declaring done.

## Process

Next steps:
- Dispatch Codex + AGY r1 on v3 SHA (separate from this self-review).
- If both PLAN-NEEDS-MINOR or PLAN-READY, consolidate into v3.1 +
  re-review.
- If both PLAN-KILL on the architectural axis, escalate per user
  instruction (do NOT spawn v4 without authorization).
- If two of three PLAN-NEEDS-MAJOR, document + STAGE Step 1 down
  to the most contained subset that can ship.
