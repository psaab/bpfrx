# Claude SMR plan-r1 (HOSTILE self-review) — #1623 Path B narrow

**Reviewer seat:** Claude SMR (Rust data structures / Arc / parse-time
population / cache-line layout / hostile self-check).

**Plan under review:** `docs/pr/1623-path-b-narrow/plan.md` v1.

**Verdict:** PLAN-NEEDS-MINOR — ship-pending with two MINOR
clarifications. Plan is structurally sound (mirrors the shipped
#1624 BookEntry precedent), but two open questions in §10 should
be answered IN THE PLAN, not just listed for reviewers.

## Findings (hostile-mode rationale per finding)

### F-SMR-r1-1 — Q4 1M-rule replication is real but out-of-scope (MINOR)

Plan §10 Q4 honestly raises the 1M-rule replication concern: an
all-cited-book rule that cites a 10-prefix book replicates the book's
prefixes into the rule's `Arc<[T]>` instead of sharing the book's
already-allocated `Arc<[T]>`. At 1M rules × 10 prefixes × 8 B
(`PrefixV4` is 8 B: 4 B addr + 1 B prefix_len + 3 B pad) = 80 MB of
v4 payload duplication per snapshot.

**Hostile analysis:** This is real waste, but the alternative shape
(`SmallVec<[Arc<[PrefixV4]>; 4]>`) diverges from #1624 BookEntry's
single-flat-Arc contract. The future LPM builder would need to
fan-out across multiple Arc refs anyway; merging them into one Arc
at LPM build time costs the same as merging them at PolicyRule
construction time.

**The honest fix:** acknowledge this in the plan text (not just §10
Q4) as a known cost the future LPM builder may need to optimize.
The PR ships the simple shape; the optimization is a follow-up if
#1622 measurements show parse-time allocation is a hotspot.

**Self-pass requirement:** plan must state explicitly that 1M-rule
replication is an ACCEPTED COST at this scaffolding stage,
deferable to a follow-up issue. Not a structural blocker for v1.

### F-SMR-r1-2 — Q5 empty-Arc footprint is structurally small (MINOR)

Plan §10 Q5 raises empty-Arc footprint: `Arc::from(&[][..])` still
allocates the 24 B header. 4 fields × 24 B × 1M rules = 96 MB.

**Hostile analysis:** This is overstated. The Rust standard library
implements `Arc::from(&[T])` for empty slices by allocating a
header + zero-length payload (one allocation per empty arc). But
crucially, *the same empty Arc can be a static* via
`Arc::<[T]>::default()` which yields a single shared global empty
Arc — most current Rust versions hand out the same `Arc::default()`
empty arc to all callers (ref-counted, single global allocation).

Verifying this requires checking the rustc version + std impl, but
the #1624 BookEntry precedent uses `Arc<[T]>` (not Option) and has
shipped without observable footprint regression. The same shape
here is structurally identical risk.

**The honest fix:** plan should switch from `Arc::from(&[][..])`
to `Arc::<[T]>::default()` in the `Default` impl — this avoids
per-rule empty-Arc allocations entirely (single global shared
empty Arc). For per-rule construction at parse time, the array
must carry actual contents (one allocation), so the parse path is
unchanged.

This is a 1-line tweak in the Default impl. MINOR.

### F-SMR-r1-3 — §4.2 "any" semantics decision is correct and load-bearing (NO FINDING, document)

Plan §4.2 picks "empty array + flag" over "synthetic /0". This
matches BookEntry semantics (parallel arrays carry input, flag
carries any). Hostile self-test: if a future LPM builder wants to
treat /0 specially via §2.6 short-circuit, both shapes work:
- "empty + flag": builder reads `source_v4_match_any` first;
  short-circuits before consulting the parallel array.
- "synthetic /0": builder reads the parallel array, detects /0,
  short-circuits via §2.6.

Both work. The "empty + flag" shape is strictly better because it
keeps the parallel array's invariant clean — "this is what the
operator literally wrote / cited". Decision is correct.

Self-pass: no change needed; plan should add a one-line note that
the decision is load-bearing for the BookEntry convention
consistency, not just stylistic.

### F-SMR-r1-4 — Cache-line concern (§10 Q3) is structurally LOW (NO FINDING after analysis)

Hostile self-check: compute current `PolicyRule` size, then
compute post-change size.

Current fields:
- rule_id: String = 24 B
- policy_id: u32 = 4 B
- from_zone: String = 24 B
- to_zone: String = 24 B
- scheduler_name: String = 24 B
- inactive: bool = 1 B (+ pad)
- source_literal_v4: PrefixSetV4 enum = ? (variable, but enum tag + payload)
- source_literal_v6, destination_literal_v4, destination_literal_v6: same enum
- source_book_idxs: SmallVec<[u32; 8]> = ~40 B (inline buffer 8×4 + len/cap)
- destination_book_idxs: same
- 4× match_any bools = 4 B + pad
- applications: Vec<ApplicationMatch> = 24 B
- compiled_apps: CompiledApplications = ? (FxHashMap inside)
- action: enum = 1 B
- hit_counter: Arc<PolicyRuleCounter> = 8 B

The struct is already large (likely 400+ B based on these fields).
Adding 4 × 16 B = 64 B brings it to ~470 B. Multiple cache lines
either way. The relevant hot-path question is: does
`evaluate_policy()` read fields in clusters that span lines?

`evaluate_policy()` accesses (per call): zone IDs (precomputed,
not on PolicyRule), action, applications/compiled_apps, the
literal PrefixSets, the match-any flags. These already span
multiple cache lines today. Adding 4 more fields anywhere in the
struct doesn't change the asymptotic line-touch count for a hit;
the additional 64 B touches 1 more line, only if any reads them
— and the plan bans hot-path reads.

**Verdict on Q3:** LOW risk. Plan should state `size_of` change
quantitatively (current vs +64 B) in the cache-line section
rather than wave at it, but the actual hot-path impact is zero
because the fields are not read on the hot path. MINOR clarity nit.

### F-SMR-r1-5 — Helper redundancy with existing parse logic (NO FINDING)

Plan §4.3 introduces `collect_rule_side_prefixes_v4/v6` helpers
that duplicate the existing `parse_v3_literal_set` and the legacy
`parse_address` loops. Hostile check: is this duplication
acceptable?

Yes — the existing parsers populate `PrefixSet` (collapsed
representation), and the new helpers populate `Arc<[Prefix]>`
(uncollapsed). They can't share a code path without restructuring
the existing parsers to return both views, which would be scope
creep.

The #1624 BookEntry implementation handles this by capturing the
intermediate Vec<PrefixV{4,6}> before it's moved into
`from_v3_literals`. The PolicyRule path is slightly different
because the rule side reads both literals + book prefixes (the
union); BookEntry only reads its own snapshot prefixes. So a
straight capture-before-move doesn't compose at the rule level —
the helper is the right shape. No finding.

### F-SMR-r1-6 — Ordering guarantee absent — could be load-bearing (MINOR-NIT)

Plan §4.3 last paragraph says "arrays are NOT sorted, NOT
deduped... carries 'union of input prefixes in parse order,
literals first then each cited book's prefixes in book_idxs
order'". This is a semantic choice the future LPM builder
inherits.

Hostile check: is "stable insertion order across book_idxs"
actually preserved by the current code? `book_idxs` is a
`SmallVec<[u32; 8]>` that `resolve_book_idxs` sort+dedups before
return. So iteration is in book-id order, NOT in
source_book_ids-declaration order.

This is fine for the contract ("book_idxs iteration order") but
the wording "literals first then each cited book's prefixes in
book_idxs order" should clarify that book_idxs is already sorted
by dense-index. Tests should assert this stability.

MINOR clarity nit. Not blocking.

### F-SMR-r1-7 — `Arc<[T]>` ref-count contention under reconcile_rules (NO FINDING)

Hostile check: `reconcile_rules` walks `PolicyState.rules` and may
clone() rules during the reconcile dance. Each PolicyRule clone is
4 additional Arc ref-count atomic increments (one per parallel
array). Is this a hot path?

No. `reconcile_rules` runs once per config-apply (rare). Bumping
4 atomics per rule clone is in the noise. The hot path
(`evaluate_policy`) never touches these Arcs. No finding.

## Convergence summary

- F-SMR-r1-1 (Q4 1M-rule replication): document as accepted cost
  in plan §3 or §6. MINOR.
- F-SMR-r1-2 (Q5 empty-Arc footprint): switch Default to
  `Arc::<[T]>::default()` to share the global empty Arc. MINOR.
- F-SMR-r1-3, F-SMR-r1-5, F-SMR-r1-7: no change.
- F-SMR-r1-4 (cache-line): add quantitative `size_of` note. MINOR.
- F-SMR-r1-6 (ordering): clarify "book_idxs is sorted by dense
  index" in §4.3. MINOR.

Net: PLAN-NEEDS-MINOR. All five MINOR items can be addressed in
a single plan v2 revision before Codex + AGY dispatch. The
architectural axis is sound (mirrors shipped #1624 precedent);
the open questions §10 Q1-Q5 are honestly stated.

## Hostile self-test: would I PLAN-KILL this?

- Is the architecture wrong? **No** — #1624 BookEntry precedent
  shipped clean under quad-review; same shape applied to
  PolicyRule.
- Is the perf justification absent? **The plan is honest about
  zero runtime perf change** — this is foundation work. User
  authorized the narrow path knowing this.
- Is there a missing consumer? **Yes**, but the issue body
  explicitly lists this as the AGY r2 #1 simplification item to
  unblock future #1623 v4 work. User authorized.
- Is the parse-time cost prohibitive? **No** — 4 Arc allocs per
  rule, O(n) prefix copies. Cold path. Acceptable.

I would NOT PLAN-KILL. PLAN-NEEDS-MINOR is the correct verdict;
addressable in one revision.

## Reviewer-id

Claude SMR seat — this in-conversation self-review. No external
task ID. Will revise to claude-smr-plan-r2.md after Codex + AGY
land their first-round verdicts, regardless of whether their
findings overlap with mine.
