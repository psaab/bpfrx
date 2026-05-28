# Claude SMR plan-review r6 — #1609 v3.1 (post-patch)

**Role**: domain SMR (same scope as r1-r5).

**Target**: `docs/pr/1609-multistage-policy-dag/plan.md` v3.1
(in-place patch of v3 + §13 addendum addressing Codex r3 5 majors +
AGY r3 5 nits).

**Verdict (round 6): PLAN-READY-WITH-NITS.**

Hostile re-read after v3.1 patches finds the round-1 v3 findings
closed with specific patches. Remaining residual gaps are
NIT-level for Step 1 scope; Step 2 will pick them up.

## v3 r1 findings closed by v3.1

| Round-1 finding | v3.1 patch | Closed? |
|---|---|---|
| Codex M1 PseudoBook + MatchAny conflation | P1 split iter_prefixes by purpose | ✓ |
| Codex M2 v6 overflow unbounded fallback | P3 commit-time hard-reject + operator counter | ✓ |
| Codex M3 v6 memory math under-counted intermediates | P4 corrected estimate to 100-500 MB realistic / 5 GB pathological + Leaf48 variant + Poptrie escape hatch | ✓ structural |
| Codex M4 pseudo-book ID namespace inconsistent | P2 PseudoBookId(u32) newtype + explicit ID layout + builder signature match | ✓ |
| Codex M5 iter_prefixes Trie DFS cost | P5 BookEntry has parallel Arc<[Prefix]>; Trie DFS only on rare rule-literal Trie variant (≤1% rules); ~50 ms total at 1M rules | ✓ |
| Codex M6 /0 + non-/0 dedup | P6 galloping-merge dedup via standard sorted union | ✓ |
| AGY nit Prefix propagation push-down | P8 documented 2-pass build + cross-book overlap test | ✓ |
| AGY nit Arc Sharing/Interning | P9 LeafArcPool content-hashed | ✓ |
| AGY nit FxHashMap → sorted Box<[]> | P7 BookCitations sorted-slice + binary/linear | ✓ |
| AGY nit Allocation-free hot path | P10 restatement; already implicit in v3 §2.7 | ✓ |
| AGY nit V6Node Leaf48 variant | P4 added explicit Leaf48(Box<MultiBookLpmV6Leaf48>) | ✓ |
| SMR r5 F-r5-1 PseudoBook citation degenerate merge | acknowledged in §2.5 note; minor inefficiency, not blocking | ✓ |
| SMR r5 F-r5-2 galloping merge unspecified | Step 2 problem; v3.1 §13 doesn't add it but acknowledges forward-link | ✓ scope |
| SMR r5 F-r5-3 PseudoBook prefix dedup | not added in v3.1; Step 2 can add content-hash dedup as optional optimization | ⚠ deferred |
| SMR r5 F-r5-4 per_zone_pair FxHashMap | P7 — closed | ✓ |

13 of 15 round-1 findings have explicit v3.1 patches; 2 are
deferred-acknowledged (F-r5-2 galloping merge belongs to Step 2;
F-r5-3 PseudoBook prefix dedup is optional).

## v3.1 hostile re-read — residual nits

### N1 — V6 5 GB pathological is the new memory cap

P4 raised the v3 §6 §Y memory budget for v6 pathological from
600 MB to 5 GB. Under relaxed budget that's still acceptable
(<8 GB single VM), but reviewers may push back on "5 GB worst case
v6" being silently raised. The relaxed-budget §Y already says
"hardware capacity, not RSS, is the constraint". I think this is
OK but worth flagging.

### N2 — LeafArcPool memory savings unproven

P9 claims 10-100× savings via interning. Realistic /24-uniform
configs have many adjacent /24 leaves with identical book_id sets,
so interning helps. But adversarial-overlapping configs (each /24
has a different book overlap set) could see zero interning win.

Step 1 microbench should report `interning_dedup_ratio` so
operators see the actual savings.

### N3 — P8 prefix propagation push-down sketch is abbreviated

The 2-pass build (sort by length ascending, broadest first; insert)
is correct in principle, but the implementation must handle the
case where a /16 insert is later "narrowed" by a /24 from the SAME
book — should that be an Arc-dedup union (same book_id, no change)
or just a no-op insert (because the /16 already covers the /24)?

Position: the inserts are idempotent at a per-(book_id, leaf) level
because they unite into a sorted set. A second insert of the same
book_id at the same leaf is a no-op. Correctness preserved.

But Step 1 should add a property test for this case explicitly.

### N4 — P3 hard-reject on v6 overflow breaks the "no rule drops"
soft framing

v3 §2.4 said "buffer overflow → master-fallback (no rule drops)".
v3.1 P3 says "v6 leaf overflow → snapshot apply hard-fail". These
are DIFFERENT failure modes:
- Stage 4 buffer overflow at evaluation time → master-fallback
  (run-time).
- v6 leaf overflow at config-apply time → hard-fail (build-time).

Both are correct; they target different failure surfaces. But the
plan should explicitly say "build-time vs run-time" failure
handling. The current §2.8 + §13 P3 together are correct but
splitting clarity helps.

### N5 — §13 P4 v6 memory estimate uses different math than §6 §Y

§13 P4 says "100-500 MB realistic; 5 GB pathological". §6 §Y as
written still has "60 MB realistic; 600 MB pathological" (the v3
estimate). v3.1 should update §6 §Y to match §13 P4. Minor doc
hygiene.

## Verdict

**PLAN-READY-WITH-NITS.** The 5 v3 round-1 majors are all closed
by v3.1 patches with specific named fixes. The 5 AGY nits are all
closed. The 4 SMR r5 nits are 3-of-4 closed (F-r5-3 PseudoBook
prefix dedup is optional Step-2 enhancement). Residual nits N1-N5
are NIT-level — they don't block Step 1 implementation.

If Codex + AGY r2 verdicts confirm v3.1 closes their round-1
findings, this goes to **PLAN-READY** for Step 1 implementation.
Otherwise the next round identifies the next set of patches.

## Why I'm still being hostile

r3 → r4 reversal pattern taught me first-pass PLAN-READY is
suspicious. r5 was PLAN-NEEDS-MINOR (NOT first-pass ready). r6 is
PLAN-READY-WITH-NITS — better, but not PLAN-READY because N4 + N5
are still real gaps. Reviewers should challenge.

## Process

Next: dispatch Codex + AGY r2 on v3.1 SHA. If both reach
PLAN-READY-WITH-NITS-or-better, proceed to Step 1 implement. If
either reverts to PLAN-NEEDS-MAJOR, document residuals + decide
between v3.2 patch round vs STAGED return.
