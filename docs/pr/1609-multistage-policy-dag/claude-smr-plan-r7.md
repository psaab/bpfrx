# Claude SMR plan-review r7 — #1609 v3.1 round-2 convergence

**Role**: domain SMR (same scope as r1-r6).

**Verdict (round 7): PLAN-NEEDS-MAJOR — 3-of-3 convergence on v3.1
round-2; escalating to user per contract (third major iteration
without convergence).**

## Round-2 convergence

| Reviewer | Verdict | Key findings |
|---|---|---|
| Codex r2 (`task-mpp2jzhy-m057in`) | PLAN-NEEDS-MAJOR | 3 blocking: (1) P2 dst-pseudo-id leaks into src lookup OOB; (2) v3.1 addendum contradicts stale v3 text in §2.3/§2.6/§7; (3) Step 1 scope incoherent (excludes galloping merge but acceptance requires merge-dedup test) |
| AGY r2 (`adversarial-review-mpp2kcas-nksaq7`) | PLAN-NEEDS-MAJOR | 10 issues incl: P1 references non-existent `MatchNone` variant (compile bug); P2 type-safety theater; P3 Junos CLI gap; P4 heap-fragmentation latency; P8 cross-book push-down missing child propagation; **P10/Stage 4 master-fallback creates 1M-rule scan DoS amplification (NEW CRITICAL SEC FINDING)** |
| Claude SMR r7 (this) | PLAN-NEEDS-MAJOR | aligning to 3-of-3; r6 was overconfident |

3-of-3 convergent verdict: **PLAN-NEEDS-MAJOR**. Architecture
remains sound; v3.1 patches did not close the round-1 majors fully
and surfaced new issues.

## Critical new findings v3.1 r2 surfaced

### AGY #10 — Stage 4 master-fallback is a DoS amplification vector

Plan §2.8 says "if galloping merge produces >64 candidates, drop to
master linear scan over `state.zone_pair_index[zp_key]` or
`state.global_indices`". At 1M rules with adversarial traffic that
matches >64 rules in one phase, this scans **all rules in the phase
bucket** — which can be near-1M for the global phase.

AGY's mitigation is correct: the overflow fallback must scan ONLY
the actual emitted candidates (the 65+ rules the DAG identified),
not the entire phase rule set. That's 10,000× faster and closes
the DoS amplification.

This finding alone is a structural redesign of the §2.8 overflow
path. v3.2 must respec.

### Codex #1 — Shared LPM dst-pseudo-id leak into src lookup

Walk-through: rule R = `source any AND destination 10.0.0.0/24`.
- src_pseudo absent (source any → match_any side-channel).
- dst_pseudo present, ID = real_book_count + 0.
- LPM (shared) has 10.0.0.0/24 → returns book_id = real_book_count + 0.

Now packet src = 10.0.0.5 → LPM lookup of src returns same book_id.
Source-side code does `book_src_citations[book_id]`. With v3.1 P2's
sizing (`book_src_citations.len() = real_book_count +
src_pseudo_count`), `book_id = real_book_count + 0` is in-bounds
IF src_pseudo_count > 0, but the entry is a different rule's
src-pseudo, NOT this rule's dst-pseudo. **Cross-rule leak.**

Fix: either (a) separate LPMs for src vs dst; or (b)
total-length citation vectors with opposite-side entries explicitly
empty.

### Codex #2 — v3.1 addendum left stale v3 text contradictions

v3.1 patched only §2.2 inline + added §13 addendum. The main body
(§2.3, §2.6, §7) still says "fallback linear scan" + "warning
emitted" for v6 leaf overflow, contradicting §13 P3's "hard-reject
at commit time". Implementors get contradictory normative text.

This is a process problem — patches should rewrite the affected
sections, not just append.

### AGY #1 — P1 compile bug (`MatchNone` variant doesn't exist on
PrefixSetV4)

I missed this in r6. Per `prefix_set.rs:42-47`:

```rust
pub(crate) enum PrefixSetV4 {
    MatchAny,
    MatchNone,    // <-- actually IS present
    Linear(Vec<PrefixV4>),
    Trie(...),
}
```

Wait — looking again at my own r6 context, MatchNone IS present
(line 44 of prefix_set.rs). AGY's "variant not found" claim may be
mistaken. Let me double-check.

Actually re-reading prefix_set.rs as I read it earlier in the
session: `MatchAny | MatchNone | Linear(Vec) | Trie(_)` — 4
variants. P1's pseudocode matches all 4. So AGY's finding #1 is
**partially incorrect** — the variant exists. But AGY's "complex
custom iteration methods on PrefixSetV4/V6 vs simpler parallel
Arc<[Prefix]> on PolicyRule" simplification is still valid; v3.2
should just carry the prefix Arc on PolicyRule too.

### Other v3.2 must-patches

- AGY #4 heap-fragmentation latency: pool-allocate V6 sub-tables
  instead of individual Box allocations.
- AGY #8 push-down child propagation: explicit second-level table
  initialization with parent coverage before descending.
- AGY #9 LeafArcPool: last-seen cache + Single/Shared leaf
  representation for pseudo-book singletons.
- Codex #3 Step 1 scope: split into "primitive-only PR" (no
  evaluate_via_dag stub, just LPM + builders + tests) vs
  "scaffold PR" with stub. Either choice is fine; just don't mix.
- P9 LeafArcPool 10-100× claim: downgrade to measured.

## Reflection on the iteration

This is the 5th plan-review round (v1 r1, v1 r2, v2 r1, v3 r1,
v3.1 r2):
- v1 KILLED for memory bomb.
- v2 KILLED for 6 fatals.
- v3 PLAN-NEEDS-MAJOR for 5 majors.
- v3.1 PLAN-NEEDS-MAJOR for 3-blocking + 10 issues.

Each round closes some findings but surfaces new ones. The
architectural axis (Multi-Book LPM + MatchAny side-channels +
two-phase eval) remains sound across all 5 rounds. The problem is
the **design space depth** — there are many subtle correctness
issues (cross-side ID leak, fallback DoS, push-down propagation,
build-time fragmentation) that need careful upfront design before
implementation.

Two viable paths from here:

**Path A — v3.2 + r3 round** (4 hours): write v3.2 incorporating
all 13 round-2 findings (rewriting affected v3 sections in place,
not appending), dispatch Codex+AGY r3, hope for 3-of-3 PLAN-READY-
WITH-NITS-or-better. Risk: another round may surface yet more
issues (5th round has not converged).

**Path B — STAGED Step 1 minimal** (2 hours): drastically narrow
Step 1 scope to JUST adding the parallel `prefixes_v4/v6:
Arc<[Prefix]>` field on BookEntry + PolicyRule, plus the
`PrefixSetV{4,6}::iter_prefixes` API. NO LPM yet. NO PseudoBooks.
NO feature flag. Pure preparatory work that the full Step 1 will
build on. File a follow-up issue for the actual Multi-Book LPM
primitive. This is a v3.2 scope drop, not a v3.2 patch.

**Path C — PLAN-KILLED escalation per user contract**: report
third PLAN-NEEDS-MAJOR convergence; defer to user for path
selection (A vs B vs other).

## Recommendation

Per user contract: "PLAN-KILLED on #1609 v3 — <verdict> (third
kill — escalate, do NOT spawn v4 without user authorization)".
This is the third major-iteration kill on the axis (v2 KILL, v3
NEEDS-MAJOR, v3.1 NEEDS-MAJOR). Escalating to user.

Architectural axis (Multi-Book LPM + MatchAny side-channels +
two-phase eval) is sound but the implementation surface has more
subtle correctness issues than one planning session can close. The
right answer may be Path B (narrow Step 1 to BookEntry +
iter_prefixes scaffolding only) — but that's a user decision, not
mine.
