# Claude SMR hostile plan-review — round 79 (plan v80 @ `91dbcb631`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r78 pass
grepped for the r77-flagged stale forms ("needs NO `m.mu`", one-state
gate phrasings) but not the FULL stale-phrase class — AGY r79 then found
two more stale phrases my grep pattern missed. Recorded before the
verdict: the SMR pass's consistency sweep has itself been
pattern-incomplete twice now (r77: cross-section contradictions; r79:
stale-phrase coverage).

## A. Fold verification (r78 findings → v80)

All five folds verified against the tree: the class-1/class-2 bullets'
one-state sentences replaced by the uniform form; the contradictory
"legacy overlap shape" sentence deleted with the four-leg oracle in its
place; the carve-out completed with the CompileConfig path
(`compiler.go:182` rejects `!dp.IsLoaded()` before registry access —
verified; reached by Compile :316, ApplyConfig apply.go:237,
CompileUserspaceShim loader.go:173; Compile touches `m.maps` at :353);
the stale Store-placement descriptions corrected; the H-attribution
stragglers fixed. FOLDED.

## B. Fresh attacks on the v80 delta (full-document consistency read)

**Attack 1 (FAILED) — the §4 outcomes bullet's item (iii) lacks the
fresh scoping.** In isolation, "(iii) the class-1 outcomes ... become
the one clean typed error, the only intentional behavior change" omits
"fresh". In context it sits under the two-state predicate three bullets
earlier and §6 carries the explicit scoping — consistent as a whole.
FAILED (with the caveat that this is exactly the class of thing the
next reviewer may still flag; the whole-document read is what decides).

**Attack 2 (FAILED) — the in-hold Store(true) creates an early-true
hazard.** An outside `IsLoaded()` reader observing true before the hold
releases observes a true statement: population completed before the
Store; only the lock release is pending, which is not state. FAILED.

**Attack 3 (FAILED) — the quiescent-retained leg contradicts the
CompileConfig carve-out.** The leg asserts retained-proceed per class;
the carve-out methods (attaches, the CompileConfig path) return their
master rejection on BOTH states — which IS master's behavior, so the
leg's "proceeds as master" and the carve-out agree. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0 from me this round; 2 confirmed from AGY r79 already landed
for the v81 fold)

AGY r79's two stale-phrase findings are REAL and confirmed against the
tree before folding: (1) `plan.md:3605` — the class-1 bullet's opening
still reads "acquire-load `m.loaded` BEFORE THE FIRST Start-state
access" (the v80 rewrite replaced the bullet's closing sentence but not
its opening phrase); (2) `plan.md:4071` — §5.1's class-2 summary still
says "WITH the acquire-load rule" (should be the synchronization
rule). AGY r79's finding 3 (`plan.md:4422` "Store(true) at Close()
entry" typo) is a MISREAD — verified: line 4422 correctly reads
"the Store(false) at `Close()`'s entry", and a full-document sweep
found no Store(true)-at-Close juxtaposition anywhere. Not folded; the
misread is documented for the record.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v80 keeps PR-1 self-contained.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the two stale phrases,
confirmed from AGY r79's report against the tree). A v81 containing
only these two pins is PLAN-READY by inspection from me.
