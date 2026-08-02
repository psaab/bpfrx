# Claude SMR hostile plan-review — round 93 (plan v96 @ `1a9bc125e148`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r92
pass verified labels against sites but did not check the 15+2 partition
ARITHMETIC against the direct-access rule — Codex r92 found Compile and
seedInterfaceCounter are single-selector under that rule. Recorded: a
partition claim must be enumerated, not just sampled. This pass
enumerates the full 17-site partition, then the rest.

## A. Fold verification (r92 minors → v96)

### 1. minor-1 (the 15+2 MULTI-ACCESS-OPERATIONS partition) — FOLDED

I enumerated the full 17-site mixed subset by host method:
ClearStaticNATEntries 2, SetNAT64Config 1, ClearNAT64Configs 1,
DeleteStaleStaticNAT 2, DeleteStaleNAT64 2, ZeroStaleNATPoolConfigs 3,
SessionCount 2, setXDPAttachedFlag 2 (:700 and :730 — two DIRECT
selectors, so multi-selector), Compile 1, seedInterfaceCounter 1.
That is exactly 15 sites in multi-selector methods + 2 composed
single-selector sites. The composition claims verify: Compile calls
clearNativeXDPFlagsForIfindexes at compiler.go:399 (verified — the
generic-fallback path), whose selector loader.go:928 sits in the
single-selector set; seedInterfaceCounter is called from AttachXDP
(:576) and AddTxPort (:1000). FOLDED.

### 2. minor-2 (the fourth outcome shape) — FOLDED

The rule now enumerates four shapes (if-ok skip, nil-guard return,
skip-and-continue, comma-ok early return) with the exhaustiveness
note. The 41 optional reads: 14 if-ok + 2 single-value + 1 comma-ok
early return = the 17 mixed; the 14 single-access-selector sites are
all `!ok → return`/`continue` (nil-guard-equivalent shape) or
if-ok... my r88 classification shows the 12 stale cleanups are
comma-ok-with-`!ok → return` (a fifth SHAPE — but wait: that IS the
"nil-guard return" shape expressed via comma-ok; the four shapes are
behavioral categories (skip/return/continue/early-return), not
syntactic forms, and the exhaustiveness claim is about the 41
optional reads' BEHAVIOR — each optional read's absent outcome is one
of the four. The 12 stale cleanups' `!ok → return` is the nil-guard
return behavior. Consistent. FOLDED.

## B. Fresh attacks on the v96 delta

**Attack 1 (FAILED) — "composed into multi-access operations"
collides with A3's direct-access classification.** A3's rule classes
a method by its DIRECT access ("touches means DIRECT access; a method
that only DELEGATES into an already-classed internal is classed by
that delegation target"). The 15+2 partition is a property of the
SITE INVENTORY (which set a selector site belongs to), not of the
method classification — the two composed sites are single-selector
by their OWN method's direct access, and the composition note
explains why they sit in the mixed INVENTORY (their callers are
multi-access operations). The two rules operate on different axes
(site inventory vs method class). No collision. FAILED.

**Attack 2 (FAILED) — the four-shape enumeration misses a fifth
behavior.** The candidates: an optional access whose absent outcome
is an ERROR would be required-by-definition (contradiction); an
absent outcome of "log and continue" — the stale cleanups log only
when entries were deleted (present path), not on absent. No fifth
behavior exists in the 41. FAILED.

**Attack 3 (FAILED) — "other-shape reads" dual-meaning.** The term
appears at :5191 and :5195 with the same referent (the 3 non-if-ok
reads in the mixed subset). Consistent. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v96 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the full 17-site partition enumerated by host
method (exactly 15 multi-selector + 2 composed single-selector,
matching v96), the composition claims verified against the code
(compiler.go:399, loader.go:576/:1000), and the four-shape
exhaustiveness holds across the 41 optional reads. My r92 miss
(not enumerating the partition) is recorded; this pass enumerated
it.
