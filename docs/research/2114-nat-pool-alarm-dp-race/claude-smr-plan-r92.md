# Claude SMR hostile plan-review — round 92 (plan v95 @ `ddfd4e52203b`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r91
pass ran the label re-grep but only for the ONE term AGY flagged —
Codex r91 then found the replacement bucket name was itself false
("non-comma-ok single-value reads" does not fit loader.go:700's
comma-ok two-value read) plus the scope falsehood and the cardinality
confusion. Recorded: a fold that invents a NEW label must be verified
against every site the label covers, not just the one that triggered
it. This pass verifies every label against every covered site first.

## A. Fold verification (r91 findings → v95)

### 1. minor-2 (the exact 14+2+1 split) — FOLDED

The bucket now reads "3 other-shape reads — TWO single-value reads
plus ONE comma-ok early return": compiler.go:353 (single-value,
skips the redirect-map population and continues at :368 — verified),
loader.go:591 (single-value nil-guard return — verified at
:590-593), loader.go:700 (comma-ok two-value read with the early
return — verified at :700-704). The §9 continuation text now says
"the single-value read SKIPS" (no longer "nil-guard SKIPS"). A
full-document label sweep: every "nil-guard" / "single-value" /
"non-comma-ok single-value" occurrence is either the v95 normative
text (correct per-site), the corrective annotation, or historical
narrative with attribution. The three residual "non-comma-ok
single-value" occurrences (:6, :46, :5234) are all historical
narrative describing the v93/v94 state — correctly attributed.

### 2. minor-3 (the MULTI-ACCESS scoping) — FOLDED

The scoping now reads "methods with MORE THAN ONE registry access".
Verified against the four counterexamples: DeleteStaleStaticNAT
(two if-ok accesses, :224/:241), DeleteStaleNAT64 (:285/:291),
ZeroStaleNATPoolConfigs (:322/:328/:336 — three), SessionCount
(:327/:337). All multi-access, none error-returning on absent.

### 3. minor-4 (the SINGLE-ACCESS-SELECTOR rename) — FOLDED

The set heading is now "SINGLE-ACCESS-SELECTOR NEUTRAL SET" with the
cardinality rationale inline (ClearSessionCounts loops two map names
at maps_screen.go:58, GetMapStats loops every descriptor at
maps_stats.go:69 — both verified). The residual "SINGLE-MAP"
occurrences (:81, :107, :3420, :5921) are historical narrative.

### 4. minor-1 (the bucket summary) — FOLDED (in v94)

The summary now reads "3 other-shape reads = 17 sites" with the
14+2+1 split pinned.

## B. Fresh attacks on the v95 delta

**Attack 1 (FAILED) — a label means two things in two places.**
Swept "optional-if-ok" (14 sites, all `if x, ok :=` shape —
consistent), "single-value read" (exactly compiler.go:353 +
loader.go:591 — consistent), "comma-ok early return" (exactly
loader.go:700 — consistent), "MULTI-ACCESS" (methods with >1
registry access — consistent at :5170 and :5190), "SINGLE-ACCESS-
SELECTOR" (one syntactic selector site per method — consistent).
No dual-meaning label. FAILED.

**Attack 2 (FAILED) — the 14+2+1 split drops a site.** 14 if-ok +
2 single-value + 1 comma-ok early return = 17 = the mixed subset.
My r88 classification's 17 mixed sites match exactly (the 14 if-ok
at maps_nat.go:261/:274/:300/:328, maps_stale.go:224/:241/:285/
:291/:322/:328/:336, maps_session.go:327/:337, loader.go:730; the
three other-shape reads). FAILED.

**Attack 3 (FAILED) — the census text still implies a wrong
split.** Every normative census mention reads 91 required + 41
optional + 3 writes = 135 (sites) or 22 METHODS / 28 selector
sites (class-2) — units labeled. No residual "79 required". FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v95 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — every normative label verified against every
covered site (the 14+2+1 split walked site-by-site against the
code), the MULTI-ACCESS scoping fits all four counterexample
methods, and the rename is normative-everywhere with historical
attribution. My r91 miss (not verifying the newly-invented label
against every covered site) is recorded; this pass did exactly
that.
