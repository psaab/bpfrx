# Claude SMR hostile plan-review — round 91 (plan v93 @ `9a30b5087a4a` + the r91 AGY residual fix)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r90
pass ran the bookkeeping sweep on cardinality phrases but NOT on the
bucket LABELS — Codex r90's minor-1 caught the "3 nil-guard reads"
bucket and my v93 fold renamed it in the body, but I did not re-grep
the label after folding, so the summary line at :5149 kept the old
label. AGY r91 caught exactly that residual. Recorded: a fold that
renames a term must be followed by a full-document grep of BOTH the
old and new term. This pass runs that sweep, then the rest.

## A. Fold verification (r90 minors → v93)

### 1. minor-1 (the "simply returns" residual + bucket rename) — FOLDED with the r91 residual

The rule's three-way phrasing (skip / nil-guard return / skip-and-
continue) verified at :5142-5144. The bucket rename landed in the
body but the summary line at :5149 kept "3 nil-guard reads" — AGY
r91's single residual, verified real, and fixed in the v94 working
tree (the summary now reads "3 non-comma-ok single-value reads = 17
sites"). A full-document grep of "nil-guard reads" now finds only the
historical narrative.

### 2. minor-2 (Detach-qualification propagation) — FOLDED

A3 (:4010-4014) and §5.1 (:4349-4353) both now carry the §9
qualification (a usable iface_zone_map seeded; the absent-map no-op
excluded). Tri-site consistency verified.

### 3. minor-3 (signature falsehood + source pin) — FOLDED

The mixed-method paragraph now says "single-registry-access methods"
with the four-void enumeration (SeedNATPortCounters :434,
SeedSessionIDCounter :611, the two internal helpers :909/:927) and
the two error-returning exceptions (UpdatePolicyScheduleState,
ClearZoneCounters). The v92 header's pin is corrected (reset :399,
lookup :400). Verified against maps_nat.go:396-401.

### 4. minor-4 (the stale count label) — FOLDED

"22 best-fit class-2 METHODS" at :3895. A lookup/method sweep finds
no other count-confusion.

## B. Fresh attacks on the v93 delta

**Attack 1 (FAILED) — another single-qualification claim summarized
unconditionally elsewhere.** Swept the A3 block's qualified claims
(the armed-Close scoping, the IsLoaded surface, the per-access
outcome rule, the Detach qualification) against §4.7/§6/§7/§8
summaries: every one now either carries the qualification or
cross-references it. FAILED.

**Attack 2 (FAILED) — the five-leg oracle's hook protocol breaks on
leg 5.** Leg 5's Close-window hook is instance-scoped and the only
ownership hook armed in its test — the same protocol as legs 3-4
(one hook per test). The Close body is straight-line; the hook
placement (after Store(false), before the link closes) is a
well-defined interval. FAILED.

**Attack 3 (FAILED) — the census labels still confuse sites and
methods.** The §11 item-7 census now reads "91 required + 41
optional + 3 writes = 135" (sites) and the class-2 label is METHODS.
The two counts live in different units and the text says which is
which. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None beyond AGY's r91 residual (verified + folded in the v94 working
tree).

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v93 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — all four r90 minors verified against the tree, the
label sweep (run first this pass) caught AGY's r91 residual
independently on re-grep, and the five-leg oracle's hook protocol is
uniformly implementable. My r90 miss (not re-grepping the renamed
label after folding) is recorded; the v94 fold closes it.
