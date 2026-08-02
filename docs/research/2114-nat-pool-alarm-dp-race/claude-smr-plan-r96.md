# Claude SMR hostile plan-review — round 96 (plan v99 @ `a862aa14d77c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r95
pass walked the 17-site coverage but did not ask what CHECKS the list
— Codex r95 found the load-bearing extensional inventory was
mechanically unchecked. Recorded: every load-bearing enumeration needs
a named checker, and the reviewer's job is to ask for it. This pass
checks the manifest mechanism first, then the rest.

## A. Fold verification (r95 minor → v99)

### The stale-checked helper-callsite manifest — FOLDED

The v99 text adds the manifest: every `lookupMapLocked`/
`lookupProgramLocked` callsite maps to its required/optional outcome,
the 17 mixed sites map to their named §9 legs, and the checking
mechanism is the registry canary's own stale-allowlist self-check
pattern (§9 item 5, :5596-5600 — "the registry-access canary's
synthetic negative tests plus its stale-allowlist self-check (r81
Codex M1)"). The callsite enumeration is mechanical — the two helper
names are exact strings, so a grep/AST pass enumerates the callsites
and the self-check compares them against the manifest (added/removed/
moved callsite → build failure until the manifest and the leg mapping
update). The manifest does NOT infer semantics (the outcome label is
the recorded decision, not an inferred one) — exactly the r95
requirement. FOLDED.

## B. Fresh attacks on the v99 delta

**Attack 1 (FAILED) — the manifest needs the absent-branch SHAPE per
callsite.** The manifest's job is to force review on callsite CHANGE,
not to re-verify behavior on every build — the behavioral coverage is
the §9 legs' job (they assert the absent-outcome behavior at runtime).
A shape column would duplicate the legs' role. The outcome label
(required/optional + the named leg) is the join key between the
callsite and its behavioral test. Sufficient. FAILED.

**Attack 2 (FAILED) — a residual review-only claim.** Swept: the
v95-era "handwritten review" phrasing at :3955 concerns the METHOD
classification labels (the 157-method class partition), which the
PreArmMethodMatrix test DOES inventory — and the v99 manifest covers
the per-access callsites. The two mechanisms together leave no
review-only load-bearing enumeration. FAILED.

**Attack 3 (FAILED) — the manifest self-check is circular.** The
self-check enumerates callsites mechanically (grep the two helper
names) and compares against the manifest; a mismatch fails the build.
The manifest is the recorded expectation, the code is the truth, the
self-check is the comparison — the same non-circular pattern as the
canary's allowlist self-check (r81 Codex M1's verified design).
FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v99 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — the callsite manifest is mechanically checked by the
canary's own stale-allowlist self-check pattern (exact-string
callsite enumeration, build-failing comparison), the outcome label +
named leg is the correct manifest granularity (behavioral coverage
stays with the §9 legs), and no load-bearing enumeration remains
review-only. My r95 miss (not asking what checks the list) is
recorded; this pass asked it first.
