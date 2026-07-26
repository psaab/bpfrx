# Claude SMR hostile plan-review — round 30 (plan v30 @ `63ace2bdc`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r29's SMR
returned PLAN-READY and confirmed §4.7; r30 re-verifies the v30 folds
of Codex's 2M/5m against the real code and attacks the v30 delta —
including the three attack questions posed to all reviewers. All line
numbers re-verified against the worktree.

## A. Fold verification (r29 findings → v30)

### 1. Codex M1 (runbook provenance branch) — FOLDED

The hazard was real: process-local debts die with the process
(`store_persist.go:397-401` — "process exit simply abandons it",
re-verified), and a pending-shaped record at the next boot
hash-matches into re-arm or expired-revert
(`store_persist.go:149-165,231-255`). The v30 split is the right
one and it is cheap: the snapshot ALREADY distinguishes DEBT-origin
from BOOT-origin substates (the RESTART-RECOVERY-OWED vs
DEBT-origin rendering at `api/health.go`), so the operator is told
which branch applies by the same surface that reported the debt.
DEBT-ORIGIN → live restore + wait for clearance (the retry loop
re-validates under the restored key and the debts heal through
their own tables — no pending-shaped record survives to replay);
BOOT-ORIGIN → stopped-restore (the latch survives restart by
design and re-validates at boot reconstruction). FOLDED.

### 2. Codex M2 (per-debt derived cause) — FOLDED

The representability failure was real (R_A + W_B + R_B coexist —
one REMOVAL bit could not hold two owners' causes), and the sticky
variant misdirected after revalidation. The v30 semantics are the
correct ones: each keyed debt carries the class of its LATEST
retained failure (re-evaluated at every raise/retain via
`errors.As`), and the snapshot mask is DERIVED OR-by-kind over LIVE
debts — a cleared debt drops out of the OR, so no independent clear
rule can erase a live sibling's cause, and a key revalidation
followed by a non-key write-failure retain correctly flips the
message away from key restoration. The latch-level cause tracks the
latch's latest observed failure class the same way. My r29
"sticky-is-acceptable" assessment was WRONG on the revalidation
case; the latest-wins derivation is strictly better and I withdraw
it. FOLDED.

### 3-7. Codex m1/m2/m3/m4/m5 — FOLDED

The clear-time re-read ERROR branch is pinned (retain + journal the
exact verification error + key-state-UNVERIFIABLE message —
restoration-required reserved for byte-mismatch; exact-bytes
compare correctly passes a same-content rewrite). The producer
enumeration and every matrix now name (w-u) alongside (w-a),
(w-b)/(w-c), R (a), R (c), D tombstone (grep: 15 `(w-u)` mentions,
every "COMPLETE" list covers it). x22 is re-specified consistently:
(x22a) asserts arm-barrier CLEARANCE (the arm's own supersession
clears D), (x22b) keeps the SyncApply-pre-rename inert leg, and the
`armedArmID` conjunct is defense-in-depth — the earlier
"inert-beside-durable-arm" expectation is gone from both copies.
The normative nonce classification is qualified (encoding/length →
pre-AEAD non-key-class, `crypto.go:328-353`; well-formed tampered →
`gcm.Open` key-class, `crypto.go:354-356`). The delivery copies are
swept: the G scope note and the §11 prerequisite-commit copy point
at the FOLLOW-UP unit, §9 carries the [CORE]/[FOLLOW-UP] partition
header, §6's count is FIVE, and the provenance assumption is scoped
outside factory reset (`factory_reset.go:252-268` — re-verified the
DB removal lives there and is operator-triggered). FOLDED.

## B. Fresh attacks on the v30 delta

**Attack 1 (FAILED) — live-restore under a WRONG-but-valid K′′.**
The debt-origin branch re-reads the slot under the restored key on
the next pass; a wrong K′′ fails authentication again (key-class,
retained — the loop never proceeds). The sub-case where the slot
record was written under an auto-created K′ during the compromised
window (the pre-existing #1894 arm behavior) and the operator then
"restores the ORIGINAL K" over it: the files are K′-encrypted, the
reads fail under K, key-class retains with the restoration message
— which correctly means "restore the key the FILES were written
under" (the key the operator clobbered). Fail-closed, loud, and
identical to master's own key-loss semantics — not a plan defect.
FAILED.

**Attack 2 (FAILED) — latest-cause flip-flopping needs hysteresis.**
A debt alternating key-class/non-key-class across retains flips
the rendered cause with each pass — but the flip always reflects
the CURRENT actionable failure, the journal carries the exact
per-attempt causes, and hysteresis would lag the truth (a
revalidated key would keep the restoration message up while the
actual blocker is now an EROFS write — the misdirection Codex M2
itself killed). FAILED.

**Attack 3 (SUCCEEDED as nit m1) — the arm-supersession clear's
barrier choice is implicit.** The m3 pin says the D clear "rides
the arm's barrier" but never names WHICH barrier. The only reading
consistent with the rest of the design is the arm's DURABILITY
barrier (the dir-fsync, `fsatomic.go:45-79`): on arm SUCCESS the
record is durable and the supersession is real, so D clears; on a
POST-rename barrier failure the record is merely VISIBLE and the
arm creates a W debt — D must SURVIVE (suppressed by the W
conjunct) and re-classify fresh when W's (w-a) lands durability;
on a PRE-rename failure the slot is untouched and the W debt again
suppresses D. The composition is safe under the durability reading
(D never clears before the supersession is durable, and the W
conjunct covers every failure case), but the plan pins neither the
barrier choice nor the failure-case behavior — an implementer
reading "rides the arm's barrier" as the RENAME (visibility) would
clear D while the record is undurable and reopen the
crash-between-rename-and-fsync coverage gap the D debt exists to
close. One sentence fixes it: the clear rides the arm's
dir-fsync durability barrier; a failed barrier (pre- or
post-rename) leaves D standing, suppressed by the resulting W debt,
re-classifying fresh when W resolves. MINOR.

## C. Findings

### MAJOR (0)

None. Both r29 majors fold on independent verification; the v30
delta survives every fresh interleave I could construct.

### MINOR (1)

**m1.** Pin the arm-supersession clear's barrier as the arm's
dir-fsync DURABILITY barrier, with the failure-case behavior
explicit: a failed barrier (pre- or post-rename) leaves D standing,
suppressed by the resulting W debt, re-classifying fresh when W
resolves — never cleared on mere rename visibility.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 as recorded — the split stands with AGY's (A) dissent
preserved; the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the barrier-choice
pin). A v31 containing only this pin is PLAN-READY by inspection
from me.
