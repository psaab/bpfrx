# Claude SMR hostile plan-review — round 80 (plan v81 @ `ef86de7b0`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r79 pass
confirmed AGY's two stale-phrase findings against the tree but did not
originate them — my own grep pattern ("needs NO `m.mu`") was too narrow,
the second pattern-incomplete sweep on record. This pass re-runs the
extinction check with the widened pattern set and verifies the v81 folds.

## A. Fold verification (r79 findings → v81)

### 1. Codex M1 (retained oracle legs) — FOLDED

`TestManager_ArmedGate_RetainedOutcomes` is now its own named quiescent
leg (seeded retained registry, no overlap, every class proceeds exactly
as master including the loaded-check set's rejections), and the
`RetainedReStartOverlap` leg reads block-during-hold + armed-after-release.
No sentence in §9 asserts outcomes-during-hold anymore (re-read the item).
FOLDED.

### 2. Codex M2 (pre-rejection side-effect clause) — FOLDED

Verified the ordering and the idempotency against the tree:
`CompileUserspaceShim` (loader.go:173) runs
`cleanupUserspaceShimLegacyTCLinks` (:174) and
`cleanupUserspaceShimLegacyOnlyMapPins` (:177) before the selector write
(:180) and the `CompileConfig` rejection (compiler.go:182). Both cleanup
bodies are idempotent by construction (os.Remove with os.IsNotExist
skip, :271-287; the TC-link sweep reads the pin dir and skips absent
entries, :288+); the selector write assigns a constant. The clause's
"fires in every state" holds: the rejection is at :182, before any
registry access. FOLDED.

### 3. Codex M3 (invariant-12 carve-out) — FOLDED

Clause (iii) now scopes "proceeds" to methods without a pre-existing
loaded check, with the loaded-check set rejecting per master on every
state. FOLDED.

### 4. Minors (acquire-load remnants; §5.5 attribution) — FOLDED

Both remnants replaced; the §5.5 attribution now names the recurrence
class for H and the generic redesign as its own follow-up. FOLDED.

## B. Fresh attacks on the v81 delta

**Attack 1 (FAILED) — the stale-phrase class survives.** Re-grepped with
the widened pattern set (`acquire-load`, "needs NO", one-state forms,
pre-v79 Store placement): every remaining hit is historical record
(header/revision history/fold notes describing what was deleted), no
normative-text instance. Extinct. FAILED.

**Attack 2 (FAILED) — RetainedOutcomes contradicts §10's generation
hazard.** The quiescent leg asserts master's retained behavior; §10
names the Teardown-retain generation confusion as a pre-existing hazard
owned by its own follow-up. Master proceeds in BOTH the Close-retained
(live pins) and Teardown-retained (dead pins) cases — so "proceeds
exactly as master" is true in both, and the hazard text is about which
KERNEL OBJECT the mutation reaches, a correctness property A3
explicitly does not claim. Consistent. FAILED.

**Attack 3 (FAILED) — the blocked legs mis-specify class-3.** Class-3
hybrids never read `loaded`; their lookups go through the registry
helper, so during the whole-batch hold they block at the helper like
everyone else, and after release they proceed — which IS their armed
observation (their outcome doesn't depend on `loaded`). The
block-then-armed assertion holds for them. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v81 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — same discipline note as r78: the verdict rests on the
widened-pattern extinction sweep and the per-fold citations above, not
on the fold count.
