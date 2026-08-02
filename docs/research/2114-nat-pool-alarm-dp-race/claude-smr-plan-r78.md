# Claude SMR hostile plan-review — round 78 (plan v79 @ `ea91b14da`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. My r77 pass
returned PLAN-READY on v78 while Codex r77 found the consistency
contradictions (the class-2 "no m.mu" clause, the impossible single
oracle, the missing attach carve-out) — my r77 pass verified the new
paragraphs but not their consistency against the older class texts.
Recorded. This pass checks v79 for exactly that failure mode: every claim
re-grepped against every other section.

## A. Fold verification (r77 findings → v79)

### 1. Codex M1 (uniform-rule consistency) — FOLDED

Re-grepped the plan for the stale forms: "needs NO `m.mu`" survives only
in the v79 header/history as the description of what was REPLACED
(historical record, correct). The class-2 bullet now routes
classification + handle selection through the registry helper; §5.1
states the uniform rule; §5.5/§6/§7 item 12/§9 4a are mutually
consistent. Verified against the tree that the only pre-existing
`!m.loaded` checks are the two attaches (loader.go:490, :1082 — the
greps returns nothing else in production code). FOLDED.

### 2. Codex M2 (oracle split + Store placement) — FOLDED

The two legs are now physically distinct: the quiescent
`TestManager_ArmedGate_FreshOutcomes` (pre-lock hook, no overlap —
per-class fresh outcomes) and the in-batch `TestManager_ArmedGate_
BlockedStart` (readers block during the hold; observe ARMED after
release because Store(true) is the batch's final in-hold step). The
external-IsLoaded-reader question resolves safely: Store(true) executes
only after the insert loops complete, so an outside observer reading
true early observes a true statement (population complete; only the
lock release is pending — not state). FOLDED.

### 3. Codex M3 (attach carve-out) — FOLDED

Verified: `AttachXDP` (:490) and `AttachTC` (:1082) carry master's own
`if !m.loaded` rejections before any registry access; the carve-out
preserves them and scopes "proceeds exactly as master" to methods
without a pre-existing check. No third method carries such a check.
FOLDED.

### 4. Codex m1/m2 (overclaim sweep; ownership correction) — FOLDED

§4.7 reads the narrowed L2 form; §10 assigns the generation hazard its
own lifecycle/generation follow-up with the standalone path evidence
(daemon_apply_commit.go:645 — verified the rollback path region).
FOLDED.

## B. Fresh attacks on the v79 delta

**Attack 1 (FAILED) — the uniform rule changes a class-3 pinned
outcome.** Class-3 hybrids run their Go-side side effects first (offset
clears under m.mu), then the scoped lookup; on fresh, the lookup
returns !ok and the pinned outcome (nil or the legacy error) follows
exactly as master. The lookup lock is new but outcome-neutral. FAILED.

**Attack 2 (FAILED) — the FreshOutcomes leg is vacuous under the
uniform rule.** A fresh method takes m.mu, classifies fresh, returns
its outcome — the quiescent leg asserts exactly that per class; the
in-batch leg asserts blocking+armed-after. Neither subsumes the other.
FAILED.

**Attack 3 (FAILED) — a stale text form survives outside the grep.**
Checked the §2 scope note, §4.7, §7, §9, §10 for the one-state gate or
the pre-v79 Store placement — none remain (the two grep hits are the
historical v79 header + the fold note). FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (0)

None.

## D. Structure confirmation (§11 q6)

CONFIRM — §4.7 stands; v79 keeps PR-1 self-contained.

## Verdict

**PLAN-READY** — with the standing discipline note: this verdict is
meaningful only because the r68-r77 chain is recorded above each round's
doc; the v79 text is the first revision where the uniform rule, the
two-state predicate, the oracle split, and the carve-outs are mutually
consistent under my re-grep. Codex's r78 pass remains the deciding
hostile read.
