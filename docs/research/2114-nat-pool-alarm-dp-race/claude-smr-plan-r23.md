# Claude SMR hostile plan-review — round 23 (plan v23 @ `d1b64a4f1`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r22's SMR
converged with Codex on the D-kind retry hazard; r23 re-verifies the
v23 folds and attacks the completed D-kind machinery (re-read
re-classification, process-local scoping, synthetic-record pins) with
fresh interleavings. All line numbers re-verified against the worktree.

## A. Fold verification (r22 findings → v23)

### 1. Codex M1 (R-first remnant) — FOLDED

The B-REWRITE bullet's (w-b) summary now reads D2 (restore-as-
supersession, subsumption on the restore's barrier); a body sweep
finds no remaining R-first language outside revision history. FOLDED.

### 2. Codex M2 = SMR M1 (D-kind retry) — FOLDED, with nit m1

The re-classify rule is exactly the fix both of us derived: the
D-raised → arm-C → retry interleaving now hits (d-iii) READABLE →
clear as moot (the arm's overwrite already performed the supersession
the debt existed for), and C is untouched. The pass holds s.mu
(`store_persist.go:402-465`), so the re-read and the synthesized
`WriteConfirm` are inside one critical section — no arm can interleave
between them. FOLDED — but the (d-i) classification boundary has one
unpinned case; see m1.

### 3. Codex M3 (process-local D) — FOLDED

The process-local scoping and operator-mediated crash remediation are
stated; no self-reconstruction claim remains; the residual is the
admitted tombstone-failure ∧ crash class with the operator-paced heal
named. FOLDED.

### 4. Codex M4 (acceptance text) — FOLDED

All three x12/x19 copies state the two-step rule; all four
ONLY-producer copies are scoped (read-back vs synthesized). FOLDED.

### 5. Codex m1/m2/m3 (scoping, synthetic pins, health schema) — FOLDED

The guarantee scoping is precise (ordering never creates the gap; a
restore failure re-exposes the admitted arm-persistence residual);
`FirstCommit=false` is load-bearing (true would trip work item H's
FirstCommit+cluster guard on any reader — verified against the guard's
predicate); `Deadline` = now + 60 s; the downgrade behavior is
documented (config-neutral, runtime-churning, self-limiting) with the
regression asserting bind-on-normal-content → revert-to-identical →
consumed (the dual-basis analysis from earlier rounds: canonical ==
legacy for normal content, so the old reader binds; exceptional
content mismatches into the stale-drop — both safe); the mask gains
`SLOT_DELETE` and the aggregate is defined. FOLDED.

## B. Fresh attacks on the v23 delta

**Attack 1 (SUCCEEDED as nit m1) — (d-i) needs a transient boundary.**
The D-kind retry's re-read can fail TRANSIENT (mount blip, EINTR —
not the permanent class the latch was built on). The v23 text assigns
only the PERMANENT-unreadable case to (d-i). An implementer writing
the synthesized tombstone on ANY read failure would overwrite a
possibly-LIVE record it could not verify — the very hazard (d-iii)
exists to prevent (a transient failure conceals the slot's content;
the record might be a live window's). The pin: the synthesized
tombstone is written ONLY on a CONFIRMED PERMANENT-class slot read
failure (or after (d-iii)'s classification); a TRANSIENT read failure
retains the D-kind debt UNTRIED (no write this pass — the slot's
content is unknowable this pass). One-line pin, load-bearing.

**Attack 2 (FAILED) — re-read/write interleave inside a pass.** s.mu
held per pass; arms take s.mu; no interleave. FAILED.

**Attack 3 (FAILED) — synthetic HashBasis inconsistency.** The
synthetic `GuardedHash` is computed on the canonical basis and
`HashBasis` is set accordingly (`canonical-v1`) — consistent; the
downgrade reader compares on its own basis per the earlier dual-basis
analysis. FAILED.

## C. Findings

### MAJOR (0)

None. The D-kind machinery is now total: provenance (eager rule),
action (two-step), failure debt (re-read + re-classify), lifetime
(process-local), and observability (SLOT_DELETE in the mask).

### MINOR (1)

**m1.** Pin the (d-i) boundary: the synthesized tombstone is written
ONLY on a CONFIRMED PERMANENT-class slot read failure (or after
(d-iii)'s classification); a TRANSIENT read failure retains the
D-kind debt untried — no write while the slot's content is
unknowable.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a one-line classification
pin). A v24 containing only this pin is PLAN-READY by inspection from
me.
