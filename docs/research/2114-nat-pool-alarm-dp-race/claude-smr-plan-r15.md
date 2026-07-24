# Claude SMR hostile plan-review — round 15 (plan v15 @ `4b3546bac`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r15 verifies
the v15 folds (binding-ambiguity scope predicate, four-state keyed debt,
ArmID identity, residual wording, factory-reset class, diagnostic hedge)
against worktree code and mounts fresh attacks. All line numbers
re-verified (origin/master `ed6999000` + plan-doc-only branch).

## A. Fold verification (r14 findings → v15)

### 1. Scope re-based to the idempotence predicate (Codex M1) — FOLDED, with one strengthening nit (m1)

- The misclassification evidence verified: `store_command.go:32-37,72-77`
  (edits mark dirty unconditionally) and `gen_commit_5848_test.go:65-90`
  (edit-away/edit-back byte-identical content) — a plain commit CAN
  leave the record's hash matching; `store_persist.go:149-159` — legacy
  empty `GuardedHash` skips the binding check entirely. The v15 split
  (tombstone on ALL confirm-type resolutions; never on idempotent-revert
  replacements) covers every case the content-based split missed.
- **The idempotence claim itself, verified**: store-side, the #5473
  design ALREADY relies on revert-re-execution safety — the
  expired-branch comment states the NEXT boot "re-reads confirm.json
  (deadline still past) and reverts to prevTree AGAIN"
  (`store_persist.go:196-220`), and
  `confirm_rollback_durable_5473_test.go:221-293` pins exactly that
  re-drive. Apply-side: `applyConfigLocked` is a re-entrant
  desired-state reconcile (`daemon_apply.go:125-138` — every boot
  applies the full active config through the same pipeline); the #4234
  deletion-clear diffs old-vs-new (empty on identical configs);
  FRR `frr-reload.py` diffs and no-ops on identical content. A revert
  to the already-active target therefore converges to the same actual
  state — no destructive second execution.
  **Nit (m1)**: v15 cites only the store-side #5473 comment for
  "idempotent BY DESIGN". Add the apply-side citations
  (`daemon_apply.go:125-138` re-entrancy doctrine + the #4234
  empty-diff clear + frr-reload's diff-no-op) so the claim doesn't
  rest on one comment.

### 2. Four-state keyed debt (Codex M2) — FOLDED

The ABSENT state is real and master's retry already converges it
(`store_persist.go:441-443`: "DeleteConfirm reaches the #4864 dir fsync
even when the file is already absent"). The four-state table
(match → tombstone+delete; absent → DeleteConfirm; mismatch → clear;
read error → retain+retry) is complete over `ReadConfirm` outcomes
(nil-record / valid-record / error). A DEGENERATE-record outcome
surfaces as a ReadConfirm ERROR (#5637 gate, `db.go:275-281`) →
state (d) retain+retry — correct: a transient IO error converges; a
persistently corrupt record stays degraded+loud rather than being
silently cleared (fail-loud, matching the #5835 doctrine). FOLDED.

### 3. ArmID identity (Codex M3) — FOLDED

`confirmRecord` fields re-verified (`db.go:169-192` — no uniqueness
token exists); `confirmGen` memory-only (`store.go:168-179`); a fresh
wall-clock deadline per arm (`store_commit.go:507-509`) collides under
clock-step. Opaque crypto/rand `ArmID` at arm, additive, consumed ONLY
by the keyed debt — the timer callback needs no identity (the
in-memory `confirmGen` guard covers it, `:860`), and recovery needs
none (the record IS the state). FOLDED.

### 4-6. Residual wording / factory reset / diagnostic — FOLDED

The hazard wording is now honest (next-boot resolution; the deadline is
a trigger, not a bound). `factory_reset.go:252-268` verified (state +
record erased under a terminal generation). The stale-drop diagnostic
update is in the implementation scope (`store_persist.go:159-165`).

## B. Fresh attacks on the v15 delta (all MOUNTED, all FAILED)

**Attack 1 (FAILED) — tombstone on the plain-commit auto-confirm path.**
The auto-confirm resolves through `clearPendingConfirmLocked` →
`resolveConfirmRemovalLocked` — the same tombstone site. The active
config was already promoted before the resolution runs; the tombstone
mutates only `Resolved`, so a mismatching record gets a harmless
belt-and-braces tombstone (Resolved-first drop at recovery either way)
and an identical-content record gets the tombstone it NEEDS. Uniform,
no special-casing. FAILED.

**Attack 2 (FAILED) — lingering UNEXPIRED record after a successful
rollback with failed removal.** Recovery re-arms; the rebuilt in-memory
gen matches the re-armed timer (`store_commit.go:505`); the second
revert targets the already-active prevTree — idempotent per §A.1.
FAILED.

**Attack 3 (FAILED) — SyncApply-identical-content corner.** Synced
content == window content: the record binds after the durable synced
write, so a failed removal leaves a binding record — but the synced
config IS the confirmed intent (the peer holds it), and the tombstone
(the sync's auto-confirm resolution is confirm-type under v15) drops
it at recovery. The v15 predicate covers it without special-casing.
FAILED.

**Attack 4 (FAILED) — ArmID-less downgrade debt.** An old build's
unkeyed retry on a record armed by a new build: the old build's debt
mechanism is its own (unkeyed); it cannot see `ArmID` but also never
wrote a keyed debt. Cross-version debt only exists within one binary's
lifetime per boot — the debt is memory-resident (`store.go:152-166`),
never persisted, so no downgrade interaction exists at all. FAILED.

## C. Findings

### MAJOR (0)

None.

### MINOR (1)

**m1.** Strengthen the idempotence citation: add the apply-side
re-entrancy evidence (`daemon_apply.go:125-138`, the #4234 empty-diff
deletion-clear, frr-reload diff-no-op) alongside the store-side #5473
comment, so "idempotent BY DESIGN" doesn't rest on a single comment.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a citation-strengthening
note). A v16 containing only this is PLAN-READY by inspection from me.
