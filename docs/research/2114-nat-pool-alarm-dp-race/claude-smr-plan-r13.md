# Claude SMR hostile plan-review — round 13 (plan v13 @ `19bc6c977`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r13 verifies
the v13 folds of the r12 findings (mine + AGY's + Codex's) against
worktree code and mounts fresh attacks. All line numbers re-verified
(origin/master `ed6999000` + plan-doc-only branch).

## A. Fold verification (r12 findings → v13)

1. **Tombstone-first linearization (Codex M1)** — v13 pins (1) durable
   read-mutate-write tombstone = linearization point, (2) in-memory
   resolution (`cancelPendingConfirmTimerLocked`,
   `store_commit.go:717-726`), (3) best-effort delete. Verified the
   ordering logic: a crash after (1) leaves a complete tombstone on disk
   (fsatomic rename — no torn state) → recovery drops it; the in-memory
   side is moot because the process died. The in-flight callback guard
   (confirmGen bump → `PromoteRollback` gen check `:860`) is untouched
   in step (2). The residual (tombstone-write failure + crash before
   retry) is honestly stated and correctly rejected the
   durability-gated-confirm alternative (inverts disk failure into
   rollback). FOLDED.
2. **Generation-safe debt (Codex M2)** — verified the pre-existing
   mechanics: `confirmRemoveDegraded` unkeyed (`store.go:152`); retry
   removes whatever exists (`store_persist.go:439-444`); pre-arm
   cleanup covers only `confirmResolvePendingPersist`
   (`store_commit.go:631-649`). The v13 supersession
   (overwrite-satisfies-debt) is sound — `WriteConfirm` overwrites via
   fsatomic rename, so after B's arm A's record is unrecoverable.
   FOLDED — with one ordering pin, see m1.
3. **Additive-field decision (Codex M3 = my r12 m1 = AGY Attack 1)** —
   `WriteConfirm` contract comment verified (`db.go:200-205` — no
   envelope, additive evolution); the real floor
   (`envelope.go:111-123`) governs `active.json` only. The v13 decision
   (additive `Resolved` + `HashBasis`, documented downgrade semantics)
   is the right one. FOLDED.
4. **Versioned hash basis (Codex M4)** — dual-basis recovery compare.
   Verified the faithfulness question myself: for a NORMAL record (no
   invalid UTF-8, no inactive retired leaf, no control-char sanitize),
   the legacy arm hash (`journalConfigHash` of the raw promoted tree,
   `store_commit.go:543-549`) and the legacy recovery compare
   (`journalConfigHash(s.active)` post-migration) AGREE — the
   migrations are no-ops on such trees and the JSON round trip is
   shape-stable (empirically anchored by the passing #5835 recovery
   tests on master). So the dual-basis is faithful: canonical records
   get the fixed comparison; legacy records get exactly what their
   arming build meant. FOLDED.
5. **Arm-site correction (Codex m1)** — `writeConfirmState`
   (`store_commit.go:524`) is the sole arm; its body
   (`:535-558`) confirms best-effort semantics; `SyncApply` arms
   nothing. FOLDED.
6. **Read-mutate-write tombstone (my r12 m2 = AGY Attack 2)** — v13
   pins full-record mutation via the existing `WriteConfirm` fsatomic
   path; the #5637 gate (`db.go:275-281`) passes unmodified;
   resolution paths and the arm both hold `s.mu`
   (`store_commit.go:534` "Caller holds s.mu"), so the
   read-mutate-write is serialized against concurrent arms. FOLDED.

## B. Fresh attacks on the v13 delta

**Attack 1 (SUCCEEDED, MINOR m1) — debt-supersession ordering vs
arm-write failure.** `writeConfirmState` is BEST-EFFORT
(`store_commit.go:530-535`: "a failure is logged, not fatal"). If the
v13 debt-clearing executes BEFORE `WriteConfirm` and the write then
FAILS, the on-disk state is A's record (fsatomic rename never landed)
with the debt CLEARED — the retry never converges A's removal, and if
A's record is pending-shaped (the irreducible write-failure residual
from the tombstone leg), it lingers forever with no debt to drive
convergence. The pin must be: clear `confirmRemoveDegraded` ONLY on
the arm's SUCCESS path (after `WriteConfirm` returns nil — the
overwrite has then actually satisfied the debt). One-line ordering pin;
the regression (x4) gains a fifth leg: arm-write FAILURE keeps the
debt (and its retry convergence) intact.

**Attack 2 (FAILED) — intermediate-basis records.** The pre-migration
fix (v11) and the canonical basis (v12) ship in the SAME PR, so no
released build can produce a record with an intermediate basis; the
`HashBasis` discriminator covers exactly the legacy/canonical split.
No third basis exists. FAILED.

**Attack 3 (FAILED) — tombstoned-then-downgrade.** A new-build
tombstone on a legacy record: the read-mutate-write preserves the
legacy record's fields (no `HashBasis` added — the helper mutates only
`Resolved`); a downgrade reader ignores `Resolved` (additive) and
compares legacy-basis — consistent with its build. The tombstone write
must NOT add `HashBasis` to a legacy record (pin covered by the
"mutates only `Resolved`" helper spec in v13's x5). FAILED (the spec
already implies it; no fold needed).

**Attack 4 (FAILED) — Resolved record with mismatched hash.** Recovery
order checks `Resolved` BEFORE the hash mismatch: a resolved record
whose active config later advanced is dropped either way — the
Resolved-first order only changes WHICH log line emits, not the
outcome. FAILED.

## C. Findings

### MAJOR (0)

None. The four r12 majors fold cleanly; the linearization, debt
identity, additive-schema, and dual-basis mechanics are all verified
against the actual configstore code.

### MINOR (1)

**m1.** Pin the `confirmRemoveDegraded` clearing to the arm's SUCCESS
path (after `WriteConfirm` returns nil); an arm-write FAILURE must
leave the debt (and retry convergence) intact. Regression (x4) gains
the arm-write-failure leg.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a one-line ordering pin
plus a test leg). A v14 containing only this pin is PLAN-READY by
inspection from me.
