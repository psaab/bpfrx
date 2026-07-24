# Claude SMR hostile plan-review — round 22 (plan v22 @ `055ee7f45`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r21's SMR
signed off with the handoff-window nit (subsumed by Codex M1); r22
re-verifies the v22 folds and attacks the new mechanics (D1/D2 scoping,
synthesized tombstone, D-kind slot debt) with fresh interleavings. All
line numbers re-verified against the worktree.

## A. Fold verification (r21 findings → v22)

### 1. Codex M1 (dominance scoped, restore prioritized) — FOLDED

D1/D2 is the correct decomposition: the r18-r20 hazard was
IDENTITY-PRESERVING writes (durably restoring a pending-shaped dead
record); the v22 restore never preserves — it REPLACES the dead record
with `s.armedRecord`. The payload can never be a dead window's record:
`armedRecord` is replaced at every arm and W re-keys at every arm, so
at debt-run time both name the newest live window; a resolution in
between clears `armedArmID` and the W debt stale-checks at its turn.
The r21 crash sequence (tombstone→delete lands, crash before restore)
is structurally impossible under restore-first: either the restore
landed (C durable, R_K cleared-by-barrier) or it did not (K intact,
both debts owed, retry). FOLDED.

### 2. Codex M2 (synthesized tombstone + D-kind slot debt) — PARTIAL, see M1 below

The synthetic record passes #5637 (non-zero `Deadline`, non-nil
`PrevTree`, `db.go:266-281`) and drops at the Resolved-first check
(`store_persist.go:149-165` ordering — Resolved precedes
GuardedHash/expired). The crash matrix closes (after (1): Resolved-
dropped; before (1): latch reconstructs + D-kind re-runs; after (2)
pre-fsync: absent-clean or tombstoned-dropped). But the D-kind retry's
re-run is specified unconditionally — see M1.

### 3. Codex M3/m1/m2 (remnants swept) — FOLDED

Identity split stated; both x4c' copies restated; §9 x19 marker text
gone; four-level precedence with enum + mask; §6 THREE messages.
FOLDED.

## B. Fresh attacks on the v22 delta

**Attack 1 (SUCCEEDED — MAJOR M1) — the D-kind retry can
synthesized-tombstone a LIVE window's record.** The D-kind slot debt
re-runs "(1)→(2)" unconditionally. Walk: BOOT latch (record
unreadable) → plain commit B lands durably → the eager rule runs, the
synthesized-tombstone `WriteConfirm` fails (post-rename — visible
tombstone or nothing) → D-kind debt raised → the operator issues a
COMMIT CONFIRMED (arm C): `writeConfirmState` OVERWRITES the slot with
C's live-window record (`store_commit.go:503-553`) → the D-kind retry
fires and re-runs step (1): it writes the synthesized `Resolved:true`
tombstone over C — a LIVE window's crash-recovery record — and step (2)
deletes it. Recovery then drops the tombstoned C (Resolved-first) and
the live unconfirmed window's rollback intent is durably gone —
system-induced, not failure-induced (strictly worse than master's
best-effort arm-failure posture, which is at least loud). The fix is
one rule: the D-kind retry RE-READS the slot and re-classifies —
(i) still unreadable (permanent) → proceed with the synthesized
tombstone → delete; (ii) ABSENT → `DeleteConfirm` re-drive → clear;
(iii) READABLE → the superseded unreadable record is already GONE
(replaced — by the arm's overwrite per the (ii-b)-for-confirmed-commit
rule, or by operator action): the D-kind debt CLEARS as moot and the
readable record follows its normal path (live-window ArmID match →
untouched; Resolved → finish the delete; otherwise → the R-kind/
seeded-orphan machinery). A readable record is NEVER
synthesized-tombstoned. The x18/x19 legs gain the arm-overwrite-
before-retry interleaving.

**Attack 2 (SUCCEEDED as nit m1) — the synthetic tombstone's
downgrade-reader behavior is unpinned.** An old reader's
`json.Unmarshal` ignores the additive `Resolved` field (the
r12-decided downgrade semantics): it sees a PENDING record with
`PrevTree` == a clone of the then-current active tree and a near-future
deadline → it re-arms and reverts to that tree — config-state NEUTRAL
(a revert to the running config) but runtime-churning per the
corrected idempotence premise (AF_XDP re-attach, generation bump, FRR
reload). One-sentence pin in the downgrade-semantics passage:
config-neutral, runtime-churning, self-limiting (the record is deleted
by the revert's own resolution path on the NEW build; on the old build
the timer fires once and the record is gone). MINOR.

**Attack 3 (FAILED) — D2 subsumption destroying a non-dead record.**
The restore payload names the newest live window at debt-run time
(arm/re-key/resolve rules); the on-disk record it overwrites is always
the dead one (a newer live window's arm would have re-keyed W and
overwritten the slot itself). FAILED.

## C. Findings

### MAJOR (1)

**M1.** The D-kind slot debt's retry must RE-READ and re-classify
before any synthesized tombstone: still-unreadable → proceed; absent →
`DeleteConfirm` re-drive → clear; READABLE → clear as moot (the
superseded unreadable record was already replaced) and the readable
record follows its normal path. As written ("re-run (1)→(2)"), an arm
landing between the debt's raise and its retry gets its live-window
record synthesized-tombstoned and deleted — a system-induced durable
loss of a live unconfirmed window's rollback intent.

### MINOR (1)

**m1.** Pin the synthetic tombstone's downgrade-reader behavior: an old
reader ignores `Resolved`, re-arms, and reverts to `PrevTree` == the
then-current tree — config-state neutral, runtime-churning,
self-limiting.

## Verdict

**NEEDS-REVISION** (1 MAJOR, 1 MINOR). Everything else in the v22
delta verified FOLDED against the code. M1 is a one-rule fix (re-read
and re-classify; never tombstone a readable record) plus its
regression leg; it does not disturb the D1/D2 scoping or the
two-step eager rule itself.
