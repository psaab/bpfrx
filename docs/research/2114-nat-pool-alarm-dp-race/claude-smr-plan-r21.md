# Claude SMR hostile plan-review — round 21 (plan v21 @ `bbd9fd43c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r20's SMR
found the marker-loss hole (converging with Codex M2); r21 re-verifies
the v21 folds and attacks the new mechanics (live-window re-key, eager
supersession delete, enum snapshot) with fresh interleavings. All line
numbers re-verified against the worktree.

## A. Fold verification (r20 findings → v21)

### 1. Codex M1 (W-kind re-key) — FOLDED

The live-window-keyed model resolves the r20 interleaving: B's
post-rename arm failure raises W keyed to B's record (visible → make
durable); C's nested pre-rename arm failure re-keys W to C (B's window
is dead — `confirmGen` bumped, new timer, `store_commit.go:470-524`);
(w-c) restores C's retained `armedRecord` over the dead B record — the
restore IS the supersession. The dead-B record is consumed by the
overwrite, and same-record dominance still holds (an R-kind debt keyed
to the dead record runs first; W then faces absence and restores).
`armedRecord` retention at every arm (nested re-arms replace it)
covers the payload completely (r20 m1). FOLDED.

### 2. Codex m1 (restore payload) — FOLDED

`s.armedRecord` retains the immutable attempted record (Deadline,
GuardedHash, HashBasis, FirstCommit, PrevTree, ArmID) at the arm site
(`store_commit.go:503-553`); the restore is verbatim — the
`store.go:168-179` pending state provably lacks deadline/hash.
FOLDED.

### 3. Codex M2/M3 + SMR M1 (eager supersession) — FOLDED, with nit m1

The eager delete closes the five-deep chain: after the plain-commit/
SyncApply delete at the durable landing, boot 2 finds NO record —
there is nothing to repair and nothing to bind. The delete's
precondition ("lands durably") is correctly pinned: a PRE-rename
writeActive failure on the replacement path means no landing → no
delete → the (unreadable) record stands, latch stands; a POST-rename
converge runs the delete at the post-durability point, where its
dir-fsync doubles as the replacement's barrier (the same-directory
argument from r16/r17 — confirm.json and active.json share
`.configdb/`). The confirmed-commit paths are exactly covered
(overwrite on success; delete on pre-rename failure with master's
best-effort posture). The probe's confirmed-absence barrier clears
the latch. FOLDED — but see m1 for the crash-window semantics inside
the delete itself.

### 4. Codex m2 (enum snapshot) — FOLDED

The enum + mask carry every promised message; the single-valued
ConfirmRecordState suffices because the single confirm.json slot
means the boot latch and any debt-origin terminal concern the same
record; precedence TerminalUnreadable > RestartRecoveryOwed >
ConfirmDebt > ActivePersist is severity-ordered; the gauge keeps the
aggregate OR. An arm-overwrite during the latch supersedes the
unreadable record ((ii-b)'s overwrite rule) and the probe's clean
read of the live record clears the latch — consistent. FOLDED.

### 5. Codex m3 (stale expectations) — FOLDED

x9 substate-keyed, x11 class-split, THREE schema fields. FOLDED.

## B. Fresh attacks on the v21 delta

**Attack 1 (SUCCEEDED as nit m1) — the R→W handoff crash window is
unstated.** Same-record dominance serializes R's tombstone→delete of
the dead record D before W's restore of the live record L. A crash
between leaves NO confirm.json with L's window LIVE: recovery sees
absence and does nothing — L's crash-recovery is lost. This is
MATERIALLY master's best-effort arm-failure posture
(`store_commit.go:548-553` — a failed arm write already leaves a live
window recordless, warned), and the window is seconds-wide (the retry
restores on the next pass), but the plan must SAY it: the handoff
crash window (dead record removed, live record not yet restored)
degrades to master's admitted arm-failure posture — join the
documented irreducible set. One-paragraph pin.

**Attack 2 (FAILED) — eager delete on a SyncApply whose writeActive
fails PRE-rename.** The sync is not visible; "lands durably" is false;
the delete is withheld; the latch and the record stand. Correct.
FAILED.

**Attack 3 (FAILED) — the delete's own unlink/fsync crash window.**
Crash between unlink and dir-fsync replays the dirent — of an
UNREADABLE record: recovery's read fails identically (transient →
fail-closed retry path; permanent → latch again). No binding is
possible (the record cannot be parsed). The terminal state is the
already-admitted residual class. FAILED.

**Attack 4 (FAILED) — arm-overwrite during the latch leaves the latch
stuck.** The arm's overwrite IS the (ii-b) supersession; the probe's
clean read of the now-readable LIVE record clears the latch (the
unreadable-era record is gone; restart-recovery-owed is moot — the
live window supersedes it). FAILED.

## C. Findings

### MAJOR (0)

None. The live-window re-key and the eager-delete rule close the last
two structural holes on independent verification; every mechanism in
the v21 delta checks against the code it names.

### MINOR (1)

**m1.** Pin the R→W handoff crash window: same-record dominance
serializes R's delete of the dead record before W's restore of the
live one; a crash between leaves a live window with no confirm.json —
materially master's admitted best-effort arm-failure posture
(`store_commit.go:548-553`), seconds-wide (the retry restores on the
next pass), stated explicitly in the irreducible-residual set.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — a one-paragraph residual
pin). A v22 containing only this pin is PLAN-READY by inspection from
me.
