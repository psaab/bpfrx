# Claude SMR hostile plan-review — round 20 (plan v20 @ `d37961cd7`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r19's SMR
signed off with two nits; r20 re-verifies the v20 folds end to end and
attacks the new mechanics (same-record dominance, debt-kind split,
BOOT-origin substates) with fresh interleavings. All line numbers
re-verified against the worktree.

## A. Fold verification (r19 findings → v20)

### 1. Codex M1 (same-record dominance) — FOLDED

The dominance rule (while any R-kind debt keys the CURRENT record K, NO
other write of K runs — W-kind rewrite or stale-keyed mismatch rewrite)
closes the R_A-first hole: R_A at its turn reads B, the membership
guard sees R_B, R_A's mismatch-rewrite is suppressed, and R_A's
stale-clear precondition (current record durably established) is met
only by R_B's tombstone barrier. The pass holds s.mu
(`store_persist.go:402-465`), so the per-pass current-record
determination is stable; arms between passes are re-read at the next.
x16's R_A-first leg pins the regression. FOLDED.

### 2. Codex M2 (debt-kind split) — FOLDED

R-kind four-state / W-kind three-state tables are coherent: the (w-c)
restore's fields exist in the in-memory window state
(`store_commit.go:503-553` — deadline/prevTree/FirstCommit/ArmID; the
GuardedHash is recomputed as `journalConfigHash(s.active)`, and
s.active CANNOT have changed under the same live window — a plain
commit or SyncApply resolves the window (debt stale), a nested
commit-confirmed re-arms with a NEW ArmID (debt mismatch →
transitions), a rollback resolves it — so the recomputed hash equals
the arm's). A W debt whose window resolved while pending is stale and
clears; the resolution's own tombstone/deletion subsumes it. Absent-for-W
NO-OP-and-clear only when a same-key R consumed it. FOLDED.

### 3. Codex M3 (BOOT-origin substates) — PARTIAL, see M1 below

The (ii-a) restart-recovery-owed and (ii-b) superseded-while-unreadable
split closes the stated counter-case — as long as the in-memory marker
survives. It does not survive a restart (see M1).

### 4. Codex m1 (measure) — FOLDED

The lexicographic remaining-stage measure is well-defined; eventual
zero given quiescence + failure-free suffix; the merge rule
(tombstone-required dominates delete-finishing) is consistent with the
dominance rule. FOLDED.

### 5. Codex m2 (confirmed-commit overwrite) — FOLDED

Overwrite-resolution avoids expanding the recordless window
(`store_commit.go:437-468,503-524`); the PRE-rename failure converts
the orphan to an R-kind debt; x17 has both legs. FOLDED.

### 6. Codex m3 (envelope) — FOLDED

Initial read + ≤3 retries (4 reads), 100/200/400 ms,
`LoadContext(ctx)` with `Load()` preserved — implementable as written.

### 7. Codex m4/m5/m6 — FOLDED

Generic message + debt-kind detail; sweep surfaces named; the
single-Store-ownership invariant (`daemon.go:1042-1053`) documented.

## B. Fresh attacks on the v20 delta

**Attack 1 (SUCCEEDED — MAJOR M1) — the SUPERSEDED-WHILE-UNREADABLE
marker is in-memory and lossy across a restart; the supersession must
be acted on DURABLY at the moment it is known.** Walk the interleaving:
(1) boot 1 — record PERMANENT-unreadable → BOOT latch set. (2) Operator
plain-commits B (durable) during the latch → marker set (in-memory).
(3) Restart BEFORE any repair → boot 2: Load reads the record, STILL
unreadable → latch again; the marker is LOST (in-memory only). Boot 2
cannot re-derive the supersession: from durable state the unreadable
record could be B's OWN armed window (armed in boot 1's uptime, died
with the process) or an older superseded one — indistinguishable, and
deleting blind could abandon B's live-window recovery file. (4)
Operator repairs the record (permanent classes ARE repairable:
malformed JSON/zero-deadline/nil-target/corrupt envelope are file
rewrites; invalid key length is a master.key fix). (5) Probe clean read
→ no marker → substate (ii-a) restart-recovery-owed → latch held, 503,
restart-required. (6) Boot 3: recovery reads repaired-A → A's
GuardedHash vs active B — on a content match (byte-identical
edit-back, SyncApply-identical) or a legacy empty hash, A BINDS →
re-arm → the timer reverts B — the operator's confirmed config — at
the deadline. The full H2 machinery stands around the hole; the
five-deep chain (permanent-latch + commit-during-latch +
restart-before-repair + repair + content-match) is constructible and
health is 503 the whole way, but the terminal outcome is exactly the
revert-of-confirmed-config H2 exists to prevent. The fix is mechanical
and removes the marker entirely: the supersession is knowable with
certainty AT B's durable landing — a plain commit or SyncApply that
lands durably while the BOOT latch stands has armed NO new window, and
B supersedes EVERY earlier window by construction — so the path
DELETES the unreadable confirm.json with the dir-fsync barrier at the
post-durability point (no tombstone needed or possible: the record is
unreadable, and a tombstone's purpose — being READ as Resolved at
recovery — is moot for a record recovery cannot parse; the deletion's
barrier is the durable transition). The confirmed-commit path is
already covered: a successful arm OVERWRITES the record; a PRE-rename
arm failure leaves the unreadable orphan, which the same
delete-superseded rule removes (B's active is durable; B's live
window has no record either way — the arm failed — matching master's
best-effort arm-failure posture, `store_commit.go:548-553`). After the
delete, the probe's confirmed-absence barrier clears the latch — and
no restart can resurrect a superseded record.

**Attack 2 (FAILED) — dominance guard vs arm-during-pass.** The pass
holds s.mu; arms serialize; the next pass re-reads. FAILED.

**Attack 3 (FAILED) — (w-c) restore hash divergence.** See §A.2:
s.active is provably unchanged under the same live window. FAILED.

## C. Findings

### MAJOR (1)

**M1.** The SUPERSEDED-WHILE-UNREADABLE marker must be replaced by
delete-superseded-at-durable-landing (plain commit/SyncApply with the
BOOT latch standing and no new window armed → delete the unreadable
confirm.json with the dir-fsync barrier at the post-durability point;
confirmed-commit PRE-rename arm failure applies the same rule to the
unreadable orphan). The in-memory marker is lost at restart, and the
restart-before-repair chain replays a repaired stale record into a
binding re-arm of the confirmed config. x18/x19 gain the
restart-before-repair leg.

### MINOR (0)

None beyond M1's test legs.

## Verdict

**NEEDS-REVISION** (1 MAJOR, 0 MINOR). Everything else in the v20
delta verified FOLDED against the code. The finding is one mechanical
rule (delete the unreadable record at the moment supersession is
certain) plus its regression leg — it does not disturb the dominance,
debt-kind, or substate architecture.
