# Claude SMR hostile plan-review — round 24 (plan v24 @ `db70b9ac8`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r23's SMR
signed off with the (d-i) transient nit (converging with Codex M1);
r24 re-verifies the v24 folds and attacks the completed machinery with
fresh interleavings. All line numbers re-verified against the worktree.

## A. Fold verification (r23 findings → v24)

### 1. Codex M1 = SMR m1 ((d-i) transient boundary) — FOLDED

The qualified split is present in the normative block AND both
acceptance copies: PERMANENT-class slot read failure → synthesized
tombstone; TRANSIENT → retain UNTRIED, no write/delete. The Codex
scenario (arm C visible via a post-rename failure while D pends +
transient EACCES at retry) now retains rather than tombstones a live
C. FOLDED.

### 2. Codex M2 ((w-u) + W-before-D) — FOLDED

(w-u) restores `s.armedRecord` over an unreadable slot — the
`WriteConfirm` rename needs no read of the existing file
(`db.go:207-218`), and its dir-fsync is the same-directory barrier.
W-before-D composes with D2's restore-priority: the restore installs
the live record and subsumes D as moot; a restore failure returns the
slot to D's (d-i) path, and the crash between that delete and the
next W pass is the admitted arm-persistence residual. FOLDED.

### 3. Codex m1 (recordless claim scoped) — FOLDED

Invariant 12 now scopes the guarantee to ordering-created gaps and
names the restore-failure → R-delete → crash-before-next-W residual
(`store_commit.go:548-553`) in the residual set. FOLDED.

### 4. Codex m2 (synthetic record) — FOLDED

`HashBasis = "canonical-v1"` pinned; the downgrade regression is
scoped to NORMAL content (legacy-basis binds → re-arm →
revert-to-identical → consumed) with the exceptional-content
stale-drop leg; the `FirstCommit=false` rationale is now correct —
verified against the OLD reader's recovery: the `Resolved` field is
invisible to it, and an expired `FirstCommit=true` record takes the
expired-first-commit path (`store_persist.go:171-194,231-247`),
reverting to the EMPTY tree instead of the no-op revert to
`PrevTree`. FOLDED.

### 5. Codex m3 (health schema) — FOLDED

All copies now carry the exact three-value snapshot with the
aggregate defined as DERIVED (`persistDegraded || mask ≠ 0 ||
enum ≠ OK`). FOLDED.

## B. Fresh attacks on the v24 delta

**Attack 1 (SUCCEEDED as nit m1) — the D-kind debt's own WRITE-failure
doctrine is unpinned.** The synthesized `WriteConfirm` can itself
fail — transiently (ENOSPC, EIO) or permanently (EROFS). The v24
text pins the retry's READ classification but not the write-failure
handling. The R-kind doctrine already covers this shape: a
tombstone-write failure retains the debt and retries with capped
backoff, health degraded, NO terminalization (write failures never
terminalize anywhere in the design — a permanently read-only
filesystem loops at 503, which is the intended loud posture). The
one-line pin: the D-kind debt follows the same doctrine — a failed
synthesized write retains the debt (the next pass re-reads and
re-classifies first, so a write that started failing because the
slot changed is re-classified rather than re-attempted blindly).
MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the operator-repaired record's
trust posture is unstated.** The remediation text says the operator
"inspects, repairs, or removes confirm.json" — "repairs" implies a
hand-crafted record is trusted. The (d-iii) classification actually
guarantees the right semantics (a readable record is CLASSIFIED,
not trusted: live-window ArmID match → untouched; `Resolved` →
finish the delete; otherwise → the R-kind / seeded-orphan
machinery). The pin is to say so in the runbook sentence: a
repaired record is re-validated through the normal classification,
never trusted on the operator's say-so; the sanctioned remediation
is removal (confirmed absence) or repair-to-a-valid-record followed
by classification. MINOR.

**Attack 3 (FAILED) — (w-u) restore over an operator-placed valid
record.** If the slot is readable, the debt is not in (w-u) — it is
in (d-iii)/normal classification. The (w-u) state requires a
CONFIRMED PERMANENT-class read failure, so the restore never
overwrites a verifiably-valid record outside the live window's own
arm path. FAILED.

## C. Findings

### MAJOR (0)

None. The v24 delta closes the last two classification boundaries
((d-i) transient, (w-u) restore) on independent verification; every
mechanism checks against the code it names.

### MINOR (2)

**m1.** Pin the D-kind WRITE-failure doctrine: a failed synthesized
write retains the debt and retries with the same capped backoff and
degraded health as every other debt (no terminalization — write
 failures never terminalize anywhere in the design), and the next
pass re-reads and re-classifies before any re-attempt.

**m2.** Pin the operator-repair trust posture in the remediation
runbook: a repaired record is CLASSIFIED (re-validated), never
trusted; sanctioned remediation is removal (confirmed absence) or
repair-to-valid followed by the normal classification.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — two one-line doctrine
pins). A v25 containing only these pins is PLAN-READY by inspection
from me.
