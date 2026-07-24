# Claude SMR hostile plan-review — round 12 (plan v12 @ `5f3aff8c1`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r12 verifies
the v12 folds (resolution tombstone = work item H2; canonical binding
basis) against worktree code and mounts fresh attacks. All line numbers
re-verified (origin/master `ed6999000` + plan-doc-only branch).

## A. Fold verification (r11 findings → v12)

### 1. Codex M1 → work item H2 (resolution tombstone) — FOLDED

- The ambiguity chain re-verified link by link:
  `ConfirmPendingOnDemotion` confirms WITHOUT changing active content
  (`store_commit.go:777-792`); `resolveConfirmRemovalLocked`
  deletes-only (:575-590); `noteConfirmRemoveFailureLocked` itself
  documents the resurrect window (:596-608 "a restart before the
  background retry heals could resurrect a stale rollback"). Since a
  confirm never changes content, a lingering record's GuardedHash
  matches forever — content equality cannot express resolution. The
  tombstone (durable `Resolved: true` written BEFORE deletion, recovery
  drops tombstoned records) is the correct minimal identity mechanism.
- Crash-window audit: arm→tombstone gap = genuinely pending (re-arm,
  correct); tombstone→delete gap = resolved (drop, correct);
  tombstone-write failure shrinks to the same class as today's
  delete-failure (retry re-drives) — no worse, honestly stated.
- In-memory leg: `clearPendingConfirmLocked` bumps confirmGen so an
  already-fired-but-blocked timer callback no-ops in `PromoteRollback`
  — the tombstone covers ONLY the restart case; no new in-memory race
  introduced (resolution paths hold `s.mu`; the gen bump is in the same
  critical section). FOLDED.

### 2. Codex M2 → canonical binding basis — FOLDED (empirically verified)

I ran the Go stdlib experiment: `json.Marshal("a\xffz")` emits
`"a�z"` (U+FFFD) and the round trip is NOT equal to the raw
input — confirming (a) the arm-time raw-tree hash diverges from any
decoded-tree hash (Codex M2 is empirically real), and (b) the Load-side
`json.Unmarshal` decode IS the normalizing leg, so the recovery basis
(hash over the decoded tree) is already canonical and needs NO explicit
round-trip — exactly as v12 states ("the decode itself is the first
round-trip leg"). The arm-side `jsonRoundTrip` is commit-path-only
(never hot path). FOLDED.

### 3. Codex m1/m2 (terminology, regression viii) — FOLDED

v12 says "canonical (round-tripped) decoded-tree `Format()` basis"
consistently; viii arms through the production `CommitConfirmed` path
and verifies against a freshly decoded `ReadActiveMeta` tree. FOLDED.

## B. Fresh attacks on the v12 delta (2 SUCCEEDED as MINOR; 2 FAILED)

**Attack 1 (FAILED) — tombstone vs in-flight timer**: covered by the
confirmGen bump + `s.mu` discipline (see A.1). No new race.

**Attack 2 (SUCCEEDED, MINOR m1) — the envelope-versioning claim is
factually wrong for confirm.json.** v12 says the tombstone's
record-schema change "rides the existing envelope versioning
(`wrapEnvelope`, `db.go:443-450); the /engineer pass decides the
writer-version bump". But `WriteConfirm` uses NO envelope — the
contract comment is explicit: "No #1917 compatibility envelope is used
— the file is transient recovery state, not a committed config, and
**confirmRecord evolves via additive JSON fields**"
(`db.go:200-205`). `Resolved` IS an additive JSON field — the
established evolution mechanism for this struct; there is no
writer-version bump to decide. The downgrade behavior to document: an
old reader's `json.Unmarshal` silently IGNORES the unknown `Resolved`
field and re-arms the tombstoned record — i.e., downgrade inside the
tombstone→delete window behaves exactly like today's delete-failure
window (re-arm of a resolved window) — no worse than master, and the
window is bounded by the retry loop on the NEW build. REQUIRED fold:
replace the envelope claim with the additive-field contract + the
downgrade semantics sentence.

**Attack 3 (SUCCEEDED, MINOR m2) — tombstone write mechanism unpinned.**
v12 says "write a `Resolved: true` TOMBSTONE into confirm.json" without
pinning read-mutate-write vs reconstruct-from-memory. Reconstruct
risks field drift and — worse — a DEGENERATE record: `ReadConfirm`
rejects zero-value/degenerate records (#5637 hardening, `db.go:219+`),
and the resolution paths hold the in-memory pending state, not
necessarily the full record (GuardedHash, Gen, arm-time fields). A
reconstructed tombstone missing a field could fail the #5637 validity
gate on the NEXT boot and be handled as an error path (warn + abandon
recovery) instead of a clean drop. REQUIRED fold: pin
read-mutate-write — read the existing `confirm.json`, set `Resolved`,
rewrite via the same fsatomic-durable path (`WriteConfirm`), then
delete; the retry loop re-drives exactly that sequence. Atomicity comes
from `fsatomic.WriteFileDurable` (temp+fsync+rename), so a crash
mid-sequence leaves either the original record (pending — correct) or
the complete tombstone (resolved — correct), never a torn file.

**Attack 4 (FAILED) — canonical hash at the SyncApply arm**: the
standby's tree is the peer-pushed config; the same canonicalization
applies (arm hashes the round-tripped tree; the standby's own Load
decodes the same persisted bytes). Peer-version asymmetry (primary on
old build) changes the PEER's arm hash, not the LOCAL recovery binding
— the record is armed and recovered by the same binary on the standby.
FAILED.

## C. Findings

### MAJOR (0)

None. The tombstone + canonical basis close the last two verified
binding-layer holes; the design's total order at recovery (Resolved
check → hash mismatch → expired → H → re-arm) is correct.

### MINOR (2)

**m1.** confirm.json has no envelope — replace the `wrapEnvelope`
versioning claim with the additive-JSON-field contract
(`db.go:200-205`) + documented downgrade semantics (old reader ignores
`Resolved`, re-arms — bounded by the new build's retry loop, no worse
than today's delete-failure window).

**m2.** Pin the tombstone write as read-mutate-write of the existing
record via `WriteConfirm`'s fsatomic path (preserves all fields,
satisfies the #5637 degenerate-record gate, atomic under crash), with
the retry loop re-driving read-mutate-write→delete.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — both factual pins against
configstore contracts verified in this review; no design change). A v13
containing only these two pins is PLAN-READY by inspection from me.
