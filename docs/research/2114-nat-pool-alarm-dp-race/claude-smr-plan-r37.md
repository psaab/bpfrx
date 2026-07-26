# Claude SMR hostile plan-review — round 37 (plan v37 @ `68a1b1376`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r36's SMR
raised the temp-cleanup nit that Codex independently returned as m1
(the second joint finding this run); r37 re-verifies the v37 folds
against the real code and attacks the producer-quiesce protocol's
mechanics. All line numbers re-verified against the worktree.

## A. Fold verification (r36 findings → v37)

### 1. Codex M1 (producer-quiesce fence) — FOLDED, with nit m1

The TOCTOU was real: the mask is a snapshot-time derivation, and
both async producers Codex named are real code — the HA demotion
path (`daemon_ha.go:466-474`) and the resolution-failure debt
raises (`store_commit.go:575-608,652-702,780-792`). The
four-step protocol is the right fence: quiesce the
operator-paced producers (windows are confirmed/rolled back by
the operator), wait out the one async producer's pass, RE-CHECK,
then stop — and the blind-spot residual is admitted with a named
recovery path (the recovered timer's operator-scale deadline
makes an inappropriate re-arm correctable; the expired-revert is
bounded to records whose own deadline had passed — the semantic
the window itself would have produced). FOLDED — but see m1:
"ONE debt-pass interval" is loose against the loop's doubling
backoff.

### 2. Codex m1 (= SMR r36 m1 — hook fate) — FOLDED

The unlink discipline is pinned against the documented
`fsatomic.go:41-44` convention ("the temp file is removed on
every failure path before rename" — re-verified, with the
defer-driven `os.Remove` at `fsatomic.go:315-321`), crash-leaked
temps are swept by `NewDB` at open (`db.go:61-68`), and the
target-unchanged/no-temp regression references the real
`fsatomic_test.go:297-347` pattern. FOLDED.

### 3. Fold-partial (cause-count copies) — FOLDED

Grep-verified: no "ALL THREE causes" or three-cause enumeration
survives; all copies name the key-class causes AND
`ConfigWriteUnverified`. FOLDED.

## B. Fresh attacks on the v37 delta

**Attack 1 (SUCCEEDED as nit m1) — "ONE debt-pass interval" is
loose against the doubling backoff.** The loop's backoff doubles
to a cap (`store_persist.go:389-428`), so "one interval" is not
a number: a debt raised DURING a pass is observable only after
that pass completes, and the operator's wait must cover at least
one FULL pass at the CURRENT backoff. The sufficient and
operator-simple bound is the loop's CAPPED interval (maxBackoff)
— one capped interval from any starting point guarantees at
least one pass boundary (heal-or-re-raise) has elapsed, making
any raised debt observable at the re-check. One clause fixes it:
the wait is one FULL pass at the loop's capped backoff (the
maxBackoff parameter), not a nominal interval. MINOR.

**Attack 2 (FAILED) — confirm-away contradicts the commit
refusal.** The re-arm case arises after a CLEAN `Load` (the
pending-shaped record decrypted at boot), which requires a
healthy key state; write-unverified requires an outstanding
key-class/probe state. The two are mutually exclusive by
construction, so the confirm-away commit is available exactly
when the re-arm case arises — including the stopped-repair
restart, where the operator's restored key makes the repaired
record decryptable at Load. FAILED.

**Attack 3 (FAILED) — the fence fails under a SyncApply
mid-wait.** A SyncApply landing during the step-2 wait supersedes
windows and persists via its own contract; a failure raises the
active-persist debt or `confirmResolvePendingPersist` — BOTH
visible in the snapshot at the step-3 re-check (mask ≠ 0 → do
not stop). The fence catches exactly the producer class it was
built for. FAILED.

## C. Findings

### MAJOR (0)

None. The r36 major folds with a constructible protocol; the
fence's producer coverage is complete (operator-paced windows,
SyncApply, the rollback timer).

### MINOR (1)

**m1.** Pin the step-2 wait to one FULL pass at the loop's
CAPPED backoff (the maxBackoff parameter), not a nominal "one
debt-pass interval" — a debt raised mid-pass is observable only
after that pass completes, and the capped interval is the
operator-simple sufficient bound.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the capped-backoff
wait pin). A v38 containing only this pin is PLAN-READY by
inspection from me.
