# Claude SMR hostile plan-review — round 40 (plan v40 @ `6cabbbe0a`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r39's SMR
raised the prefer-removal nit (independently converged by AGY's
attack-2 and elevated by Codex to M4); r40 re-verifies the v40 folds
of Codex's 6M against the real code and attacks the fence protocol's
remaining TOCTOU chain. All line numbers re-verified against the
worktree.

## A. Fold verification (r39 findings → v40)

### 1. Codex M1 (full-state re-check) — FOLDED

The gap was real: `ActivePersistDegraded` is a separate flag from
the confirm-side mask, and a queued local apply can leave it set
with the old record as the sole crash-recovery intent
(`store.go:687-717,738-746` — re-verified the cancel-then-write
ordering and the `noteActivePersistFailureLocked` raise). The
re-check now requires `ConfirmDebtKindMask == 0` AND
`persistDegraded == false`; the queued apply is correctly noted
as LOCAL and synchronously observable after its pass
(`cluster/sync.go:594-616,850-857`,
`sync_conn_config.go:325-351`). FOLDED.

### 2. Codex M2 (peer preflight + ordering) — FOLDED

The asymmetry was real (the plan's own rule forbids stopping
with process-local debt — the peer needs the same preflight).
The ordering is the right one: peer fenced until the target is
fully stopped, then START THE LOCAL first (cluster comms start
only after `Load`, `daemon_run.go:157-177,393-398` —
re-verified), then restart the peer; an unclean peer makes the
stopped path unavailable and the live removal path is the
fallback. FOLDED.

### 3. Codex M3 (down em0 dropped) — FOLDED

The fabric fallback is real (`daemon_ha_sync.go:774-785,820-860`
— control interface only when both control fields exist, fabric
otherwise, with redundant paths). The peer stop is transport-
universal. Grep-verified: no surviving down-em0 offer. FOLDED.

### 4. Codex M4 (= SMR r39 m1 = AGY attack-2 — REMOVAL) — FOLDED

Three-way convergence on the same nit. The validation ordering
makes it mandatory: `ReadConfirm`'s #5637/structure checks
(`db.go:254-281`) run BEFORE the Resolved branch, so a bare
`Resolved: true` record without a parseable nonzero `Deadline`
and non-null `PrevTree` fails validation outright; and the
downgrade-old reader ignores `Resolved` entirely (the r22
analysis), requiring the full synthetic field set. Hand-authoring
is out; REMOVAL is the instruction. The two stale
pre-tombstone/pending-shaped copies are swept to the shape-split
(LIVE window's record repairs pending-shaped; DEAD record is
removed). FOLDED.

### 5. Codex M5 (durable offline removal) — FOLDED

`db.go:284-315` (`DeleteConfirm`'s parent-directory fsync)
re-verified as the live barrier; the offline form is `rm` +
`sync -f` on `.configdb/` — the equivalent. FOLDED.

### 6. Codex M6 (bare-commit probe forbidden) — FOLDED, with nit m1

The diagnostic correction is real and important: only
`ConfirmCommitAs` returns "no pending confirmed commit"
(`store_commit.go:729-746`); a bare commit falls through to an
ordinary promotion (`cli_config.go:257-280`,
`store_commit.go:155-225`), and after the expired recovery reset
the candidate to the reverted tree, that promotion commits the
reverted (possibly EMPTY) configuration — after which
`shouldBootstrapFromFile`'s predicate
(`bootstrap.go:65-79,237-247`) no longer holds and the
`xpf.conf` import is suppressed. The staged-config guidance is
the correct instruction. FOLDED — but see m1 on the H branch's
clustered sub-case.

## B. Fresh attacks on the v40 delta

**Attack 1 (FAILED) — the peer-side preflight TOCTOU chain.** A
sync initiated by the peer between its preflight and its stop:
in-flight → delivered to the local receiver → drained by the
local capped pass (the apply runs locally and raises its debts
synchronously, observed at the local full-state re-check);
queued at the peer (unsent) → dies with the peer's process (the
peer's queue is in-memory); the reconciler re-drives on the
peer's restart — which the ordering places AFTER the local
classification completes. Every link is covered. FAILED.

**Attack 2 (SUCCEEDED as nit m1) — the H branch's clustered
stage+commit is a wasted step.** After the H revert (empty
active, no runtime), an operator following the M6 "stage the
intended config and commit" guidance with a CLUSTERED intended
config hits the same preflight rejection
(`cluster_topology_preflight.go:59-97`). The rejection is
harmless — it fires BEFORE store promotion
(`daemon_apply_commit.go:194-205`) and its own error text names
the restart recovery — but the runbook should state the split
explicitly so the operator doesn't take the wasted step: in the
H case, a staged commit works only for a NON-clustered intended
config; the clustered recovery is the restart-into-clustered-
config path (boot import or offline seed). One sentence.
MINOR.

**Attack 3 (FAILED) — the full-state check itself races a new
failure.** A failure landing between the full-state re-check and
the local stop: every producer the plan enumerates is now fenced
(commits refrained, peer stopped, the rollback timer's windows
resolved in step (1)) — the only remaining producers are the
retry loop's own debts, which are exactly what the check
measures; a debt raised mid-check is by one of the fenced
producers. The residual is the same admitted blind spot as
before, bounded to a pass. FAILED.

## C. Findings

### MAJOR (0)

None. All six r39 majors fold on independent verification; the
fence protocol is now a complete, ordered, full-state procedure
with a transport-universal barrier.

### MINOR (1)

**m1.** State the H branch's config-shape split explicitly: in
the H case a staged commit works only for a NON-clustered
intended config — a staged CLUSTERED commit is preflight-
rejected (cleanly, pre-promotion, `daemon_apply_commit.go:194-205`)
— and the clustered recovery is the restart-into-clustered-
config path (boot import or offline seed-and-restart).

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the H-branch
config-shape split). A v41 containing only this pin is
PLAN-READY by inspection from me.
