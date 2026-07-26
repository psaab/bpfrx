# Claude SMR hostile plan-review — round 38 (plan v38 @ `95866d9c3`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r37's SMR
raised the wait-interval nit (folded into Codex M1's quiescence
barrier); r38 re-verifies the v38 folds of Codex's 2M/2m against the
real code and attacks the completed remediation protocol's last
surface. All line numbers re-verified against the worktree.

## A. Fold verification (r37 findings → v38)

### 1. Codex M1 (cluster-sync quiescence barrier) — FOLDED

The async producer is real: peer reconnect, promotion, and the
periodic reconciler all initiate SyncApply independent of operator
commits (`daemon_ha_sync.go:417-430,500-522,926-956`), and a
post-re-check SyncApply under the BOOT latch raises a
process-local D debt (`store_commit.go:575-608` family) that the
stop abandons (`store_persist.go:397-401`). The v38 barrier adds
the quiescence check to step (2) and the capped-backoff pass, and
the residual admission is correctly BENIGN: D's raise rule (the
(ii-b) eager rule) fires only where a newer durable config landed
AFTER the record's window — the record is dead by construction —
so abandonment leaves an unreadable record that the next boot
re-classifies into the SAME terminal latch (the sanctioned live
removal remediates — removal is always live-safe) or a readable
dead record the seeded-orphan machinery resolves at the next
commit (resolution is overwrite/removal, never a revert — the
plan's own rule). No live-window replay can arise from an
abandoned D. FOLDED.

### 2. Codex M2 + m1 (recovery guidance corrected) — FOLDED

All three corrections verify against the code: the recovered
timer re-arms for the record's ORIGINAL remaining interval
(`store_persist.go:231-253` — the deadline is carried in the
record, not reset); confirmation is the bare `commit`
(`store_commit.go:729-748` — `ConfirmCommit` cancels the timer)
and `commit check` only validates (`cli_config.go:177-185` —
re-verified); manual record removal does NOT cancel the
in-memory timer (the timer persists until `ConfirmCommit`);
and the FirstCommit+cluster class is H's inside-`Load` revert by
design — no service-time confirmation opportunity exists for it,
so the guidance is re-commit-after-revert. The
re-arm/commit-refusal consistency holds: re-arm follows a clean
`Load` (healthy key state, not write-unverified), so the bare
`commit` is admitted exactly when needed. FOLDED.

### 3. Codex m2 (fsatomic docs) — FOLDED

The package comment (`fsatomic.go:1-4`) and
`pkg/fsatomic/README.md:3-12` join the inventory for the third
writer. FOLDED.

## B. Fresh attacks on the v38 delta

**Attack 1 (CONSIDERED-AND-CLOSED) — the quiescence check's
observability.** "Peer stable, no in-flight config sync" is not a
perfectly observable predicate: the operator can see the cluster
link/heartbeat state and the sync journal, but not prove a
negative at an instant. The protocol's structure absorbs this:
the check is a best-effort gate and the ADMITTED residual (the
benign D-abandonment) is the authoritative backstop — an
in-flight SyncApply that escapes the check produces at most a
dead-record debt whose boot re-classification lands in the same
terminal state the operator was already remediating. The
protocol never depends on the check being perfect. CLOSED — not
a defect.

**Attack 2 (FAILED) — the readable-dead-record branch reverts
something.** The seeded-orphan rule resolves a seeded
Present(record) with no in-memory window BY OVERWRITE (confirmed
commit) or by the post-durability finalize (plain
commit/SyncApply) — removal, never a revert; the only revert
paths are the expired-during-downtime branch (bounded to records
whose own deadline passed — the semantic the window itself would
have produced) and the re-arm branch (the admitted residual with
the bare-commit escape). No NEW hazard hides in the branch.
FAILED.

**Attack 3 (FAILED) — the quiescence check contradicts the
cluster's own sync contract.** SyncApply promotes in-memory per
degrade-not-fail; the fence asks the operator to verify
quiescence, not to block syncs — the peer keeps syncing freely,
and any sync that lands mid-fence either finalizes (observable
at the re-check) or raises the benign residual. The cluster
never diverges and the fence never lies. FAILED.

## C. Findings

### MAJOR (0)

None. Both r37 majors fold on independent verification; the
protocol's residual accounting is now complete (operator-paced
windows, peer-driven SyncApply, the rollback timer — each with a
named, bounded outcome).

### MINOR (0)

None. My r37 wait-interval nit is folded into the capped-backoff
step with the synchronous-raise observation correctly noted.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved;
the design is identical under either packaging.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR) — with the §4.7 structure: PR-1
ships the `d.dp` accessor core; the G+H+H2 follow-up carries this
document's design as its seed. Equally PLAN-READY as a single PR
if the user prefers AGY's (A) packaging.
