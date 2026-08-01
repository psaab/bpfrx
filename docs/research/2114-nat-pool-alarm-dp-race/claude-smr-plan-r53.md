# Claude SMR hostile plan-review — round 53 (plan v53 @ `f3f651145`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r52's SMR
raised the publication-method name and the seqlock writer double-bump
(folded into the §5.1 contract text in v53); r53 re-verifies the v53
folds of Codex's 4M/1m against the real code and attacks the attempt
token's own lifecycle and the pending arm's observability. All line
numbers re-verified against the worktree.

## A. Fold verification (r52 findings → v53)

### 1. Codex M1 (composite reader joins the snapshot) — FOLDED

The separate-transaction reads verify (`daemon_ha_sync.go:544-568`
reads `ShowActive()` then `ActiveApplied()`;
`store_format.go:31-36`, `store.go:803-809`), including the
high-water advance consequence (`sync_conn_config.go:319-324,
390-395`). The v53 text reads the (text, applied) pair from ONE
versioned snapshot — the same configstore-owned publication the
predicate uses — and §9 carries the composite-reader leg. I grepped
for other ShowActive/ActiveApplied pairings: this shortcut is the
only composite reader of the pair. FOLDED.

### 2. Codex M2 (attempt-tokened join) — FOLDED, with nit m1

The unordered-completion hazard verifies (the status loop runs
outside applySem, `process_status.go:150-186`). The token rule —
converged only when the pipeline AND every arm's completion carry
the CURRENT attempt token — covers the dedup/catch-up completion
paths (a completion carries the token of the deferral it answers;
an older token is ignored). FOLDED — but see m1: the token's
cross-restart seeding is not pinned.

### 3. Codex M3 (the other async arms) — FOLDED

The XSK-liveness gap (`manager_compile.go:338-402` publishes nil
before liveness; `maps_sync.go:461-545` fails closed with a log) and
the swallowed link-cycle rebind (`daemon_apply_dataplane.go:390-401`,
`process_linkcycle.go:184-224`) verify. The arm enumeration matches
the daemon's apply-time dataplane interactions (the manager
ApplyConfig, the deferred-MAC second apply, the link-cycle notify) —
complete to both reviewers' sweeps and my own walk. FOLDED.

### 4. Codex M4 (obsolete witness gate struck) — FOLDED

Grep-verified: the live runbook no longer gates on the
ConfigsSent tick or the marker no-op; the two surviving mentions are
revision-history records (the v51 entry's design description and the
v53 entry's defect description). The interval-bracketed double
digest check is the only join. FOLDED.

### 5. Codex m1 (pending/failed distinction) — FOLDED, with nit m2

The tri-state (CONVERGED / PENDING / FAILED), pending not moving the
count, and the predicate's count==0 AND no-pending-outstanding AND
lastOK are stated consistently across the runbook, acceptance, §5.1,
and §9. FOLDED — but see m2: the pending arm's observability is
not pinned.

## B. Fresh attacks on the v53 delta

**Attack 1 (SUCCEEDED as nit m1) — the attempt token's cross-restart
seeding.** The userspace HELPER can outlive the daemon process, and
the manager re-attaches to it — the #6034 resume pattern exists for
exactly this (the helper's replace-generation fence outlives the
Manager; the manager resumes from the helper's applied generation,
`process_status.go:165-172`). A deferred-publication completion from
the PREVIOUS daemon incarnation can therefore arrive at the new
manager. The v53 token is process-lifetime; without the seeding
rule, a pre-restart completion could carry what looks like a current
token. One clause: the attempt token seeds from the helper's
reported generation on manager attach (the existing resume pattern),
so a pre-restart arm completion can never carry a current token.
MINOR.

**Attack 2 (SUCCEEDED as nit m2) — the pending arm's observability.**
The predicate requires "no pending arm outstanding", but the v53
text never says the versioned snapshot CARRIES a pending-arm count
(or per-arm mask) — the operator surface must expose it for the
predicate to be checkable. One clause: the snapshot carries the
current attempt token and a pending-arm count (incremented when an
arm defers, decremented on a token-matching completion), rendered
beside lastOK/count. MINOR.

**Attack 3 (FAILED) — a completion with no apply in flight.** The
completion carries its deferral's token; with no apply in flight the
latest token is the last apply's; a token-matching completion marks
the arm complete (converged when all arms complete); an older-token
completion is ignored. The rule covers the case. FAILED.

**Attack 4 (FAILED) — the pending count and the process-lifetime
counter diverge across a restart.** Both are process-lifetime and
initialize at process start before the boot apply; the predicate is
consulted post-restart, where both reflect only the current
incarnation. FAILED.

**Attack 5 (FAILED) — the token mint is a torn read of the
snapshot.** The token mints at the central entry and publishes with
the same versioned snapshot discipline (bump, publish, bump); a
reader either sees the pre-entry or post-entry publication, never a
torn token. FAILED.

## C. Findings

### MAJOR (0)

None. All five r52 findings fold on independent verification.

### MINOR (2)

**m1.** Pin the attempt token's cross-restart seeding: the token
seeds from the helper's reported generation on manager attach (the
#6034 resume pattern, `process_status.go:165-172`), so a pre-restart
arm completion can never carry a current token.

**m2.** Pin the pending arm's observability: the versioned snapshot
carries the current attempt token and a pending-arm count
(incremented on deferral, decremented on a token-matching
completion), rendered beside lastOK/count so the predicate's
no-pending-outstanding term is checkable.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 2 MINOR — the token seeding and
the pending-arm observability). A v54 containing only these two pins
is PLAN-READY by inspection from me.
