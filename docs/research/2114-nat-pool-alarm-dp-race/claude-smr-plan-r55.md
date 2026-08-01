# Claude SMR hostile plan-review — round 55 (plan v55 @ `f437e4dd6`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r54's SMR
raised the claim-ordering pin (folded in v55 as part of the
send-boundary protocol, IS part of Codex M1/M2); r55 re-verifies the
v55 folds of Codex's 6M/2m against the real code and attacks the
mutex-across-send stall and the pending set's cross-attempt
lifecycle. All line numbers re-verified against the worktree.

## A. Fold verification (r54 findings → v55)

### 1. Codex M1+M2+M3+m1 (send-boundary protocol) — FOLDED

All four sub-findings verified in code: the non-atomic re-check
(`store_format.go:31-36` releases before the send;
`sync_conn_config.go:234-243,267-272` admits the late claimant);
the CLAIMED-is-PUSHED marker poisoning
(`daemon_ha_sync.go:474-489`, reachable via the syncPeer=false
event-engine commits, `daemon_apply_commit.go:596-599`); the
separate-transaction gate/text reads (`daemon_ha_sync.go:462-471`);
and the FNV-vs-SHA-256 type mismatch
(`daemon_ha_sync.go:381-388,467-472` vs `store.go:772-779,812-829`).
The v55 protocol — `configSyncMu` held from validation through
send-completion, every push path taking it, the boundary
revalidation set (authority + epoch/liveness + ConfigSync + active
identity via `configGenerationHash(ShowActive())` — same function,
same type), and the claim only at the send boundary — closes all
four by construction: a validated send and a commit push serialize,
so a stale capture can never land after a newer one; and a drop
never claims, so the marker never suppresses a needed push. The
commit push path taking `configSyncMu` is a plan REQUIREMENT the
§5.1 inventory carries (the reconciler already takes it for the
claim). FOLDED.

### 2. Codex M4 (outer mint) — FOLDED

The preflight/compile early returns verify
(`daemon_apply_commit.go:98-126,194-222,551-575`), and the v55 mint
point — the OUTER apply-attempt entry (`commitAndApply` and the
background wrappers, before preflight) — covers them: every apply
attempt, including one that fails at preflight, mints a token and
publishes a FAILED outcome with no arms. The direct
`applyConfigLocked` call sites (`daemon_apply_commit.go:246,489,697`)
are all INSIDE commitAndApply-driven flows, so no apply path bypasses
the outer mint. FOLDED.

### 3. Codex M5 (per-arm registration) — FOLDED, with nit m1

The duplicate-completion and post-return-increment hazards verify
(`manager_compile.go:357-402` can launch a callback before
returning). The v55 rule — (token, arm-ID) registrations recorded
BEFORE launch, a per-arm-ID pending set, exactly-once retirement,
unregistered completions ignored — closes both; the daemon-side
registration is achievable because the six arm-IDs are a fixed
enumeration the daemon knows before calling the manager (the
manager-internal launches like OnXSKBound are pre-registered by
their arm-ID before the manager call that can launch them).
FOLDED — but see m1: the pending set's cross-attempt lifecycle is
not pinned.

### 4. Codex M6 (six-arm inventory) — FOLDED

The two additional arms verify (`OnXSKBound`'s goroutine with the
logged fabric-IPVLAN failure, `maps_sync.go:451-457` +
`daemon_apply_interfaces.go:98-109`; `PrepareLinkCycle`'s suppressed
failures, `daemon_apply_dataplane.go:289-296` +
`process_linkcycle.go:145-162`). All six are now tokened and
registered. My own walk of the apply-time userspace interactions
finds no seventh async outcome. FOLDED.

### 5. Fold-verification corrections (a)-(d) — FOLDED

The namespace correction (the #6034 seed is the neighbor-replace
generation — the registration rule, not the seed, rejects
cross-incarnation completions), the deferred-MAC PENDING correction
(unbounded retry, `manager_worker_arm_5134.go:18-38` —
fail-closed pending, not terminal), the rendering alignment
(token + pending-set beside lastOK/count), and the struck
OBSERVED-complete prerequisite are all in the text. FOLDED.

## B. Fresh attacks on the v55 delta

**Attack 1 (FAILED) — the mutex-across-send stall.** `QueueConfig`'s
write carries the 5s `syncWriteDeadline`; a stalled send holds
`configSyncMu` for at most 5s, which is well inside the 30s
reconcile interval and merely delays a commit push by the same
bound (commits are operator-paced). The lock order
`configSyncMu` → `writeMu` is the only order present (heartbeat
senders take `writeMu` alone), so no inversion. FAILED.

**Attack 2 (SUCCEEDED as nit m1) — the pending set never resets
across attempts.** Registrations are process-lifetime; an arm that
never completes (a stuck retry, a lost completion) pends FOREVER in
the set, so the predicate's no-pending-outstanding term can never
pass again even after a LATER attempt fully converges. One clause:
the pending set is PER-ATTEMPT — a new mint supersedes the prior
attempt's registrations (the prior arms' completions then arrive as
unregistered completions and are ignored, per the M5 rule), so the
predicate evaluates only the current attempt's arms. MINOR.

**Attack 3 (FAILED) — the boundary revalidation's own gate-flip
race.** The gates are re-read under `configSyncMu` at the boundary;
a ConfigSync-disable commit flips the gate via its own commit push
path, which takes the same mutex — so the flip serializes against
the reconciler's send, and the next boundary read sees it. FAILED.

**Attack 4 (FAILED) — a validated-then-dropped pass's alarm
floods.** The drop is per stale capture, which requires a config
change mid-claim — rare; and the alarm is a one-line Warn, not a
per-packet log. FAILED.

## C. Findings

### MAJOR (0)

None. All six r54 majors and both minors fold on independent
verification; the send-boundary protocol closes the claimant class
by serialization rather than timing.

### MINOR (1)

**m1.** Make the pending set per-attempt: a new mint supersedes the
prior attempt's registrations (prior arms' completions arrive
unregistered and are ignored), so an arm that never completes
cannot permanently block the predicate after a later attempt fully
converges.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the per-attempt
pending-set reset). A v56 containing only this pin is PLAN-READY by
inspection from me.
