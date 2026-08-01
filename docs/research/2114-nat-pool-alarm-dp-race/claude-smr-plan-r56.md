# Claude SMR hostile plan-review — round 56 (plan v56 @ `269b4c70c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r55's SMR
raised the per-attempt pending-set reset (folded in v56 — IS Codex
M6); r56 re-verifies the v56 folds of Codex's 9M/2m against the real
code and attacks the authority generation's restart semantics and the
debt re-registration query's blocking. All line numbers re-verified
against the worktree.

## A. Fold verification (r55 findings → v56)

### 1. Codex M1 (provider coherence + success semantics) — FOLDED

The provider-identity revalidation is well-defined: the current
provider is `getSessionSync()`'s return, compared pointer-wise
against the captured `ss` (the replacement paths,
`daemon_apply_tail.go:238-255` and `daemon_ha_sync.go:658-667,
1405-1415`, re-point exactly that accessor's result). The success
return propagates through both `QueueConfig` exit paths (the
nil-conn no-op and the `writeMsg` failure + `handleDisconnect`,
`sync_conn_config.go:234-250`), and the marker publishes only on
send-success while still locked — so a failed or no-op send never
claims, and the fabric-0-fails/fabric-1-survives case
(`sync_conn.go:480-498,569-570`) leaves the retry unsuppressed.
FOLDED.

### 2. Codex M2 (authority generation) — FOLDED

The validate-as-primary → demote-mid-write → rejected-frame →
re-promote construction closes: the demotion and the re-promotion
both bump the authority generation (the RG0 transition path,
`daemon_ha.go:438-475`), the rejected frame's claim is invalidated
with the pre-demotion generation, and the next reconcile re-claims
under the new generation — no suppression. The receiver's rejection
(`daemon_ha_sync.go:544-548`) is silent to the sender, but it only
arises when the sender's authority changed — which is exactly the
case the generation invalidation covers. FOLDED.

### 3. Codex M3 (lock discipline) — FOLDED

One locked-send owner plus a lock-assuming marker helper resolves
the self-deadlock (`pushConfigToPeer` → `markConfigSyncPushed`,
`daemon_ha_sync.go:355-377,407-414`); the helper never re-locks and
the owner holds through the send. FOLDED.

### 4. Codex M4 (complete enumeration + admission-ordered mint) — FOLDED

The enumeration matches the code: the five direct
`applyConfigLocked` calls (`daemon_apply.go:56,86`,
`daemon_apply_commit.go:246,489,697`) all sit inside the enumerated
outer entries (`commitAndApply`, `commitConfirmedAndApply`,
`syncAndApply`, the rollback path, `applyConfig`,
`applyConfigResult`). The mint-after-admission ordering
(`daemon_apply_commit.go:172-175,528-531,332-335`,
`daemon_apply.go:50-51,84-85`) prevents the waiting-on-applySem
supersession, and the terminal-return classification covers the
`commitWithGenBinding` retry (`daemon_apply_commit.go:102-125`).
FOLDED.

### 5. Codex M5 (manager self-registration) — FOLDED

Moving the registration into the manager's own `m.mu` atomically
with the launch decision removes the daemon-side check/set race
entirely (`daemon_apply_interfaces.go:61,98-100`,
`manager.go:424-433`, `maps_sync.go:451-456`) — no cross-lock
ordering remains to get wrong. FOLDED.

### 6. Codex M6 (supersession with re-registration) — FOLDED

The query-at-mint is race-free: the manager's status loop holds
`m.mu` for the whole poll (`process_status.go:150-174`), so the
debt-state query under the same mutex returns a consistent
snapshot, and a concurrently completing arm's retirement is
serialized by the same lock. FOLDED.

### 7. Codex M7 (seventh arm terminal) — FOLDED

The detach failure as a returned terminal pipeline failure composes
with the #5679 deferred-error doctrine (`daemon_apply_dataplane.go:
145-159`): it joins the tail's error join and the commit reports
failure — fail-closed and complete. FOLDED.

### 8. Codex M8/M9/m1/m2 — FOLDED

The no-pending term is now in the runbook, the acceptance copy, and
the status inventory; the count semantics read terminal-only
everywhere (grep-verified — the one surviving "every non-converged
return" hit is the v53 revision-history description of the defect);
the deadline is corrected (2s, `sync.go:88`, inside `writeFull`
after the `writeMu` wait, `sync_protocol.go:59-74`); and the §9
send-boundary legs (h2i) exist. FOLDED.

## B. Fresh attacks on the v56 delta

**Attack 1 (FAILED) — the authority generation's restart collision.**
The wire generation never regresses across restarts within a boot
(the #3931 seed, `sync.go:847-857`), and the marker/authority
generation are process-lifetime — a post-restart claim starts fresh
on a fresh daemon; nothing pre-restart survives to collide. FAILED.

**Attack 2 (FAILED) — the debt re-registration query stalls the
mint.** The query takes `m.mu` behind at most one bounded
control-socket round-trip (the status poll's `requestLocked`),
which is small against the apply path's own compile-time block;
operator-paced commits are seconds apart. The CLAUDE.md
control-socket contention rule is respected: the query fires once
per apply attempt, not per tick. FAILED.

**Attack 3 (SUCCEEDED as nit m1) — the §9 contention regression is
referenced but not named.** The v56 text pins the contention bound
"with a §9 contention regression", but the (h2i) legs enumerate the
send-boundary orderings and no leg exercises the mutex-held-across-
writeMu-wait-plus-2s-write bound. One clause: the contention leg
(a blocked write holding `configSyncMu` for the full deadline while
a commit push waits) joins (h2i). MINOR.

**Attack 4 (FAILED) — the send-success return vs the receiver's
silent rejection.** The receiver's rejection
(`daemon_ha_sync.go:544-548`) is invisible to the sender, but it
arises only on an authority change, which bumps the authority
generation and invalidates the claim — the next reconcile
re-pushes. Covered by the M2 fold. FAILED.

## C. Findings

### MAJOR (0)

None. All eleven r55 findings fold on independent verification.

### MINOR (1)

**m1.** Name the §9 contention leg: a blocked write holding
`configSyncMu` for the full `syncWriteDeadline` (2s,
`sync.go:88`, starting inside `writeFull` after the `writeMu`
wait, `sync_protocol.go:59-74`) while a commit push waits —
the v56 text references the regression without naming it in
(h2i).

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the contention-leg
name). A v57 containing only this pin is PLAN-READY by inspection
from me.
