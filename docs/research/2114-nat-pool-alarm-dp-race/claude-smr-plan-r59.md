# Claude SMR hostile plan-review — round 59 (plan v59 @ `5a0df2b2c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r58's SMR
raised the acceptance-copy residual enumeration nit (folded in v59);
r59 re-verifies the v59 folds of Codex's 4M/1m against the real code
and attacks the QUEUED publication's overwrite semantics and the
authority check's timing. All line numbers re-verified against the
worktree.

## A. Fold verification (r58 findings → v59)

### 1. Codex M1 (complementary-authority check) — FOLDED

The dual-primary false green verifies exactly (both nodes holding
fully-applied intended text with every digest and apply-health field
green while both forward, `daemon_ha.go:273-325`,
`daemon_ha_sync.go:545-548`). The v59 check — the RG0 election
SETTLED with EXACTLY ONE primary matching the intended mastership —
is observable: the cluster status surface renders per-RG state
(`status.go`'s FormatStatus covers the RG state machine), and the
check is fail-closed on a pre-settlement read (the operator waits
and re-reads). A post-declaration flap is ordinary cluster operation,
not a repair-integrity issue. FOLDED.

### 2. Codex M2 (callback lifecycle-total + outcome-truthful) — FOLDED

The shutdown-window half verifies (`daemon_run_shutdown.go:50-64,
214-230` — the drain releases applySem and the detached callback
could run after), and the `stopping`-fence re-check after acquiring
applySem closes it (the work-item-G fence is already in the §5.1
daemon inventory). The outcome-truthfulness half verifies
(`daemon_ha_fabric.go:29-50,78-88,115-147` — the ignored parent-up
failure and the logged-only address/MTU/up failures), and reporting
the fire-time outcome into the arm's registration (FAILED, never
converged, on any creation/reconciliation failure) closes it.
FOLDED.

### 3. Codex M3 (queued state published at enqueue) — FOLDED, with nit m1

The queued-waiter window verifies (`daemon_dhcp.go:73-90,231-260` —
the lease change precedes the semaphore wait, and the reapply
rebuilds the address-scoped enforcement). Publishing QUEUED at
enqueue closes it. FOLDED — but see m1: the QUEUED publication's
overwrite semantics against the running attempt's fields are not
pinned.

### 4. Codex M4 (M6 contradiction resolved by serialization) — FOLDED

The false-green interleave verifies (a registration between the
snapshot and the supersession could be discarded with its
completion ignored, `process_status.go:150-198`,
`maps_sync.go:451-456`). The v59 rule — registration, completion,
AND the mint-boundary supersession all serialize through the
manager's `m.mu` — makes the interleave impossible by construction
(the snapshot and the supersession are one critical section; a
registration either lands before the snapshot (included) or after
the supersession (registered under the new token)). The residual
(vi) is now honestly scoped to the cross-incarnation precision
follow-up. FOLDED.

### 5. Codex m1 (§9 legs + acceptance alignment) — FOLDED

The (h2k) hybrid-closure legs exist (rollback-fork and
stale-callback), and the acceptance copy carries the residuals
(iv)-(vi) by reference plus the authority check. Grep-verified.
FOLDED.

## B. Fresh attacks on the v59 delta

**Attack 1 (SUCCEEDED as nit m1) — the QUEUED publication's
overwrite semantics.** The QUEUED-at-enqueue publication races the
RUNNING attempt's own publications: attempt B queues while attempt A
runs; if B's QUEUED write blindly overwrites the snapshot, A's
in-flight state (lastOK false-at-entry) is erased — and if A then
fails, its FAILURE publication lands on a superseded snapshot
position. One clause: the QUEUED publication is ADDITIVE (the
snapshot carries the running attempt's state AND the queued flag);
the supersession happens only at B's mint (admission), which is
necessarily after A completes (A holds applySem until it returns).
MINOR.

**Attack 2 (FAILED) — a stale QUEUED from a prior incarnation.** The
snapshot and the queued flag are process-lifetime; a restart
re-initializes both before the boot apply; the predicate is
consulted post-restart. Nothing leaks. FAILED.

**Attack 3 (FAILED) — the authority check's settle timing.** The
check is fail-closed: a pre-settlement read (both nodes in startup
hold, or a flap in progress) fails the check and the operator
re-reads; the only pass state is exactly-one-primary with the
intended mastership. FAILED.

**Attack 4 (FAILED) — a SUCCESS publication for a superseded
token.** B mints only at admission, which requires applySem, which A
holds until A returns — so A's terminal publication always precedes
B's mint; A's SUCCESS is never published after supersession. FAILED
(given m1's additive-QUEUED pin for the enqueue window).

## C. Findings

### MAJOR (0)

None. All five r58 findings fold on independent verification.

### MINOR (1)

**m1.** Pin the QUEUED publication as ADDITIVE: the snapshot carries
the running attempt's state AND the queued flag (a QUEUED write
never erases the in-flight attempt's fields), with the supersession
only at the new attempt's mint (admission).

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the additive-QUEUED
pin). A v60 containing only this pin is PLAN-READY by inspection
from me.
