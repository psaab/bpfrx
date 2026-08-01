# Claude SMR hostile plan-review — round 44 (plan v44 @ `e30ea7a3e`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r43's SMR
raised the witness-surface pin (folded in v44); r44 re-verifies the
v44 folds of Codex's 3M/2m against the real code and mounts the
strongest attacks I can construct against the reservation-ordered,
all-ingress counter design — including the post-drain dispatch chain
Codex's fold-1 note flagged. All line numbers re-verified against the
worktree.

## A. Fold verification (r43 findings → v44)

### 1. Codex M1 (publication order) — FOLDED

The Go semantics are as Codex stated: in `select { case ch <- item:
... }` the send completes — and a waiting consumer can receive —
before the arm body executes. The v44 reservation shape (increment
BEFORE the enqueue attempt; rollback ONLY on the nil-channel guard and
the queue-full `default:` arm, `sync_conn_read.go:318-331`) is exactly
balanced: the send either succeeded (the consumer's dequeue-scoped
`defer` is the sole retirement) or it did not (the rollback is the
sole retirement) — the two are mutually exclusive per token by
`select` semantics, so no double-decrement and no leak. A reservation
held across a full-queue window reads false-BUSY, never false-idle.
FOLDED.

### 2. Codex M2 (all-ingress join) — FOLDED

Verified the funnel claim: `OnConfigReceived` has exactly ONE call
site (`sync_conn_config.go:351`, the consumer), wired only at
`daemon_ha_sync.go:910-913`; every config frame — registered-reader,
pre-install pending frame (`sync_conn.go:122-127`), superseded reader
(`sync_conn.go:244-267,480-498`), post-Stop-cap reader — reaches the
consumer through the same `handleMessage` switch's `syncMsgConfig`
case, where the reservation lives. No cold-prime, bulk-sync, or test
path applies config outside it. Unkeyed third-party ingress dispatches
through the same case and is counted. The counter IS the all-ingress
join. FOLDED.

### 3. Codex M3 (honest bound for residual iii) — FOLDED

Both sub-claims re-verified: (a) `reconcileConfigSyncToPeer` skips
unless peer-connected AND RG0-authority AND past the stability
threshold (`daemon_ha_sync.go:447-465`), and preemption is
priority-based (`cluster/election.go:172-193`) — convergence to the
authority's config, possibly the peer's older persisted one, is a
bounded regression to a PERSISTED state, not a silent divergence;
(b) the post-rename failure class leaves the new content VISIBLE
(`fsatomic.go:45-53,66-72`; the plan's own :2381-2391), the restart
loads it (`store_persist.go:21-55,110-114`,
`daemon_run_bringup.go:516-520`), the equal-and-applied re-push skips
`SyncApply` (`daemon_ha_sync.go:550-568`), and the process-local
degradation is not reconstructed. The v44 restatement names both, and
the operational closure is pinned: the repair's directory `sync` of
the configdb, plus the post-restart verification — which v44 (with
the pre-dispatch self-fix) pins as comparison against the OPERATOR'S
intended config, defeating the cross-node-agreement-on-an-older-
config false pass. FOLDED.

### 4. Codex m1 (acceptance enumerates residual iii) — FOLDED

The acceptance copy now carries residual (iii) with the failure-class
split, the authority-conditional convergence, and both operational
closures; the normative and acceptance copies agree. FOLDED.

### 5. Codex m2 + SMR r43 m1 (witness generalized + surfaced) — FOLDED

The witness is the terminal exit of every relevant ingress reader
(dispatch only after complete verification, `sync_conn_read.go:22-93`),
observed on `IsSyncConnected` (`sync_state.go:66-74`,
`status.go:263-267`). Verified the aggregation: `handleDisconnect`
stores `connected = conn0 != nil || conn1 != nil`
(`sync_conn.go:479-498`), so the surface reads Down ONLY when BOTH
redundant sessions are down; a stale superseded disconnect is ignored
(:492-495) — which is correct, because superseded readers are covered
by the COUNTER, not the witness. FOLDED.

## B. Fresh attacks on the v44 delta

**Attack 1 (FAILED) — the post-drain superseded-reader dispatch.**
The strongest window I can construct: a superseded reader completes a
full frame read + verify before the peer dies, is descheduled BEFORE
`handleMessage`, the peer dies, both registered conns EOF and exit,
the witness flips Down, and the drain reads the counter as zero — all
before the superseded reader wakes and dispatches. The dispatch then
reserves and the consumer applies AFTER the drain. Walk the fence:
(i) if the late dispatch lands before the re-check (3), the re-check's
`ConfigSyncOutstanding == 0` term CATCHES it — the counter is re-read
at (3), and the reservation precedes the apply, so (3) cannot observe
zero while the apply is pending; (ii) if it lands between (3) and the
local stop (4), it is exactly residual (iii)'s LOCAL post-re-check
window — admitted, bounded by the (4) abandonment, the next-boot
re-classification, the repair's directory `sync`, and the
post-restart verification step. For a REGISTERED reader the window
does not exist at all: reservation (dispatch) happens-before reader
exit happens-before witness-Down, so witness-Down + counter==0 is a
true join for every registered conn. The superseded/pre-install
residual is admitted and bounded. FAILED.

**Attack 2 (FAILED) — double-decrement.** Reservation + successful
send → the consumer `defer` is the only retirement; reservation +
nil/full disposition → the rollback is the only retirement. `select`
semantics make the send's success exclusive. No path runs both.
FAILED.

**Attack 3 (FAILED) — a bypass apply path.** Cold-prime and bulk sync
prime SESSIONS, not config; the only config-apply entry is
`OnConfigReceived` from the consumer. Test hooks
(`configSyncPushForTest`, `daemon_ha_sync.go:441-443`) are
outbound-only. FAILED.

**Attack 4 (FAILED) — witness/counter read order at (2c).** The plan
pins witness-first, counter-second: a registered reader's dispatch
precedes its exit, which precedes witness-Down, so the counter read
after witness-Down sees every registered dispatch; and (3) re-reads
the counter regardless. A reversed order would admit a
dispatch-between-reads window; the pinned order does not. FAILED.

**Attack 5 (FAILED) — the false-BUSY wedge.** A reservation rolled
back on queue-full is balanced immediately; a reservation retired by
the consumer defer is bounded by the apply's return; the only
long-lived hold is the applySem-blocked apply, which is precisely the
state the drain exists to wait out. No permanent wedge. FAILED.

## C. Findings

### MAJOR (0)

None. The reservation-ordered, node-lifetime, all-ingress counter plus
the witness-first drain and the honestly-bounded residual set close
every window raised across r41-r43 that I can re-attack.

### MINOR (0)

None. The v44 text pins the surfaces, the order, the failure classes,
and the verification step to the precision the prior rounds demanded;
the pre-dispatch self-fix closed the intended-config false-pass before
review.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR — five documented fresh attacks all
FAILED on code evidence; the fold verification is independent, not a
rubber stamp: each fold was re-derived from the cited code, and the
two strongest attacks against the v44 delta — the post-drain
superseded-reader dispatch and the read-order window — were walked to
their admitted, bounded residuals).
