# Claude SMR hostile plan-review — round 57 RULING (plan v57 @ `a4094634c`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. This
round carries the engineering ruling on the r56 M1-M6 mechanism-depth
findings, plus the v57 consistency-fold verification. All line
numbers re-verified against the worktree.

## A. Fold verification (r56 consistency findings → v57)

### 1. Codex M7 (contract synchronization) — FOLDED

The acceptance copy now carries the full send-boundary protocol
(provider identity, authority generation, success-only publication,
the lock-assuming helper); the §5.1 inventory gains the
authority/provider state (`daemon.go:420-424`,
`daemon_ha.go:438-475`) and the pkg/dataplane/userspace change list
(the token threading, the atomic install/register/already-bound
operation, the short-held debt ledger answering the
`process_status.go:150-255` whole-poll `m.mu` hold with its 2s
dial / 120s round trip, `process_control.go:34-56,129-142`, and the
`errors.Join` detach conversion, `manager_compile.go:211-214,
567-591`); §6's signature list now names `QueueConfig`'s success
return and the token parameters (`apply.go:37-40,130-134`). FOLDED.

### 2. Codex M8 + m1 (§9 legs) — FOLDED

The (h2j) legs exist and exercise what they name (the OnXSKBound
callback interleave, PrepareLinkCycle registration, the
completion-vs-next-mint transaction, the slow-poll mint, the
returned detach failure with attempt-all `errors.Join`, the
authority leg through re-promotion), and the contention leg is
named in (h2i) with the corrected 2s/`writeMu`-wait arithmetic
(`sync.go:88`, `sync_protocol.go:59-74`). FOLDED.

### 3. Codex m2 (pending-term omissions) — FOLDED

The post-reactivation predicate and the rendering inventory both
carry the no-pending-outstanding term now. FOLDED.

## B. The ruling: (B) — simplify the claim

I rule **(B)**, on the following analysis. The H2 done-predicate's
safety property is: never declare the repair done over an
unconverged or unclean node. Walking each r56 M1-M6 construction
and asking which direction it degrades under (B):

- **M1 (receiver rejection / dual-primary marker suppression)** —
  the receiver rejects a config frame when IT considers itself
  primary (`daemon_ha_sync.go:544-548`), and the sender's marker
  can then suppress every same-connection retry. Under (B): the
  peer's digest never matches the intended digest, the
  interval-bracketed double read catches it, and the operator's
  re-drive (a commit push always carries the newest wire
  generation, `sync_conn_config.go:234-243`) overwrites it. The
  truly silent tail — the marker suppression persisting AFTER the
  procedure with no operator watching — is the pre-existing #5863
  safety-net's semantics in the shipping code, not introduced by
  this plan; the apply-level ACK hardens that generally and goes to
  a named follow-up issue. DETECTED-AND-RECOVERABLE in-procedure;
  named pre-existing residual post-procedure.

- **M2/M3 (provider-generation linearization; authority
  invalidation racing publication)** — under (B), both produce at
  worst a stale or rejected push, which presents as a digest
  divergence at the bracketing reads → re-drive. The
  send-boundary protocol (already folded: validate-claim-then-send
  under `configSyncMu`, claim on success only) shrinks both windows
  to the genuinely pathological. DETECTED-AND-RECOVERABLE.

- **M4 (rollback health fork)** — the one finding that is NOT
  optional even under (B), because an unclassified rollback outcome
  can strand the predicate permanently (false-red) or bless a
  failed rollback (false-green). The (B) fold is small and stays:
  the rollback path's branches get explicit neutral/success/failure
  outcomes published through the same boundary
  (`daemon_apply_commit.go:645-708` — the stale-timer no-op is
  NEUTRAL, the nil-target teardown and the apply/session-clear
  failures are FAILURE). This is outcome classification, not a new
  mechanism. KEPT.

- **M5/M6 (callback identity; debt-transfer transaction)** — under
  (B), a mis-registered or stranded arm presents as a pending arm
  that never completes → the predicate stays unblessed →
  fail-closed. The exactly-once transactionality is a false-RED
  refinement, not a false-green one. The manager-side
  self-registration (already folded) plus the per-attempt
  supersession give the safe direction; the deeper transaction
  (single retoken transaction) becomes a named precision follow-up
  rather than a gate. SAFE DIRECTION.

The decisive test the prompt sets: no r56 construction remains that
produces an UNDETECTED, UNRECOVERABLE bad outcome under (B). The
only unrecoverable-in-procedure case is the already-named terminal
corner (encrypted origin-pinned artifact + no operator text +
cross-node need — runbook-unrecoverable, fail-closed, rebuild from
config management), and the only silent post-procedure case is the
pre-existing #5863 marker semantics, which the ACK follow-up owns.

(A) is rejected on the evidence of ten rounds: every instantaneous-
correctness mechanism has revealed a further layer (the ACK being
the latest — a new wire message), and there is no evidence the next
layer is the last, because the system's asynchronous surface is
genuinely large. (C) is rejected: the machinery is the H2 runbook's
substance; splitting further defers the same ruling without
changing it.

## C. What (B) keeps vs. re-scopes (the v58 edit list if the panel
concurs)

KEEPS (already converged, each a real correctness improvement on
its own): the `ConfigSyncOutstanding` counter (reservation-ordered,
gated, node-lifetime); the dispatch epoch; the configstore-owned
versioned snapshot with the seqlock read side; the tri-state with
terminal/pending and the per-arm registration; the send-boundary
protocol (validate-then-claim-then-send under `configSyncMu`,
success-only claim, provider identity, authority generation) — a
standalone reconciler correctness fix the rounds proved necessary
against the A→B→A marker-poisoning construction; the two-node
quiesce/re-activation; the capture protocol; the
interval-bracketed double digest check with the re-drive.

RE-SCOPES to named bounded residuals with detection-and-recovery:
the receiver-rejection/dual-primary marker suppression (detected by
the bracket, recovered by the re-drive; the ACK is the named
follow-up); the provider/authority races with publication (same
detection/recovery); the exactly-once debt-transfer transaction
(fail-closed bias; the single-retoken transaction is a precision
follow-up).

KEEPS as small pins even under (B): the rollback outcome
classification (M4).

## D. Structure confirmation

CONFIRM §4.7 — unchanged by the ruling; the split stands with AGY's
(A) dissent preserved either way.

## Verdict

**PLAN-READY-WITH-NITS** — ruling (B); the remaining edits are the
residual-naming and the follow-up issue's seeding, both of which the
v58 fold can carry by inspection if Codex and AGY concur.
