# Claude SMR hostile plan-review — round 54 (plan v54 @ `8cc30c5f1`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r53's SMR
raised the token-seeding and pending-observability nits (both folded
in v54 — IS parts of Codex M2 and M3); r54 re-verifies the v54 folds
of Codex's 4M/1m against the real code and attacks the staleness
re-check's marker interaction and the boundary publication's lock
ordering. All line numbers re-verified against the worktree.

## A. Fold verification (r53 findings → v54)

### 1. Codex M1 (staleness re-check + de-circularized order) — FOLDED, with nit m1

The paused-claimant class verifies exactly (claim-then-unlock-then-send,
`daemon_ha_sync.go:462-497`; the fresh wire gen at resume,
`sync_conn_config.go:230-243`). The v54 re-check — re-validate the
captured generation against the store's current active generation
immediately before `QueueConfig`; a stale capture drops with an
alarm — closes the class by construction: the captured value is the
`configGenerationHash` of the captured text
(`daemon_ha_sync.go:470-473`), and the store's current active
generation is recomputed over `ShowActive()` at the re-check point —
comparable types, same hash — so the comparison is implementable as
stated. The observation order is now non-circular (detect →
re-converge → the two bracketing reads). FOLDED — but see m1: the
drop leaves the marker claimed for a generation never pushed.

### 2. Codex M2 (token lifecycle) — FOLDED

The lifecycle now enumerates the mint point (the central entry),
owner (daemon), publication (with the configstore's versioned
snapshot), transport (the deferring manager calls gain it), the
helper-restart inheritance (the #6034 resume pattern seeds from the
helper's reported generation on attach,
`process_status.go:165-172` — verified the seeding exists), and the
process-lifetime namespace. A pre-restart completion can only arrive
via the helper, and the seeding prevents a stale match. FOLDED.

### 3. Codex M3 (pending inventoried + observable) — FOLDED

The snapshot now carries the current attempt token + a pending-arm
count (incremented on deferral, decremented on a token-matching
completion), rendered beside lastOK/count — the predicate's
no-pending term is operator-checkable. FOLDED.

### 4. Codex M4 (count semantics aligned) — FOLDED

Grep-verified: the surviving count-incrementing texts now all say
TERMINAL — the §5.1 convergence-point text records the deferred-MAC
and nil-dp outcomes as terminal failures, the pending-XSK deferral
is PENDING (count unmoved), and the §9 h2d leg reads
rejection-is-pending / exhaustion-increments. The tri-state is
consistent across the runbook, acceptance, §5.1, and §9. FOLDED.

### 5. Codex m1 (publication method + double-bump ACTUALLY written) — FOLDED

The v53 honest-fold failure is repaired: the §5.1 contract now names
the store's `NoteApplyOutcome`-shaped boundary method (the single
publication entry every failure class flows through, including
pre-promotion compile failures) and the writer's bump-BEFORE-and-AFTER
discipline (odd-in-flight / even-stable; retry on odd-or-changed).
FOLDED.

## B. Fresh attacks on the v54 delta

**Attack 1 (SUCCEEDED as nit m1) — the drop leaves the marker
claimed for a generation never pushed.** The claimant claims the
(epoch, gen) marker BEFORE the re-check; a dropped stale capture
leaves the marker saying that gen was pushed. In the fence's
post-restart phase the peer is connected, and a later pass computing
the SAME generation (the current active unchanged since the capture)
would no-op against the claimed marker — suppressing a NEEDED push
until the next config change. The clean fix is one clause: the
re-check runs BEFORE the marker claim (validate-then-claim-then-send),
or the drop un-claims. MINOR.

**Attack 2 (FAILED) — the boundary publication's lock ordering.**
The apply boundary holds applySem and publishes through the store's
method, which takes the store's `s.mu` briefly — the SAME
applySem → store.mu order every commit path already establishes
(`commitAndApply` holds applySem and calls `store.Commit`,
which takes `s.mu`). The store never calls back into the apply
path (the store is a leaf dependency). No inversion. FAILED.

**Attack 3 (FAILED) — the re-check's own TOCTOU.** Between the
re-check and the send, the store's active can change — but any such
change is the operator's own re-drive commit (whose push carries the
newest wire gen and the newest capture), and a change landing after
the re-check simply makes this pass's capture stale for the NEXT
pass, which re-computes and pushes the current text. The re-check
bounds staleness to the current pass; the next pass converges.
FAILED.

**Attack 4 (FAILED) — the marker no-op after an un-claim.** An
un-claimed drop lets the next pass for the same generation push
normally — the no-op only fires after a REAL push claimed the
marker. No suppression of a needed push. FAILED (given the m1 pin).

## C. Findings

### MAJOR (0)

None. All five r53 findings fold on independent verification.

### MINOR (1)

**m1.** Order the staleness re-check BEFORE the marker claim (or
un-claim on the drop): a dropped stale capture currently leaves the
(epoch, gen) marker claimed for a generation never pushed, and a
later pass computing the same generation no-ops against it —
suppressing a needed push until the next config change
(`daemon_ha_sync.go:474-489`). Validate-then-claim-then-send.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the claim-ordering
pin). A v55 containing only this pin is PLAN-READY by inspection
from me.
