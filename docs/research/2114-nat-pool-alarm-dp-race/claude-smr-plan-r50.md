# Claude SMR hostile plan-review — round 50 (plan v50 @ `2ca8da070`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r49's SMR
raised the re-capture scope and restart-reconciliation nits (both
folded in v50 — IS Codex m2 and Codex M3 / AGY M1 respectively); r50
re-verifies the v50 folds of Codex's 3M/2m + AGY's 1M against the real
code and attacks the election-aware choreography's own timing. All
line numbers re-verified against the worktree.

## A. Fold verification (r49 findings → v50)

### 1. Codex M1 (apply-health state machine specified) — FOLDED

The v49 honest-fold failure is repaired: the §5.1 pkg/daemon
inventory now CARRIES the state (process-lifetime
`applyFailureCount` + `lastApplyOK`, initialized before the boot
apply), not merely references it. The single-entry claim verifies:
every full apply flows through `applyConfigLocked`
(`daemon_apply.go:141-355`) — the boot apply
(`daemon_run_bringup.go:516-520` → `applyConfig` →
`applyConfigLocked`), the DHCP/feed wrappers
(`daemon_dhcp.go:90`, `daemon_apply.go:49-86`), and the commit /
rollback / sync paths (`daemon_apply_commit.go:246,489,697`) — so
`lastApplyOK` false-at-entry / true-only-on-nil-return and the
failure counter cover every wrapper. The §9 legs exist: (h2a) the
sticky-failure regression, (h2b) the parked-mid-apply regression.
FOLDED.

### 2. Codex M2 (reactivation mirrors the quiesce) — FOLDED

Both copies now require the re-activation on BOTH nodes with each
commit's own success (the ConfigSync=false push-suppression,
`daemon_ha_sync.go:336-364`, and the promote-before-apply abort
window, `daemon_apply_commit.go:225-246` +
`daemon_apply_tail.go:194-202`, are exactly why), followed by the
COMPLETE predicate — not merely digest equality. FOLDED.

### 3. Codex M3 + AGY M1 (election-aware choreography) — FOLDED, with nit m1

The non-executable "ensure authority by restart order" claim is
gone. The v50 form — restart the intended holder first, start the
peer, let the election settle (preemption possible,
`election.go:172-193`), read the resulting RG0 state, and
`load override` + `commit` the intended text on WHICHEVER node
holds authority, with the per-node form when sync is disabled — is
executable with existing commands, and the precedence rule against
the r39 local-first pin is explicit and correct (the pin's
protection is per-node: each node's Load completes before its own
comms, `daemon_run.go:157-177,393-398`). FOLDED — but see m1: the
post-stability push window is not named.

### 4. Codex m1 (acceptance termination branch) — FOLDED

The acceptance (3) now carries the re-baseline rule AND the
termination clause (still-advancing epoch after the second
re-baseline → stopped remediation UNAVAILABLE; fence the source or
use live removal). FOLDED.

### 5. Codex m2 (re-capture scope) — FOLDED

Both copies now cover both baselines explicitly (pre-quiesce digest
AND the fence-time pair). FOLDED.

## B. Fresh attacks on the v50 delta

**Attack 1 (SUCCEEDED as nit m1) — the post-stability push window is
unnamed.** With sync enabled and the older-config peer holding
authority after the election, the peer's reconciler pushes the OLDER
config once the 30s stability gate elapses
(`daemon_ha_sync.go:447-465`); an operator-paced `load override`
races that window. The lost race IS caught — the holder then holds
the older config, the final predicate's digest comparison fails, and
the operator re-drives (the captured text makes the re-drive
possible; the holder's rollback history is a second copy) — so the
choreography is race-SAFE, but the plan never says so: an operator
reading the runbook should know the window exists, that losing it is
detected, and that the recovery is the re-drive. One clause naming
the window + the catch. MINOR.

**Attack 2 (FAILED) — the never-applied process state.** The
predicate is consulted after the post-restart bringup; the boot
apply runs inside the bringup (`daemon_run_bringup.go:516-520`), so
at done-time a successful boot apply reads count==0/lastOK==true, a
failed one reads count==1/lastOK==false, and a still-running one
reads lastOK==false (false-at-entry) — every non-converged state
fails the predicate, none falsely. FAILED.

**Attack 3 (FAILED) — the per-node re-convergence with sync disabled
diverges the done predicate.** The per-node form applies the same
operator text to both nodes; the final predicate compares both
digests against the captured intent — a per-node failure (a commit
error on one node) is loud at that commit's own result and fails
the digest comparison. FAILED.

**Attack 4 (FAILED) — the failure counter and the fail-closed
termination clause compose.** A wedge in one (a persistent apply
failure post-restart) fails the predicate; a wedge in the other
(continuous ingress) declares the stopped path unavailable; both
fail closed with named operator actions. No interaction. FAILED.

## C. Findings

### MAJOR (0)

None. All r49 findings fold on independent verification; the v49
honest-fold failure (referenced-but-absent §5.1/§9 artifacts) is
repaired and verified present.

### MINOR (1)

**m1.** Name the post-stability push window in the choreography:
with sync enabled and the older-config peer holding authority, its
reconciler pushes the older config once the 30s stability gate
elapses (`daemon_ha_sync.go:447-465`); the operator's
`load override` on the resulting authority races that window, and a
lost race is CAUGHT (the final predicate's digest comparison fails)
and RECOVERED by the re-drive (the captured text; the holder's
rollback history) — the runbook should say the window exists, that
losing it is detected, and that the recovery is the re-drive.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved; the
design is identical under either packaging.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the push-window
clause). A v51 containing only this pin is PLAN-READY by inspection
from me.
