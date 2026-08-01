# Claude SMR hostile plan-review — round 66 (plan v66 @ `bbbb6078b`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r65's SMR
raised the two missing §9 legs (folded in v66 — IS Codex's
fold-1/fold-2 testing partials); r66 re-verifies the v66 folds of
Codex's 3M/1m against the real code and attacks the reserved-set
drain's hung-callback case and the zeroize latch's timing. All line
numbers re-verified against the worktree.

## A. Fold verification (r65 findings → v66)

### 1. Codex M1 (the join waits on the reserved set) — FOLDED

The unscheduled-goroutine gap verifies (`go m.OnXSKBound()`,
`maps_sync.go:451-456` — a semaphore drain never sees a
not-yet-started callback). The v66 form — the admission-gate
reservation recorded at launch under the ledger lock is the join
state, and a not-yet-scheduled callback's first act is the fence
check (gate closed ⇒ abandon and retire) — drains the reserved set
through every path: a scheduled callback completes or abandons and
retires; an unscheduled one abandons at its first fence check and
retires. The hung-netlink-call case is covered by the 5s
disposition (the shutdown proceeds; the callback abandons at its
next fence check; a never-returning call dies with the process at
SIGKILL). FOLDED.

### 2. Codex M2 (scheduler safe terminal state) — FOLDED

The disposition verifies as safe: the policy scheduler's mutations
flow through the apply machinery (`commitAndApply`/`applyConfig`),
so an abandoned stop leaves the scheduler's next mutation hitting
the shared fence; its state is in-memory and dies with the process;
and the 5s bound matches the drain's, adding no new sequential wait.
The `schedulerWg.Wait()` unboundedness
(`daemon_scheduler.go:192-203`, `scheduler.go:103-116,207-217`) is
bounded by the process exit. FOLDED.

### 3. Codex M3 (the zeroize latch) — FOLDED

`resetting` is latched before the zeroize's applySem release
(`daemon_apply_reset.go:59-89`), so a callback acquiring after the
wipe reads it and abandons; the three-state fence
(`runCtx.Err()` OR `stopping` OR `resetting`) is checked after
acquisition and before each mutation on every callback path.
FOLDED.

### 4. Codex m1 (reset taxonomy) — FOLDED

The taxonomy is stated: the reset runs on both Teardown paths
(reusable, `bootstrap.go:470-475`, and terminal,
`daemon_run_shutdown.go:222-229`), never on `stopLocked`'s
helper-restart paths, and `Close` (`manager.go:471-475`) needs no
reset. FOLDED.

### 5. The §9 v65 shutdown legs — FOLDED

The (h2o) legs exist: preemption-between-check-and-call,
Teardown→reset→B-registration→A-generation-rejection, and the
reserved-set-drain leg. Grep-verified. FOLDED.

## B. Fresh attacks on the v66 delta

**Attack 1 (FAILED) — a callback blocked inside a netlink call past
the bound.** Its reservation never retires, but the set-drain's 5s
disposition bounds the wait; the shutdown proceeds; the callback
abandons at its next fence check; and a never-returning kernel call
dies with the process at `TimeoutStopSec`. The overlap is one
in-flight call, as the disposition states. FAILED.

**Attack 2 (FAILED) — the retained pre-wipe config in the zeroize
window.** The callback's fire-time re-derivation reads the current
config — in the post-wipe window the retained config is the
pre-wipe one, but `resetting` is latched before the applySem
release (`daemon_apply_reset.go:59-89`), so every mutation path
abandons at the fence before touching netlink. FAILED.

**Attack 3 (FAILED) — the reserved set live-locks on a slow
callback.** The set-drain has the 5s bound; a slow-but-finishing
callback retires on completion; a stuck one is bounded by the
disposition. No livelock. FAILED.

**Attack 4 (FAILED) — the gate close itself races a launch.** The
close takes the ledger lock; the launch's reservation records under
the same lock inside the (`m.mu` → ledger) section; either the
reservation precedes the close (and is drained) or the close
precedes it (and the launch abandons). FAILED.

## C. Findings

### MAJOR (0)

None. All three r65 majors and the minor fold on independent
verification; the join's semantics are now stated against the
reserved set, not the semaphore.

### MINOR (0)

None. The v66 delta is consistent; the referenced legs exist; the
predicate copies agree.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY** (0 MAJOR, 0 MINOR — four documented fresh attacks
all FAILED on code evidence; the fold verification is independent:
each fold was re-derived from the cited code, and the two strongest
attacks against the v66 delta — the hung-callback drain case and
the zeroize latch timing — were walked to their safe orderings).
