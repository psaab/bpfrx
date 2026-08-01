# Claude SMR hostile plan-review — round 65 (plan v65 @ `36b8f6cfb`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r64's SMR
returned PLAN-READY with four documented failed attacks; Codex r64
then found the downstream drain holes (M1) and the reset-scope
unsafety (M2) — both verified real, both folded in v65. r65
re-verifies the v65 folds of Codex's 3M/1m against the real code and
checks the two referenced §9 legs for actual existence. All line
numbers re-verified against the worktree.

## A. Fold verification (r64 findings → v65)

### 1. Codex M1 (three downstream holes) — FOLDED, with nit m1

All three holes verify: the UNCAPPED reacquisition
(`stopPolicySchedulerLoop` at `daemon_run_shutdown.go:78` →
`daemon_scheduler.go:170-183`, `context.Background()`), the
startup-abort path skipping the drain (`daemon_run.go:157-197`)
while phase four can launch the callback
(`daemon_run_bringup.go:493-520`), and the
preemption-between-check-and-call window. The v65 folds — a bounded
context on the reacquisition (the scheduler stop is moot at process
exit; the expiry disposition is safe), the UNCONDITIONAL gate close
at every shutdown entry (signal-driven, startup-abort, and the
CLI-exit path all funnel through `runShutdownSequence`, and the
close precedes any conditional drain) — close the first two.
FOLDED — but see m1: the third hole's §9 leg is referenced but
absent.

### 2. Codex M2 (Teardown-specific reset scope) — FOLDED, with nit m1

The caller enumeration verifies: `stopLocked` runs from the helper
restart paths (`process.go:18-33,133`,
`manager_compile.go:242-249`, `process_status.go:61-70`) AND from
the reusable Teardown — so a `stopLocked`-scoped reset would strand
epoch readiness on a compile restart. The v65 scoping (reset only
on Teardown, preceding the early return at `process.go:210-216`,
with the generation comparison after the callback's applySem
acquisition) closes it. FOLDED — but see m1: the
Teardown→reset→B-registration→A-generation-rejection regression is
referenced but absent.

### 3. Codex M3 (queued-set rendering) — FOLDED

The §5.1 rendering inventory now carries the per-attempt QUEUED set
beside the token/pending. Grep-verified. FOLDED.

### 4. Codex m1 (budget arithmetic) — FOLDED

The live text now reads 18s (with the Run-defers addition and the
pre-existing unbounded `wg.Wait` named,
`daemon_run_shutdown.go:62-64`); the 23s figure survives only in
the v64 revision-history record. FOLDED.

## B. Fresh attacks on the v65 delta

**Attack 1 (SUCCEEDED as nit m1) — two referenced §9 legs do not
exist.** The v65 text references "the preemption-between-check-and-call
case" (plan.md:7245) and "the §9
Teardown→reset→B-registration→A-generation-rejection regression"
(plan.md:7179), but §9's leg enumeration has neither — the h2m legs
cover timeout-inside-mutation and LinkDel, and h2n covers
arm-ID-reuse, but no leg exercises a fence-check-then-preempt
ordering or the Teardown/re-registration/generation-rejection
sequence. This is the same reference-without-leg class I flagged at
r56/r63 — one clause naming both legs. MINOR.

**Attack 2 (FAILED) — the bounded reacquisition's expiry leaves the
scheduler running.** At process exit the scheduler's fate is moot;
the bound's expiry merely lets the shutdown proceed past the stuck
acquisition. FAILED.

**Attack 3 (FAILED) — a shutdown entry bypasses the unconditional
close.** The entries (signal-driven, startup-abort, CLI-exit) all
funnel through `runShutdownSequence`; the close is at its top,
ahead of the conditional drain. No bypass. FAILED.

**Attack 4 (FAILED) — the generation comparison after applySem
acquisition misses a pre-acquisition fire.** The callback acquires
applySem before its body (the v58 closure); the generation
comparison after the acquisition reads the current epoch at the
latest safe point; a fire that never acquires (abandoned at the
gate) never compares. FAILED.

## C. Findings

### MAJOR (0)

None. All three r64 majors and the minor fold on independent
verification.

### MINOR (1)

**m1.** Name the two referenced §9 legs: the
preemption-between-check-and-call leg (a fence check, then a
preemption, then the netlink call beginning after the timeout —
the callback must not start the call) and the
Teardown→reset→B-registration→A-generation-rejection leg (the
epoch-A callback's fire in epoch B is rejected by the generation
mismatch while epoch B's own registration fires cleanly).

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the two missing §9
legs). A v66 containing only this pin is PLAN-READY by inspection
from me.
