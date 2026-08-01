# Claude SMR hostile plan-review — round 67 (plan v67 @ `ebeaaf607`)

Reviewer: Claude (in-conversation SMR pass). Stance: HOSTILE. r66's SMR
returned PLAN-READY with four documented failed attacks; Codex r66
then found the defer/disposition hole (M1), the check-then-enter
impossibility (M2), and the scheduler's missing fence (M3) — all
verified real, all folded in v67. r67 re-verifies the v67 folds
against the real code and attacks the critical section's hold time
and the terminal latch's re-entry. All line numbers re-verified
against the worktree.

## A. Fold verification (r66 findings → v67)

### 1. Codex M1 (defer-bound reservation + honest disposition) — FOLDED

The defer covers every non-fatal exit (completion, abandon, error);
a panic or `os.Exit` in the callback ends the process, making the
reservation moot. The hung-call disposition is now honest: one
in-flight netlink call past the bound, the next mutation abandoning
at the fence, and a never-returning call bounded by the process
exit at `TimeoutStopSec=20`. FOLDED.

### 2. Codex M2 (check-then-enter critical section) — FOLDED, with nit m1

The construction verifies (the preempted-after-check callback could
resume and enter the call under repeated loads). The v67 section —
the fence check and each mutation's entry under the ledger lock —
means a callback can never START a call after the gate closes.
FOLDED — but see m1: the section's hold across a blocking netlink
call's entry is unbounded.

### 3. Codex M3 (scheduler fence + terminal latch) — FOLDED

All three parts verify: `publishPolicyScheduleState` checks only
epoch before dataplane mutation (`daemon_scheduler.go:192-217,
229-241` — the fence was genuinely absent); Run's defer re-entry
(`daemon_run.go:89-100`) is answered by the terminal latch; and the
teardown's wait behind one in-flight scheduler snapshot
(`manager_compile.go:447-453,526-564` under `m.mu`,
`manager.go:471-482`) is bounded by the control-request deadline
with the fence preventing new mutations. FOLDED.

### 4. Codex m1 (zeroize consistency) — FOLDED

The two-term "full" references now read the three-term form, and
the ZEROIZE CALLBACK leg exists in §9 (grep-verified). FOLDED.

## B. Fresh attacks on the v67 delta

**Attack 1 (SUCCEEDED as nit m1) — the critical section's hold
across a blocking netlink entry is unbounded.** The check-then-enter
section holds the ledger lock around the netlink call's entry; a
netlink operation is a syscall that can block, and the ledger lock
is also taken by the mint's supersession query and the gate closure
— so a hung call stalls the mint (and every apply, via the
applySem → ledger order). One clause: the section's hold is bounded
by the netlink call's own deadline (the daemon's netlink operations
carry timeouts), and a deadline-less hang is the pre-existing
stuck-netlink class, bounded by process exit. MINOR.

**Attack 2 (FAILED) — the terminal latch blocks a legitimate later
stop.** The stop paths (`runShutdownSequence:78` and Run's defer,
`daemon_run.go:89-100`) are both process-exit paths; no non-exiting
shutdown path exists, so no legitimate later stop needs the latch
open. FAILED.

**Attack 3 (FAILED) — the defer doesn't run on panic.** A panicking
callback crashes the process; the reservation and the whole
join state die with it; there is no partial state to leak. FAILED.

**Attack 4 (FAILED) — the gate close starves behind a hung
section.** Same shape as attack 1 — the hang is the pre-existing
stuck-netlink class, bounded by process exit, and named in m1.
FAILED (folded into m1).

## C. Findings

### MAJOR (0)

None. All three r66 majors and the minor fold on independent
verification.

### MINOR (1)

**m1.** Bound the critical section's hold: the check-then-enter
section's ledger-lock hold is bounded by the netlink call's own
deadline (the daemon's netlink operations carry timeouts), and a
deadline-less hang is the pre-existing stuck-netlink class bounded
by process exit — named so the mint's supersession query and the
gate closure can never be stalled past that bound.

## D. Structure confirmation (§11 q6)

CONFIRM §4.7 — the split stands with AGY's (A) dissent preserved.

## Verdict

**PLAN-READY-WITH-NITS** (0 MAJOR, 1 MINOR — the section-hold
bound). A v68 containing only this pin is PLAN-READY by inspection
from me.
