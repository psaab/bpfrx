# AGY adversarial plan-review r1 — verdict PLAN-READY

Job: adversarial-review-mpsh02bx-mm52n8 (base 38e6fec53)

## Summary of AGY verdict (PLAN-READY)

1. **v1 refutation SOUND & DECISIVE** — 18g=14.25 G from one worker proves
   the ~3-4 G/class limit is resource-division + scheduling, not thread
   serialization.
2. **§3.A (push ceiling = physics) HIGH CONFIDENCE / CORRECT** —
   `park_root=0`, aggregate pins ~22-24 G across sweeps; CoS cannot
   allocate bandwidth the forwarding plane can't deliver.
3. **§3.B DEEP-DIVE: AGY proposes a Phase-2 epoch-lockout bug** —
   `mod.rs:793` refills `waterfill_pass1_remaining_bytes` only when `== 0`;
   Phase-1 break leaves a small positive value; Phase-2 returns without
   zeroing it; so the epoch never refills and the worker "locks in Phase-2
   forever," relegating co-hosted mid classes (3g/6g) to best-effort
   residual.
4. **Reconciliation with #1630-r4 FULLY RECONCILED** — different
   behavioral regimes of the same state machine.
5. **#1628 aggregation does NOT hide the split** — each queue is
   single-owner, so per-class counters are inherently per-owner.
6. Path B REQUIRED; Path A RECOMMENDED; suggested hardening: reset
   `pass1_remaining` to 0 on Phase-1 break, or refill below min quantum.

## Claude SMR's hostile cross-check of AGY's central claim (finding 3)

AGY's epoch-lockout mechanism is a PLAUSIBLE LATENT BUG but is **REFUTED
as the active #1614 cause by the live telemetry**, which AGY did not have:

- Interface `waterfill_epochs` climbed 7.68M → 9.41M during the 33 s run
  (~52K/s). A permanently-wedged epoch would show FLAT epochs. The epoch
  rotates continuously.
- `phase1_admit` is the DOMINANT admit path for EVERY class incl 24g
  (84% Phase-1). A worker locked in Phase-2 would show ~0 phase1_admit.

So AGY's code-read is internally consistent but does not match the running
system. The lock-in either does not trigger under this rate/quantum mix
(Phase-1 honor drains the budget to exactly 0 often enough to refill), or
a path AGY did not trace resets it. v3 folds this as §3.B.1 "epoch
lock-in REFUTED as active mechanism" and §7-Q5 "is the wedge a real latent
bug worth independent hardening."

AGY's finding 5 (counters are per-owner because single-owner) DISAGREES
with Codex r1 finding 3 (counters are summed across workers and hide the
per-worker split). v3 §7-Q2 records this disagreement and defers it to an
empirical per-worker dump in the /engineer round rather than adjudicating
on paper — both reviewers' code-reads are partially right (the queue is
single-owner, so the SUM is over one owner per queue; but a worker hosting
TWO queues has a shared per-worker `pass1` budget that no per-queue
counter exposes — that per-worker budget state is what is hidden).
