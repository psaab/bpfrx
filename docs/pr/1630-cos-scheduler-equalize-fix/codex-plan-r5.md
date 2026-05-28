[2026-05-28T17:00:09.116Z] Final output
I couldn’t write [codex-plan-r5.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/codex-plan-r5.md) because this session is read-only. Exact content:

```md
# Codex plan-r5

## Verdict: PLAN-NEEDS-MAJOR

## Findings

1. [HIGH] Test 5 does not pin the regression it claims to cover. In [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/plan.md:340), the fixture is only `4 small + 1 large`, and the drive pattern is “delta `now_ns` by `VISIT_NS` each call.” That is not the smoke regime that killed v4 or v5. It never exercises the 6-large-class residual rotation, and with one call per epoch it cannot meaningfully assert “each small class is honored at least once per epoch.” This test needs `4 small + 6 large`, multiple selections per epoch before advancing time, and assertions on the Phase-2 starting queue across successive timed epochs.

2. [MEDIUM] The plan’s own fairness proof is internally contradictory. In [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/plan.md:243), epoch 1 is walked all the way to the legacy Phase-2 no-selection reset, then the exhausted-path refill resets the cursor to 0 again inside the same lease epoch. But in [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/plan.md:277), epoch 2 fairness relies on carrying a nonzero cursor from epoch 1. Both cannot be true. The design likely wants the r4 regime where timed refresh happens before the legacy reset path; the plan needs to state that explicitly and test it.

3. [MEDIUM] The v6 rewrite is not clean yet. [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/plan.md:52) says “only the time-based refresh path refreshes `pass1` and `waterfill_epoch_start_ns`,” but the code sketch later refreshes on `time_refresh || exhausted`. The scratch prose at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/plan.md:259) and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/docs/pr/1630-cos-scheduler-equalize-fix/plan.md:266) (“Wait”, “Hmm”) should not survive a final hostile rewrite.

## Answers

1. If the timed-refresh path is reached with a nonzero Phase-2 cursor, v6 is the right semantics: over 3 epochs the large-class starts rotate `24/21/18/15`, then `12/9/24/21`, then `18/15/12/9`, so all 6 large classes get residual service. But the current plan does not prove that this is the path actually taken in the smoke regime.

2. If `time_refresh` and `pass1 == 0` fire together, the sketch does one refill and resets the cursor because `exhausted` is true. That is the right precedence. Branch order in the `if time_refresh || exhausted` predicate does not matter; the post-refill `if exhausted` does.

3. Pre-fix exhausted behavior is preserved for cursor reset: the legacy `pass1 == 0` path still resets the cursor, matching current [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/1630-cos-scheduler-equalize-fix/userspace-dp/src/afxdp/cos/queue_service/mod.rs:787) semantics. The subtle new behavior is that exhausted refresh also rebases `waterfill_epoch_start_ns`, so waterfill timing is no longer purely “since last timed refresh.”

4. Test 5 is not concrete enough to fail under v4 and pass under v6. As written, it is under-specified and uses the wrong fixture shape.

5. Test 4 does distinguish v5 from v6, because v5 resets the cursor on timed refresh and v6 must not. It would be stronger if it asserted the next Phase-2 pick comes from the preserved cursor, not just the raw field value.

6. Lease-epoch vs waterfill-epoch drift is not a new correctness race by itself. Duration parity matters; exact timestamp identity does not. But the plan should explicitly document that exhausted-path refills rebase `waterfill_epoch_start_ns`.

7. The document is not clean yet. The v6 core idea is better than v5, but the prose and the key regression test still need another pass before implementation.

## Bottom line

The v6 semantic change itself is probably the correct direction: timed pass1 refresh without timed cursor reset. What is still missing is a coherent proof and a regression test that actually exercises the 6-large-class, multi-epoch residual-rotation case that motivated the fix.
```
