# Codex plan-r4 — task-mppq1orc-p9huty (verbatim)

## Verdict: PLAN-NEEDS-MAJOR

## Findings

1. [HIGH] The v5 idea fixes the real v4 bug only halfway. Refreshing `pass1` on elapsed time is correct, but resetting `waterfill_phase2_cursor` on every timed refresh creates a new residual-starvation path. The reset is in plan.md:446 and plan.md:472; the current Phase-2 cursor semantics are in queue_service/mod.rs:922 and queue_service/mod.rs:990. With `VISIT_NS = 200_000` in tx/drain/mod.rs:561, the smoke fixture's exact quanta are 2.5K, 25K, 75K, 150K, 225K, 300K, 375K, 450K, 524,288, 524,288 bytes; `iperf-uncapped` is non-exact and not in this selector. Per epoch, `pass1 = 437,500`. Epoch 1 honors `100m`, `1g`, `3g`, `6g`, then the `6g` remainder, leaving `131,000`; `9g` breaks to Phase 2. Actual bytes sent by those small classes are about `250.5 KB`, so only about `374.5 KB` of root budget remains, which is about four Phase-2 visits. If the cursor restarts at the largest queue every 200 us, epochs 1, 2, and 3 all begin `24g -> 21g -> 18g -> 15g`, and `12g`/`9g` stay behind the cut indefinitely. That violates the residual-sharing contract. **The right fix is: time-refresh `pass1`, but do NOT reset the Phase-2 cursor on the elapsed-time refresh path.**

2. [MEDIUM] The plan document is still internally inconsistent and not implementation-ready. It says v5 dropped the old mask path/tests at plan.md:587, but stale v3/v4 mask and `>64` fallback instructions remain at plan.md:518, plan.md:531, and plan.md:761. It also still calls this a "Single hunk" rollback at plan.md:878, which is false for v5.

3. [MEDIUM] The new test coverage still does not pin the actual saturation bug. The timer test at plan.md:592 proves the timestamp branch, and the burn test at plan.md:619 proves single-epoch Phase-2 entry, but neither proves that small queues are re-honored after 2-3 elapsed epochs while Phase 2 succeeds every time. That exact case is what killed v4.

## Answers

1. Time-based refresh is the right mechanism. Time-based refresh plus Phase-2 cursor reset is not.
2. The `pass1 == 0` path is compatible and should stay. If both predicates are true, one refresh is fine.
3. Long idle is fine. One refresh on the next call is correct; do not bank multiple idle epochs.
4. `elapsed == 0` is fine. If time has not advanced, a new waterfill epoch should not appear.
5. The waterfill epoch and lease epoch do not need identical timestamps. Matching duration is enough.
6. "Have Phase 2 decrement `pass1`" is worse. Decrementing by candidate budget overcounts badly on `TX_BATCH_SIZE`-limited visits; decrementing by actual bytes requires post-submit plumbing and rollback handling.
7. New hole in v5: yes, residual exact starvation from resetting the Phase-2 cursor on every timed refresh.
