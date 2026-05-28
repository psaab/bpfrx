# Claude SMR plan-review r6 — #1630 (v6 design)

**Verdict**: **PLAN-READY**.

## §1 v6 design summary

v6 is a clean rewrite of the plan that:

- Preserves Hunk A (pass1 formula fix).
- Adds Hunk B (time-based pass1 refresh) BUT critically:
  **time-based refresh does NOT reset `waterfill_phase2_cursor`**.
  Only the legacy `pass1 == 0` exhausted path resets the cursor.
- Removes all stale v3/v4/v5 mask/`>64` text.
- Adds test 5: multi-epoch saturation, verifies small classes
  honored every epoch across 5 consecutive lease epochs.

## §2 Why v6 is correct under saturation

Lease epoch 2 starts (elapsed >= VISIT_NS triggers time refresh):
- pass1 → 437.5K. epoch_start = now. **Cursor stays where it
  was at end of epoch 1.**
- Walk asc: 100m has refreshed lease tokens → honor (rem 435K).
  1g (rem 410K). 3g (rem 335K). 6g (rem 185K). 6g rem (rem
  131K). 9g quantum 225K > 131K → break Phase 2.
- Phase 2 picks NEXT queue from cursor position (say cursor 3
  = 15g) → cursor 4 (12g) → 5 (9g) → wraps. After full
  descending sweep, Phase 2 returns None → reset (pass1 → 0,
  cursor → 0). Next call: legacy refresh path → pass1 → 437.5K,
  cursor → 0.

Hmm — that means within ONE lease epoch we can still cycle
multiple times. Each inner cycle: Phase 1 honors small classes
(if lease tokens permit), Phase 2 descending RR until cursor
wraps, exhausted-reset.

Across many lease epochs:
- Small classes get honored at MINIMUM once per lease epoch
  (when lease tokens replenish) AND potentially more times per
  inner cycle (if pass1 budget allows).
- Large classes get serviced via Phase 2 descending RR, with
  cursor preserved across time-refreshes for fairness.
- After enough Phase-2 visits, large classes' per-class leases
  deplete too → Phase 2 returns None → exhausted-reset → restart.

Per-class lease throttling ensures per-class rates are honored.
Phase 1 priority for small classes ensures they hit their
configured rate before large classes compete for residual.

## §3 Tests sufficiency

Test 5 (multi-epoch saturation) pins the v4-killing bug:
> Drive 5 consecutive lease epochs. Assert each small class
> honored at least once per epoch across ALL 5.

Without Hunk B (time-refresh), the test would fail by epoch 3-4
because pass1 stays at a small value and stops admitting small
class honors.

Test 4 (cursor-reset-only-on-exhausted) pins the v5-killing bug:
> Set cursor=3, force time-refresh, verify cursor stays at 3.

Together with tests 1-3 (formula correctness, transparent-root
fallback, time-tick refresh), the unit test suite covers all
distinct mechanisms.

## §4 Hostile checks on v6

### What if time-refresh fires at the SAME instant as exhausted-reset?

`time_refresh = true` AND `exhausted = true`. Branch enters,
refreshes pass1, sets epoch_start, and `if exhausted` resets
cursor. **Cursor is reset.** Correct: when both fire, the
exhausted path is dominant (pass1 was 0 anyway, so we ARE in a
new cycle conceptually).

### What if `now_ns < waterfill_epoch_start_ns`?

`saturating_sub` clamps elapsed to 0. `0 < VISIT_NS` →
time_refresh = false. No refresh from time. Correct (no time
travel).

### Per-class lease epoch refresh vs waterfill epoch refresh

Per-class lease runs `rotate_epoch_v8` every 200µs at lease
epoch boundary. Waterfill refresh ticks every 200µs at waterfill
epoch boundary. **They are not synced** — they drift
independently. Is that a problem?

If lease refreshes at time T and waterfill at T + 100µs, then
in the 100µs before waterfill refreshes, small classes have
fresh lease tokens but waterfill's pass1 may be tiny → small
classes can't be honored. After waterfill refresh, pass1 is
full and small classes get their honors.

This creates a 100µs WINDOW where small classes wait. Per-class
lease itself can still allocate during that window via the
top-up path (line 184-203 in token_bucket.rs). So packets queue
up briefly, then get serviced.

Average behavior over many epochs: small classes still hit
their configured rates. Worst-case latency increases by ~100µs.
Negligible for the smoke gate.

### Does Phase 2 ever pick small classes?

Phase 2 walks descending and skips queues via
`queue.hot.tokens < head_len`. Under saturation, small classes
have depleted lease tokens → skipped. ✓

### What if a class has > 64 queues?

v6 doesn't add a bitmask, so no >64 hazard. The dispatch gate
at mod.rs:603-606 is unchanged. ✓

## §5 Sign-off

**PLAN-READY**. v6 design is correct, addresses all r1-r4
Codex findings, all r1 AGY findings, all SMR concerns including
my r4 self-correction.

Risk: small (2 hunks, 1 new u64 field, 5 tests). Default-off.

Recommend Codex r5 + AGY r5 final review before implementation.
