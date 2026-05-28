# Claude SMR plan-review r3 — #1630

**Verdict**: **PLAN-READY**.

## §1 What changed in v3 vs v2

v3 addresses Codex r2 PLAN-NEEDS-MAJOR with these substantive changes:

1. **Codex r2 #2 (queue_idx >= 64 release-build hole)**:
   replaced `debug_assert!` with HARD RUNTIME FALLBACK at the
   dispatch gate. Configurations with > 64 exact queues fall
   back to legacy RR. Belt-and-braces `debug_assert!` retained.

2. **Codex r2 #1 (test 5 underspecified)**: §11.5 reworked
   with explicit concrete arithmetic. Critically, while working
   through the test arithmetic I uncovered that the persistent
   mask must ALSO gate the Phase-1 ascending walk (otherwise
   small queues are re-picked repeatedly even with the mask).
   The mask design is now: set on Phase-1 honor, checked by BOTH
   Phase-1 ascending walk AND Phase-2 descending walk. Cleared
   only on pass1 refill.

3. **Codex r2 #3 (Phase-2 proportional contract untested)**:
   added §11.7 — multi-epoch tally test asserting Phase-2
   byte distribution ratio matches rate ratio within ±10%.

4. **Codex r2 #4 (Pass B "All 3 gates PASS")**: corrected
   wording to "Gate 1 + Gate 3 PASS; Gate 2 logged not blocking".

5. **New test 8** for the > 64 fallback path.

## §2 Why v3 is PLAN-READY

The plan has been hardened through three independent
hostile-reviewer rounds. The key insight from Codex r2 — that
the dead-local `honored_mask` plus the small-pass1 budget create
a worse bug than just Phase-2 over-servicing (Phase-1 over-
servicing of small queues) — is now resolved. The persistent
mask gates BOTH walks, ensuring each queue gets exactly one
Phase-1 honor per epoch, and large queues get the Phase-2
descending residual.

## §3 Hostile checks (round 3)

### Does the mask-gates-Phase-1-walk change cause a new bug?

Without the change: ascending walk re-picks the smallest runnable
queue on every call until it depletes. Per-class lease throttles
it naturally. So "re-picking" was naturally bounded.

With the change: ascending walk advances strictly through the
sorted list, one honor per queue per epoch. Each queue's
candidate_budget = its quantum (rate × VISIT_NS) — already
size-appropriate. Per-class lease still throttles independently.

**No new bug.** The change just ENFORCES the documented contract:
"Phase 1 honours small-rate exact classes ascending by R_i up to
fraction × cap" — emphasis on "ascending", which means each queue
honored once per epoch in ascending order.

### Test 5 arithmetic check (concrete numbers)

After v3's mask change, the test becomes deterministic regardless
of `pass1_remaining` value:
- 4 selections in Phase-1, one per queue.
- 5th selection: ascending walk, all 4 mask bits set → skip all,
  fall through to Phase-2 descending walk, also skip all → return
  `None`. Pass1 NOT yet refilled (still > 0).
- 6th selection: same — `None`. Pass1 still > 0 since we returned
  `None` without selecting and didn't decrement.

Actually re-reading: on the 5th call, the for-loop walks ascending,
all queues skipped, exits loop normally. Phase-2 cursor walk: same.
The function returns `None` without resetting pass1 (lines 1004-1005
only run when Phase-2 walks find no candidate within the loop body,
i.e., they HIT the start_phase2 boundary). Currently that reset
clears pass1 to 0, triggering refill on next call. So 6th call
refills pass1 and walks ascending afresh.

That's the correct epoch boundary. ✓

### >64 fallback safety

The fallback is at the dispatch gate (mod.rs:603-614), BEFORE
the waterfill function is called. So even if a Junos config
somehow gets 65+ exact queues (e.g., future hardware change),
the system gracefully degrades to legacy RR. No SIGABRT, no
silent incorrect behavior. ✓

### Does the additional Phase-1 mask check break legacy proportional?

The dispatch gate (mod.rs:603-606) routes proportional mode to
the legacy RR selector at line 619+. The waterfill is GuaranteeRate-only.
Mask gate only matters when waterfill runs. Proportional mode is
bit-for-bit preserved. ✓

## §4 Sign-off

**PLAN-READY**. All Codex r1 + r2 findings addressed. AGY r1
findings addressed. SMR concerns addressed. Phase-1 ascending-walk
mask gate is the right way to enforce "each queue honored once per
epoch" and makes the implementation MATCH the documented contract.
The fallback for >64 queues makes the design release-safe.

Risk surface remains small: opt-in mode (default off), single
arithmetic change in pass1 formula, single u64 field added,
2 small mask-check additions to ascending + descending walks.

Recommend dispatching Codex r3 + AGY r3 for final confirmation.
3-of-3 PLAN-READY → proceed to implementation.
