# AGY adversarial plan review r1 (adversarial-review-mpvavgvw-04ia5f) — PLAN-READY

Root-cause bit-for-bit correct vs master. All 7 hostile checks pass,
including the N->N+1 double-serve trace (impossible: Phase-1 runs
first every call, re-sets honored bits before Phase-2). Hunk A u128
math overflow-safe. Undersubscribed case correct.

RISK-1 (substantive): if operator sets a tiny-positive fraction,
pass1 = floor(cap*frac) = 0 -> exhausted true every call -> refill +
cursor-reset every call -> Phase-2 starves from index 0. Mitigation:
clamp pass1 to >= 1 (or QUANTUM_MIN) when frac > 0, OR guard the
cursor reset against pass1==0 thrash.

RISK-2 (minor): idle-path refill thrash (return None resets pass1=0,
next call refills) — extremely low cost; acceptable.
