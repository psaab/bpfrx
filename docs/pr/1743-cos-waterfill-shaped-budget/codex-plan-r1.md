# Codex plan review r1 (task-mpvav706-nx3l72) — PLAN-NEEDS-MINOR

Root cause holds against master e4556085a. All 7 hostile checks pass.

Minor:
1. Fixture math: 10 exact classes not 11; quantum_sum (with 512 KiB
   clamp) = 2,651,076 B; legacy x0.7 = 1,855,753 B (not ~1.91 MB).
   Ratio 1,855,753/437,500 = 4.24x holds.
2. Add explicit undersubscribed shaped-root (shaper > sum R_i) unit test.

Hunk A units correct (shaping_rate_bytes is bytes/sec, matches
cos_guarantee_quantum_bytes). Hunk B does not over-charge 0.7 fixture
(honors {100m,1g,3g,6g}, breaks at 9g). Hunk C consistent with #1732
(bits clear before Phase-1 re-honors; no double-serve at N->N+1).
HA portability correct. Mandatory live gate stands.
