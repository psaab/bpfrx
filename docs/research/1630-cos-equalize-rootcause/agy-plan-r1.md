# AGY adversarial plan-review — #1630 r1
# Job: adversarial-review-mppvapja-8sjwm6
# Verdict: PLAN-NEEDS-MAJOR-REWORK
# (full text captured from agy_result; key results below)

VERDICT: PLAN-NEEDS-MAJOR-REWORK

Validates the multi-worker ownership fragmentation root cause.

KEY MECHANICAL PROOF (resolves Q1/M2): cos_guarantee_quantum_bytes =
rate × 200us clamped [1500, 512K]. For the 100 Mbps class quantum =
2500 B. Drain (drain.rs:69-72) breaks when remaining_secondary < len:
frame1 (1500B) ok -> remaining 1000B; frame2 (1500B) > 1000B -> break.
The 1000B is wasted (no carry-forward; pass1_remaining recomputed each
epoch; v8 epoch_total_grant_cap also resets each 200us,
rotate_epoch_v8.rs:220-222). Max efficiency oscillates by rate:
  100 Mbps (q=2500):  1 frame -> 60.0%
  200 Mbps (q=5000):  3 frames -> 90.0%
  300 Mbps (q=7500):  5 frames -> 100.0%
  700 Mbps (q=17500): 11 frames -> 94.2%
  1 Gbps  (q=25000):  16 frames -> 96.0%
=> Gate 1 (>=95% of CONFIGURED shape) is MATHEMATICALLY IMPOSSIBLE for
the 100m class under 1500B MTU. Gate must become ">=95% of the
MTU-clamped quantum-efficiency ceiling".

Q2: one core handles 10.1G @ 1500B MTU (~840 Kpps) easily, but at 64B
frames 10.1G ~= 15 Mpps / 25G ~= 37 Mpps -> single owner CPU-bound.
Add a CPU-bottleneck gate (10G @ 64B, no drops, <80% CPU).

Q3: v8 lease fair-share does NOT break under single-owner (sole owner ->
my_share == cap). Confirmed via ensure_v8_lease_attached
token_bucket.rs:129-149.

Q5: queue_service/mod.rs:807 Vec clone is on the per-packet TX hot path;
single-owner amplifies. honored_mask (line 806) is dead — Phase 1
returns immediately on selection (line 907), so mask is always 0 when
Phase 2 runs; the line 938 skip-honored check is dead code. MUST fix
before Path 2.

Q4: do NOT silently trigger single-owner from `guarantee-rate`; use an
explicit `guarantee-rate { single-owner; }` sub-knob to avoid regressing
existing multi-worker deployments on upgrade.

Recommendation: Path 2 approved as opt-in ONLY after: revise gate to
MTU-ceiling basis, add CPU-bottleneck gate, eliminate hot-path alloc +
dead honored_mask, explicit single-owner knob.
