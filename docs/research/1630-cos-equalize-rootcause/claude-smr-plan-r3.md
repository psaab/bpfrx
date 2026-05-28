# Claude SMR hostile plan-review — #1630 r3

Reviewer role: CoS-scheduler / WFQ / DRR / token-bucket / AF_XDP
multi-worker-shaper domain expert. Hostile by mandate. This is the round
where I check whether the convergence is real or a soft-pass.

**VERDICT: PLAN-READY** (after the 3 Codex r3 minors were folded into
v3.1; I verified each fold against code rather than rubber-stamping).

## Why this is genuinely READY and not a soft-pass

The plan went through a real reframe driven by EVIDENCE, not opinion:
- v1 (multi-worker fragmentation + flat root shaper) was FALSIFIED by
  `park_root=0` telemetry on the live cluster.
- v2 (selector-only DRR) was FALSIFIED by all three r2 reviewers proving
  the lease top-up watermark caps the bucket at ~1-2 frames.
- v3 targets the PROVEN dominant blocker (P1 watermark) + the secondary
  clamp (P2), and r3 confirms rate-safety.

That is the opposite of the SMR-soft-pass failure mode — each round
killed the prior hypothesis with a verified counter-example.

## Independent verification of the r3 minors (Codex)

1. **`max_total_leased` (folded as §7 step 3)**: I confirm the concern is
   real. `compute_shared_cos_lease_config` (shared_cos_lease/mod.rs:712-716)
   sets `max_total_leased = burst/4 .min(max_frame_lease_bytes ×
   active_shards)` with `max_frame_lease_bytes = lease_bytes.max(4096)`.
   `try_bump_outstanding` (the Step-B gate in acquire_v8) refuses grants
   past `max_total_leased`. For 100m with low `active_shards`,
   `max_total_leased` could be < the intended N×MTU bank, defeating the
   watermark raise. The plan now requires raising `max_frame_lease_bytes`
   (or proving active_shards≈6 makes the cap sufficient). Correctly
   folded. NOTE for /engineer: with active_shards=6 and N=8,
   `max_frame_lease_bytes × 6` must be ≥ 8×4096=32KB ⇒ need
   `max_frame_lease_bytes ≥ ~5.5KB`; current is 4096, so even at 6 shards
   the cap is `4096×6=24KB < 32KB` — the raise to `max_frame_lease_bytes`
   IS required, not optional. Good that the plan flags it.

2. **Gate 4 scope (folded)**: correct — transparent
   (`transmit_rate_bytes()==0`, token_bucket.rs:167) and `surplus_sharing`
   exact queues (bypass the lease in Surplus phase, tx_completion.rs:343)
   are legitimately outside the rate-cap assertion. Scoping Gate 4 to
   hard-cap exact guarantee queues is right.

3. **Non-exact vs surplus (folded)**: correct — best-effort q0 / uncapped
   q11 are surplus-path, not non-exact guarantee; the plan no longer
   claims P2 fixes them.

## Residual judgment

- **Rate-safety (the one I most wanted to break)**: I tried to find a
  path where the raised bucket watermark lets a class exceed `rate ×
  elapsed`. There is none for exact queues: the bucket is refilled ONLY
  via `acquire_via_lease` → `acquire_v8`, which is bounded by
  `epoch_total_grant_cap = rate × min(elapsed, 200µs)` (reset each
  rotation) AND `max_total_leased`. The watermark only sets how much of
  an already-rate-metered grant the bucket may HOLD, not the grant rate.
  `consume(sent_bytes)` debits actual bytes. Gate 4 is structurally safe.
  AGY reached the same conclusion independently. CONFIRMED.
- **N sizing is an implementation sweep, not a plan defect**: Gate 1's
  small-four-alone A/B is the right empirical knob to pick N. AGY's
  N=8→16 guidance and 4×MTU visit cap are sensible starting points; the
  plan correctly leaves the exact value to the /engineer sweep.
- **No HA/failover surface, no v8 seqlock change**: confirmed — Path A
  touches token_bucket.rs (watermark) + selectors (visit cap) +
  `compute_shared_cos_lease_config` (max_total_leased sizing). Rejecting
  Path B (rotation carry) keeps the seqlock untouched, which is the right
  risk call (the v8 rotation linearization is fragile per the in-tree
  comments).

## One thing /engineer must NOT lose

The Gate-1 A/B (small-four-alone, currently 69/79/87/86%) is the
canonical pass/fail. If after raising the watermark + max_total_leased
the 100m class still can't reach 95%, the fallback is Path D (reframe the
gate to achievable-ceiling + document) — the plan keeps that escape hatch
honestly. But the mechanism analysis (only loss was the watermark + the
clamp, both now removed) predicts ≥95% is reachable.

This is PLAN-READY. The architecture is correct, rate-safe, scoped, and
the three reviewers converge. Copilot joins at /engineer on the real
code PR.
