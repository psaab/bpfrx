# AGY adversarial plan-review — #1630 r3
# Job: adversarial-review-mppvx6qs-lth0pl
# Verdict: PLAN-READY

VERDICT: PLAN-READY

Full report: agy brain artifact adversarial_review_r3.md. Summary of the 5 focus verdicts:

1. Watermark & rate safety (CONFIRMED): raising the bucket watermark to N x MTU
   resolves P1 by keeping headroom to request the full epoch lease cap. Exact
   queues are refilled EXCLUSIVELY via acquire_via_lease (token_bucket.rs:180-203);
   acquire_v8 strictly enforces epoch_total_grant_cap (reset at rotation,
   mod.rs:1069-1131). Gate 4 holds absolutely — no other refill path exists for
   exact queues.
2. Deficit field NOT needed: queue.hot.tokens does not reset at rotation and
   accumulates the per-visit remainder. A per-visit frame cap in the selectors
   preserves the remainder in the bucket; explicit guarantee_deficit_bytes is
   redundant.
3. Latency CONFIRMED SAFE: TX_BATCH_SIZE=64 x 1500B = 96KB takes 30.72us at 25G
   line rate, negligible vs a single 100m frame's 120us transmission time. No
   head-of-line blocking spike.
4. Non-exact queues FULLY COVERED by the P2 visit-cap fix (refill to buffer_bytes,
   only the selector clamp constrains them). Uncapped q11 bypasses via surplus.
5. Path B rejection HIGHLY CORRECT: Path B alone is mathematically incapable —
   if the watermark stays at 4096, the worker early-returns (token_bucket.rs:188)
   and requests <=1096B, wasting any carried remainder. Adding carry state in the
   rotate_epoch_v8 seqlock tick increases critical-section duration + write
   contention. Reject Path B.

Implementation params recommended: N=8 (32KB) watermark, increment to 16 if 100m
< 95%; per-visit frame cap ~4 x MTU for low-rate classes for tight RR; omit the
deficit counter (rely on queue.hot.tokens).
