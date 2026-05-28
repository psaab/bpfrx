# AGY adversarial plan-review — #1630 r2
# Job: adversarial-review-mppvn7jw-khzbbp
# Verdict: PLAN-NEEDS-MAJOR (Path A dead-on-arrival as written)

VERDICT: PLAN-NEEDS-MAJOR

v2 root cause (quantum-MTU waste, park_root=0 confirms not root) is
CORRECT, but Path A is dead on arrival.

Q1 (epoch-by-epoch trace): maybe_top_up_cos_queue_lease
(token_bucket.rs:184-195) clamps the top-up request to
lease_bytes.saturating_sub(tokens) where lease_bytes = rate x 200us
(=2500B for 100m, floored at tx_frame_capacity=4096). So queue.hot.tokens
can NEVER exceed the watermark. Steady state: each epoch grants only
~1500B (=2500-1000 carried), sends 1 frame, carries 1000B; the unspent
~1000B of lease cap is discarded at each epoch rotation
(rotate_epoch_v8.rs:56-65 swap-to-zero, no carry). Result: permanently
stuck at 1500B/200us = 60 Mbps = 60%. A DRR deficit on the selector
secondary_budget cannot help because secondary_budget = deficit.min(tokens)
and tokens <= watermark. => Path A alone insufficient.
FIX must EITHER (1) carry the lease cap remainder across epoch rotations
in rotate_epoch_v8, OR (2) raise lease_bytes/watermark in token_bucket.rs
to a small multiple of the quantum (e.g. lease_bytes + N x MTU) so the
bucket can bank >=2 frames and average to 100% rate.

Q2: Path B also fails for exact queues — tokens still capped at
watermark 2500B; can't reach 3000B for 2 frames in one visit. park_queue
high because after sending 1 frame tokens=1000<1500=head_len ->
ParkReason::QueueTokenStarvation, runnable=false until wheel wakeup.

Q3: classic DRR carry-forward WILL regress RR fairness. A 24g class
(quantum clamped 512K) starved 4 visits accrues 2MB deficit -> 1365
frames in one drain pass -> exhausts TX ring, head-of-line blocks all
other queues. MANDATORY per-visit burst cap (e.g. 64KB/~42 frames) or
spend-over-multiple-visits.

Q5: non-exact guarantee queues ALSO hit the 60% ceiling: refill_cos_tokens
accumulates tokens to burst ceiling (96KB) but the selector clamps
guarantee_budget to the quantum (2500B) every visit -> still 1 frame/visit
-> 60%; excess refilled tokens silently discarded at burst ceiling. The
bug is structural across BOTH selectors (the .min(quantum) clamp), plus
the exact-only watermark blocker on top.

Rollback: dual change (DRR + lease/token watermark) widens surface in
queue_service + token_bucket; keep a clean revert path.
