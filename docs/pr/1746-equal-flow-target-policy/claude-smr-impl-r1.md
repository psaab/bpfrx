# Claude SMR hostile implementation review — PR #1867, round 1

Reviewer: Claude (domain SMR: CoS scheduling / CPU arch / SW design),
hostile pass per `feedback_triple_review_includes_claude_smr`.
Head reviewed: `dae961b138a0` (+ the hierarchical-AST test added during
this review).

## Verdict: MERGE-READY (no Critical/High; 2 documented observations, 1 test added during review)

## What I verified by reading code (not the PR body)

1. **Slowest byte-identity.** The publisher loop body is unchanged for
   all guards (`ZeroTarget` per-worker, `LowDemandWorker`,
   `UnsampledActiveWorker` prior-share, the `min` fold at
   `publish_equal_flow_epoch_v8.rs`); the policy `match` selects the
   identical `min` value for `Slowest`, and the post-loop
   `u64::MAX || 0 → ZeroTarget` check is unchanged. The two added
   saturating adds are dead weight on the Slowest arm (computed, not
   read) — behaviorally inert. `new_v8_with_rate_mode` keeps its
   signature and delegates with `Slowest`, so every pre-PR constructor
   call is byte-unchanged, including `new_v8`. The Go snapshot field is
   `omitempty` and the Rust field `skip_serializing_if`, so the
   unset-config wire is byte-identical in both directions — pinned by
   the untouched `protocol_wire_v1.json` fixture passing.
2. **Stale-lease.** `matches_config_v8` now takes the policy and
   compares `v8.equal_flow_target_policy`; the coordinator threads
   `queue.equal_flow_target_policy` into both the match and the
   constructor. forwarding_build gates the policy on
   `equal_flow_enforcement`, so CstructDefault queues always carry
   `Slowest` and cannot spuriously rebuild. Pinned by the new
   coordinator reuse/rebuild test.
3. **Wire contract both sides** (per
   `feedback_wire_protocol_both_sides`): grepped BOTH `protocol.go`
   and `protocol/cos.rs` — tags `equal_flow_target_policy` match
   byte-for-byte on snapshot and status; legacy decode defaults pinned
   by the Rust round-trip test.
4. **Dual AST shapes.** Flat-set covered by the compile test; I probed
   the hierarchical shape live during review
   (`equal-flow-target-policy mean;` → "mean") and added
   `TestEqualFlowTargetPolicyCompileHierarchical` to pin it. Same
   `nodeVal` path as `priority`.
5. **Hot path.** The policy match + sums run once per rotation
   (≥200 µs) in EqualFlowSuppress mode only; the CstructDefault
   rotation path and the per-packet path are untouched. No allocation.
6. **Metrics.** Info metric registered in Describe; const-metric per
   collect so a policy change atomically swaps series. Empty-label
   guard prevents a mixed-version (old Rust helper) empty `policy`
   series.

## Required worked trace: slow-flow join/leave dynamics under `mean`

Setup: shaped class, capacity-limited; workers w0..w3 carry {4,3,2,1}
flows; w0 saturates at 0.87 G/flow; the rest can do ~1.6-1.8 G/flow.

**Steady state (does `mean` ratchet or oscillate?).** Let T_n be the
enforced target. Clipped workers grant `T_n × f_i`; the uncapped slow
worker grants its achieved rate. Then
`T_{n+1} = (g_slow + T_n·Σf_fast)/Σf = 0.348 + 0.6·T_n` (this
example), a geometric contraction toward the fixed point
`T* = g_slow/f_slow = 0.87 G` — i.e. **`mean` drifts toward
clip-to-slowest under sustained full clipping**, NOT toward the static
1.242 G of the plan's one-shot model. HOWEVER the drift is bounded by
the pre-existing `LowDemandWorker` governor: as soon as clipping pushes
any sampled worker's grant below 80 % of its fair share
(`prev_grant×5 < prior_share×4`), the publisher FAILS OPEN, resets the
streak + smoothed target, and re-measures unclipped rates for ≥2
epochs before re-enforcing. The result is a bounded enforcement duty
cycle (period a few 200 µs epochs), not a ratchet to the floor and not
starvation: no flow is ever capped below the slowest achieved per-flow
band, and every fail-open epoch restores full fair shares. This
limit-cycle dynamic is IDENTICAL in kind to the shipped `slowest`
policy (which jumps to the floor in one epoch and trips the same
governor); the knob does not introduce it. The live F1 data confirms
the system-level outcome: large cap-hit deltas with ~zero aggregate
cost and reduced CoV — the governor converts the naive model's −12 %/
−30 % aggregate loss into intermittent top-band trimming.

**Slow flow JOINS (w0 4→5 flows):** the acquire-time sticky-max sample
captures the new count next epoch; Σf grows, T drops by ≤ the
contraction factor per epoch, EWMA (×3+1)/4 slows the step to ~25 % per
epoch. No discontinuity; worst case is one over-clipped epoch on fast
workers, bounded by the governor above.

**Slow flow LEAVES (w0 4→3):** Σf shrinks, per-flow grant on w0 rises,
T rises monotonically toward the new mean; rising targets can only
unclip — no transient starvation window. If w0 empties entirely, it
leaves the sampled set (idle-at-rotation exclusion, #1745) and T jumps
to the mean of the remaining workers; if that leaves <2 sampled
workers, the publisher fails open — safe.

## Observations (documented, not blocking)

- **O1 (`ideal-share` units).** `nominal_epoch_bytes` assumes exactly
  one `EPOCH_DURATION_NS` of budget, while a lagged rotation grants
  `rate × elapsed` (up to K epochs). Under visit lag the ideal-share
  target is conservative (lower than the true nominal share for the
  elapsed window) → more clipping than nominal, bounded by the same
  LowDemandWorker governor. Acceptable for a policy documented as
  "nominal-share semantics"; noted in the F1 doc caveat 2 (live
  ideal-share is not a strict no-op).
- **O2 (`mean` drift vs plan model).** The plan's §4 one-shot model
  predicts a static 1.242 G mean target; the closed-loop fixed point is
  the slowest band, bounded by the fail-open governor (trace above).
  The operator-visible contract ("clips lucky outliers toward the
  mean, keeps more aggregate than slowest") is still what the live F1
  cells measured; the docs table is labeled as a model and the
  measured table is shipped alongside it.

## Measurement honesty check

The F1 PASS is computed on cell means (52 % rel CoV, −5 % cost) and
re-computed excluding the OFF-cell RSS outlier (30.2 % rel, −3 %) —
still passing, disclosed as gate-edge. 12-stream validation present on
every rep; enforcement proven by counter deltas, not by the
(post-traffic, correctly zero) `enforced` gauge. I attempted to break
the claim that `mean` enforces (vs silently failing open): the
per-cell `xpf_userspace_cos_equal_flow_target_policy{policy="mean"}`
series plus cap-hit deltas in the same scrape pair close that hole.
