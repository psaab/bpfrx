# Claude SMR hostile implementation review — PR #1867, round 2

Head reviewed: `bf7014bd5` (post Codex-r1 fixes + supplementary matrix).

## Verdict: MERGE-READY

## Re-verification of the r1-fix code (hostile pass)

1. **Reorder neutrality (Codex r1 F1 fix).** The moved block in
   `rotate_epoch_v8.rs` reads `self.config.rate_bytes`, `now_ns`,
   `start` and reads/writes `epoch_carry_bytes`. I walked every
   statement between the block's old position (post-STEP-5) and its new
   position (pre-publish): the equal-flow branch, the bypass-grace
   STEP 4/5 logic, and `total_flows` read none of
   `epoch_carry_bytes`/`new_cap` before the move. All of it executes
   inside the single-writer ODD seqlock section, so external readers
   cannot observe intermediate ordering. Identical values are stored to
   `epoch_total_grant_cap` at the unchanged location. The ONLY
   behavioral delta is the intended one: the IdealShare numerator is
   now `new_cap`. `CstructDefault` rotations execute the same
   instructions in a different order with identical results —
   byte-unchanged outputs.
2. **Lag semantics.** Post-stall carry bursts make `new_cap` spike up
   to the documented `(2K−1)·rate·EPOCH` bound; the IdealShare target
   spikes proportionally and the cap consumer is gated by the same
   budget, so target and budget scale together (the r1 defect was
   exactly that they did not). EWMA mixing of differently-sized epoch
   windows is the same pre-existing dynamic the grant-based candidates
   already have. The new lagged test pins regime-1 math precisely
   (3-epoch lag → 6000 candidate → EWMA 3000 → cap 12000) and the
   prediction matched on first run — the model and code agree.
3. **Worked-trace consistency.** The r1 SMR trace (mean's closed-loop
   fixed point = slowest band, bounded by the `LowDemandWorker`
   fail-open governor) is now empirically visible in the supplementary
   cells: near-floor baselines show the enforcement duty cycle ADDING
   variance (+5-6 CoV points) at 4-8 % aggregate cost — exactly the
   "governor limit cycle perturbs balanced flows" prediction.

## Judgment on the mixed measurement disposition

The supplementary cells weaken the headline but do not flip my verdict:

- The kill arm of the F1 gate was written against the live-no-op
  failure mode (sample-set collapse); enforcement deltas in every cell
  exclude it decisively.
- `mean` wins exactly in the regime the issue exists for (chronic
  high-CoV skew: 52 % relative) and hurts where NO cap policy can help
  (near the structural floor). That hazard profile is not new: the
  already-shipped `slowest` default (#1304/#1745) has the same
  one-directional-cap structure and the same governor dynamics. The
  knob adds operator choice within an existing opt-in feature; it does
  not create a new hazard class.
- Defense-in-depth for the footgun: default-OFF feature, explicit
  non-work-conserving commit warning on `slowest`/`mean`, regime
  guidance in `docs/cos-traffic-shaping.md`, and the honest
  measurement doc. This matches `feedback_junos_feature_parity` (do
  not strip operator knobs because one setting can be misused — make
  the semantics explicit instead).

Residual honest position: if reviewers prefer to gate `mean` harder
(e.g. require an additional live signal before enforcement), that is a
follow-up issue, not a blocker for an opt-in knob with documented
regime guidance.
