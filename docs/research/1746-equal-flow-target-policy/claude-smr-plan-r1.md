# Claude SMR hostile plan-review r1 — #1746

Domain SMR (CoS/QoS scheduling) + CPU/cache + SW-design pass. Hostile by
default. Adjudicates the Codex (PLAN-NEEDS-MAJOR) vs AGY (PLAN-KILL)
divergence.

## What both other reviewers got right (confirmed against source)

- **The naming/back-compat knot is real and unresolved.** Both Codex
  (`plan.md:264-280`, `plan.md:421-426`) and AGY flag the same defect: the
  current default math is `candidate_target.min(per_flow)`
  (`publish_equal_flow_epoch_v8.rs:129`), NOT
  `scheduler_rate/total_flows`, yet the plan names a value `ideal-share`
  and at one point proposes making `ideal-share` mean the literal share —
  which would make the unset default (`""`) and the explicit
  `ideal-share` value DIFFER. Confirmed defect. r1's §5.2/§9 is
  self-contradictory.
- **The §10 model is numerically inconsistent.** `{1,2,3,4}` sums to 10,
  not the `-P12` it claims (`plan.md:172-175` vs `plan.md:193-194`); the
  baseline "16-17 G" line (`plan.md:452`) contradicts the model's own
  12.42 G sum. Both reviewers independently recomputed the SAME corrected
  numbers I did: baseline CoV 27.7%, clip-to-mean T=1.242 G → CoV 16.7%
  (40% relative reduction) at 12% aggregate cost; clip-to-slowest → 0%
  CoV at 30% aggregate cost. The plan's prose is wrong; the corrected
  numbers are agreed.

## Where AGY overreaches (the kill is not justified AS STATED)

AGY's PLAN-KILL rests on two claims, one weak and one factually wrong:

1. **"Footgun → kill" is an argument against a DEFAULT, not against an
   opt-in knob.** AGY: "Any target-policy knob is a dangerous operational
   footgun ... false sense of fairness." But the plan's §3/§6 keep the
   default byte-unchanged; clip-to-mean/clip-to-slowest are strictly
   opt-in with a commit-check WARNING documenting the aggregate cost. By
   AGY's own numbers clip-to-mean delivers a **40% relative CoV
   reduction** (27.7%→16.6%) at a **12% aggregate cost** — that is a
   legitimate, quantified jitter-vs-throughput trade an operator with a
   latency/jitter-sensitive class might rationally choose. "An operator
   could misuse it" is not a counter-example to "an operator could use
   it"; per `feedback_junos_feature_parity` we do not delete/refuse
   operator-selectable knobs because an audit dislikes one setting.
2. **AGY's factual error:** it asserts "the default `ideal-share` is
   mathematically identical to `clip-to-slowest`" as a kill reason. That
   identity is NOT a property of the design — it is precisely the
   unresolved Q1 naming choice. Under the corrected resolution (below)
   the three policies are genuinely distinct. AGY killed partly on a
   defect that is fixable by naming, not a structural impossibility.
   Per the PLAN-KILL evidence bar, an unresolved-naming defect is
   NEEDS-MAJOR, not KILL.

AGY's #1748 comparison (rebalance → +101% for starved flows, +40.9%
aggregate, 0% CoV) is correct and important — but it argues #1748 is
BETTER, not that #1746 is worthless. They are not mutually exclusive:
#1748 is multi-month, repeatedly plan-killed hardware-steering work
(#937/#840/#1211/#1693/#1742); clip-to-mean is a ~1-day opt-in math
branch. Shipping the cheap partial win does not foreclose the expensive
full win.

## Where I am MORE hostile than Codex (additional findings)

- **F1 (severity: MAJOR — could justify kill on its own):** clip-to-mean
  in the *live* regime may be a near-no-op too, for the SAME reason the
  current target is. The §10 model assumes the sampler cleanly captures
  the heavy (4-flow, 0.87 G) AND light (1-flow, 1.81 G) workers in one
  epoch. But the #1745 fail-open guards
  (`publish_equal_flow_epoch_v8.rs:62-72, 122-128`:
  `UnsampledActiveWorker`, `LowDemandWorker`) plus the 2-epoch
  valid-streak gate frequently collapse the sampled set to a SUBSET, and
  the EWMA (`smoothed = (3·prev + candidate)/4`) lags. If the heavy
  worker is the one that fails the `prev_grant×5 < prior_share×4`
  low-demand check or is intermittently unsampled, `Σgrants/Σflows`
  computes over the light subset and lands ABOVE 1.81 G → clips nothing,
  exactly the observed live no-op. **The plan MUST require the /engineer
  smoke to measure clip-to-mean's ACTUAL live CoV, not just the
  arithmetic ideal, and gate ship on a measured material win (Q3).**
  Without that gate, this could ship a third no-op.
- **F2 (MINOR):** §5.3 proposes a label on the existing target gauge as
  one option. Codex correctly warns relabeling changes series identity;
  the plan should COMMIT to the sibling info-metric, not list relabel as
  an option.
- **F3 (MINOR):** `matches_config_v8` must include the policy
  (`plan.md` §11 risk notes this) — confirm the test asserts a live
  policy change rebuilds the lease, since a stale lease silently keeps
  the old policy (`coordinator/mod.rs:1526-1537` reuse path).

## Required revisions for PLAN-READY

1. **Resolve the naming knot definitively (Q1/Q4).** Adopt: unset
   default (`""`) ≡ named value that is byte-identical to today's `min`
   math. Name that value to MATCH its math. Since today's math is "clip
   every flow to the slowest sampled per-flow rate," the honest name for
   the default is **`slowest`** (or `clip-to-slowest`). Then:
   `ideal-share` = literal `scheduler_rate/total_active_flows` (the
   documented no-op, kept only for operators who want the Junos-style
   nominal share); `mean` = `Σgrants/Σflows`. Default = `slowest` =
   byte-unchanged. Three genuinely distinct targets, no "" vs named
   divergence. Drop the contradictory "IdealShare is the default"
   framing.
2. **Replace §10 with the corrected, internally consistent model**
   (observed-band model = 10 flows matching the exact #1745 banding;
   note the nominal -P12 with 2 colliding flows separately). Numbers:
   baseline 12.42 G / CoV 27.7%; clip-to-mean T=1.242 G → 10.93 G /
   16.7% (−12% agg, −40% rel CoV); clip-to-slowest 8.70 G / ~0% (−30%
   agg). State the 0.87 G floor is identical across ALL policies.
3. **Add the F1 live-measurement gate to §8.2 + §9 Q3**: ship clip-to-
   mean only if the /engineer smoke shows a measured material CoV
   reduction; if it is a live no-op (sample-set collapse), PLAN-KILL at
   /engineer time. This converts AGY's legitimate skepticism into an
   explicit ship gate rather than a blanket kill.
4. Commit to the sibling info-metric (F2); add the lease-rebuild test
   (F3).

## Verdict

These are all addressable by editing the plan doc (no design
impossibility). AGY's kill is not supported by a structural
counter-example — it is a default-policy objection that the opt-in design
+ the F1 ship-gate already answer, plus a fixable naming defect.

VERDICT: PLAN-NEEDS-MAJOR (converging toward PLAN-READY after the four
revisions; NOT PLAN-KILL — clip-to-mean's 40% relative CoV win at 12%
aggregate cost is a real, operator-selectable trade, gated on a live
measurement so it cannot ship as a third no-op).
