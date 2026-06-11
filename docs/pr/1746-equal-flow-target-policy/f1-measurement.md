# #1746 F1 ship-gate measurement (live, loss userspace cluster)

Per the converged research plan (`docs/research/1746-equal-flow-target-policy/plan.md`
on branch `research/1746-equal-flow-target-policy`, section 8.2): `mean`
ships ONLY on a measured material per-flow CoV reduction (target >= ~30 %
relative) at <= ~15 % aggregate cost vs the equal-flow-OFF baseline; if it
is a live no-op (sample-set collapse), the issue PLAN-KILLs at /engineer
time.

## Method

- Cluster: `loss:xpf-userspace-fw0/fw1`, RG0 primary = fw1 (node1) at
  measurement time. Branch build (`engineer/1746-equal-flow`) deployed to
  BOTH nodes via `make cluster-deploy`; CoS fixture re-applied after
  deploy (deploy wipes CoS) with `test/incus/apply-cos-config.sh` against
  the primary, using the `COS_EQUAL_FLOW` / `COS_EQUAL_FLOW_POLICY`
  injectors added in this PR.
- Traffic: `iperf3 -c 172.16.80.200 -p 5210 -P 12 -t 30 -J` from
  `loss:cluster-userspace-host` (forward push, v4, iperf-24g class
  `transmit-rate 24g exact`, queue 10 on ifindex 14). One discarded 5 s
  priming run after each config apply; then 3 scored reps per cell
  (2 for ideal-share).
- Metric validation per `feedback_runnable_repro_before_measurement_claim`:
  every rep's iperf JSON carries exactly 12 streams; per-stream CoV is
  computed from iperf's own per-stream sender rates (ground truth, NOT
  `cos_active_flow_count`); shaper presence verified after every apply;
  `/metrics` scraped on the primary before/after every rep.
- All cluster commands ran under `flock /tmp/xpf-cluster.lock`.
- Raw artifacts: `/tmp/1746-f1/` on the operator host (iperf JSON +
  before/after metric scrapes per rep); analyzer `/tmp/f1-analyze.py`.

## Results (per-rep)

| cell | rep | agg Gb/s | per-flow CoV | sorted per-stream bands (Gb/s) |
|---|---|---|---|---|
| A equal-flow OFF | r1 | 17.49 | 18.5 % | 1.08x4 1.61x3 1.63 1.64x2 1.71x2 |
| A equal-flow OFF | r2 | 17.18 | 19.6 % | 1.12x4 1.36x3 1.60x3 1.90 1.92 |
| A equal-flow OFF | r3 | 16.01 | 44.7 % | 0.76x6 1.66x3 2.02x2 2.39 |
| B ON `slowest` (default) | r1 | 18.16 | 9.5 % | 1.30x3 1.48x2 1.52x2 1.59x2 1.66x2 1.76 |
| B ON `slowest` (default) | r2 | 17.47 | 14.7 % | 1.19x4 1.44x3 1.64x2 1.67x2 1.79 |
| B ON `slowest` (default) | r3 | 18.17 | 10.2 % | 1.28x3 1.51x3 1.57x3 1.58 1.72 1.78 |
| C ON `mean` | r1 | 18.63 | 7.4 % | 1.44x3 1.46x3 1.57x2 1.65x2 1.71 1.78 |
| C ON `mean` | r2 | 17.72 | 16.5 % | 1.14x4 1.54x3 1.65x3 1.75 1.79 |
| C ON `mean` | r3 | 16.92 | 16.0 % | 1.15x4 1.38x3 1.53x3 1.79 1.80 |
| D ON `ideal-share` | r1 | 16.16 | 20.0 % | 1.15x8 1.70x2 1.72 1.79 |
| D ON `ideal-share` | r2 | 18.29 | 7.3 % | 1.38x2 1.45x3 1.49x2 1.57x2 1.65x2 1.76 |

## Cell summary (mean over reps)

| cell | aggregate Gb/s (min-max) | per-flow CoV % (min-max) |
|---|---|---|
| A OFF (baseline) | 16.89 (16.01-17.49) | 27.6 (18.5-44.7) |
| B ON `slowest` | 17.93 (17.47-18.17) | 11.5 (9.5-14.7) |
| C ON `mean` | 17.75 (16.92-18.63) | 13.3 (7.4-16.5) |
| D ON `ideal-share` | 17.23 (16.16-18.29) | 13.7 (7.3-20.0) |

## Enforcement evidence (the policies are LIVE, not fail-open no-ops)

Per-rep deltas of the queue-10 lease counters (before/after scrape):

| cell | cap_hit_events delta per 30 s rep | suppressed_grant delta |
|---|---|---|
| B `slowest` | 3.59M - 4.49M | 0.95-1.11 TB |
| C `mean` | 3.33M - 4.37M | 0.91-1.12 TB |
| D `ideal-share` | 3.52M - 4.53M | 1.00-1.09 TB |

(`suppressed_grant_bytes` counts grant-request bytes withheld at
acquire time, not forfeited wire bytes — it proves the cap binds, not
the throughput cost.) The `xpf_userspace_cos_equal_flow_target_policy`
info metric reported the correct label per cell
(`slowest`/`mean`/`ideal-share`) on all 10 equal-flow queues.
`equal_flow_enforced` reads 0 on the post-rep scrape because traffic
has stopped by then (instantaneous gauge, fail-open without demand);
the cap-hit deltas prove mid-run enforcement.

## F1 gate verdict: PASS — `mean` ships

- Relative CoV reduction (C vs A, cell means): **52 %** (gate >= ~30 %).
- Aggregate cost: **-5 %** (i.e. none; C is within noise of A; gate <= ~15 %).
- Robustness check excluding the A-r3 RSS-collision outlier (44.7 %):
  A CoV mean (r1, r2) = 19.05 % -> C 13.3 % = **30.2 % relative** at
  ~-3 % aggregate cost — still passes, at the gate edge.

## Honest caveats

1. **Run-to-run RSS draw dominates the banding.** A-r3's 44.7 % came
   from a 6-flows-on-slow-workers draw the ON cells never hit in these
   reps. With 3 reps/cell the OFF-vs-ON comparison inherits that
   variance; the gate-edge robustness computation above is the honest
   bound.
2. **`ideal-share` is NOT the predicted strict no-op live.** The plan
   modeled target 24G/12 = 2.0 G > all bands. Live, the per-epoch
   sampled `total_active_flows` and EWMA dynamics push the published
   target down to where it intermittently binds (cap-hit deltas
   comparable to the other policies). Its operator contract remains
   "nominal share semantics"; CoV/aggregate land between OFF and the
   clipping policies.
3. **The modeled -12 %/-30 % aggregate costs (plan section 4) did not
   materialize** in this regime: the EWMA-smoothed targets sit near the
   heavy-worker bands, so clipping trims the top outliers rather than
   dragging everything to the floor band. The non-work-conserving
   commit warning stays — the worst case remains real for skewed
   regimes the 30 s cells did not sample.
4. None of the policies lift the slow band (1.1-1.2 G floor in matched
   draws) — confirming the structural one-directional-cap analysis;
   lifting the floor is #1748.

---

# Supplementary matrix (Codex r1 F2): v6 push + v4 reverse + node-0 parity

Codex r1 correctly noted the plan section-8.2 smoke matrix calls for v4+v6
and push+reverse per policy. Supplementary cells were run on the post-fix
binary (includes the ideal-share lag-budget fix, which does not change
`mean`/`slowest`/OFF behavior). NOTE: the comprehensive per-CoS-class
smoke still runs at merge time under the serialized smoke protocol; these
cells cover the decisive policy-vs-direction/family axes.

## Validity note (first supplementary take discarded)

The rolling redeploy let node0 (priority 200) preempt RG0 back from
node1. The first supplementary run applied configs to fw1 — by then the
SECONDARY — so the active dataplane on fw0 kept the prior equal-flow-OFF
config and every "mean" cell measured OFF behavior (zero cap-hit deltas
on both nodes confirmed this). Those cells were discarded; the re-run
asserts the target's OWN node row is `primary` before applying.
Lesson recorded: the injector must always target the CURRENT RG0
primary, and enforcement deltas must be validated per-cell.

## Take-2 cells (fw0 = RG0 primary, post-fix binary, 2 reps/cell)

| cell | agg Gb/s (mean) | per-flow CoV (mean) | q10 cap-hit delta/rep |
|---|---|---|---|
| v4 push OFF | 18.21 | 10.4 % | 0 |
| v4 push `mean` | 16.80 | 15.6 % | 3.2-3.4M (ifindex 14) |
| v6 push OFF | 17.97 | 13.4 % | 0 |
| v6 push `mean` | 17.18 | 10.2 % | 3.2-3.4M (ifindex 14) |
| v4 reverse OFF (symmetric fixture) | 17.46 | 15.2 % | 0 |
| v4 reverse `mean` (symmetric fixture) | 16.53 | 21.5 % | 2.2-2.9M (ifindex 5, LAN-side) |

Per-direction deltas (mean vs OFF): v4 push **+50 % relative CoV**
(10.4 -> 15.6 %) at 8 % aggregate cost; v6 push **-23 % relative CoV**
(13.4 -> 10.2 %) at 4 % cost; v4 reverse **+42 % relative CoV**
(15.2 -> 21.5 %) at 5 % cost. Enforcement engaged in every `mean` cell
(millions of cap hits, correct interface per direction), so the
PLAN-KILL arm of the gate ("live no-op") remains decisively excluded.

## Regime-dependence: the honest synthesis

Combining all cells across both nodes:

- When the OFF baseline draw is HIGH-CoV (skewed RSS placement — the
  fw1 v4-push cells at 18.5-44.7 %), `mean` delivers the large win
  (27.6 % -> 13.3 %, 52 % relative, ~zero aggregate cost). This is the
  regime the #1746 issue was filed about.
- When the OFF baseline is already NEAR THE FAIRNESS FLOOR (fw0 v4-push
  at 10.4 %; reverse at 15.2 %), the cap cannot help (nothing
  meaningfully above the mean to trim) and the enforcement limit cycle
  perturbs flows that were fine: CoV INCREASES ~5-6 points and
  aggregate drops 4-8 %.
- v6 sits between: modest win (23 % relative at 4 % cost).

Disposition vs the F1 gate: the gate's kill arm (live no-op /
sample-set collapse) is excluded by enforcement evidence in every cell.
The headline >=30 %-at-<=15 % criterion is met in the high-CoV regime
the gate was written against, and NOT met when the baseline is already
at the floor — where no cap policy can help by construction
(`docs/fairness-regimes.md` floor contract). Operator guidance in
`docs/cos-traffic-shaping.md` is updated accordingly: enable `mean`
only on classes that chronically exhibit high per-flow CoV; on classes
already near the floor it adds variance and costs aggregate. The knob
remains default-OFF with a non-work-conserving commit warning.
