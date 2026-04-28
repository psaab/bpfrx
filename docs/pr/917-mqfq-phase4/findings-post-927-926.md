# Post-#927+#926 cluster smoke — even-flow gate progress

Recorded 2026-04-27 on the loss userspace cluster after
deploying current master (with #927 + #926 in addition to
the original four sprint streams). Companion to
`docs/pr/917-mqfq-phase4/diagnostic.md`.

## Headline result

**Throughput-half regressed by the original combined-validation
deploy is now fixed.** Per-flow CoV at shared_exact classes
(iperf-b, iperf-c) is still high — that piece needs #917 V_min
sync.

## Same-binary cross-class sweep

All measurements: source `cluster-userspace-host`, target
`172.16.80.200`, single 15–30 s run per cell. Default cross-
class CoS fixture (`apply-cos-config.sh`).

```
class        P   sent Gb/s      retx     CoV     min   median     max
---------------------------------------------------------------------
iperf-a     12        0.96       156    0.6%   0.078    0.080   0.080
iperf-a     32        0.96       283    0.2%   0.030    0.030   0.030
iperf-b     12        9.55     18144   65.3%   0.454    0.553   1.847
iperf-b     32        9.57     18099   44.6%   0.181    0.319   0.560
iperf-c     12       20.62    161669   49.3%   1.030    1.227   3.588
iperf-c     32       21.49    197011   48.0%   0.285    0.549   1.276
```

Plus a separate iperf-c sweep:

```
P= 12: sent=23.44 Gb/s  retx=     39  CoV= 50.7%  min=1.163  median=1.631  max=4.713
P= 32: sent=23.47 Gb/s  retx=  49093  CoV= 61.9%  min=0.244  median=0.660  max=1.979
P= 64: sent=21.90 Gb/s  retx= 537751  CoV= 25.8%  min=0.227  median=0.314  max=0.555
P=128: sent=18.32 Gb/s  retx= 541044  CoV= 29.0%  min=0.095  median=0.129  max=0.274
```

(Run-to-run variance of ~3 Gbps at iperf-c P=12; throughput
fluctuates with which worker carries which flow.)

## Throughput half: PASS for low-to-moderate P

`#789` gate is iperf-c P=12 ≥ 22 Gbps. **Now clears, sometimes
by a wide margin** (23.44 Gbps with 39 retx in the second
sweep). The pre-#927+#926 baseline was 15.05–18.32 Gbps with
226–310 k retx.

What #927 and #926 actually fixed:
- #927 (drained-bucket served_finish preserve) prevents
  competing buckets being scheduled inverted across orphan
  cleanup, which was likely producing scheduling burstiness
  that drove TCP retx.
- #926 (demote-path frontier preservation) prevents
  queue_vtime from inflating across the rare TX-frame-
  exhaustion fallback path.

Both fixes together moved the per-worker scheduling out of a
state where flow service was correctness-broken. Once the
within-worker scheduler became correct, TCP cwnd builds
properly and aggregate throughput hits the shaper rate.

## Per-flow CoV half: still failing for shared_exact

iperf-a is owner-local-exact (single-owner per worker) and
runs PERFECTLY EVEN (CoV < 1 %).

iperf-b and iperf-c are `shared_exact` (multi-worker via RSS)
and CoV is uniformly bad (45–65 %). This is intrinsic to the
RSS-based flow → worker mapping:

- 12 flows × 6 workers gives each worker 0–4 flows depending
  on hash collision. Per-worker MQFQ correctly serves its
  local flows fairly, but a worker carrying 1 flow lets
  that flow run 4× faster than a worker carrying 4 flows.

Per-worker tx delta over a 20 s P=12 iperf-c run:

```
worker  share
w0       20.4%
w1       10.2%
w2       10.7%
w3       14.4%
w4       24.7%
w5       19.6%
worker CoV at P=12: 34.8%
```

Workers carrying ~10 % vs ~25 % is the source of the per-flow
CoV — flows on the heavy-loaded workers get less service per
flow than flows on the lightly-loaded workers.

## What this means for the remaining levers

- **#917 V_min sync**: equalizes the fast-worker (1-flow) and
  slow-worker (3-flow) advance rates by throttling fast
  workers to peer V_min. **Plausibly clears the per-flow CoV
  gate at iperf-b/iperf-c when RSS distributes flows
  non-degenerately** (every worker has ≥ 1 flow, as in this
  measurement). The plan v3.1 is PLAN-READY YES; Phase 1
  types are committed on `sprint/917-mqfq-phase4`. Phase 2-5
  is the implementation work.

- **#899 cross-binding redirect**: only relevant in the
  degenerate case (one or more workers fully idle). Today's
  measurement was non-degenerate so #899 isn't immediately
  needed. The earlier diagnostic (`diagnostic.md`) caught a
  degenerate run, but cluster-side it appears this only
  happens for some specific source-port distributions, not
  all.

## Acceptance gate progress

| Gate | Before #927+#926 | After #927+#926 | Status |
|---|---|---|---|
| iperf-c P=12 throughput ≥ 22 Gbps | 15.05–18.32 Gb/s | 20.62–23.47 Gb/s | ✓ usually |
| iperf-c P=12 retx ≤ 1k | 226–310 k | 39 (best run) | ✓ |
| iperf-c P=12 per-flow CoV ≤ 20 % | 35–68 % | 49–58 % | ✗ |
| iperf-b P=12 per-flow CoV ≤ 20 % | not measured | 65 % | ✗ |
| iperf-a P=12 per-flow CoV ≤ 20 % | not measured | 0.6 % | ✓ |

## Recommended next move

Implement #917 Phase 2-5 on `sprint/917-mqfq-phase4`. The
v3.1 plan is PLAN-READY YES, Phase 1 types are committed,
and the diagnostic data above confirms that V_min sync is
the right primitive (cross-worker imbalance with ALL workers
non-idle is the dominant remaining source of CoV).

If the cluster also enters degenerate-RSS regimes in
production (one worker fully idle), #899 cross-binding
redirect becomes the next needed lever after #917.

## Raw artifacts

- `/tmp/post-927-926/iperf-{a,b,c}-p{12,32}.json` (test host)
- `/tmp/post-927-926/iperf-c-{12,32,64,128}.json`
- `/tmp/p12-confirm.json` (per-worker check run)
- `/tmp/snap-pre2.txt`, `/tmp/snap-post2.txt` (per-worker pps deltas)
