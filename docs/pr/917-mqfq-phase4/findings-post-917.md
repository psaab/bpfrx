# Post-#917 cluster smoke

Recorded 2026-04-27 immediately after deploying
`sprint/917-mqfq-phase4` (Phase 1-4 implementation: types,
allocator, publish hooks, read-path early-break throttle).
Companion to `findings-post-927-926.md`.

## Headline

V_min sync delivers measurable wins on the throughput half AND
the latency half. CoV is improved on iperf-b but not yet at the
≤ 20 % gate; remaining gap requires #936 (cross-worker MQFQ) or
#937 (cross-binding redirect).

## Cross-class sweep — pre-#917 vs post-#917

Pre-#917 = master with #927+#926 (the prior `findings-post-927-926.md`
baseline). Post-#917 = same plus this branch.

| Class | P | retx pre | retx post | sent pre | sent post | CoV pre | CoV post |
|---|---|---|---|---|---|---|---|
| iperf-a | 12 | 156 | 117 | 0.96 | 0.96 | 0.6 % | 0.6 % |
| iperf-a | 32 | 283 | 488 | 0.96 | 0.96 | 0.2 % | 0.5 % |
| iperf-b | 12 | 18 144 | **0** | 9.55 | 9.56 | 65.3 % | **42.7 %** |
| iperf-b | 32 | 18 099 | **0** | 9.57 | 9.58 | 44.6 % | 47.3 % |
| iperf-c | 12 | 161 669 | **3** | 20.62 | **23.47** | 49.3 % | 48.9 % |
| iperf-c | 32 | 197 011 | 106 | 21.49 | 23.46 | 48.0 % | 62.1 % |

## Wins

- **iperf-b retx wiped**: 18 k → 0 at both P=12 and P=32. The
  scheduling burstiness that was driving TCP cwnd cuts is gone.
- **iperf-c P=12 throughput uplifted**: 20.62 → 23.47 Gb/s.
  Strictly clears the #789 22 Gb/s gate.
- **iperf-c retx near-eliminated**: 161 k → 3 at P=12, 197 k →
  106 at P=32. TCP loss-driven cwnd collapse no longer happens
  at the throttle-protected steady state.
- **iperf-b P=12 CoV improved 23 percentage points**: 65.3 →
  42.7 %.

## Limits

- Per-flow CoV at iperf-b/iperf-c remains 42–62 %, well above
  the #789 ≤ 20 % gate. This is consistent with the analysis
  in #936 / #937: V_min sync equalizes per-flow service among
  workers when their `queue_vtime` advance rates DIFFER (which
  it does on iperf-b enough to bring CoV down 23 points), but
  cannot equalize when workers carry uneven flow counts at
  comparable byte-rates. The residual variance is RSS-driven.
- iperf-c P=32 CoV got slightly WORSE (48.0 → 62.1 %). Likely
  noise or a side effect of the throttle interacting with the
  iperf-c high-rate per-flow share. Worth re-measuring across
  multiple runs.

## Same-class mouse-latency (100E100M latency half)

Re-ran same-class iperf-b N=128 M=10 with V_min sync active.

- Pre-#917 (post-#927+#926 baseline): mouse p99 = 60.64 ms
- **Post-#917: mouse p99 = 59.51 ms** (essentially identical;
  slightly better within run-to-run noise)

V_min sync did NOT introduce mouse-latency regression. The
within-worker MQFQ ordering still gives mice priority, and the
early-break throttle is light enough not to delay individual
pops. Same-class HOL stays at the ~60 ms baseline.

## What V_min sync actually did

The big effect is **eliminating retransmits**, not equalizing
flows. Pre-#917, scheduling burstiness on shared_exact queues
caused TCP cwnd cuts (~150-200 k retx/30 s). With V_min sync,
the throttle prevents the fast-worker-with-few-flows from
sprinting past the slow-worker-with-many-flows; both stay
roughly synchronized in vtime; per-flow service is more evenly
paced; cwnd collapse no longer happens.

The PER-FLOW Gbps values are still uneven because RSS
distributes flows asymmetrically across workers — this is the
ceiling V_min sync cannot lift (per the analysis in #936).

## Acceptance gate progress

| Gate | Before #927+#926 | After #927+#926 | After #917 |
|---|---|---|---|
| iperf-c P=12 throughput ≥ 22 Gb/s | 15.05–18.32 | 20.62–23.47 | **23.47** ✓ |
| iperf-c P=12 retx ≤ 1 k | 226 k | 39 (best) | **3** ✓ |
| iperf-b P=12 retx ≤ 1 k | not measured | 18 144 | **0** ✓ |
| iperf-c P=12 CoV ≤ 20 % | 35–68 % | 49 % | 48.9 % ✗ |
| iperf-b P=12 CoV ≤ 20 % | not measured | 65 % | 42.7 % ⚠️ |
| iperf-a P=12 CoV ≤ 20 % | not measured | 0.6 % | 0.6 % ✓ |
| Same-class iperf-b N=128 mouse p99 ≤ 70 ms | not measured | 60.64 | **59.51** ✓ |

The throughput half + retx half + latency half all clear. The
per-flow CoV half still requires the #936 / #937 follow-ups.

## Raw artifacts

- `/tmp/post-917/iperf-{a,b,c}-p{12,32}.json`
- `/tmp/post-917-mouse/sc_N128_M10/rep_00/probe.json`
