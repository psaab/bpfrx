## Smoke-time finding: algorithm needs further refinement

Live smoke on loss userspace cluster post-deploy with
`oversubscription-policy guarantee-rate 0.7` set on
`reth0 unit 80`:

Push direction simul-load (all 11 classes):

| Class | Shape | Achieved | %shape |
|-------|-------|----------|--------|
| iperf-100m | 0.10 G | 0.02 G | 20% |
| iperf-1g | 1.00 G | 0.19 G | 19% |
| iperf-3g | 3.00 G | 0.64 G | 21% |
| iperf-6g | 6.00 G | 1.30 G | 22% |
| iperf-9g | 9.00 G | 2.02 G | 22% |
| iperf-12g | 12.00 G | 2.73 G | 23% |
| iperf-15g | 15.00 G | 3.17 G | 21% |
| iperf-18g | 18.00 G | 2.81 G | 16% |
| iperf-21g | 21.00 G | 3.09 G | 15% |
| iperf-24g | 24.00 G | 3.73 G | 16% |
| iperf-uncapped | uncap | 0.00 G | — |
| **Sum** | | **19.7 G** | |

The distribution is approximately the same as `proportional` default mode
(~21% of shape per class), despite the new waterfill activating (config
flows to dataplane: snapshot shows `cos_oversubscription_policy:
"guarantee-rate"` + `cos_oversubscription_guarantee_fraction: 0.7`).

**Root cause**: the implemented waterfill bounds total Phase 1 BYTE
budget, not per-queue rate. With pass1_remaining ≈ 1.8 MB and
per-visit quantum ≈ 1.5-3 KB, every queue gets visited every Phase 1
cycle before the byte budget is exhausted. The per-queue token
bucket is what actually caps each queue, and under oversubscription
ALL queues hit their per-queue token bucket simultaneously
(proportional behaviour emerges).

**Fix needed in follow-up**: track per-queue per-epoch byte
allocation against `rate × epoch_ns / 1e9` and skip queues
that have hit their rate cap. Then small classes' epoch caps
fill first, leaving Phase 2 budget for larger classes —
producing the documented Junos-style distribution where small
classes hit their full configured rate.

The current PR ships the WIRE SURFACE + Phase-0/SCAFFOLD A1
algorithm; the proper guarantee-honor mechanism (per-queue
epoch caps) is filed as a focused follow-up. This is honest
about what the PR delivers vs the v5 plan's full intent.
