# #1626 smoke measurement under guarantee-rate 0.7

## Setup

- Cluster: `loss:xpf-userspace-fw0` / `xpf-userspace-fw1` (deploy
  `make cluster-deploy` from this branch SHA 7774731eb / docs at
  3f88a5575).
- Apply: `./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0`.
- Smoke: `./test/incus/cos-simul-load-smoke.sh push` (12 streams ×
  11 classes for 30s; target 172.16.80.200).
- Knob: `oversubscription-policy guarantee-rate 0.7` confirmed
  active in running config via Phase-3.5 round-trip assertion (it
  PASSED — assertion would have triggered rollback otherwise). The
  `show class-of-service interface` output also shows `Guarantee:
  yes` on every exact-rate class.

## Result

Aggregate push throughput: **19.78 Gbps** across 11 classes.

| Port | Class | Shape (G) | recv (G) | % of shape | retransmits |
|-----:|-------|----------:|---------:|----------:|------------:|
| 5201 | iperf-100m     |   0.1 | 0.019 |  19% |    23 |
| 5202 | iperf-1g       |   1.0 | 0.200 |  20% |   138 |
| 5203 | iperf-3g       |   3.0 | 0.672 |  22% |   217 |
| 5204 | iperf-6g       |   6.0 | 1.364 |  23% |   534 |
| 5205 | iperf-9g       |   9.0 | 2.004 |  22% |   984 |
| 5206 | iperf-12g      |  12.0 | 2.809 |  23% |  1294 |
| 5207 | iperf-15g      |  15.0 | 2.747 |  18% |  1129 |
| 5208 | iperf-18g      |  18.0 | 3.567 |  20% |  1404 |
| 5209 | iperf-21g      |  21.0 | 3.545 |  17% |  1377 |
| 5210 | iperf-24g      |  24.0 | 2.854 |  12% |  1267 |
| 5211 | iperf-uncapped |   —   | 0.001 |   0% |    87 |

## Verdict

**The algorithm is still equalizing to ~20% per class even with the
knob ON.** Gate 1 fails: small classes (100m, 1g, 3g, 6g) are NOT
honoured to ≥ 95% of their configured rate. Under `guarantee-rate 0.7`
with `shaping-rate 25g`, the Phase-1 budget should be 17.5g (sum of
small classes 10.1g fits comfortably) and small classes should hit
their configured rates first. They don't.

This confirms the #1625 quad-review's suspicion: the simul-load smoke
isn't just a measurement bug. The waterfill scaffold shipped in
PR #1618 either has the Phase-2 lock-in defect at
`userspace-dp/src/afxdp/cos/queue_service/mod.rs:889-893`, or the
worker_fair_share math is wrong, or both. The algorithm is functioning
as if it were still in `proportional` mode regardless of the knob.

## Next step

File **#1627** with this evidence as the next-priority bug. #1627's
job is to find and fix the actual scheduler defect that's causing the
proportional-mode equalization under guarantee-rate. The #1626 PR is
the prerequisite: it makes the smoke harness actually exercise the
guarantee-rate branch so #1627 has a faithful regression target.

Out-of-scope-for-this-PR observations worth recording for #1627:

1. The 19.78 Gbps aggregate is consistent with the push-direction
   NIC ceiling (~18-20G under simul-load with 132 streams) so the
   workload IS saturating the pipe — there's no slack hiding the
   bug.
2. Priority-low (iperf-uncapped) gets 1 Mbps — gate 2 fails
   spectacularly. Under proper guarantee-rate this should get at
   least 5% of cluster ceiling (~900 Mbps).
3. CoV is in the 18-58% range, with the highest CoV on the largest
   shape classes. This is consistent with proportional spreading
   where smaller per-stream slots see more variance.
4. Retransmits cluster around 1000-1400 for mid/large classes —
   indicates the qdisc-level drop is happening but the discipline
   isn't honouring the shape order.
