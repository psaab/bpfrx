# #831 Fairness-Config: workers=6 on 6-core / 6-RX-ring loss cluster

## Context

PR #830 (#829 Slice B) landed cross-binding MQFQ gate. Remaining
per-flow unfairness on p5202 was traced to uneven RSS-to-binding
distribution — with workers=4 on a host that has 6 RX rings and
6 CPUs, bindings carry 2-10 flows unevenly (`[10, 4, 2]`
distribution observed).

Empirical finding: **workers=6 matches RX ring count, eliminating
the idle-ring asymmetry and dropping per-binding flow variance
substantially**. Testing confirms:

| Config | p5201 CoV | p5202 CoV | p5201 Jain |
|--------|---:|---:|---:|
| workers=4, Slice B | 28-126% (variable) | 40-46% | 0.57-0.93 |
| **workers=6, Slice B** | **7-21%** | **19-92%** (bimodal) | **0.96-0.995** |

Best p5201 run: CoV 7.3% (below the 15% target), Jain 0.995
(essentially perfect fair). p5202 now hits ≤20% on good RSS runs.

Aggregate throughput is preserved on both cells (0.96 Gbps on
p5201, 9.57 Gbps on p5202).

## Change

Bumps `workers 4;` → `workers 6;` in
`docs/ha-cluster-userspace.conf` so the test environment uses
one worker per RX ring on the loss cluster.

## Why only the test config, not the daemon default

Correct worker count is hardware-dependent (`min(nproc, rx_rings)`
for the critical interfaces). An auto-detecting default requires
daemon-side discovery logic (#TODO future PR). For now, the
loss-cluster config is the surface that the fairness measurements
rely on, so updating it unblocks per-flow fairness progress
without a daemon-wide change.

## Remaining work

p5202 CoV is still bimodal (19-92% across runs) because 16 flows
/ 6 bindings has non-trivial RSS hash variance. Full per-flow
fairness at all RSS hash outcomes requires Slice C (AFD) or a
more sophisticated RSS/distribution approach (see #786 §2.3
and §2.4).

Superseded (for now): the planned Slice C AFD implementation at
#831 is deferred behind this simpler configuration win. Will
re-open if subsequent benchmarking shows the workers=N match
alone is insufficient for production workloads.
