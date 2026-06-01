# #1743 live validation gate — loss:xpf-userspace-fw0 (matched A/B)

Master baseline = e4556085a. Fix = fix/1743-cos-waterfill-shaped-budget.
CoS fixture cos-iperf-config.set (shaping-rate 25g, oversubscription-policy
guarantee-rate 0.7, 10 exact classes 100m..24g + best-effort + uncapped).
Ground truth = iperf3 per-stream throughput CoV (NOT cos_active_flow_count,
which is buggy per #1741).

## Primary signal — Phase-2 admission (waterfill_phaseN_admissions_total deltas)
Full 11-class simul push, 20s, P12 each, 3 matched runs per build:

| run | MASTER p2/p1 | FIX p2/p1 |
|----:|-------------:|----------:|
| 1   | 0.0064       | 1.433     |
| 2   | 0.0059       | 1.323     |
| 3   | 0.0054       | 1.405     |

Master Phase-2 admits ~0.6% of Phase-1 (phase2_admit effectively 0 — the
reported regression). Fix Phase-2 admits ~135% of Phase-1 — the surplus
distribution phase is alive. ~230x increase in the phase2/phase1 ratio.
This is the phase2_admit 0->nonzero transition the gate requires.

Also on master gate_2 (priority-low/uncapped min share) FAILED (uncapped
got 0.00 Gbps — starved by the dead Phase-2); on the fix it PASSED.

## Ground truth — isolated high-shape per-stream CoV (5209+5210 alone, P12, 12s, 5 reps)
Isolating the two high-shape classes removes the 11-class divided-ceiling
noise so per-flow CoV reflects intra-class fairness.

| metric  | MASTER mean (5 runs) | FIX mean (5 runs) | delta     |
|---------|---------------------:|------------------:|----------:|
| 21g CoV | 35.6%                | 25.1%             | -10.5 pts |
| 24g CoV | 45.7%                | 31.9%             | -13.8 pts |

Material CoV drop at BOTH high shapes. Gate satisfied.

MASTER raw: 21g {43.3,49.5,33.3,27.1,24.8} 24g {72.6,51.6,49.7,24.2,30.3}
FIX raw:    21g {23.0,16.3,37.3,22.3,26.4} 24g {17.4,34.0,28.3,29.4,50.4}

## Conclusion
Both halves of the hard gate pass: phase2_admit 0->nonzero (~230x), and
high-shape per-stream CoV drops materially (-10.5 / -13.8 pts). The
root-cause and fix hold up empirically on the live cluster.
