# #905 mouse-latency tail measurement — findings

Issue: #905
Plan: `docs/pr/905-mouse-latency/plan.md`
Harness PR: #906 (merged); follow-up fixes PR: #907 (open)

## TL;DR

Mouse-latency tail under elephant load was measured across two
elephant CoS classes on the loss userspace HA cluster:

| Setup | Gate ratio | Verdict |
|---|---:|---|
| iperf-a same-class (1 Gb/s shaper) | **1.10×** | **PASS** |
| iperf-c same-class (25 Gb/s shaper, post #910 + 1500 hugepages) | **31.80×** | **FAIL** |

The PASS in iperf-a class was the original #905 question; the FAIL
in iperf-c class is the consequential follow-up the user added
("test at 25 Gb/s with mice in the same class"). The headline:

- The firewall holds mouse latency well when the **shaper** is the
  bottleneck (iperf-a, 1 Gb/s). Per-flow fairness across the queue
  works as designed.
- The firewall does **not** hold mouse latency when the **firewall
  hot path itself** is the bottleneck (iperf-c, capacity-bound at
  ~15 Gb/s well below the 25 Gb/s shaper). Mice get HOL-blocked.

The cross-NIC userspace memcpy (~13 % of CPU, structural at the
AF_XDP layer on this hardware) sets the upper bound on hot-path
throughput. With #910 + hugepages the path now hits 15.7 Gb/s on
iperf3 -P 128 (up from 7.20 Gb/s baseline) but the additional
mouse-latency relief from those optimizations is zero — the
bottleneck moved from packet-processing to queue management.

## What was measured

12-cell matrix per CoS class:
- `N` (elephants on shaped class) ∈ {0, 8, 32, 128}
- `M` (concurrent mice on echo server port 7) ∈ {1, 10, 50}
- 10 reps × 60s probe each; up to 15 reps as needed for 10 valid

The mouse class was set to match the elephant class via
`cos-mouse-shared-iperf-c.set` (a #907 follow-up fixture). This is
the **same-class HOL test** — the original `iperf-a-shared` cell from
the #905 issue body, generalized to other classes.

## iperf-a same-class: PASS at 1.10×

Pre-existing measurement (saved at `/var/tmp/905-results-iperf-a/`,
not committed but referenced from prior session work; numbers
preserved here for the comparison):

| Cell | Median p99 |
|---|---:|
| N=0 M=10 (idle) | 8.68 ms |
| N=8 M=10 | 8.36 ms |
| N=32 M=10 | 8.29 ms |
| N=128 M=10 | 9.51 ms (1.10× idle) |

iperf-a's 1 Gb/s shaper holds elephants below the firewall's
hot-path capacity. The shaper queue's per-flow scheduler keeps
mice within ~1 ms of the idle p99 across the entire elephant
sweep. PASS.

## iperf-c same-class: FAIL at 31.80×

Full data at `docs/pr/905-mouse-latency/results-iperf-c-shared/summary.json`.
Headline cells:

| N | M=1 | M=10 | M=50 |
|---:|---:|---:|---:|
| 0 (idle) | 5.20 ms | **6.67 ms** | 21.94 ms |
| 8 | 8.04 ms | 11.79 ms | 35.49 ms |
| 32 | 16.91 ms | 16.04 ms | 46.97 ms |
| 128 | INSUFFICIENT-DATA | **212.02 ms** | 31.06 ms |

**Gate**: p99(N=128, M=10) / p99(N=0, M=10) = 212.02 / 6.67 = **31.80×**.

Notable patterns:

- p99 grows non-linearly with elephant count at M=10. N=8 is
  ~1.7× idle; N=32 is ~2.4×; N=128 jumps to 31.8×. The
  per-flow scheduler degrades faster than the workload scales.
- M=1 with N=128 hit `cwnd-not-settled` on all 15 reps — the
  matrix wrapper logged INSUFFICIENT-DATA for that cell. This is
  a harness-level failure mode, not a measurement: at M=1 the
  iperf3 elephants need >20s to reach 0.5 × shaper. Tracked as a
  follow-up to relax the cwnd-settle floor for high-N iperf-c.
- M=50 with N=128 came in at 31 ms p99, lower than N=32 M=50
  (47 ms). At very high elephant counts the connect-storm of 50
  mice may interact with the conntrack/policy backpressure in a
  way that forces faster drain — counter-intuitive but
  reproducible across reps. Not a metric we should rely on; it
  reflects something about the queueing dynamics the harness
  doesn't capture.
- p99 across the M=10 row scales the way the original #905
  hypothesis predicted: mouse latency is bounded by the
  scheduler's ability to dequeue mice ahead of HOL elephants,
  and that bounds breaks down at the high N × high shaper combo.

## What the optimization stream proved

The matrix was run with #910 (metadata prefetch, +43 % aggregate
throughput) and explicit 2 MB hugepages on both nodes (1500
nr_hugepages persisted in `/etc/sysctl.d/90-xpf-hugepages.conf`).

Compared to a re-run of the same matrix BEFORE these optimizations
(`/var/tmp/905-results-iperf-c-shared-pre-prefetch/`, M=10 row only,
4 cells × 10 reps):

| Cell | Pre-opt p99 | Post-opt p99 | Δ |
|---|---:|---:|---:|
| N=0 M=10 (idle) | 8.50 ms | 6.67 ms | **-22 %** |
| N=8 M=10 | 10.73 ms | 11.79 ms | +10 % |
| N=32 M=10 | 21.80 ms | 16.04 ms | -26 % |
| N=128 M=10 (loaded gate) | 211.12 ms | 212.02 ms | ~0 % |
| Gate ratio | 24.83× | 31.80× | _grew_ |

The ratio grew because the IDLE baseline shrank (the optimizations
helped that path) but the LOADED p99 didn't budge. **The bottleneck
under N=128 elephant load is not in the firewall hot path** —
it's in the queueing layer (CoS / SFQ scheduler / conntrack
backpressure). Optimizing the dataplane fast path doesn't move
the loaded-path tail.

This is a useful negative finding: future fairness/latency work
on iperf-c-class loads must target the queueing layer specifically,
not generic "make the firewall faster" optimizations.

## What the throughput-side optimizations did

| Stage | iperf3 -P 128 / 25 Gb/s aggregate | Notes |
|---|---:|---|
| Original (master pre-#910) | 7.20 Gb/s | CPU-bound on the cross-NIC memcpy + cold metadata load |
| #910 (metadata prefetch only) | 10.30 Gb/s | +43 %; site-level cmpl/jne stall reduced |
| #910 + 1500 hugepages | 15.70 Gb/s | +118 % vs original; explicit MAP_HUGETLB across all 18 UMEMs per node |

The remaining ~9 Gb/s gap to the 25 Gb/s shaper is structural:
12.5 % of CPU is in the cross-NIC userspace memcpy that AF_XDP
zero-copy cannot avoid on this hardware (different physical NICs
for LAN and WAN). `docs/shared-umem-plan.md` documents the failed
cross-NIC zero-copy attempt (mlx5 driver fails the second `bind()`
with EINVAL when the UMEM is already DMA-mapped by another NIC).

## Caveats

- v4-only. v6 mouse path not measured; results do not generalize.
- Mouse class was set via the `cos-mouse-shared-iperf-c.set`
  fixture from #907; that fixture is iperf-c-specific. Other CoS
  classes need their own fixture to measure the same-class HOL
  pattern (one-line change per class).
- The N=128 M=1 INSUFFICIENT-DATA cell is a harness limitation,
  not an empirical failure of the cluster. The iperf-c elephants
  need >20s to reach 0.5 × shaper at this exact N + M
  combination; the cwnd-settle gate timed out.
- The 24.83× → 31.80× change in gate ratio is dominated by the
  idle baseline change. The loaded p99 (the actual mouse-latency
  pain point) is unchanged at ~211-212 ms.

## Recommended next steps

1. **Dataplane is fast enough; queueing layer is the new
   bottleneck.** Future mouse-latency work on iperf-c-class loads
   should target the SFQ / per-flow scheduler / CoS queue
   pressure, not the per-packet processing speed.

2. **Operational**: the 1500 hugepage reservation is now persisted
   on both loss userspace cluster nodes. Other test environments
   should add the same conf file to actually use the in-tree
   hugepage UMEM path (THP fallback works but explicit
   MAP_HUGETLB is faster on cold-start).

3. **Harness limitation**: if the N=128 M=1 cell matters for a
   future investigation, raise the `SETTLE_BUDGET` (currently 20s)
   or relax the `0.5 × shaper` floor for the M=1 case. Tracked
   informally; not blocking the iperf-c verdict.

4. **The #905 PASS-gate question is answered both ways**:
   - For iperf-a-shared (1 Gb/s class): mice survive elephant
     load. PASS.
   - For iperf-c-shared (25 Gb/s class): mice get HOL-blocked
     under heavy elephant count. FAIL.
   The right disposition for #905 is to close it with this
   findings doc as the reference; any further fairness algorithm
   work should be a fresh issue scoped on the queueing layer
   findings above.

## Files

- `docs/pr/905-mouse-latency/plan.md` — original 7-Codex-round plan
- `docs/pr/905-mouse-latency/findings.md` — this document
- `docs/pr/905-mouse-latency/results-iperf-c-shared/summary.json` —
  aggregator output for all 12 cells
- `/var/tmp/905-results-iperf-c-shared/` — raw per-rep JSON (not
  committed; ~3 MB, lives on the host that ran the matrix)
- `/var/tmp/905-results-iperf-a/` — iperf-a same-class data (also
  not committed; preserved for reference)
- `/var/tmp/905-prof/perf.data` — pre-optimization perf profile
- `/var/tmp/perf-after.data` (on `loss:xpf-userspace-fw1`) —
  post-optimization perf profile
