# #800 — Worker count vs RSS queue count investigation

Cluster under test: `loss:xpf-userspace-fw0` (primary, RG0/1/2) +
`loss:xpf-userspace-fw1` (secondary) + `loss:cluster-userspace-host`
(iperf3 client). Server: `172.16.80.200` (external). Branch:
`pr/800-workers-queues-alignment` off `master`.

Cluster baseline at investigation start: **`--workers 4`**, mlx5
interfaces `ge-0-0-1` and `ge-0-0-2` both at **`combined 6`**, D3
active (reshapes the 6-queue indirection table so hash outputs land
only on queues 0..3). Issue #800 report: queues 4/5 IRQs pin to CPU
4/5 per mlx5 default but workers 0/1 service them on CPU 0/1,
crossing L2 per packet on those queues.

## Methodology

Matched 3-run measurement harness at `/tmp/800-measurements/run_matched.sh`.
Each matrix cell runs iperf3 from `cluster-userspace-host` → external
server through the firewall:

- `p5201-fwd` — `-P 16 -t 20` (shortened from plan's t=60 to fit timebox)
- `p5201-rev` — `-P 16 -t 20 -R`
- `p5203-fwd` — `-P 12 -t 10` (fairness gate)

Plan asked for 5-run t=60 / t=20; shortened to 3-run t=20 / t=10 for
tractability. CoV reported per cell so noise is visible.

## Results

| Matrix | master (4w/6q) — run 1 | master_confirm | master_confirm2 | A (6w/6q) — run 1 | A_confirm | B (4w/4q) |
|---|---|---|---|---|---|---|
| p5201-fwd Gbps | 22.65 | 22.89 | 22.98 | 23.48 | 22.89 | 21.72 |
| p5201-fwd CoV | 1.0% | 0.4% | 0.2% | 0.01% | 0.2% | **7.3%** |
| p5201-fwd retr (mean) | 936 | 299 | 252 | 1269 | 626 | 2877 |
| p5201-rev Gbps | 20.79 | 20.63 | 20.59 | 22.48 | 20.49 | 20.87 |
| p5201-rev CoV | 0.2% | 1.0% | 0.6% | 0.18% | 1.3% | 1.0% |
| p5201-rev retr (mean) | 1666 | 755 | 140 | 6763 | 32 | 6153 |
| p5203-fwd Gbps | 21.63 | 22.69 | 21.58 | 23.46 | 21.47 | 21.48 |
| p5203-fwd CoV | **8.7%** | 1.5% | 8.5% | 0.15% | 8.4% | **7.8%** |
| p5203-fwd retr (mean) | 8711 | 0 | 0.7 | 0.3 | 0 | 155 |

Pooled (master & master_confirm2 vs expA_confirm — both taken after
the first config settle cycle; those are the most directly
apples-to-apples cells):

| Matrix | master_confirm2 (4w/6q) | A_confirm (6w/6q) | Δ (A − master) |
|---|---|---|---|
| p5201-fwd Gbps | 22.98 | 22.89 | **-0.09** |
| p5201-rev Gbps | 20.59 | 20.49 | **-0.10** |
| p5203-fwd Gbps | 21.58 | 21.47 | **-0.11** |
| p5203-fwd CoV | 8.5% | 8.4% | no change |

## Interpretation

**The first expA run looked like a big win — +0.59/+1.85/+1.83 Gbps
and CoV crushed to <0.2% across the board.** The retest
(expA_confirm) did not reproduce any of it. The paired
master_confirm2 vs expA_confirm cells land within 0.11 Gbps of each
other on all three scenarios — well inside single-run noise.

The most likely explanation for the first A run's exceptional
numbers: a fresh daemon-restart state with cold queue dispatch
coincidentally aligning a fast-path window. Across three matched
baselines the cross-cache penalty from queue 4/5 IRQs hitting
CPU 4/5 is not detectable at this load level — it is either
overwhelmed by the other loss-userspace pipeline bottlenecks, or it
is genuinely a minor cost at this traffic rate.

**Experiment B (4w/4q via `ethtool -L combined 4`) is strictly
worse** on throughput (-0.9 to -1.2 Gbps across all three scenarios)
AND dramatically worse on CoV (7.3% and 7.8% on fwd/p5203 vs 0.2%
and 1.5% on master_confirm). Per the plan's rollback-gate rule this
ruled B out immediately. Reducing NIC RSS parallelism to match
worker count loses more than it gains.

## Decision — per plan §Pick the winner

Plan threshold: **"≥ +2 Gbps on p5201 with no fairness regression"**
to justify a PR. The pooled A-vs-master comparison is within the
noise floor. **NEITHER config clearly wins.**

Action: per the plan's fallthrough clause, close issue #800 with
"measured, no net improvement, pre-existing behavior retained" and
commit this findings doc only.

## Secondary finding — non-blocking, separate issue

Observed during experiment setup: when the operator bumps
`system dataplane workers` 4→6 on a 6-queue NIC, the D3 code path
correctly identifies `workers (6) >= queues (6)` and logs a skip,
but it does NOT restore the indirection table from the previous
workers-4 layout (which concentrated hash outputs on queues 0..3).
The table stayed weighted to queues 0..3 even though all 6 workers
were running, until manually reset via `ethtool -X <iface> weight 1
1 1 1 1 1`.

Impact in production: low — the default path is workers=4 on a
6-queue NIC, and D3 is idempotent in that direction. Operators who
change `workers` live on mlx5 hardware may see stale indirection
until the next daemon restart with a different worker count.

Proposed disposition: file a follow-up issue "D3 should restore
default indirection when workers >= queue_count". Scope: single
code change in `pkg/daemon/rss_indirection.go` — the skip branch
should call `restoreDefaultRSSIndirection` when the previous state
was a constrained indirection table. Out of scope for #800.

## Cluster state at end of investigation

- fw0 RG0/1/2 primary, fw1 secondary
- `--workers 4`, `combined 6` on ge-0-0-1/2 (pre-existing baseline)
- Post-restore smoke: `iperf3 -P 4 -t 5 -p 5201` → 21.5 Gbps, 0 retr

## Artefacts

Raw iperf3 JSON for every run is under
`/tmp/800-measurements/<label>/<scenario>-run<N>.json`. Per-label
`summary.tsv` contains mean Gbps / stdev / CoV / mean retransmits.
Labels: `master`, `master_confirm`, `master_confirm2`, `expA`,
`expA_confirm`, `expB`.
