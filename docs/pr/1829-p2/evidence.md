# #1829 Phase 2 — §6.1d live-evidence gate: results and verdict

Date: 2026-06-10. Build under test: master `g00346ec1a`
(userspace-forwarding-ok-20260402-bfb00432-2123) with #1829 Phase 1
(PR #1846, sojourn telemetry) deployed on `loss:xpf-userspace-fw0/fw1`,
CoS iperf fixture applied per-rep by the harness.

## Method

Two runs:

**Main sweep** — re-ran the #1359 100E100M cells (exact command shape
from the issue: `mouse_latency_probe.py`, persistent mode,
`--min-interval-ms 20`, 60 s probes, M=100 mice; elephants
`iperf3 -P 100` → 172.16.80.200:5202, 1 Gbps exact class q2) plus a
same-class shaped-low-rate regime (8 elephants → 5201, 100 Mb class q1
with 500 KB buffer; 10 mice on 6201, same class), via
`test/incus/test-mouse-latency.sh` — the canonical #905/#1359 harness,
which applies the strict/surplus CoS fixture per rep and runs
cwnd-settle and HA validity gates.

**Supplementary cells** (added after a hostile self-review flagged the
single-flow gap in the per-class coverage) — `iperf3 -P {1,2,8}` →
5202 (1 g exact, 4 MB buffer) and `-P 1` → 5201 (100 m exact), strict
fixture, 60 s, sojourn sampler only.

**Mouse-port substitution:** the operator-provisioned 6200 echo
listener on 172.16.80.200 is currently down (connection refused);
the probe used port **7** (the original #905 echo service, verified
echo-correct), which like 6200 matches no `bandwidth-output` filter
term and classifies to the same best-effort queue 0. All other 620x
listeners are up; 6201 was used for the same-class cells.

**Concurrent sojourn capture:** a 1 Hz sampler on both fw nodes
recorded `xpf_userspace_cos_sojourn_{windowed_min,ewma,peak}_ns` and
`xpf_userspace_cos_flow_fair_{flows_active,buckets_occupied}` for all
12 queues (ifindex 14 = reth0.80) with node-local ms timestamps;
node↔driver clock offset measured before/after (fw0 −84.7 s, drift
9 ms over the sweep — corrected in analysis). 94–97 samples per
loaded-rep window; the only >3 s gaps fall between cells (CoS
re-apply), never inside a rep. fw1 (secondary, carries no traffic)
exported no CoS metrics — expected.

Sampler watched the right queues: `flows_active` showed q2=100
(elephants) and q0=100 (mice) during the 100E100M cells, q1=18
(8 elephants + 10 mice) during the same-class cells, and q2={1,2,8}
in the supplementary cells.

## Results — main sweep

Probe percentiles (`probe.json` `rtt_us`), elephants from iperf3 SUM;
sojourn columns are the max over the rep window of the per-queue
gauges (MAX-merged across workers by the collector).

| Cell | rep | valid | p99 µs | p99.9 µs | eleph Gb/s | max windowed_min (any queue) | q-of-interest EWMA max |
|---|---|---|---|---|---|---|---|
| surplus-idle | 0 | yes | 4 939 | 9 059 | – | 0.00 ms | q0 0.00 ms |
| surplus-idle | 1 | yes | 4 944 | 8 774 | – | 0.00 ms | q0 0.00 ms |
| surplus-loaded (#1359 fail cell) | 0 | yes | 47 529 | **58 205** | 1.27 | **0.00 ms** | q2 **0.01 ms**, q0 0.00 ms |
| surplus-loaded | 1 | yes | 46 444 | **56 112** | 1.26 | **0.00 ms** | q2 0.01 ms, q0 0.00 ms |
| surplus-loaded | 2 | yes | 32 490 | **38 989** | 1.27 | **0.00 ms** | q2 0.01 ms, q0 0.00 ms |
| surplus-loaded | 3 | no (degenerate-coroutine) | 37 541 | 981 183 | 1.27 | **0.00 ms** | q2 0.67 ms, q0 0.00 ms |
| exact-loaded (#1359 pass control) | 0 | yes | 5 763 | 9 530 | 0.95 | 0.06 ms | q2 **16.96 ms** |
| exact-loaded | 1 | yes | 5 739 | 10 464 | 0.95 | 0.05 ms | q2 11.65 ms |
| sc100m-idle | 0 | yes | 6 799 | 11 583 | – | 0.00 ms | q1 0.13 ms |
| sc100m-loaded | 0 | yes | 3 914 | 7 725 | 0.10 | 2.47 ms | q1 12.05 ms |
| sc100m-loaded | 1 | yes | 3 827 | 7 710 | 0.10 | 1.84 ms | q1 11.91 ms |

The #1359 dichotomy reproduces exactly: surplus loaded/idle p99.9
ratio ≈ 4.4–6.5× (gate ≤ 2.0, FAIL) with elephants borrowing to
1.27 Gb/s; strict exact ratio ≈ 1.07–1.18 (PASS) capped at 0.95 Gb/s.
One surplus rep went degenerate (1.07 s spike, INVALID) — the same
signature #1359 recorded.

## Results — supplementary single/few-flow exact cells

60 windowed-min samples per 60 s cell on the loaded queue:

| Cell | shape held | windowed_min max | samples > 5 ms | longest consecutive run | EWMA max |
|---|---|---|---|---|---|
| exact1g-P1 | 953 Mb/s | **9.61 ms** | **33/60** | 5 (≥ 5 s above target) | 10.31 ms |
| exact1g-P2 | 954 Mb/s | **8.41 ms** | 25/60 | 4 | 9.95 ms |
| exact1g-P8 | 954 Mb/s | 3.61 ms | 0/60 | 0 | 9.61 ms |
| exact100m-P1 | 95.3 Mb/s | **10.83 ms** | **45/60** | 12 (≥ 12 s above target) | 12.72 ms |

Single/few-flow strict-exact shaped queues DO sustain windowed-min
sojourn ~8–11 ms — genuinely above the 5 ms codel-target for many
consecutive 100 ms intervals. This is the admission-designed BDP
buffering (per-flow cap `max(fair_share×2, bdp_floor)` with ECN at
1/3 cap holding cwnd there); throughput stays pinned at the shape.
At P=8 the per-flow caps shrink and cross-bucket mixing zeroes the
per-queue min below target.

## §6.1d criteria mapping (verbatim semantics)

The gate: *"Phase 2 proceeds only if BOTH hold: (a) shaped queues
sustain sojourn above codel-target (5 ms) for ≥ one interval (100 ms)
in a regime we care about, AND (b) the sojourn excursions correlate
in time with the failing p99.9 probe cells."* Evaluated on
`sojourn_windowed_min_ns` (the gate metric per AGY r2 F2).

**(a) HOLDS — but only in the single/few-flow strict-exact regime.**
exact1g-P1/P2 and exact100m-P1 sustain windowed-min 8–11 ms for
multi-second stretches. Everywhere else (a) fails: the #1359
100E100M cells show 0.00 ms windowed-min on every queue in every
sample (~240 loaded samples across 4 reps), the multi-flow per-class
cells max at 2.47–3.61 ms. The metric pipeline demonstrably reports
nonzero values, so the zeros are measurements.

**(b) FAILS — the correlation is inverted.** The failing-p99.9 cells
(surplus, 39–58 ms) show **no queue residence at any granularity**:
the elephants' q2 EWMA maxes at 0.01 ms (a shift-add EWMA over every
pop cannot sit at ~10 µs if any meaningful fraction of pops waited
milliseconds), and the mouse q0 EWMA is 0.00 ms while `flows_active`
confirms all 100 mice transit q0. Surplus borrowing (1.27 G > 1.0 G
configured) drains the queue faster than the offered load — the
queues are near-empty precisely when the probes fail. Conversely,
every regime where queues DO stand (strict exact, single-flow or
100-flow; sc100m) has passing mouse probes or no probe-relevant
latency failure at all. Standing queues ↔ passing probes; failing
probes ↔ empty queues.

**Verdict per the gate: both criteria do NOT hold → Phase 2 does not
proceed.** The §6.1d (b)-fail handling applies verbatim: *"Phase 2 is
still viable as bufferbloat control (the queues DO stand) but must
not be sold as the #1359 fix — and the #1359 residual goes back to
the surplus-scheduling lineage (#1743)."* The evidence above makes
the de-attribution measured fact, not belief: the 39–58 ms mouse
excursions under surplus occur with empty CoS queues, so they are
service/scheduling gaps (drain arbitration, wake latency), not queue
residence. A dequeue-time AQM has nothing to act on in that regime —
there is no head packet waiting.

**Why "viable as bufferbloat control" does not clear the bar to
implement here.** What (a) found standing is the intentional,
ECN-governed BDP buffering of single bulk flows holding a shaped
class at exactly its configured rate (953/954/95.3 Mb/s). The only
beneficiary of CoDel-marking that queue down to ≤5 ms is the bulk
flow's own in-queue latency — no project acceptance gate measures
it, MQFQ already isolates other flows from it (sc100m mice: p99.9
7.7 ms, better than idle), and pushing cwnd below the
admission-designed envelope is the #704/#707/#754 low-rate
oscillation territory with throughput risk and zero measurable lab
win. This is plan §3's "what it does NOT add" case and §12 Q2's
invited kill, now with measurements. The genuine consumer for a
per-bucket control law is the #1828 WAN-SQM scenario (operator bulk
flows on a constrained real-world uplink where their own latency
matters); that work can revive the Phase-2 design with its own
evidence on its own issue.

## Caveats (recorded honestly)

1. **Per-queue windowed-min cannot detect per-bucket standing on a
   mixed MQFQ queue.** Enqueue and dequeue share the per-pass
   `now_ns`, so any packet serviced in its arrival tick contributes
   a 0 to the window minimum; with many flows some bucket is almost
   always fresh, structurally zeroing the per-queue min (visible in
   the P=1→P=8 progression: 9.61 → 3.61 ms while EWMA stays ~10 ms).
   A per-bucket FQ-CoDel would see standing the gate metric cannot.
   This does not change the verdict: in the failing regime the EWMA
   evidence excludes standing at every granularity (0.01 ms), and in
   the standing regimes there is no failing consumer (above).
2. **1 Hz sampling subsamples the 100 ms windows (~10–20%
   coverage).** Sustained standing is excluded outright in the
   surplus cells; episodic standing is bounded: the ~264 slow
   transactions per surplus rep would imply hundreds of standing
   episodes, of which 1 Hz sampling of a 1–2-window-lifetime gauge
   would catch dozens — zero were caught, and the EWMA (integrating
   every pop, decaying slowly) corroborates at 0.01 ms.
3. **Mouse port 7 instead of 6200** — same forwarding class
   (best-effort q0, no filter term), verified echo-correct; idle
   baselines (8.8–9.1 ms p99.9) match #1359's 6200 baselines
   (6.9–7.4 ms) within the normal band.

## Review trail

- Codex concise sanity review (task-mq8xcau1-yw9g12): **KILL-SOUND**
  on the main-sweep evidence; independently recomputed the
  windowed-min aggregation from the raw artifacts; non-blocking
  residuals = the sampling-cadence and rep-granularity caveats above.
- Claude hostile SMR self-review: flagged the missing single-flow
  per-class cell → supplementary cells run → criteria mapping
  corrected from "(a) fails everywhere" to "(a) holds narrowly,
  (b) fails, both required" (this document).
- Codex re-review of the corrected mapping (task-mq8xmu38-ws7wad):
  **KILL-SOUND** — independently recomputed all supplementary
  windowed-min numbers from the raw log (exact match), and confirmed
  the "proceeds only if BOTH hold" sentence is binding with the
  "still viable as bufferbloat control" clause a descriptive
  side-branch, not an implementation-acceptance override.

## Artifacts

`/tmp/xpf-1829-gate-20260610-195328/` (main sweep) and
`/tmp/xpf-1829-gate-supp-*/` (supplementary cells) — per-rep harness
artifacts (probe.json, iperf3.txt, cos-apply.log, manifests,
validity), 1 Hz sojourn timelines, `cells.tsv` rep windows,
`clock-offsets.txt`. Driver: `/tmp/xpf-1829-gate-driver.sh` +
`/tmp/xpf-1829-gate-supp.sh`; analyzer: `/tmp/xpf-1829-gate-analyze.py`.

## Verdict

**PLAN-KILL Phase 2** per §6.1d's both-criteria requirement:
(a) holds only for intentional single-flow BDP buffering in strict
exact; (b) fails with inverted correlation — the motivating #1359
failure is measured to be scheduling, not queue residence, and goes
back to the #1743 lineage. #1829 closes with Phase 1 (PR #1846) as
the deliverable. The #1828 Option B rider ("WAN smart queueing must
build on this engine *including the FQ-CoDel sojourn AQM proposed
here*") dies with Phase 2; the §4 engine-boundary verdict (kernel
qdisc is a no-op for forwarded traffic; SQM must live on the
userspace CoS path: shaper + MQFQ) stands unaffected.
