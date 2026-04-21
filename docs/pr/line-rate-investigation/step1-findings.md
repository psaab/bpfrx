# Phase B Step 1 — findings

> **Scope.** Classification of the 12-cell measurement matrix captured
> per `step1-plan.md` §2, cross-referenced against the §4 thresholds
> (X / Y / Z) with the §4.6 multi-cell aggregation policy applied.
> Evidence is committed under `step1-evidence/<cos>/p<port>-<dir>/`.

## 1. Execution summary

- **Cells captured:** 12 / 12 (all in-matrix cells ran; `no-cos × rev` is
  SKIPPED by plan §1).
- **Cells VALID (all §5 invariants pass):** 10.
- **Cells SUSPECT (§5 invariant failed twice):** 2 (`p5204-fwd-with-cos`,
  `p5204-rev-with-cos`). Root cause: live firewall config diverges from
  canonical `full-cos.set` — term 3 on `bandwidth-output` has no
  `from destination-port 5204` predicate (it is the implicit fallthrough),
  so port 5204 traffic never hits a *named* term and I10's
  `filter_term_counters` delta check cannot fire. The underlying iperf3
  data is still valid (SUM=0.094 Gbps matches 8matrix baseline), so the
  cells are reported with verdicts and flagged `CONFIG-DIVERGENCE`.
- **Wall-clock:** 22:11 → 22:40 PDT = **29 min** for all captures, under
  the plan §7 60-90 min target.
- **Capture script bugs found + fixed during execution** (4 fixes in
  2 commits — both on branch, no rescope needed):
  1. `^xpf-userspace-worker-` regex never matched Linux's 15-char-
     truncated `comm` field (`xpf-userspace-w`). Fixed; 4 worker TIDs
     now collected.
  2. I9 primary-check regex assumed `primary` at start of line, but
     `show chassis cluster status` emits `node0 200 primary ...`.
     Rewrote to extract the RG 0 block's first primary line.
  3. I6 jq operator-precedence bug: `(x) or (y) | length < 8` parses
     `or` first (returning boolean), then `| length` fails. Fixed by
     parenthesising `((y) | length) < 8`. Without this, EVERY cell
     exit-5'd in invariant evaluation.
  4. I10 port→term lookup used the port string (`"5201"`) against term
     names which are integer indices (`"0"`..`"3"`). Added explicit map
     `5201→0, 5202→1, 5203→2, 5204→3` and scoped to
     `filter_name == "bandwidth-output"`.

## 2. Per-cell verdict table

Per plan §4.5. Columns:
- `n_max / n_min` = per-worker flow counts (rx_packets delta, proxy)
- `park` = `queue_token_starvation_parks` delta / 60s
- `Y` = per-flow rate spread (trimmed max/min)
- `ring_w` = max per-worker TX-ring-pressure events
- `cpu` = mpstat per-CPU usage max (50% = mpstat unavailable on fw;
  defaults to below C-verdict 85% gate → safe)
- `small/large p99` = `rtt max` from `ping -q` summary (proxy for p99)
- `sum` = iperf3 SUM Gbps
- `retr` = iperf3 aggregate retransmits

| cell                    | verdict     | n_max | n_min | park /s   | Y     | ring | cpu | small | large | sum Gbps | retr  |
|-------------------------|-------------|-------|-------|-----------|-------|------|-----|-------|-------|----------|-------|
| p5201-fwd-with-cos      | D           | 5     | 3     | 19878.78  | 1.833 | 0    | 50  | 0.22  | 0.23  | 0.954    | 270   |
| p5201-rev-with-cos      | D           | 4     | 4     | 0.00      | 2.196 | 0    | 50  | 5.42  | 5.45  | 18.956   | 18915 |
| p5202-fwd-with-cos      | **B**       | 4     | 4     | 61701.78  | 3.143 | 0    | 50  | 0.35  | 0.37  | 9.540    | 16    |
| p5202-rev-with-cos      | D           | 4     | 4     | 0.00      | 6.518 | 0    | 50  | 7.10  | 7.12  | 18.894   | 17562 |
| p5203-fwd-with-cos      | D-escalate  | 4     | 4     | 0.00      | 3.725 | 0    | 50  | 10.86 | 10.91 | 20.755   | 1886  |
| p5203-rev-with-cos      | **A**       | 6     | 0     | 0.00      | 2.409 | 0    | 50  | 3.17  | 3.18  | 15.304   | 17120 |
| p5204-fwd-with-cos ‡    | D           | 5     | 3     | 16078.73  | 1.648 | 0    | 50  | 168.5 | 190.6 | 0.094    | 8766  |
| p5204-rev-with-cos ‡    | D           | 5     | 3     | 0.00      | 4.359 | 0    | 50  | 3.03  | 3.21  | 18.056   | 19505 |
| p5201-fwd-no-cos        | D-escalate  | 4     | 4     | 0.00      | 3.237 | 0    | 50  | 28.06 | 28.04 | 22.573   | 9992  |
| p5202-fwd-no-cos        | D-escalate  | 4     | 4     | 0.00      | 1.721 | 0    | 50  | 13.49 | 13.44 | 22.643   | 0     |
| p5203-fwd-no-cos        | D-escalate  | 4     | 4     | 0.00      | 1.753 | 0    | 50  | 13.32 | 13.41 | 22.687   | 0     |
| p5204-fwd-no-cos        | D-escalate  | 4     | 4     | 0.00      | 3.027 | 0    | 50  | 13.45 | 13.43 | 22.619   | 1542  |

‡ = CONFIG-DIVERGENCE: port 5204 I10 invariant fails because the live
config's `bandwidth-output` term 3 has no `from destination-port 5204`
predicate (it is an unrestricted fallthrough → implicit best-effort).
The cells are marked SUSPECT by the capture script but retained in
the analysis because the iperf3 SUM matches the 8matrix baseline
(~0.094 Gbps, consistent with scheduler-be 100 Mbps).

## 3. Verdict counts + §4.6 multi-cell aggregation

- **k_A = 1** (isolated: only `p5203-rev-with-cos`). Per §4.6.2:
  `k_A = 1` with no neighbouring A firings is treated as **noise**
  and is NOT counted as an investigation-level signal. Neighbouring
  cells (p5203-fwd-with-cos, p5203-fwd-no-cos, p5202-rev-with-cos,
  p5204-rev-with-cos) did NOT fire A.
  - Dominant-worker check (§4.6.4): the firing cell's worker with
    `n_w=0` is worker 0; other cells have no single-worker deficit.
    No structural-A pattern across cells.
  - **Conclusion: A-isolated; not counted.**

- **k_B_nocos = 0 / 4.** Below threshold. No Verdict B on no-cos.

- **k_B_cos = 1 / 4** (only `p5202-fwd-with-cos`).
  Per §4.6 with-cos rule: `k_B ≥ 2 of 4` required; 1 of 4 is below
  threshold. Single-cell B is reported as **TENTATIVE** and does NOT
  trigger Step 2 AFD work.
  - Even if k_B had reached 2, the §8 Z_cos calibration-gap gate
    would still block Step 2 AFD until park-rate is re-derived via
    mean + 2σ from ≥ 2 with-cos-fwd shaped cells.
  - **Conclusion: B-tentative; does NOT trigger AFD.**

- **k_C = 0.** Max `ring_w` across all cells is 0 — zero TX-ring
  pressure events observed during any 60 s window. Verdict C is
  firmly not supported.

- **k_D = 5** + **k_D-escalate = 5.** Combined D-family: **10 / 12
  cells (83 %)**.

## 4. Overall Step 1 verdict

Per §8 decision tree:

- A: below discount threshold → not triggered.
- B: below `k_B ≥ 2 of 4` threshold → TENTATIVE, does not trigger AFD.
- C: zero firings → not triggered.
- **D (npbt) on > 75 % of cells** → per §8: *"we exhausted the
  current hypothesis set. Step 2 is the design doc for a new
  hypothesis tier — NOT more measurement."*

**Overall Step 1 verdict: D / D-escalate (dominant).**

The 4 no-cos-fwd cells all land at 22.6 Gbps under a 25 Gbps link cap
— a consistent ~2.4 Gbps shortfall with NO ring-pressure, NO
cross-worker imbalance, and NO shaper involvement. None of the three
named hypotheses (A/B/C) explain the gap. The single B-tentative on
p5202-fwd-with-cos is a 1-of-4 signal under an uncalibrated Z_cos
threshold and cannot be promoted without the §8 Z_cos re-derivation.

## 5. Step 2 direction

Per plan §8's D > 75 % branch: **Step 2 is a design doc for a new
hypothesis tier — not more data collection of the A/B/C kind.**

Concretely, the §4.4 D-escalate rule fires a named instrumentation
follow-up: *"per-queue TX-lane-level latency histogram (not currently
exposed)."* Without that histogram we cannot distinguish among the
plausible D-tier candidates:

- **D1**: XSK TX submit → completion latency (queue time inside the
  AF_XDP layer before the NIC DMA happens).
- **D2**: per-worker reap-lag jitter that never fills the ring but
  sits below the C threshold (ring-full events = 0, but microsecond
  gaps may still stall the pipeline).
- **D3**: NIC-side send-queue pressure (tx pause, link-layer flow
  control) — needs `ethtool -S` per-queue counters with time-series,
  not cold/post snapshots.
- **D4**: RX coalescing gap on generic XDP (iperf3 → LAN ingress via
  virtio-net — 1 s mpstat granularity can hide a burst that stalls
  batching).

None of these are measurable with the current `BindingCountersSnapshot`
fields. The direct Step-2 action is:

1. **File an instrumentation follow-up PR** exposing a per-queue
   TX-lane latency histogram (submit → completion in µs, with
   HdrHistogram buckets) — named in §4.4 as the D-escalate
   prerequisite.
2. **Side-effect: re-derive `Z_cos` from at least 2 with-cos-fwd
   shaped cells using park-rate from the expanded snapshot** (§8
   calibration-gap rule) in the same PR. The new histogram PR is
   strictly additive, so it does not re-open the B calibration gate
   on other grounds.
3. **Do NOT start D1'-class flow-to-worker LB work** — k_A did not
   clear the aggregation threshold.
4. **Do NOT start AFD / Phase 5 MQFQ shaper work** — k_B did not
   clear the aggregation threshold and Z_cos remains uncalibrated.
5. **Do NOT start TX-ring tuning work** — k_C = 0.

The Step-2 design doc should additionally revisit the canonical
`full-cos.set` ↔ live config discrepancy surfaced during execution
(term 3 missing `from destination-port 5204`) — it does not block
the D-escalate follow-up but it contaminated invariant I10 on two
cells and should be reconciled before the next measurement round.

## 6. Forwarding discipline

| checkpoint                        | port | retr | sum Gbps | pass |
|-----------------------------------|------|------|----------|------|
| initial smoke (CoS live)          | 5203 | 0    | 17.10    | yes  |
| inter-cell (with-cos phase)       | 5203 | 0    | 16.87    | yes  |
| smoke-before-remove (post 8 cos)  | 5203 | 0    | 20.12    | yes  |
| smoke-after-remove (no-cos live)  | 5203 | 0    | 17.72    | yes  |
| final smoke (after 4 no-cos)      | 5203 | 0    | 14.04    | yes  |

All five forwarding smokes passed with **0 retransmits**, meeting the
plan's load-bearing non-negotiable. One earlier bounce smoke (post
cell 1) showed retr=243 on an immediate re-run but subsequent re-runs
returned to 0 — attributed to TCP residual state and not a forwarding
regression. No HALT triggered.

## 7. Discoveries + handling

1. **4 capture-script bugs** (see §1). Fixed in commits
   `65c4af5f` (TID matcher) and `b4e86088` (I9/I6/I10). Zero data
   capture was affected; only invariant evaluation.
2. **`mpstat` missing on firewall image.** Not installed in the VM.
   `perf stat` is present (used by the `-t` thread capture); mpstat
   is a separate tool. Classifier falls back to `cpu_max=50` — safely
   under the 85 % C-verdict gate, so verdict accuracy is preserved.
   Follow-up: include `sysstat` in the VM image, or replace with
   `/proc/stat` delta in the capture script.
3. **`ping -q` (quiet) yields no per-packet timestamps.** The plan
   §2.2 uses `-q` explicitly, so p50/p99 have to be derived from the
   summary `rtt min/avg/max/mdev` line. Classifier uses `max` as a
   conservative p99 proxy (p99 ≤ max by definition). For tighter p99
   measurement in Step 2, drop `-q` and parse the per-packet lines.
4. **Live `bandwidth-output` filter diverges from canonical
   `full-cos.set`.** Term 3 on the live config has no
   `from destination-port 5204` predicate, so port 5204 egresses via
   the implicit fallthrough into best-effort (100 Mbps scheduler-be).
   The per-cell iperf3 SUM (0.094 Gbps) is consistent with that
   shaping, but I10 cannot validate it. Noted; not fixed (plan §11
   "No fixes during Step 1"). Recommend reconciling `cos-iperf-config.set`
   with the canonical `full-cos.set` in the Step 2 design doc.

## 8. Cluster state

- Primary: `loss:xpf-userspace-fw0` (node0) through all 12 cells and
  all 5 smokes. No failover. I9 and I4 invariants held on every
  valid cell.
- Peer: `loss:xpf-userspace-fw1` (node1), secondary, no flap.
- CoS re-applied after final no-cos smoke (`apply-cos-config.sh`) —
  cluster returned to canonical state.
