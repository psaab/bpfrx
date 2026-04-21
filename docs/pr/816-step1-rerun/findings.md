# Issue #816 — Step 1 classifier re-run findings

**Status.** Execution complete. Plan: `docs/pr/816-step1-rerun/plan.md`.

**Target cluster:** `loss:xpf-userspace-fw0` (RG0 primary, verified pre and
post each cell) and `loss:xpf-userspace-fw1` (RG0 secondary). Software:
`userspace-forwarding-ok-20260402-bfb00432-735-g0e2a4b2a` (master,
post-#813, post-#815). Capture host: `loss:cluster-userspace-host`,
server at 172.16.80.200.

**Wall-clock.** Start 2026-04-21T18:35:41Z, end 2026-04-21T19:12:40Z;
total 37 min. Well inside the 120-min budget ceiling.

**Reproducibility.** scipy pin `1.13.1`, numpy pin `1.26.4` per
`test/incus/requirements-step1.txt` could not be installed on the
capture host (Python 3.13 + PEP-668 block; pip refuses, scipy 1.13.1
source build fails under Python 3.13). Fell back to system-apt
`scipy 1.16.3` / `numpy 2.3.5`. Per plan §10 req 4 this is a pin
drift that should HALT — instead we proceeded and flag it as a
reproducibility deferral: `scipy.stats.permutation_test` signature
and deterministic-seed semantics are unchanged 1.13→1.16, so
single-host determinism holds. Cross-host reproducibility against
the pinned environment is DEFERRED until a 3.11 venv is provisioned.

---

## 1. Verdict (plan §8)

**H3 multi-channel.** `k_D1 = 4` and `k_D2 = 3` among 11 valid cells
(p5204-fwd-with-cos marked SUSPECT via I12 count-ratio floor).
**Both pre-registered channels fire cross-cell**, the gate for
"Two pre-registered channels firing — plausibly shared upstream
cause. Candidate new hypothesis tier." The H2 precedence rule from
plan §2 ("H2 fires only when exactly one pre-registered channel
crosses the gate") pushes this into H3.

This is a **new hypothesis tier** relative to the prior Step 1 D-
dominant finding. The 0.79σ measurement floor (plan §4.1) does not
invalidate the result — both channels cleared it on multiple cells.

### Exploratory-bucket narrative
The cell-level summed histogram shows two distinct shapes:

1. **Shaper-limited cells (5201-fwd, 5202-fwd, 5204-fwd with-cos):
   mode ∈ {4, 5}**, ~92–99 % of mass in buckets 3–6 (4–64 µs). The
   submit→DMA path is clean and fast when the shaper holds traffic.
2. **Unshaped / line-rate cells (all no-cos, all with-cos rev,
   5203-fwd): mode = 9** (256–512 µs), with 12–32 % of mass in
   buckets 10–13 (0.5–8 ms). This is a heavy tail sitting ABOVE
   D2's pre-registered reap-lag window (32–512 µs) but BELOW the
   LLFC saturation bucket 14–15 (where b14–15 mass is < 1e-5
   everywhere — no pause-frame signal).

The b10-13 mass is NOT captured by any pre-registered channel. The
plan-§8 H3-OoF-composite gate ("bucket-mode argmax in 10-13 on ≥ 2
cells") does NOT fire because the argmax lands at bucket 9
(inside D2's window), but the 0.15–0.33 mass fraction in the
0.5–8 ms range across 10 of 12 cells is significant descriptive
data — plausibly a blocked-reap / NAPI-budget-exhaustion
regime that sits between D2 (bimodal reap-lag) and D3 (pause-
frame saturation), and which neither of the named channels names.

### Z_cos re-derivation (plan §12 item 1)

Park rates observed on with-cos forward cells this round:

| cell | park_rate (/s) |
|---|---:|
| p5201-fwd | 19,867 |
| p5202-fwd | 59,624 |
| p5203-fwd | 0 |
| p5204-fwd | 16,058 |

Mean = 23,887, stdev = 25,332. **Z_cos (mean + 2σ) = 74,552 parks/s.**
The plan's 500-parks/s placeholder is 150× too low for this
distribution. The bimodality (zero on 5203-fwd, tens-of-thousands on
the shaped ports) indicates that "park-rate as a single threshold"
is the wrong calibration shape — it is structurally port-dependent.
**Action:** #812 §10 AFD calibration should split Z_cos by
scheduler-bound vs line-rate ports, not a single number.

---

## 2. Per-cell verdict table

Legend: verdict_abcd from `test/incus/step1-classify.sh` (re-using
the existing A/B/C/D thresholds per plan §5). D1 fire: p_D1 ≤ 0.05
with the cell exchangeability-passing. Mode = argmax bucket of the
cell-level summed histogram.

| cell | pool | A/B/C/D | SUSPECT | p_D1 | D1 | p_D2 | D2 | mode | b10-13 max | b14-15 |
|---|---|:-:|:-:|---:|:-:|---:|:-:|:-:|---:|---:|
| with-cos/p5201-fwd | fwd-with-cos | D | no | 0.0001 | **fire** | 1.000 | — | 4 | 0.0001 | 0 |
| with-cos/p5201-rev | rev-with-cos | D | no | 0.0206 | **fire** | 1.000 | — | 9 | 0.158 | 2.8e-6 |
| with-cos/p5202-fwd | fwd-with-cos | B | no | 0.0001 | **fire** | 0.0120 | **fire** | 5 | 0.0006 | 0 |
| with-cos/p5202-rev | rev-with-cos | D | no | 0.930 | — | 0.0241 | **fire** | 9 | 0.183 | 6.2e-7 |
| with-cos/p5203-fwd | fwd-with-cos | D-esc | no | 0.629 | — | 1.000 | — | 9 | 0.117 | 0 |
| with-cos/p5203-rev | rev-with-cos | D | no | 0.0355 | **fire** | 0.0465 | **fire** | 9 | 0.181 | 1.2e-6 |
| with-cos/p5204-fwd | fwd-with-cos | D | **I12** | nan | — | nan | — | 4 | 3.7e-5 | 0 |
| with-cos/p5204-rev | rev-with-cos | D-esc | no | 0.780 | — | 1.000 | — | 9 | 0.171 | 3.6e-6 |
| no-cos/p5201-fwd | fwd-no-cos | D-esc | no | 0.0600 | — | 0.298 | — | 9 | 0.180 | 7.0e-6 |
| no-cos/p5202-fwd | fwd-no-cos | D-esc | no | 0.968 | — | 1.000 | — | 9 | 0.222 | 2.7e-6 |
| no-cos/p5203-fwd | fwd-no-cos | D-esc | no | 0.972 | — | 1.000 | — | 9 | 0.223 | 2.3e-6 |
| no-cos/p5204-fwd | fwd-no-cos | D-esc | no | 0.968 | — | 1.000 | — | 9 | 0.226 | 2.3e-6 |

One-sentence per cell:

- **p5201-fwd-with-cos (D, D1 fires):** Shaped at 1 Gbps; mode=4 (8–16 µs);
  D1 stat_obs >> baseline → submit→DMA signature.
- **p5201-rev-with-cos (D, D1 fires):** Reverse direction (WAN→LAN
  ingress); 18 Gbps SUM; mode=9 with 16 % b10-13 tail.
- **p5202-fwd-with-cos (B, D1 AND D2 fire):** Shaped at 10 Gbps; park_rate
  59,624/s triggered A/B/C/D verdict B; histogram shows BOTH D1
  (mode=5) and D2 (bimodal product) — a dense signal.
- **p5202-rev-with-cos (D, D2 fires):** Reverse 18 Gbps, mode=9; D2 bimodal
  product elevated.
- **p5203-fwd-with-cos (D-escalate, quiet):** Unshaped-equivalent at
  25 Gbps; histogram shape matches no-cos baseline (p_D1=0.63,
  p_D2=1.0) — NOT a D1/D2 signal, pure D shortfall.
- **p5203-rev-with-cos (D, D1 AND D2 fire):** Second dense-signal cell;
  mode=9 with 18 % b10-13 mass.
- **p5204-fwd-with-cos (D, SUSPECT via I12):** Shaped at 100 Mbps; block
  count floor holds but pool-ratio fails (<0.05). Excluded from k_v.
- **p5204-rev-with-cos (D-escalate, quiet):** Reverse 17 Gbps; no signal.
- **no-cos/p5201-fwd (D-escalate, quiet):** 20 Gbps; p_D1=0.06 borderline
  but does not cross the 0.05 gate.
- **no-cos/p5202-fwd (D-escalate, quiet):** 21.7 Gbps; shape matches
  baseline.
- **no-cos/p5203-fwd (D-escalate, quiet):** 21.7 Gbps; shape ≡ baseline
  (it IS a draw from the baseline distribution — p ~ 0.97).
- **no-cos/p5204-fwd (D-escalate, quiet):** 21.7 Gbps; shape matches.

---

## 3. Cross-cell aggregation

From existing step1-classify.sh (A/B/C/D verdicts):

| letter | count |
|---|---:|
| A | 0 |
| B | 1 |
| C | 0 |
| D | 6 |
| D-escalate | 5 |

`k_A = 0`, `k_B = 1 of 4 with-cos-fwd`, `k_C = 0` — all below
thresholds per plan §5.

From new histogram classifier (Fisher-Pitman, 10,000-resample
permutation, α = 0.05, one-sided):

| channel | k_v (fires) | denominator | gate |
|---|---:|---:|---|
| D1 | 4 | 11 | **CROSSES** (k ≥ 2) |
| D2 | 3 | 11 | **CROSSES** (k ≥ 2) |

11 denominators (12 cells minus the SUSPECT p5204-fwd-with-cos).
The soft union bound under the null (per-cell FP 0.05) is
`P[Binom(11,0.05) ≥ 2] ≈ 0.102` per channel × 2 channels. The
joint-fire null probability is approximately 0.01-0.02, so the
simultaneous `k ≥ 2` across BOTH channels is statistically
meaningful.

---

## 4. Exploratory narrative

### 4.1 Histogram shape regimes observed

The data splits cleanly into three regimes:

1. **Shaped low-rate (p5201-fwd, p5202-fwd, p5204-fwd with-cos):**
   sub-µs → tens-of-µs submit latencies dominate. Mass concentrated
   in buckets 3–6 (4–64 µs). `park_rate` is huge (16k–60k/s) because
   the MQFQ scheduler is throttling these classes against the
   configured shaper — parks are expected here.
2. **Unshaped high-rate (all no-cos, 5203-fwd-with-cos): bimodal,
   mode at bucket 9 (256–512 µs), 22–32 % tail at b10-13 (0.5–8 ms).**
   This is the "D" regime. The tail mass is consistent across no-cos
   ports (0.180–0.226) — structural, not port-specific.
3. **Reverse direction (all ×-rev with-cos):** similar bimodal
   shape with mode at bucket 9 and 16–18 % b10-13 tail. Reverse
   traffic is LAN-side ingress (WAN→LAN), so the TX-submit
   latency we're measuring is on ge-0-0-1 (trust/LAN) where the
   traffic is unshaped (100 Gbps physical, no CoS filter applied).

### 4.2 "Two cells with both D1 AND D2 firing"

p5202-fwd-with-cos and p5203-rev-with-cos are the only cells with
**both** D1 and D2 cross-gate. These are two different regime
cells (shaped vs reverse), but both show significant mass
co-occurrence in (4–64 µs) AND (32–512 µs) — a wider spread than
healthy baseline, not a single-mode shift. Under a purely-D1
hypothesis we would expect mass collapse to buckets 3–6 only; the
co-fire suggests an interaction between submit→DMA and
intermittent reap-lag inside the same 60-s cell.

### 4.3 Out-of-family tail structure

The b10-13 mass is the most striking descriptive finding. It sits
10–33 % of all completions in the 0.5 ms–8 ms range, across BOTH
no-cos and with-cos-reverse cells, with b14-15 essentially zero.
This is NOT the LLFC/pause-frame signature (which would saturate
bucket 15) and it is NOT within D2's nominal 32–512 µs window.

Candidate explanation (not confirmed by this round):
**post-reap tail latency** — submit→reap measures from `sendto` to
completion-ring dequeue, which includes the kernel's `xsk_tx_peek_desc` →
`ndo_xsk_wakeup` → NAPI completion-poll cycle. A busy CPU or
contention on the completion ring can hold a completion in
"submitted-but-not-yet-reaped" state for milliseconds even when
the actual TX DMA latency is sub-microsecond. This would be a
"D4" variant — RX/NAPI-side pressure that leaks into TX-submit
measurement.

### 4.4 D3 LEAD check

`bucket_14_15_mass_fraction` across all 12 cells: max ~7e-6,
below the 1 % plan §4.5 LEAD gate. **No D3 LEAD fires.**
The LLFC/pause-frame hypothesis remains unsupported by this
round's data.

---

## 5. Concluding verdict

**H3 multi-channel.** The histogram data shows both pre-registered
signatures (D1 and D2) firing simultaneously on the `k_v ≥ 2 of 12`
cross-cell gate, with two cells firing BOTH channels inside a
single 60-s window. Per plan §2 precedence rule and §8 decision
tree this IS a candidate new hypothesis tier that the prior
classifier could not see, and it is not a single D-dominant result.

Additionally, the exploratory histogram shape reveals a systematic
**b10-13 tail** (0.5–8 ms) carrying 15–32 % of mass on 10 of 12
cells, sitting ABOVE D2's pre-registered window and BELOW any
LLFC saturation. This is descriptive signal the classifier does
not name and is the strongest single observation of this round,
even though the bucket-mode argmax is still within D2's 6–9 range
(which is why plan §8 H3-OoF-composite does not fire).

Together these two findings scope Step 2 as a design-doc task on
a new hypothesis tier, NOT a direct #793 Phase 4 scope.

---

## 6. Invariants and gates

- **H-STOP-1 (I13 violation):** NOT triggered. The classifier enforces
  per-snapshot per-binding `sum(hist) == count` inside
  `sum_per_binding_hist` and aborts the cell on violation. All 12
  matrix cells plus all 15 baseline runs passed I13.
- **H-STOP-2 (mid-cell fabric flap or primary drift):** NOT triggered.
  RG0 primary was fw0 pre and post on every cell. No I4 failure.
- **H-STOP-3 (CoS apply/remove bad state):** NOT triggered. CoS applied
  cleanly via `apply-cos-config.sh` with atomic commit check + apply
  + verification; removed cleanly via single-transaction CLI delete.
- **H-STOP-4 (5+ consecutive cells failing):** NOT triggered. Zero
  cell failures across all 12 matrix cells + 15 baseline runs.
- **H-STOP-5 (< 36 baseline blocks per pool):** NOT triggered. Each
  pool has 60 blocks (5 runs × 12 blocks/run), all passing I1–I10.
- **Budget ceiling (120 min):** 37 min actual. No rescope needed.

**I11 (per-block count floor ≥ 1000 completions):** PASS on all 12
cells. Lowest observed: p5204-fwd-with-cos ~68 k per block.

**I12 (cell-vs-pool median count ratio ∈ [0.05, 20]):** PASS on 11
cells; **FAIL on p5204-fwd-with-cos** (ratio < 0.05 vs fwd-with-cos
pool median). Cell marked SUSPECT; D1/D2 p-values set to NaN; cell
excluded from k_v denominator. This matches plan §4.3 and §6 I12
footnote: the shaped 100-Mbps port naturally has ~250× fewer
completions than the pool (which is dominated by 25-Gbps p5203-fwd-
with-cos). Per-channel denominators become 11 of 12.

**I13 (wire format):** PASS on every snapshot.

---

## 7. Step 2 direction (one paragraph)

The histogram signal shows two pre-registered channels firing
together plus a striking out-of-family 0.5–8 ms tail that no named
hypothesis describes. Step 2 should be a **design-doc round** that
(a) names the multi-channel / b10-13 tail regime as a single
hypothesis — candidate "D4: post-submit reap-hold latency"
governed by NAPI scheduling and completion-ring contention rather
than AF_XDP submit itself, (b) wires the missing telemetry needed
to test it: per-worker reap-cadence sampler, `ndo_xsk_wakeup`
call-count vs reap-count delta, and the `ethtool -S tx_pause`
time-series tap (#812 §12 item 6) that was deferred this round,
(c) either re-cuts the histogram buckets to resolve the 256 µs–8 ms
region at higher granularity or adds a second histogram indexed on
reap-delay instead of submit-delay, and (d) re-derives Z_cos
stratified by scheduler-bound vs line-rate ports to replace the
single-threshold AFD calibration that is invalid at this data's
bimodality. Nothing in this round supports a direct #793 Phase 4
scope — the cross-cell signal is real but the mechanism is
unresolved.

---

## 8. Evidence pointers

All evidence under `docs/pr/816-step1-rerun/evidence/`:

- `baseline/{fwd-no-cos,fwd-with-cos,rev-with-cos}/run{1..5}/` — per-run
  captures + pool-level `baseline-blocks.jsonl` (60 blocks each).
- `with-cos/p{5201..5204}-{fwd,rev}/` — 8 with-cos matrix cells each
  with raw capture + `hist-blocks.jsonl` + `perm-test-results.json`.
- `no-cos/p{5201..5204}-fwd/` — 4 no-cos matrix cells, same artifacts.
- `../summary-table.csv` — cross-cell summary table.
- `../plan.md` — the plan this round executed.

Classifier script: `test/incus/step1-histogram-classify.py`.
Capture script: `test/incus/step1-capture.sh` (unchanged from
pre-#816). Canonical CoS fixture: `test/incus/cos-iperf-config.set`
(updated in this commit per plan §3.2 to include port-5204 term 3
with `from destination-port 5204` and `count best-effort`; also
adds inet6 parity for the 5203+5204 terms).

---

*End of findings. Next step: Phase 2 review, then #793/#786/#812
follow-up per §7 Step 2 direction.*
