# Issue #816 — Step 1 classifier re-run findings

**Status.** Execution complete. Plan: `docs/pr/816-step1-rerun/plan.md`.
Findings revised under Path A after two-angle Round 1 review
(decision record: `docs/pr/816-step1-rerun/path-decision.md`).

**Target cluster:** `loss:xpf-userspace-fw0` (RG0 primary, verified pre and
post each cell) and `loss:xpf-userspace-fw1` (RG0 secondary). Software:
`userspace-forwarding-ok-20260402-bfb00432-735-g0e2a4b2a` (master,
post-#813, post-#815). Capture host: `loss:cluster-userspace-host`,
server at 172.16.80.200.

**Wall-clock.** Start 2026-04-21T18:35:41Z, end 2026-04-21T19:12:40Z;
total 37 min. Well inside the 120-min budget ceiling.

**Reproducibility.**
- Plan §10 req 4 specified pinned `scipy 1.13.1` / `numpy 1.26.4` per
  `test/incus/requirements-step1.txt`. Capture host Python 3.13 +
  PEP-668 prevented `pip install`; pinned `scipy 1.13.1` source build
  fails under Python 3.13. Implementor proceeded under system-apt
  `scipy 1.16.3` / `numpy 2.3.5`.
- Cross-version determinism is asserted — `scipy.stats.permutation_test`
  signature and `random_state` semantics are stable 1.13→1.16 — but
  **not byte-for-byte verified**. The exact permutation stream under
  the pinned versions is not reproducible from this round's artifacts
  alone.
- Tracked as deferral: **Path B (issue #817)** re-runs the histogram
  classifier against the existing captures under the pinned environment
  to validate. Per Path B's §"When to come back" trigger list, this
  re-run becomes load-bearing if any downstream decision (Phase 4
  scoping under #793, tighter α gate) depends on Monte-Carlo precision.
- Risk: **low** for the D1 H2 verdict (`stat_obs ≈ 0.9` won't move on
  RNG reshuffle); **none** for the D2 downgrade (reclassified as
  exploratory regardless of scipy version — see §2); **none** for the
  non-RNG findings (baseline-outlier, Z_cos bimodality, H3-framing
  correction — all are descriptive / structural, independent of
  permutation p-values).

### Risk-by-finding table — what Path B (#817) closes per finding

(Codex Round 2 MED: explicit close-criteria for the scipy-pin deferral.)

| Finding | RNG-sensitive? | Artifact to recompute under pinned scipy | Close condition for #817 |
|---|:-:|---|---|
| H2 D1 verdict (k_D1 ≥ 2 fires across shaped-fwd cells) | NO — stat_obs ≈ 0.9 dwarfs MC SE | `evidence/with-cos/{p5201-fwd,p5202-fwd}/perm-test-results.json` | Pinned p_D1 ≤ 0.05 on both cells |
| Cleaned-baseline k_D1 = 5 (sensitivity §4) | LOW — p5203-fwd cleaned p=0.0246 is 0.027 above gate | re-run `step1-histogram-classify.py` with run1 dropped from `baseline/fwd-with-cos/` | Pinned cleaned p_D1 stays ≤ 0.05 (or finding gets a sensitivity caveat) |
| Reverse-cell D1 fires (p5201-rev p=0.021, p5203-rev p=0.036) | MEDIUM — within 2× MC half-width of gate | `evidence/with-cos/{p5201-rev,p5203-rev}/perm-test-results.json` | Pinned p_D1 stays ≤ 0.05 OR cell drops to "near-gate LEAD" framing |
| D2 downgrade (k_D2 excluded from verdict) | N/A — downgrade is methodological, not RNG | none | Always closed; D2 stays exploratory regardless of scipy |
| Z_cos bimodal cluster summary | N/A — descriptive | none | Always closed; structural, not statistical |
| H3-framing rejection | N/A — descriptive | none | Always closed; structural, not statistical |
| Baseline-outlier identification | N/A — `baseline-blocks.jsonl` per-run summary | optional pinned re-derivation | Always closed; arithmetic, not RNG |

**Acceptance for #817 closure:** all rows above marked "close condition" pass under the pinned environment. Diff committed as `docs/pr/816-step1-rerun/evidence/scipy-pin-validation.md`. If any reverse-cell D1 fire flips to quiet under the pinned RNG, findings.md §1.1 / §3 require an addendum noting the cell now reports as a near-gate LEAD instead of a fire (does not change the verdict; tightens the per-cell story).

---

## 1. Verdict (plan §8)

**H2 D1.** Per plan §8: *"XSK submit→DMA latency elevated cross-cell."*
`k_D1 = 4` among 11 valid cells, all four fires concentrated on
shaped-traffic and reverse-direction cells; **`k_D2` is withdrawn from
the cross-cell aggregation** (see §2 — D2 is downgraded to
exploratory-only). Step 2 direction is enumerated in §7 and
deliberately stops short of committing Phase 4 scope because the data
does not yet distinguish among candidate mechanisms for elevated
submit→DMA latency.

**Why not H3 multi-channel (rejecting the Round-1 framing).** Plan §2
defines the H3 multi-channel branch as:

> Multiple pre-registered channels fire simultaneously (`k_D1 ≥ 2 AND
> k_D2 ≥ 2`) — **plausibly two symptoms of a shared upstream cause**,
> but the verdict-to-action mapping is ambiguous …

That "plausibly shared upstream cause" condition is load-bearing, and
the data does not meet it:

1. **D2 does not pass a mechanistic significance floor.** The three
   D2 "fires" are on cells with 3-13 raw frames (total across the
   whole 60-second cell) in T_D2's buckets 0-2 — i.e. single-digit
   frames per ~11 M-frame cell. The baseline pool against which D2 is
   scored is **59 / 60 zero blocks**: T_D2 is a degenerate null where
   one nonzero block controls the entire permutation tail. Statistical
   fire ≠ mechanistic fire. Treating this as "channel D2 is firing"
   misreads what the test actually measured.
2. **The two "both-fire" cells are in structurally disjoint regimes.**
   p5202-fwd-with-cos is shaped traffic, mode=5 (8-16 µs submit
   latency), park_rate ≈ 60 k/s, SUM ≈ 9.5 Gbps (shaper-bound).
   p5203-rev-with-cos is reverse-direction line-rate, mode=9
   (256-512 µs), park_rate = 0, SUM ≈ 18 Gbps. These are not two
   symptoms of one upstream cause — they are two different workloads
   whose histograms happen to both clip an under-powered D2 gate.
3. **The H3 out-of-family branch does not fire either.** Exploratory
   bucket-mode argmax lands at bucket 9 (inside D2's nominal window)
   on 9 of 12 cells; bucket 14-15 mass stays below `1e-5` everywhere.
   Neither the "H3 OoF composite" nor the "H3 OoF only" gate of plan
   §8 fires.

So the live branch is H2 D1.

### 1.1 Per-cell stat_D1 heterogeneity (the fires are not uniform)

The four D1 fires span ~80× in effect size (largest/smallest stat_obs ratio = 0.969 / 0.0124 ≈ 78×):

| cell | `stat_D1` | p_D1 | regime |
|---|---:|---:|---|
| p5201-fwd-with-cos | 0.969 | 0.0001 | shaped 1 Gbps, mode=4, near-theoretical max |
| p5202-fwd-with-cos | 0.885 | 0.0001 | shaped 10 Gbps, mode=5, near-theoretical max |
| p5201-rev-with-cos | 0.0169 | 0.0206 | reverse line-rate, mode=9, just above gate |
| p5203-rev-with-cos | 0.0124 | 0.0355 | reverse line-rate, mode=9, just above gate |

`stat_D1` is the Fisher-Pitman test statistic
(`mean(cell_T_D1) − mean(base_T_D1)`), with T_D1 being the per-block
mass fraction in buckets 3-6. A `stat_obs` of 0.97 means the cell's
T_D1 mean is ~97 percentage-points above the baseline mean —
near-saturated distributional separation. A `stat_obs` of 0.012 means
it is ~1.2 percentage-points above, which clears α = 0.05 because the
baseline's per-block stdev is small in absolute terms (the signal is
small too). Binary `fire = True` collapses these two regimes into one
column and hides the fact that **only the two shaped-forward cells
show a near-theoretical-max D1 signature**. `summary-table.csv` now
carries `stat_D1` / `stat_D2` columns so this heterogeneity is visible
to downstream consumers, not just in the per-cell JSONs.

### 1.2 The shaped-forward cells are the load-bearing D1 evidence

p5201-fwd-with-cos and p5202-fwd-with-cos are the cells that scope
H2 D1 as a real mechanistic claim. They are:

- shaped by the MQFQ scheduler at 1 Gbps / 10 Gbps respectively;
- consistent with "submit→DMA path is fast-and-narrow when the shaper
  holds traffic to the configured class-rate" (mode in buckets 4-5,
  4-64 µs);
- associated with the largest park-rate observations in the matrix
  (§1.3) — parks are the MQFQ throttle's signature;
- `stat_D1 ≈ 0.9` — distributional separation is near maximum.

The two reverse-direction fires (p5201-rev, p5203-rev) are mode-9
cells with tiny `stat_D1` right at the gate; they are consistent with
the H2 D1 framing but are not independently strong.

### 1.3 Z_cos derivation — retracting the single-number figure

Park-rate observations on `with-cos-fwd` cells:

| cell | park_rate (/s) |
|---|---:|
| p5201-fwd | 19,867 |
| p5202-fwd | 59,624 |
| p5203-fwd | 0 |
| p5204-fwd | 16,058 |

**Round 1 reported `Z_cos = mean + 2σ = 74,552 parks/s`. That figure
is withdrawn.**

```
Park-rate observations on with-cos-fwd cells: [19867, 59624, 0, 16058].
The distribution is visibly bimodal (line-rate p5203-fwd = 0; shaped
cells = 16058-59624 parks/s, n=3). A Gaussian mean+2σ summary is the
wrong statistic for bimodal data and produces a number that
corresponds to no real operating point. Replacement summary:
{line-rate cluster: 0 parks/s; shaped cluster: 19867-59624 parks/s,
n=3}. Phase 4 / AFD calibration must stratify Z_cos by scheduler-
bound vs line-rate ports; no single threshold is derivable from n=4
observations that include a zero.
```

The plan's 500-parks/s placeholder is simultaneously ~33× too low for
the shaped cluster and ~∞× too high for the line-rate cluster —
the right calibration shape is two thresholds conditioned on whether
a shaper is engaged on the interface, not one number.

---

## 2. Per-cell verdict table

Legend: `verdict_abcd` from `test/incus/step1-classify.sh` (existing
A/B/C/D thresholds per plan §5). `stat_D1` / `stat_D2` are the
Fisher-Pitman test statistics (cell-mean minus baseline-mean).
Binary `D1 fire` = `p_D1 ≤ 0.05 AND not suspect`. **`D2` column is
statistical-only — retained for transparency but excluded from the
verdict aggregation per the degenerate-null problem described below.**
`mode` = argmax bucket of the cell-level summed histogram.

| cell | pool | A/B/C/D | SUSPECT | p_D1 | stat_D1 | D1 | p_D2 | stat_D2 | D2 (stat-only) | mode | b10-13 max | b14-15 |
|---|---|:-:|:-:|---:|---:|:-:|---:|---:|:-:|:-:|---:|---:|
| with-cos/p5201-fwd | fwd-with-cos | D | no | 0.0001 | 0.969 | **fire** | 1.000 | −2.1e-09 | — | 4 | 0.0001 | 0 |
| with-cos/p5201-rev | rev-with-cos | D | no | 0.0206 | 0.0169 | **fire** | 1.000 | −1.6e-09 | — | 9 | 0.158 | 2.8e-6 |
| with-cos/p5202-fwd | fwd-with-cos | B | no | 0.0001 | 0.885 | **fire** | 0.0120 | 2.0e-08 | **stat-fire** | 5 | 0.0006 | 0 |
| with-cos/p5202-rev | rev-with-cos | D | no | 0.930 | −0.0067 | — | 0.0241 | 1.0e-07 | **stat-fire** | 9 | 0.183 | 6.2e-7 |
| with-cos/p5203-fwd | fwd-with-cos | D-esc | no | 0.629 | −0.0026 | — | 1.000 | −2.1e-09 | — | 9 | 0.117 | 0 |
| with-cos/p5203-rev | rev-with-cos | D | no | 0.0355 | 0.0124 | **fire** | 0.0465 | 2.3e-08 | **stat-fire** | 9 | 0.181 | 1.2e-6 |
| with-cos/p5204-fwd | fwd-with-cos | D | **I12** | — | — | — | — | — | — | 4 | 3.7e-5 | 0 |
| with-cos/p5204-rev | rev-with-cos | D-esc | no | 0.780 | −0.0043 | — | 1.000 | −1.6e-09 | — | 9 | 0.171 | 3.6e-6 |
| no-cos/p5201-fwd | fwd-no-cos | D-esc | no | 0.0600 | 0.0080 | — | 0.298 | 4.9e-09 | — | 9 | 0.180 | 7.0e-6 |
| no-cos/p5202-fwd | fwd-no-cos | D-esc | no | 0.968 | −0.0079 | — | 1.000 | −1.7e-09 | — | 9 | 0.222 | 2.7e-6 |
| no-cos/p5203-fwd | fwd-no-cos | D-esc | no | 0.972 | −0.0085 | — | 1.000 | −1.7e-09 | — | 9 | 0.223 | 2.3e-6 |
| no-cos/p5204-fwd | fwd-no-cos | D-esc | no | 0.968 | −0.0079 | — | 1.000 | −1.7e-09 | — | 9 | 0.226 | 2.3e-6 |

**D2 is exploratory-only — it is not counted in `k_v`.** Framing:

- "Statistical fire at α = 0.05 on 3 cells, but effect sizes
  (3-13 raw frames per 60-second cell out of tens of millions) are
  below any plausible mechanistic floor."
- "Baseline pools have 59 / 60 zero blocks for T_D2 — degenerate null
  distribution. Permutation test is mathematically defined but
  operationally meaningless at this scale."
- "`k_D2 = 3` is removed from the cross-cell aggregation that drives
  the verdict; D2 column retained in the per-cell table for
  transparency."

Breakdown of raw b0-2 frame counts on the three D2 stat-fire cells
(computed directly from `hist-blocks.jsonl`):

| cell | total raw b0-2 frames | nonzero-b02 blocks | cell-total completions |
|---|---:|:-:|---:|
| p5202-fwd-with-cos | 5 (1 + 2 + 1 + 1) | 4 / 12 | ~55 M |
| p5202-rev-with-cos | 13 (2 + 11) | 2 / 12 | ~97 M |
| p5203-rev-with-cos | 3 (1 + 2) | 2 / 12 | ~96 M |

One-sentence-per-cell narrative:

- **p5201-fwd-with-cos (D, D1 fires, `stat_D1` ≈ 0.97):** Shaped at
  1 Gbps; mode=4 (8-16 µs); near-theoretical-max D1 — the clearest
  submit→DMA signature in the matrix.
- **p5201-rev-with-cos (D, D1 fires, `stat_D1` ≈ 0.017):** Reverse
  direction (WAN→LAN ingress); 18 Gbps SUM; mode=9 with 16 % b10-13
  tail; `stat_D1` just over the gate.
- **p5202-fwd-with-cos (B, D1 `stat_D1` ≈ 0.89, D2 stat-only):** Shaped
  at 10 Gbps; park_rate 59,624 / s drove A/B/C/D verdict B; D1 near
  maximum. D2 stat-fire rests on 5 frames total in b0-2 across 12
  blocks — reported for completeness, not for mechanism.
- **p5202-rev-with-cos (D, D2 stat-only):** Reverse 18 Gbps, mode=9;
  D2 stat-fire rests on 13 frames in b0-2 across 12 blocks, 11 of
  them in a single block. Not mechanistically meaningful.
- **p5203-fwd-with-cos (D-escalate, quiet):** Unshaped-equivalent at
  25 Gbps; histogram shape matches no-cos baseline (`p_D1 = 0.629`,
  `p_D2 = 1.0`) — NOT a D1/D2 signal, pure D shortfall. **Sensitivity
  note:** cell mean T_D1 = 0.0248; dropping the run1 baseline outlier
  (§4) would push the comparison baseline from 0.0274 to 0.0181,
  making the cell-vs-cleaned-baseline ratio ~1.4× — still below any
  reasonable fire threshold, but the quiet call becomes less quiet.
- **p5203-rev-with-cos (D, D1 fires `stat_D1` ≈ 0.012, D2 stat-only):**
  Second "both-fire" cell in the Round-1 framing — but D2 rests on
  3 frames.
- **p5204-fwd-with-cos (D, SUSPECT via I12):** Shaped at 100 Mbps;
  block count floor holds but pool-ratio fails (< 0.05). Excluded
  from `k_v`. `perm-test-results.json` now emits `null` (not bare
  `NaN`) for unavailable numerics — strict-JSON fix per §8.
- **p5204-rev-with-cos (D-escalate, quiet):** Reverse 17 Gbps; no
  signal.
- **no-cos/p5201-fwd (D-escalate, quiet):** 20 Gbps; p_D1 = 0.06
  borderline but does not cross the 0.05 gate.
- **no-cos/p5202-fwd (D-escalate, quiet):** 21.7 Gbps; shape matches
  baseline.
- **no-cos/p5203-fwd (D-escalate, quiet):** 21.7 Gbps; shape ≡
  baseline (it IS a draw from the baseline distribution — p ≈ 0.97).
- **no-cos/p5204-fwd (D-escalate, quiet):** 21.7 Gbps; shape matches.

---

## 3. Cross-cell aggregation

From `test/incus/step1-classify.sh` (A/B/C/D verdicts, reconciled
directly from the committed `evidence/{with-cos,no-cos}/*/verdict.txt`
files):

| letter | count |
|---|---:|
| A | 0 |
| B | 1 |
| C | 0 |
| D | 5 |
| D-escalate | 6 |

(The prior revision of this document reported `D = 6, D-escalate = 5`;
that was prose-vs-CSV drift. The machine-readable `verdict.txt` files
and `summary-table.csv` agree on `D = 5, D-escalate = 6`; findings is
now aligned.)

`k_A = 0`, `k_B = 1 of 4 with-cos-fwd`, `k_C = 0` — all below A/B/C
thresholds per plan §5.

From the histogram classifier (Fisher-Pitman, 10,000-resample
permutation, α = 0.05, one-sided, seed = 42):

| channel | k_v (fires) | denominator | gate | included in verdict |
|---|---:|---:|---|---|
| D1 | 4 | 11 | **CROSSES** (k ≥ 2) | yes |
| D2 | 3 (stat) | 11 | crosses statistically | **no — exploratory only per §2** |

11 denominators (12 cells minus the SUSPECT p5204-fwd-with-cos).

The `k_D1 = 4` fire plus the regime split in §1.1 (two shaped-forward
cells at `stat_D1 ≈ 0.9`, two reverse cells at `stat_D1 ≈ 0.01-0.02`)
is the load-bearing positive finding of this round. D2's statistical
`k = 3` is not evidence of a channel firing — see §2's raw-frame-count
breakdown and the degenerate-null framing.

---

## 4. Baseline outlier (new subsection — not in Round 1)

`evidence/baseline/fwd-with-cos/run1` is a **3.5× T_D1 outlier**
relative to runs 2-5:

| run | mean T_D1 | mean T_D2 | zero T_D2 blocks |
|---|---:|---:|:-:|
| run1 | 0.0649 | 1.03e-08 | 11 / 12 |
| run2 | 0.0180 | 0        | 12 / 12 |
| run3 | 0.0168 | 0        | 12 / 12 |
| run4 | 0.0180 | 0        | 12 / 12 |
| run5 | 0.0194 | 0        | 12 / 12 |

- Runs 2-5 are tightly clustered (stdev ≈ 0.0009 on T_D1).
- run1 at `mean T_D1 = 0.0649` is ~3.5× higher than the runs-2-5
  mean of 0.0181.
- **run1 is the sole contributor to every nonzero T_D2 block in the
  fwd-with-cos pool.** The one nonzero T_D2 block in the entire
  60-block pool came from run1.

This violates the Fisher-Pitman exchangeability assumption on which
the D1 p-values for `fwd-with-cos` cells depend. The pooled mean for
fwd-with-cos T_D1 is 0.0274 — ~60 % of that pooled mean comes from
run1 alone.

<!-- Codex Round 2 LOW: stale evidence/summary-table.csv removed; the
canonical summary-table.csv at docs/pr/816-step1-rerun/summary-table.csv
is the single artifact. -->

**Sensitivity analysis (run1 dropped) — re-run with the actual classifier
(`scipy.stats.permutation_test`, `random_state=42`, `n_resamples=10000`,
48-block cleaned baseline):**

| cell | full-baseline p_D1 | full stat_D1 | cleaned p_D1 | cleaned stat_D1 | cleaned fire? |
|---|---:|---:|---:|---:|:-:|
| p5201-fwd-with-cos | 0.0001 | +0.969 | 0.0001 | +0.979 | YES (was YES) |
| p5202-fwd-with-cos | 0.0001 | +0.885 | 0.0001 | +0.895 | YES (was YES) |
| p5203-fwd-with-cos | 0.629  | −0.003 | **0.0246** | **+0.00677** | **YES (was NO)** |

- **p5203-fwd-with-cos flips from D1-quiet to D1-fire** when run1 is
  removed from the baseline pool. Codex Round 2 caught this; the
  prior version of this section understated the effect ("still below
  any reasonable fire threshold") and was wrong. Recomputed with the
  same permutation-test machinery the verdict run used.
- **p5201-fwd and p5202-fwd** are insensitive to run1 — `stat_obs`
  near 0.9 is far above any baseline-mean perturbation of order 0.02.
- **p5204-fwd** stays SUSPECT via I12 in either scenario.

**Cleaned-baseline `k_D1 = 5`** (vs full-baseline `k_D1 = 4`). The H2
D1 verdict not only survives, it strengthens — three shaped-forward
cells fire D1 instead of two. The full-baseline result was a
*conservative* read of the same signal; the cleaned-baseline read is
the more accurate one. Reverse cells and D2 channel are unaffected
(verified by re-running the classifier with run1 dropped on each).

**Action for future rounds.** Baseline runs must pass a
**per-baseline-run sanity check** before pooling — re-classify each
baseline run against the others and reject any run whose T_D1 mean is
more than 2× the median of the remaining runs. This would have caught
run1 automatically in this round. Deferred to the Step 2 design doc
under #793 scoping (§7 below). Not blocking for the Path A verdict
because D1 is robust to run1 on the load-bearing cells and the
exchangeability risk is documented here.

---

## 4A. Exploratory narrative (descriptive, not verdict-bearing)

### 4A.1 Histogram shape regimes observed

The data splits cleanly into three regimes:

1. **Shaped low-rate (p5201-fwd, p5202-fwd, p5204-fwd with-cos):**
   sub-µs → tens-of-µs submit latencies dominate. Mass concentrated
   in buckets 3-6 (4-64 µs). `park_rate` is large (16 k – 60 k/s)
   because the MQFQ scheduler is throttling these classes against
   the configured shaper — parks are expected here.
2. **Unshaped high-rate (all no-cos, 5203-fwd-with-cos): bimodal,
   mode at bucket 9 (256-512 µs), 22-32 % tail at b10-13 (0.5-8 ms).**
   This is the "D" regime. The tail mass is consistent across no-cos
   ports (0.180-0.226) — structural, not port-specific.
3. **Reverse direction (all ×-rev with-cos):** similar bimodal shape
   with mode at bucket 9 and 16-18 % b10-13 tail. Reverse traffic is
   LAN-side ingress (WAN → LAN), so the TX-submit latency we're
   measuring is on ge-0-0-1 (trust/LAN) where the traffic is
   unshaped (100 Gbps physical, no CoS filter applied).

Nine of twelve cells exhibit the mode=9 high-tail regime
(regimes 2 + 3); three cells (the shaped-forward ones) sit in regime 1
with mode ∈ {4, 5}. The b10-13 max value ranges 0.117-0.226 across
the nine regime-2/3 cells.

### 4A.2 Out-of-family tail — structural, but not a Step 2 scope
    commit

The b10-13 mass sits at 11-23 % of completions in the 0.5 ms – 8 ms
range on nine cells, with b14-15 below 1e-5 everywhere. It is NOT
the LLFC / pause-frame signature (which would saturate bucket 15)
and it is NOT within D2's nominal 32-512 µs window (it sits above
it). It is a descriptive shape — **not a classifier fire**: plan §8's
H3 OoF composite gate requires "bucket-mode argmax in 10-13 on ≥ 2
cells", and bucket-mode argmax is 9, not 10-13. This is not a channel
or verdict; it is shape context.

Candidate explanations (not discriminated by this round's data):
post-reap tail latency where a busy CPU or completion-ring contention
holds a completion in "submitted-but-not-yet-reaped" state; or NAPI
budget exhaustion that leaks the TX submit-latency measurement past
the 512 µs boundary. Both are enumerated in §7 candidate mechanism
list — neither is confirmed.

### 4A.3 D3 LEAD check

`bucket_14_15_mass_fraction` across all 12 cells: max ~7e-6,
below the 1 % plan §4.5 LEAD gate. **No D3 LEAD fires.**
The LLFC / pause-frame hypothesis remains unsupported by this
round's data.

---

## 5. Concluding verdict

**H2 D1 (XSK submit→DMA latency elevated cross-cell on shaped-traffic
cells).** Per plan §8:

> *"XSK submit→DMA latency elevated cross-cell."* → Scope #793
> Phase 4 against in-AF_XDP submit-path queueing / per-CPU NAPI
> drift / sendto kick regressions.

Data supporting the verdict:

- `k_D1 = 4 of 11` valid cells cross the α = 0.05 gate.
- Two of those fires are **near-theoretical-max** effect sizes
  (`stat_D1 ≈ 0.97, 0.89` on p5201-fwd and p5202-fwd with-cos); both
  are shaped-traffic cells. The other two are just above gate and
  sit in the reverse-direction line-rate regime.
- `k_D2 = 3` is statistically defined but mechanistically meaningless
  (3-13 raw frames per 60-second cell over a 59 / 60-zero-block
  null). D2 is downgraded to exploratory-only and excluded from the
  cross-cell aggregation.
- The H3 multi-channel branch of plan §2 / §8 is rejected because
  its "plausibly shared upstream cause" condition is not met: the
  "both-fire" cells sit in structurally disjoint regimes (shaped
  10 Gbps vs reverse 18 Gbps), and D2 does not pass mechanistic
  significance.
- No H3 out-of-family branch fires either: bucket-mode argmax lands
  in D2's nominal window (bucket 9) on 9 of 12 cells, not at 10-13;
  b14-15 stays below 1e-5.
- A/B/C/D tier is D-dominant as expected (`k_B = 1`, all below §5
  thresholds).

The verdict commits to **direction** — submit→DMA latency is elevated
on shaped cells. Step 2 (§7) must still discriminate the mechanism;
this round's data does not yet distinguish among candidate causes,
so §7 does not commit Phase 4 scope.

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
  pool has 60 blocks (5 runs × 12 blocks/run), all passing I1-I10.
  **Note:** H-STOP-5 is a *count* gate; it did not catch the run1
  outlier documented in §4, which is a *distribution* drift inside a
  passing count. Future plans should add a per-run sanity gate.
- **Budget ceiling (120 min):** 37 min actual. No rescope needed.

**I11 (per-block count floor ≥ 1000 completions):** PASS on all 12
cells. Lowest observed: p5204-fwd-with-cos ~68 k per block.

**I12 (cell-vs-pool median count ratio ∈ [0.05, 20]):** PASS on 11
cells; **FAIL on p5204-fwd-with-cos** (ratio < 0.05 vs fwd-with-cos
pool median). Cell marked SUSPECT; D1/D2 statistics now set to
strict-JSON `null` (was bare `NaN` in Round 1 — see §8); cell
excluded from `k_v` denominator. This matches plan §4.3 and §6 I12
footnote: the shaped 100-Mbps port naturally has ~250× fewer
completions than the pool (which is dominated by 25-Gbps
p5203-fwd-with-cos). Per-channel denominators are 11 of 12.

**I13 (wire format):** PASS on every snapshot.

---

## 7. Step 2 direction (enumerated candidate mechanisms)

The data shows **D1 fires on shaped-traffic cells**. The data does
**NOT** distinguish among the candidate mechanisms for that elevated
submit→DMA latency. The Step 2 design doc must wire telemetry to
discriminate before committing Phase 4 scope.

Candidate mechanisms (not mutually exclusive) and the telemetry
needed to discriminate each:

1. **Submit → TX DMA stalls under no-shaper backpressure.**
   Telemetry needed: per-worker `xdp_redirect_map` retry-loop
   counter; AF_XDP `sendto` kick latency histogram (separate from
   the existing submit-latency histogram, measured from `sendto`
   issue to syscall return).

2. **RX-side NAPI budget exhaustion leaking into TX scheduling.**
   Telemetry needed: `napi_complete_done` cycle accounting on the
   RX queue; cross-CPU scheduling delay traces between RX softirq
   and TX worker threads.

3. **Kernel scheduler descheduling the worker between `sendto` and
   reap.** Telemetry needed: `sched_switch` events on the worker
   CPU during the 12-block window; voluntary vs involuntary
   context-switch rate per block. A submit→DMA latency elevation
   that correlates with involuntary context switches points at
   scheduler jitter.

4. **Virtualization jitter.** This VM runs on a nested hypervisor.
   Telemetry needed: `KVM_REQ_*` exit reasons via `perf`; HALT /
   IPI frequency on the worker vCPU during the capture window.

5. **iperf3 client-side burstiness.** Telemetry needed: client-side
   per-packet send-time histogram; compare against the server-side
   receive-side jitter. If the client is already bursty, elevated
   submit→DMA latency may be downstream of input waveform shape
   rather than a dataplane issue.

**Explicit framing.** The data shows D1 fires on shaped-traffic cells;
the data does NOT distinguish among (1) – (5). The Step 2 design doc
must wire telemetry to discriminate before committing Phase 4 scope.

The Step 2 design doc must also:

- Restate Z_cos calibration as a **stratified** threshold
  (scheduler-bound vs line-rate), not a single number — per §1.3.
  The plan's placeholder (500 parks/s) and the Round-1 single-number
  `74,552` are both invalid shapes for this telemetry's bimodal
  distribution.
- Re-specify T_D2 with a minimum-count floor (e.g. require ≥ 100
  raw frames in b0-2 for a block to contribute a nonzero T_D2) OR
  re-cut the bucket boundaries; the current T_D2 definition has a
  degenerate null and is not operationally useful at observed
  per-block frame counts. This is a plan-level revision for
  whatever round uses D2 again.
- Add the per-baseline-run sanity gate described in §4 so the next
  round catches its own run1-analogue before it pollutes the pool.

Nothing in this round supports a direct #793 Phase 4 scope commit
beyond the H2 D1 direction. The mechanism is unresolved; Step 2 is
the place to scope the telemetry that will resolve it.

---

## 8. Evidence pointers and reproducibility notes

All evidence under `docs/pr/816-step1-rerun/evidence/`:

- `baseline/{fwd-no-cos,fwd-with-cos,rev-with-cos}/run{1..5}/` — per-run
  captures + pool-level `baseline-blocks.jsonl` (60 blocks each).
- `with-cos/p{5201..5204}-{fwd,rev}/` — 8 with-cos matrix cells each
  with raw capture + `hist-blocks.jsonl` + `perm-test-results.json`.
- `no-cos/p{5201..5204}-fwd/` — 4 no-cos matrix cells, same artifacts.
- `../summary-table.csv` — cross-cell summary table (this Path A
  revision adds `stat_D1` / `stat_D2` columns so reviewers can see
  effect-size heterogeneity — a binary fire= column collapsed
  `stat_obs ≈ 0.97` and `stat_obs ≈ 0.012` into the same cell).
- `../plan.md` — the plan this round executed.
- `../path-decision.md` — the Path A vs Path B decision record
  (Round 1 MERGE NO × 2; this findings is the Path A revision).
- `../methodology-findings-review.md`,
  `../codex-findings-review.md` — Round 1 review artifacts this
  revision addresses.

Classifier script: `test/incus/step1-histogram-classify.py`
(this revision emits strict-JSON `null` for suspect-cell `p` and
`stat_obs` instead of bare `NaN`; prior round's
`evidence/with-cos/p5204-fwd/perm-test-results.json` has been
patched to match. Codex Round 1 LOW-3.).

Capture script: `test/incus/step1-capture.sh` (unchanged from
pre-#816). Canonical CoS fixture: `test/incus/cos-iperf-config.set`
(updated earlier in this PR per plan §3.2 to include port-5204 term 3
with `from destination-port 5204` and `count best-effort`; also
adds inet6 parity for the 5203 + 5204 terms).

**Deferred to Path B (issue #817):** re-run the histogram classifier
under the pinned `scipy 1.13.1` / `numpy 1.26.4` environment against
the existing evidence tree; no new captures required (histogram
analysis is pure post-processing). Acceptance criteria: byte-for-byte
agreement on verdict letters and sign of `stat_obs`; numeric agreement
on p-values within Monte-Carlo 95 % CI half-width. Triggered load-
bearing if any downstream decision (Phase 4 scoping, tighter α gate)
depends on Monte-Carlo precision.

---

*End of findings (Path A revision). Next step: Phase 2 two-angle
findings review Round 2; on MERGE YES × 2, close #816 with the
H2 D1 verdict and open the Step 2 design-doc issue per §7.*
