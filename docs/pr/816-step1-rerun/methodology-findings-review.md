# Second-angle Findings Review — stats & methodology

**Commit reviewed:** `9f789d87`. Artifacts: `docs/pr/816-step1-rerun/findings.md`,
`evidence/…/perm-test-results.json`, `evidence/baseline/*/baseline-blocks.jsonl`,
`test/incus/step1-histogram-classify.py`.

**Angle:** statistical soundness, exchangeability, effect-size interpretability.
Codex covers correctness & verdict arithmetic in parallel; I intentionally do
not touch those.

---

## HIGH-M1 — T_D2 fires are counted on single-digit frame events: the D2 verdict is a frame-counting artifact, not signal

`evidence/with-cos/p5202-fwd/perm-test-results.json` reports `D2 p=0.0120,
fire=true, stat_obs=2.0e-08`. Manual recomputation from
`hist-blocks.jsonl` shows the **entire** p5202-fwd cell T_D2 signal comes
from **5 raw frames total** landing in buckets 0-2 (ranges `[0, 4) µs`),
spread across 4 of 12 blocks (1, 2, 1, 1 frame). Total completions in the
cell: ~55 million. That is 5 frames in 11-million-frame blocks — basically
a Poisson(λ ≈ 0.4/block) fluctuation.

The other two D2-fire cells are in the same regime:

- `p5203-rev-with-cos` — 3 total frames in b0-2 across 12 blocks of ~8 M
  each (stat_obs 2.3e-08, p=0.0465 — right on the gate).
- `p5202-rev-with-cos` — 13 total frames across 12 blocks, 11 of them in
  one single block (stat_obs 1.0e-07, p=0.0241).

The baseline pools' T_D2 is worse: `rev-with-cos` baseline has **T_D2 = 0
in 59 of 60 blocks** (one outlier block in run1 carries the entire pool
mean). `fwd-no-cos` same — 59/60 zero. So the null against which a "D2
fire" is being measured is a degenerate distribution with one spike. The
Fisher-Pitman test on a near-all-zero baseline is mathematically defined,
but the permutation null tail is driven by which **single block** gets
reshuffled into the cell side. Reporting these p-values to 4 decimal
places at α=0.05 and then calling it "D2 channel fires" is not a defensible
statistical claim — it is frame-count noise crossing the nominal gate.

**File:line:** `findings.md:92-103` (verdict table D2 "fire" column);
`test/incus/step1-histogram-classify.py:166-171` (T_D2 definition);
`findings.md:148-156` (k_D2=3 verdict).

**Mitigation.** findings.md §2 and §3 must recharacterize D2 as
**"statistically fires at α=0.05 but at effect sizes (3-13 frames per
60 s cell) that are below any plausible mechanistic floor."** Step 2
direction paragraph must not treat D2 as a confirmed channel — it is a
LEAD at best. The correct operational conclusion is: the T_D2 statistic
as defined in plan §4.2 has a degenerate null for unshaped cells (b0-2
mass is effectively always zero) and an undefined operational meaning at
these scales. Either (a) re-cut T_D2 to require a minimum-count floor
on `m02 × m69 × count` (e.g. require ≥ 100 frames in b0-2 for the block
to contribute a nonzero T_D2 value), or (b) drop D2 from the formal
cross-cell aggregation in this round and carry it as exploratory only.
The H3 multi-channel verdict should be retracted until this is resolved.

---

## HIGH-M2 — Baseline pool `fwd-with-cos` is not exchangeable: run1 is a 3.5× T_D1 outlier

`evidence/baseline/fwd-with-cos/baseline-blocks.jsonl` decomposes to:

| run | mean T_D1 | mean T_D2 |
|-----|----------:|----------:|
| run1 | 0.0649 | 1.03e-08 |
| run2 | 0.0180 | 0 |
| run3 | 0.0168 | 0 |
| run4 | 0.0180 | 0 |
| run5 | 0.0194 | 0 |

Runs 2-5 are tightly clustered (σ ≈ 0.001). Run1 is ~3.5× higher on
T_D1 and is the sole contributor to every nonzero T_D2 block in the
pool. The pooled mean (0.0274) is a weighted lie: 60 % of the pool's
T_D1 mean comes from run1.

This violates the Fisher-Pitman exchangeability assumption the plan §4.3
invokes and on which the p-values depend. Plan §4.3 argues per-pool
baselines are *more* defensible than Round-1's single-pool; the logic
is right, but the *pool itself* fails the same check it was introduced
to enforce. Specifically:

- `p5203-fwd-with-cos` cell gets `p_D1 = 0.629` (quiet). But if run1
  were dropped from the baseline, cell mean T_D1 (0.0248) would be
  ~1.4× the run2-5 baseline mean (0.0181) — potentially a fire.
- Inversely, `p5202-fwd-with-cos` gets `p_D1 = 0.0001` (fires hard).
  That is robust — stat_obs = 0.885 dwarfs any baseline fluctuation
  of order 0.02 — so this specific cell's D1 conclusion stands. But
  the *rate* at which other cells fire depends on how representative
  the baseline is, which it is not.

**File:line:** `findings.md:63-80` (Z_cos table inherits same problem);
`findings.md:171-186` (exploratory narrative assumes pool homogeneity).

**Mitigation.** findings.md must add a subsection documenting the
run1 outlier and quantifying its effect. Either (a) re-run the
permutation test excluding run1 and report both p-values side by
side (sensitivity analysis), or (b) explicitly flag run1 as a
baseline outlier and move it out of the pool with a documented
reason from `control-status-pre.json` (daemon restart timing,
CoS re-apply, etc.). The Z_cos re-derivation (§1.3) is subject to
the same concern — run1's park-rate may also dominate the with-cos-
forward pool; without the per-run Z_cos breakdown we cannot tell.

---

## HIGH-M3 — Z_cos mean+2σ is methodologically unsound for a visibly bimodal distribution

`findings.md:63-80` reports "Z_cos = mean + 2σ = 74,552 parks/s" on
four values `[19 867, 59 624, 0, 16 058]`. Implementor then correctly
observes this is bimodal (0 on p5203-fwd, tens of thousands elsewhere).

A Gaussian mean+2σ summary is the wrong statistic for a visibly
bimodal distribution. The underlying data has two clusters (0 and
~20k-60k) and a mean+2σ of a mixture produces a number that
corresponds to no real operating point of either mode. Implementor
even writes this down ("this distribution… is structurally
port-dependent") and then reports 74,552 anyway as if it were a
threshold.

Findings.md already draws the right conclusion (AFD calibration must
be stratified), but publishing 74,552 as the "re-derivation" risks
someone downstream copy-pasting it as a threshold into code or a
follow-up plan. The single number has no operating meaning.

**File:line:** `findings.md:74` (the 74,552 figure).

**Mitigation.** Replace the single-number Z_cos with: (a) a
two-cluster summary `{line-rate cluster: 0 parks/s, shaped cluster:
19,867–59,624 parks/s (n=3)}`, and (b) an explicit statement that
no single threshold is derivable from n=4 observations that include
a zero. The action ("AFD calibration should split Z_cos by
scheduler-bound vs line-rate") is correct and should stay, but the
74,552 figure should be struck out or qualified as "arithmetic
only, not a threshold."

---

## HIGH-M4 — H3 multi-channel verdict conflates two distinct mechanistic regimes into one hypothesis tier

Plan §2 defines H3 multi-channel as "Multiple pre-registered channels
fire simultaneously — plausibly two symptoms of a shared upstream
cause." The verdict fires because `k_D1 = 4` AND `k_D2 = 3`. But the
two channels are:

- **D1 (buckets 3-6, 4-64 µs mass fraction)** — fires on the three
  shaped-traffic cells (p5201-fwd, p5202-fwd, and mildly p5201-rev
  and p5203-rev): the submit→DMA path sits in the µs regime when the
  shaper holds traffic.
- **D2 (b0-2 × b6-9 bimodality product)** — fires on b0-2 *single-
  frame* events in p5202-fwd, p5202-rev, p5203-rev (§HIGH-M1).

The two-cells-both-fire instances are `p5202-fwd-with-cos` and
`p5203-rev-with-cos`. Their aggregated histograms (computed from
`hist-blocks.jsonl`) are **structurally disjoint**:

```
p5202-fwd-with-cos: mode=5, mass 0.92 in b3-6,  b6-9 mass 0.26, b0-2: 9e-8
p5203-rev-with-cos: mode=9, mass 0.07 in b3-6,  b6-9 mass 0.81, b0-2: 3e-8
```

These are not "two symptoms of a shared upstream cause" — they are two
completely different latency regimes (shaped low-rate vs. reverse-
direction line-rate) that happen to co-trip a gate built on a 4-frame
counting fluctuation in the near-zero bucket. The H3 classification
treats them as a single mechanism tier. That framing is wrong.

Adding to the concern: the plan's H3 definition explicitly allows for
"plausibly shared upstream cause," and the classifier cannot distinguish
"two real independent phenomena" from "one shaped cell fluctuating on
D1 while a separate reverse cell fluctuates on D2." A Phase 4 design
doc that starts from "H3 multi-channel: shared upstream cause" will
start from a false premise.

**File:line:** `findings.md:28-41` (verdict statement), `findings.md:189-197`
(§4.2 "two cells with both D1 and D2 firing" — overstates coherence).

**Mitigation.** findings.md §4.2 "both D1 AND D2" narrative needs to
explicitly note that the two dual-fire cells are in different regimes
and that D2 in those cells fires on single-digit frame counts.
Concluding verdict §5 should be softened from "H3 multi-channel
candidate new hypothesis tier" to "D1 signature confirmed cross-cell
on shaped ports; D2 signature is statistically-present-but-
mechanistically-inconsequential — NOT a second hypothesis tier."
This also affects Step 2 scope (§HIGH-M5).

---

## MED-M5 — Step 2 "D4: post-submit reap-hold latency" is a guess dressed as a finding

`findings.md:283-299` names a specific mechanism — "post-submit reap-
hold latency governed by NAPI scheduling and completion-ring
contention" — and lists specific instrumentation to wire
(reap-cadence sampler, `ndo_xsk_wakeup` call-count delta).

Nothing in this round's data distinguishes reap-hold latency from
(a) genuine submit→TX DMA stalls under no-shaper backpressure,
(b) RX-side NAPI budget exhaustion leaking into TX,
(c) kernel scheduler descheduling the worker thread between `sendto`
and reap,
(d) virtualization jitter (this is a VM running on a nested
hypervisor), or
(e) iperf3 client-side burstiness.

The b10-13 mass (0.5-8 ms) is consistent with any of those. Implementor
picks (a)/reap-hold as the named hypothesis without showing why it is
favored over the alternatives. That is a hypothesis generation step,
not a data-driven finding, and naming it in the Step 2 paragraph risks
anchoring the next round's design on the wrong frame.

**File:line:** `findings.md:210-215` (candidate explanation),
`findings.md:286-288` ("D4: post-submit reap-hold latency").

**Mitigation.** Reword §7 to list ≥3 candidate mechanisms and identify
which telemetry each would need to discriminate between them. The
current single-mechanism framing will pre-commit Step 2 to a specific
direction that the data does not support.

---

## MED-M6 — 0.79σ MDE floor claim in findings is not re-validated against observed baseline SDs

Plan §4.1 derives an 80 %-power MDE of ~0.79σ for the 12-vs-60 design
under the pooled-SD scaling assumption `sqrt(1/12 + 1/60)`. findings.md
§1 inherits this number verbatim.

Actual observed pooled standard deviations (from `baseline-blocks.jsonl`
vs the per-cell `hist-blocks.jsonl`) per channel:

| baseline pool | σ(T_D1) | σ(T_D2) |
|---|---:|---:|
| fwd-with-cos | 0.0208 | 1.59e-08 |
| rev-with-cos | 0.0053 | 1.26e-08 |
| fwd-no-cos | 0.0156 | 1.28e-08 |

For the D2 channel the baseline σ is dominated by a single outlier
block (§HIGH-M1). The ratio max/median across pools is 3.9× for σ(T_D1)
and similar for σ(T_D2) — the pooled-SD-within-pool assumption that
Fisher-Pitman relies on is clearly not uniform across the three pools.

findings.md's "0.79σ measurement floor does not invalidate the result"
claim (§1 final paragraph) is true if σ is interpreted as the pool's
own SD, but the D2 channel's pool SD is dominated by a single block
that is itself a rare-event fluctuation. The 0.79σ MDE statement in
findings.md is inherited from the plan without a sanity check against
the realized data.

**File:line:** `findings.md:38-40` ("The 0.79σ measurement floor… does
not invalidate the result").

**Mitigation.** findings.md §1 should add a one-sentence observation
that the D2 channel's pool σ is itself driven by a single outlier
block and that the 0.79σ MDE claim applies to D1 substantively but is
largely meaningless for D2 given the degenerate baseline distribution.

---

## MED-M7 — Monte-Carlo resolution 0.00427 is ~8.5% of α=0.05 — reported p-values near the gate have overlapping confidence intervals

Per plan §4.1 the Monte-Carlo 95% half-width on the p-value estimator
is ±0.00427 at the gate. Three of the four D2-fire p-values are
within 2× that half-width of α=0.05:

| cell | p_D2 | distance from 0.05 | MC 95% half-width |
|------|-----:|-------------------:|------------------:|
| p5203-rev-with-cos | 0.0465 | 0.0035 | 0.0043 |
| p5202-rev-with-cos | 0.0241 | 0.0259 | 0.0043 |
| p5202-fwd-with-cos | 0.0120 | 0.0380 | 0.0043 |

`p5203-rev-with-cos D2` is ~0.8σ below the gate on the Monte-Carlo
estimator itself. A re-run with a different random seed could plausibly
push p_D2 above 0.05, which would drop k_D2 from 3 to 2 — still
crossing the gate but at the edge. Under the assumption of a
non-degenerate null the CIs do not overlap the gate by enough to flip
the k_D2 ≥ 2 verdict. Under the degenerate null in §HIGH-M1 the
analytical MC SE argument is not reliable — the permutation null
itself is structurally degenerate and MC sampling SE is not the
right uncertainty to report.

**File:line:** `findings.md:149-163` (cross-cell aggregation inherits
the p-values at face value without MC-SE-aware discussion).

**Mitigation.** findings.md §3 should add a "Monte-Carlo jitter"
footnote noting that `p5203-rev-with-cos D2=0.0465` is within the
estimator's 95% half-width of the gate and that the verdict depends
on the specific seed=42 draw. Cross-referenced with HIGH-M1 / HIGH-M4
this strengthens the case that k_D2=3 is not a robust cross-cell
signal.

---

## MED-M8 — Effect sizes (stat_obs) are recorded per-cell but not rolled up into the summary table or verdict

Per-cell `perm-test-results.json` carries the correct `stat_obs` values:

| cell | stat_D1 | stat_D2 |
|------|--------:|--------:|
| p5201-fwd-with-cos | +0.969 | −2.1e-09 |
| p5202-fwd-with-cos | +0.885 | +2.0e-08 |
| p5201-rev-with-cos | +0.017 | −1.6e-09 |
| p5202-rev-with-cos | −0.007 | +1.0e-07 |
| p5203-rev-with-cos | +0.012 | +2.3e-08 |

The D1 stat_obs for the two shaped-fwd cells (0.97, 0.89) is enormous
(order 1.0 — close to the theoretical max of 1.0 for a shape fraction).
The D1 stat_obs for the three reverse cells that fire or nearly-fire
is ~0.01-0.02 — two orders of magnitude smaller. A design doc consumer
reading findings.md §2 will see the binary `fire=true` column and
treat all four D1 fires as equally strong; they are not.

**File:line:** `findings.md:91-104` (per-cell verdict table); `summary-
table.csv` missing stat_obs columns.

**Mitigation.** Add `stat_D1` and `stat_D2` columns to the
findings.md §2 table and to `summary-table.csv`. The report already
carries the values; publishing them surfaces the ~100× effect-size
heterogeneity that the binary fire column hides.

---

## LOW-M9 — scipy 1.16.3 vs plan-pinned 1.13.1: the Implementor's claim that determinism carries across is not fully validated

`findings.md:13-23` documents the scipy version drift (1.13.1 pinned,
1.16.3 actually used) and claims "single-host determinism holds" because
"`scipy.stats.permutation_test` signature and deterministic-seed
semantics are unchanged 1.13→1.16."

This is probably true but is asserted without a cross-version
reproduction check. `scipy.stats.permutation_test` between 1.13 and
1.16 saw at least two minor-version refactors (see scipy release notes
1.14.0 and 1.15.0 for permutation-test code churn). The classifier also
uses `np.random.default_rng(seed)` rather than the `random_state=42`
plan spec, which adds another source of across-version variation if
numpy's PCG64 stream changes (it has been stable since 1.17 but not
explicitly guaranteed across major versions like 2.3).

**File:line:** `findings.md:16-23`; `test/incus/step1-histogram-
classify.py:181-183`.

**Mitigation.** findings.md §1 should note that cross-version
determinism is asserted, not verified, and file a follow-up to run
the pinned environment on a separate host and diff the
`perm-test-results.json` files byte-for-byte. Given the p-values
near the gate (HIGH-M1, MED-M7), this matters more than it would
for a clean classifier.

---

## LOW-M10 — `suspect` invariant logic has a dead branch in the classifier

`step1-histogram-classify.py:201-204`:

```python
    suspect = "PASS" not in invariants.values() or "FAIL" in invariants.values()
    # Correct: suspect = any invariant FAIL
    suspect = any(v == "FAIL" for v in invariants.values())
```

The first line is dead code (immediately overwritten). Cosmetic but
hints at code-review churn that did not make it into the plan's
evidence trail.

**File:line:** `test/incus/step1-histogram-classify.py:201-204`.

**Mitigation.** Delete the first line in a cleanup commit. Not
blocking.

---

## Summary table

| ID | Severity | Area | One-line |
|----|----------|------|---------|
| HIGH-M1 | HIGH | statistic validity | T_D2 fires are 3-13 frames in b0-2 — below any mechanistic floor |
| HIGH-M2 | HIGH | exchangeability | fwd-with-cos baseline run1 is a 3.5× outlier dominating the pool |
| HIGH-M3 | HIGH | interpretation | Z_cos mean+2σ is wrong statistic for bimodal data |
| HIGH-M4 | HIGH | hypothesis framing | H3 conflates shaped-D1 and reverse-D2 as one mechanism |
| MED-M5 | MED | Step 2 direction | "D4 reap-hold" is a guess, not a data-supported finding |
| MED-M6 | MED | MDE claim | 0.79σ floor not re-validated against realized pool σ |
| MED-M7 | MED | MC resolution | D2 p-values near gate have overlapping 95% MC CIs |
| MED-M8 | MED | reporting | Binary fire column hides 100× D1 effect-size heterogeneity |
| LOW-M9 | LOW | reproducibility | scipy 1.16 cross-version determinism asserted not verified |
| LOW-M10 | LOW | code hygiene | dead branch in classifier `suspect` logic |

---

## Verdict

Four HIGH findings change the interpretation of the result. HIGH-M1 +
HIGH-M4 together undermine the H3 multi-channel verdict: D2 fires on
single-digit frame counts and the two "both-fire" cells are in
different regimes. HIGH-M2 undermines the baseline pool itself. HIGH-M3
is an isolated reporting error but publishing 74,552 parks/s as a
"re-derivation" will propagate into downstream calibration work.

The D1 signature on **shaped-traffic cells** (p5201-fwd, p5202-fwd) is
a real, large-effect-size signal (stat_obs ≈ 0.9). That part of the
finding is robust and survives all of the concerns above. The D2
signature, the H3 multi-channel framing, and the Step 2 "D4 reap-hold"
direction do not.

ROUND 1: FINDINGS-ACCEPTED NO

Open items: HIGH-M1, HIGH-M2, HIGH-M3, HIGH-M4, MED-M5, MED-M6, MED-M7,
MED-M8, LOW-M9, LOW-M10.

---

## Round 2 verification

**Commit reviewed:** `bd5c18ee` on branch `pr/816-step1-rerun`.
Path-decision at `docs/pr/816-step1-rerun/path-decision.md` (Path A:
in-place revision without re-run; Path B re-run under pinned scipy
deferred to #817).

Per-finding verification against the revised `findings.md`,
`summary-table.csv`, and `evidence/with-cos/p5204-fwd/perm-test-
results.json`:

### HIGH-M1 — D2 downgrade — RESOLVED

`findings.md:62-69` names the degenerate-null framing explicitly.
`findings.md:184-203` downgrades D2 to "stat-fire" with a raw-frame
breakdown table (5 / 13 / 3 frames). `findings.md:273-274` excludes
`k_D2` from the verdict aggregation with "no — exploratory only per
§2". `§7:515-522` adds a plan-level action to re-specify T_D2 with a
minimum-count floor before D2 is used in any future round. The
"statistical fire ≠ mechanistic fire" distinction is now explicit
throughout. Clean.

### HIGH-M2 — baseline run1 outlier — RESOLVED

New `§4 Baseline outlier` (`findings.md:286-336`) documents the per-run
table with the 3.5× outlier quantified. Sensitivity analysis correctly
identifies that p5201-fwd / p5202-fwd fires are insensitive
(`stat_obs ≈ 0.9` is near-saturated) and that p5203-fwd "quiet" call
becomes ~1.4× less quiet (does not flip). `§6:446-449` adds a note
that H-STOP-5 is a count gate and did not catch the distribution drift;
future plans need a per-run sanity gate. Action item is documented
(§4:329-336) and explicitly deferred to Step 2 design doc. Clean.

### HIGH-M3 — Z_cos methodology — RESOLVED

`findings.md:137-138` explicitly withdraws the 74,552 figure. The
replacement summary (`§1.3:141-150`) uses the two-cluster framing I
recommended ("line-rate cluster: 0 parks/s; shaped cluster: 19,867 -
59,624 parks/s, n = 3"). `§1.3:152-155` states "no single threshold is
derivable from n=4 observations that include a zero." AFD calibration
is flagged as needing stratification. `§7:511-516` carries this into
Step 2 direction. Clean.

### HIGH-M4 — H3 multi-channel framing — RESOLVED

Verdict changed to **H2 D1** (`findings.md:41-50`). Round 1's H3
framing is explicitly rejected with three numbered arguments
(`§1:51-82`): (1) D2 does not pass a mechanistic significance floor,
(2) the two "both-fire" cells are in structurally disjoint regimes
(shaped 10 Gbps mode-5 vs reverse 18 Gbps mode-9), (3) the H3
out-of-family branch also does not fire. The disjoint-regime
observation is load-bearing and correctly framed — "not two symptoms
of one upstream cause, but two different workloads whose histograms
happen to both clip an under-powered D2 gate." Clean.

### MED-M5 — "D4 reap-hold" guess — RESOLVED

`§7:468-508` replaces the single-mechanism "D4 post-submit reap-hold"
framing with five enumerated candidate mechanisms (submit→DMA stalls,
RX NAPI budget exhaustion, kernel descheduling, virtualization
jitter, iperf3 client burstiness) each with specific discriminating
telemetry. `§7:506-508` has the explicit "data shows D1 fires on
shaped cells; the data does NOT distinguish among (1) - (5)"
statement. Clean.

### MED-M6 — 0.79σ MDE not re-validated — RESOLVED

Addressed via the HIGH-M1 D2 downgrade framing rather than a separate
discussion of σ heterogeneity across pools. The 0.79σ floor is no
longer invoked in a verdict-bearing way — it survives only as a
plan-level reference, and the D2 degenerate null is the load-bearing
explanation for why D2 is unreliable. Both interpretations reach the
same outcome. Acceptable, but a future plan revision should explicitly
state that the 0.79σ derivation assumes homoscedastic pools and the
realized pools are ~4× heterogeneous in σ. Noted for the Step 2 design
doc; not blocking for this verdict.

### MED-M7 — MC CIs near the D2 gate — RESOLVED BY SUBSUMPTION

With D2 removed from the verdict aggregation (§HIGH-M1), the
MC-resolution concern for D2 p-values is moot. The D1 p-values are
not near the gate on the two load-bearing cells (`p = 9.999e-05` on
p5201-fwd and p5202-fwd). The two near-gate D1 fires (p5201-rev at
p = 0.021, p5203-rev at p = 0.036) are correctly framed in §1.1 as
"just above the gate" with `stat_D1 ≈ 0.012-0.017` — their verdict
contribution is visible in `stat_D1` and the H2 D1 verdict does not
rest on them alone. Acceptable.

### MED-M8 — effect sizes in summary — RESOLVED

`summary-table.csv` now carries `stat_D1` and `stat_D2` columns
(confirmed via line 1 header: `cell,pool,verdict_abcd,suspect,
suspect_reason,i11_pass,i12_pass,i13_pass,p_D1,stat_D1,D1_fire,
p_D2,stat_D2,D2_fire,mode_bucket,oof_10_13_max,b14_15`). Per-cell
table in `findings.md:169-182` adds `stat_D1` / `stat_D2` columns.
`§1.1:85-107` calls out the two-orders-of-magnitude heterogeneity
explicitly. Clean.

### LOW-M9 — scipy version drift — RESOLVED

`findings.md:16-37` documents the unverified cross-version determinism
claim honestly, enumerates the low-risk / no-risk finding categories,
and defers byte-for-byte verification to Path B (issue #817) with
specific acceptance criteria (verdict letters, sign of `stat_obs`,
p-values within MC 95% CI half-width). Fair disposition.

### LOW-M10 — dead branch in classifier — ACKNOWLEDGED

Not addressed in the revised commit (classifier code unchanged per
Path A scope). Non-blocking cosmetic cleanup, as Round 1 flagged.
Accepted deferral.

### Additional sanity checks

- `p5204-fwd/perm-test-results.json` strict-JSON `null` fix verified
  (replaces bare `NaN`). `p_D1`, `stat_obs` both serialize as `null`
  for the I12-suspect cell.
- `summary-table.csv` A/B/C/D counts (`D = 5, D-escalate = 6`) agree
  with `findings.md:257-258`. The prose-vs-CSV drift from the earlier
  revision is called out and reconciled (`§3:260-263`).
- H-STOP-5 inability to catch the run1 outlier is correctly flagged
  in `§6:446-449`.

### Verdict

All 4 HIGH findings are resolved. MED-M5, MED-M7, MED-M8 are resolved;
MED-M6 is resolved-by-subsumption and flagged for a future plan
revision. LOW-M9 has a fair deferral to #817 with acceptance criteria;
LOW-M10 deferred cosmetic. The revised H2 D1 verdict is defensible:
two shaped-forward cells at `stat_D1 ≈ 0.9` are robust, the D2
channel is correctly excluded, and Step 2 direction is constrained
to mechanism-discriminating telemetry rather than a specific
hypothesis.

ROUND 2: FINDINGS-ACCEPTED YES
