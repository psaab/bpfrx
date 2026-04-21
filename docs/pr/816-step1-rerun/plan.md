# Issue #816 — Step 1 classifier re-run on master with TX latency histogram

> **Status.** Architect Round 2 revision. Round 1 Codex review closed
> (see `codex-plan-review.md` §"Round 1 response"). Awaiting Round 2
> Codex hostile review per `docs/development-workflow.md` §Phase 1.
>
> **Scope.** Measurement + analysis. Re-run the 12-cell Step 1 matrix
> on `loss:xpf-userspace-fw0` at current master (post-#813, post-#815)
> using the now-landed `tx_submit_latency_hist` per-binding signal,
> then run a #812 §11.3-derived two-sample Fisher-Pitman block
> permutation classifier on two pre-registered channels (D1, D2) to
> either **confirm** the prior D-dominant verdict or **surface a new
> hypothesis tier** (D1 / D2 signature per #812 §11.1) that scopes
> #793 Phase 4.
>
> **Non-goal.** No code changes to the histogram or daemon. No fix
> work during the measurement. No formal D3 channel this round
> (deferred, see §4.2). Step 1 still produces a *classification*,
> not a fix (step1-plan §8).

## 1. Problem statement

`docs/pr/line-rate-investigation/step1-findings.md` §4 reported:

> "**Overall Step 1 verdict: D / D-escalate (dominant).** … 10 / 12
> cells (83 %) … None of the three named hypotheses (A/B/C) explain
> the gap."

Per step1-plan §8 decision tree
(`docs/pr/line-rate-investigation/step1-plan.md:1100-1102`):

> "If verdict is **D (npbt)** on > 75 % of cells: we exhausted the
> current hypothesis set. Step 2 is the design doc for a new
> hypothesis tier — NOT more measurement."

The named prerequisite for that next tier (step1-plan §4.4
"D-escalate", step1-findings §5) was a per-queue TX-lane-level
latency histogram. That instrumentation **landed in PR #813
(closes #812)** at 2026-04-21 09:00 UTC as merged commit on master.
The live PR validation run (`p5203-fwd`, P=16 t=60) reported mass
concentrated in **buckets 8-11 (256 µs–4 ms)** — a signature that,
per #812 §11.1, points at C (ring full) or D2 (heavy reap-lag
tail), NOT the D1 (submit→DMA shift) regime. Crucially,
step1-findings recorded `ring_w = 0` on every cell, so a bucket-8+
mass that is **not** correlated with `dbg_tx_ring_full` is the D2
signature — a new hypothesis tier that the prior classifier could
not see.

What changed since the prior Step 1 run:

1. `tx_submit_latency_hist`, `tx_submit_latency_count`,
   `tx_submit_latency_sum_ns` per-binding now emitted on the
   `status.per_binding[]` and `status.bindings[]` shapes
   (`userspace-dp/src/protocol.rs:1333-1338` and `:1420-1425`;
   `pkg/dataplane/userspace/protocol.go:682-684` and `:726-728`).
2. `step1-capture.sh` already polls `{"type":"status"}` every 5 s
   × 12 samples (lines 286-309), so the histogram is captured
   **for free** in the existing `flow_steer_samples.jsonl` —
   **no capture-script change is required to fetch it**. Deltas
   are computed by subtracting snapshot `t_i+1 − t_i`.
3. `#814` (MAX_INTERFACES = 65536) landed on master in PR #815
   on 2026-04-21. fw1 is no longer a known-bad failover target.
   H-STOP-2 is rewritten accordingly (§11).
4. What IS new analysis work: a new script
   `test/incus/step1-histogram-classify.py` (committed in the
   same commit that lands this plan, per §10 reproducibility
   invariant) consumes `flow_steer_samples.jsonl`, extracts
   per-block histogram deltas, enforces invariants I11-I13,
   and runs the #812 §11.3-derived Fisher-Pitman permutation
   test on two channels (D1, D2). Full algorithmic spec in §4.6.

## 2. Hypotheses

This re-run tests three mutually-exclusive outcomes. Precedence
rule (resolving Round-1 MED-9): **H2 fires only when exactly one
pre-registered channel crosses the gate; any multi-channel fire or
out-of-family bucket mode is H3.**

- **H1 — D-dominant verdict persists.** Aggregate verdict again
  lands D / D-escalate on > 75 % of valid cells; the histogram
  shows *no* systematic D1/D2 signature (all `k_v < 2`, mass in
  buckets 0-2 across all cells, tail exploratory-only). Per #812
  §11.1 "D confirmed (no new signal)" this means the remaining
  ~2.4 Gbps shortfall is NOT in the TX-completion path — it is in
  RX coalescing (D4) or upstream. **Action:** declare Phase B
  fairness done at the measurement floor; close #786; deprioritize
  #793 until a new signal surfaces.

- **H2 — Histogram reveals exactly ONE pre-registered signature.**
  Exactly one of D1, D2 fires cross-cell (`k_v ≥ 2 of 12`), and the
  other does NOT fire at the `k ≥ 2` threshold. **Action:** findings
  names the signature and scopes #793 Phase 4 concretely.

- **H3 — Histogram reveals something we did not pre-register as H2.**
  This covers:
  - Multiple pre-registered channels fire simultaneously
    (`k_D1 ≥ 2 AND k_D2 ≥ 2`) — plausibly two symptoms of a shared
    upstream cause, but the verdict-to-action mapping is ambiguous
    so findings.md must treat it as a candidate new hypothesis
    tier, not a direct Phase-4 scope.
  - An out-of-family bucket mode (e.g. mass concentrated at buckets
    10-13) that neither D1 nor D2 describes — detected in the
    exploratory histogram-shape table (§4.7).
  - Exploratory D3 telemetry (bucket 14-15 nonzero mass) that would
    need wiring before it can feed the formal classifier (§4.2).
  **Action:** findings.md writes up the signature as a *candidate*
  hypothesis, files a design-doc issue, does NOT push into #793
  Phase 4 until a follow-up round scopes it.

The re-run must distinguish all three branches. The block-
permutation test (§4) is the formal discriminator for H1 vs H2;
the H2-vs-H3 split is resolved by the precedence rule above.

## 3. Execution matrix

### 3.1 Cells

**Re-use the prior 12 cells** from step1-plan §1 (2 CoS-states ×
4 ports × 2 directions, minus the 4 `no-cos-rev` SKIPs):

| # | cos-state | port | dir |
|---|-----------|------|-----|
| 1 | with-cos | 5201 | fwd |
| 2 | with-cos | 5201 | rev |
| 3 | with-cos | 5202 | fwd |
| 4 | with-cos | 5202 | rev |
| 5 | with-cos | 5203 | fwd |
| 6 | with-cos | 5203 | rev |
| 7 | with-cos | 5204 | fwd |
| 8 | with-cos | 5204 | rev |
| 9 | no-cos  | 5201 | fwd |
| 10 | no-cos | 5202 | fwd |
| 11 | no-cos | 5203 | fwd |
| 12 | no-cos | 5204 | fwd |

Each cell follows step1-plan §2's capture protocol verbatim.

### 3.2 p5204 CONFIG-DIVERGENCE resolution — IN SCOPE

step1-findings §1 reported that `p5204-fwd-with-cos` and
`p5204-rev-with-cos` ran SUSPECT under the prior matrix because
`bandwidth-output` term 3 on the live config lacks
`from destination-port 5204`. Unchanged from Round 1:

- Reconcile `test/incus/cos-iperf-config.set` and (if different)
  the live-applied `bandwidth-output` filter with canonical
  `docs/pr/line-rate-investigation/full-cos.set` so that term 3
  has an explicit `from destination-port 5204` predicate.
- Verify post-fix with `cli -c "show configuration firewall
  family inet filter bandwidth-output term 3"` showing the new
  `from destination-port 5204` line.
- Run a smoke `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5204` and
  confirm SUM ≈ 100 Mbps (scheduler-be applies to port 5204).

Fallback: proceed with `p5204-*-with-cos` cells still marked
SUSPECT, and findings.md documents the reduced `k_B` denominator
(3 of 4) with the adjusted binomial FP math inline.

### 3.3 Per-cell captures

No new instrumentation beyond step1-capture. The 13-point snapshot
series the script already writes (1 cold + 12 during-run) supports
exactly **12 non-overlapping 5-second blocks** per cell. Block-
delta indexing `b ∈ 0..=11` (inclusive on both ends — 12 blocks
total; Round 1 LOW-11 off-by-one fix):

```
block_b.bucket_k = sample[b+1].bucket_k - sample[b].bucket_k   (b ∈ 0..=11)
block_b.count    = sample[b+1].count    - sample[b].count
```

### 3.4 Capture script evolution

Audit of `test/incus/step1-capture.sh` versus this plan:

| Does the script fetch `tx_submit_latency_hist`? | YES — transitively. The `{"type":"status"}` payload carries every `BindingCountersSnapshot` field by construction (`protocol.rs:719-720`). |
| Does the script compute per-block deltas? | NO — it writes raw snapshots. Block-delta computation is in `step1-histogram-classify.py` (§4.6). |
| Does the script need a new per-cell hist-delta check? | Minor. An optional log line asserting `tx_submit_latency_count > 0` on each with-cos-fwd snapshot would catch a daemon regression before the full 60 s capture runs. Non-blocking — invariant I13 (§6) covers it post-capture. |

**Conclusion: no `step1-capture.sh` change required for #816.**
Analysis-side changes (new `step1-histogram-classify.py`, §4.6) are
the only deltas.

### 3.5 Runtime budget

Round-2 fix for MED-8 (budget truthfulness): the Round-1 table
underestimated by at least 7 minutes (baseline capture not in table)
and did not account for the per-pool baselines HIGH-2 now requires.
Honest table:

| Activity | Per-unit | Count | Total |
|---|---|---|---|
| Pre-run p5204 config fix | — | — | ~10 min |
| Baseline captures — 3 pools × 5 runs × 60s iperf3 | 60 s + 30 s setup + 30 s teardown | 15 runs | ~30 min |
| Setup + cold captures (matrix) | 30 s | 12 | 6 min |
| iperf3 + concurrent captures (matrix) | 60 s | 12 | 12 min |
| Teardown + deltas + verdict.txt (matrix) | 30 s | 12 | 6 min |
| Inter-cell smoke | 5 s | 11 | ~1 min |
| CoS apply / remove (2 transitions) | ~90 s × 2 | — | 3 min |
| Settling between states | ~30 s | 2 | 1 min |
| Block-permutation analysis (new script, §4.6) | — | 12 | ~15 min |
| Findings write-up | — | — | 10-20 min |
| Re-run buffer | — | — | ~10 min |
| **Sum** | | | **~104-114 min** |

**Target: 100-120 min wall-clock.** Hard ceiling raised to **120 min**
from the prior 90-min ceiling — Round 1 HIGH-2 per-pool baselines
and MED-8 budget honesty force the change, and the cost is
inarguable: 3 baseline pools × 5 runs × 60 s alone adds 15 min of
iperf3 time plus overhead, which was not in the prior table at all.
If the real runtime overruns 120 min, rescope per step1-plan §7:

1. Drop reverse cells first (4 cells worth of setup / teardown).
2. Then drop the matrix-run buffer if still overrun.
3. Baseline captures are NOT droppable — the permutation test is
   undefined without them.

## 4. New analysis step — #812 §11.3 block-permutation classifier

The analysis wiring is the load-bearing novelty of this plan. It
implements the statistical procedure specified in
`docs/pr/812-tx-latency-histogram/plan.md:1302-1471` (§11.3 R3),
adapted for the as-built 5 s sampler cadence.

### 4.1 N_blocks choice — honest derivation

**Design: B = 12 cell blocks (5 s each) vs B_base = 60 baseline
blocks per pool.** Derivation (replacing Round 1 HIGH-1 errors):

- **60 one-second blocks (the #812 §11.3 reference value) on the
  CELL side.** Would require re-architecting the sampler to poll
  at 1 Hz. Rejected: the control-socket sampler's 5-s retry budget
  (step1-plan §2.2, `step1-capture.sh:290-295`) would see 5× the
  contention under concurrent iperf3 load. Rejected.
- **6 ten-second cell blocks.** Too few — the pooled permutation
  null over `C(6 + 60, 6) = C(66, 6) ≈ 9.0 × 10⁷` is fine for
  Monte-Carlo resolution but drives 80 %-power MDE to ~1.05σ.
  Rejected.
- **12 five-second cell blocks + 60 one-second OR 60 five-second
  baseline blocks per pool** (chosen). B_base is captured as
  5 runs × 60 s × sampler = 5 × 12 blocks = 60 five-second blocks
  per pool. Per-pool design is HIGH-2's fix (§4.3 below).

**Partition-count and Monte-Carlo resolution (HIGH-1 fix).**
For the 12-vs-60 design the pooled permutation null has
`C(B + B_base, B) = C(72, 12) = 15 363 284 301 456` unique
partitions (≈ 1.54 × 10¹³). Round-1 text's `C(24, 12) = 2 704 156`
claim was wrong and is withdrawn. With `N_perm = 10 000` Monte-Carlo
draws and a gate near the p-value threshold `p_gate = 0.05`, the
Monte-Carlo estimator's one-σ absolute error on the *p-value
estimate itself* (Bernoulli with success probability `p_gate`) is
`sqrt(p_gate(1−p_gate)/N_perm) = sqrt(0.05 · 0.95 / 10 000) ≈
0.00218`, 95 % half-width ≈ 0.00427. **This is the SE of the
permutation p-value estimator, not the SE of anything based on
per-block frame counts** — the frame-count figures above feed
K_skew dilution, not the permutation Monte-Carlo SE. That is
~8.5 % of α = 0.05 — not "an order of magnitude smaller." Round-1's
"~0.4 % relative error" claim was wrong and is withdrawn. We
accept 0.00427 as the Monte-Carlo resolution; the permutation p
resolution of ±0.5 % around the gate is fine for single-cell
decisions, and the cross-cell `k_v ≥ 2 of 12` aggregation rule
(§4.4) dominates the uncertainty budget anyway.

**Per-block completion volume (HIGH-1 arithmetic fix).** Corrected
1500-byte frame arithmetic:

- `p5203-fwd-no-cos` at ~22.6 Gbps × 5 s / (1500 × 8 bits) ≈
  **9.4 M** frames per 5-s block (was incorrectly stated as 6.3 M).
- `p5201-fwd-with-cos` at ~0.95 Gbps × 5 s / (1500 × 8) ≈
  **0.4 M** frames per block (was 0.26 M).
- `p5204-fwd-with-cos` at ~0.094 Gbps × 5 s / (1500 × 8) ≈
  **39 k** frames per block (was 26 k).

K_skew noise (#812 §3.6: 3 completions / snapshot) dilutes to
`3 / 39 000 ≈ 7.7 × 10⁻⁵` in the worst cell — far below α = 0.05.

**Honest MDE statement (HIGH-1's real fix).** The 80 %-power
standardized minimum detectable effect for the mean-difference
statistic scales as `sqrt(1/B + 1/B_base)`:

| Design | SE factor | 80 %-power MDE (one-sided, α=0.05) |
|---|---|---|
| 60 vs 60 (aspirational #812) | `sqrt(1/60 + 1/60)` | ≈ 0.45σ |
| **12 vs 60 (this plan)** | `sqrt(1/12 + 1/60)` | **≈ 0.79σ** |
| 12 vs 12 | `sqrt(1/12 + 1/12)` | ≈ 1.02σ |

**We accept 0.79σ as the measurement-floor for this re-run.**
Per-channel shifts smaller than ~0.79σ (of the pooled per-block
standard deviation for that channel) may not be detected at 80 %
power and are reportable-floor-adjacent. Findings.md must state
this floor explicitly and flag any single-cell "quiet" result as
"consistent with zero within the 0.79σ floor" rather than
"confirmed absent."

**Why not recover 0.45σ via more blocks?** To move to B = 60 on
the cell side would require a 1-Hz sampler, which introduces
measurement-of-the-measurer hazard under concurrent iperf3 load
(§4.1 rejection above). To increase B_base further has diminishing
returns: going from B_base = 60 to B_base = 120 only drops MDE
from 0.79σ to ~0.76σ (the cell-side B = 12 now dominates the SE).
The right way to tighten the floor in a future round is to add
cell-side repeats (2 × 60 s captures per cell → B_cell = 24 vs
B_base = 60 → MDE ~0.64σ), not extra per-run seconds.

### 4.2 Per-block statistic — two channels (D3 ejected per HIGH-3)

**Round-2 scope change: formal classifier is D1 + D2 only.** D3 is
ejected from the permutation test family and reported as exploratory
telemetry in §4.7. Rationale (HIGH-3 fix): #812's D3 statistic was
`1{tail} × 1{tx_pause > 0}`; `tx_pause` is not in
`BindingCountersSnapshot` and wiring it requires ethtool-scraping
changes to `step1-capture.sh` (#812 §12 item 6), which this re-run
explicitly keeps out of scope. A half-wired "tail indicator only"
is a generic rare-tail detector, not D3, and inheriting #812's
pre-registration / FP story for a different hypothesis is
dishonest. Exploratory telemetry is the honest path.

Per cell, per block `b ∈ {0..=11}` (12 blocks), define:

- **`T_D1,b = mass_b(buckets 3..=6) / count_b`** — 4-64 µs mass
  fraction. Fires on D1 (XSK submit→DMA shift — "latency elevated
  but everything else clean"). Bucket range corrected: buckets
  3..=6 span `[2^12, 2^16) ns = [4 µs, 64 µs)` per
  `userspace-dp/src/afxdp/umem.rs:178-181`. Round-1 prose
  "4-128 µs" was off-by-one and is withdrawn (see §4.7.1 bucket
  table).
- **`T_D2,b = (mass_b(0..=2) / count_b) × (mass_b(6..=9) / count_b)`**
  — bimodality product. Fires on D2 (intermittent reap-lag,
  bimodal histogram). `6..=9` covers `[2^15, 2^19) ns =
  [32 µs, 512 µs)`.
- **D3 is NOT a formal statistic this round.** Bucket 14-15 mass
  is recorded per-cell in the exploratory table (§4.7.2). No
  permutation test on it, no `k_D3 ≥ 2` gate, no LEAD branch. If
  exploratory telemetry shows bucket 14-15 mass ≥ 1 % in any cell,
  findings.md records a LEAD for a follow-up round to wire the
  ethtool `tx_pause` tap (#812 §12 item 6) and re-run the D3
  channel with it.

**Per-block values are the samples. No max-reduction.** Cell-level
decision for `v ∈ {D1, D2}` compares `{T_v,b : b = 0..=11}`
(12 values) directly to `{T_v,b^base : b = 0..=59}` via
Fisher-Pitman. This is the Codex round-5 fix in #812 §11.3
(line 1363).

### 4.3 Baseline selection — per-pool (dir × cos) — HIGH-2 fix

**Round-2 fix: per-pool baselines, NOT a single cross-config pool.**
Round-1 used one `p5203-fwd-no-cos` pool against all 12 cells;
HIGH-2 showed this violates #812 §11.3's exchangeability
assumption and pre-excludes cells (`p5201-*-with-cos`,
`p5204-*-with-cos`) that fall outside the 20× I12 count-ratio
band. We accept the budget cost (20 min of iperf3 time, §3.5)
and capture per-pool baselines. Strict per-cell-config baselines
would cost 60 min and blow the ceiling, so the pool granularity
is (direction × cos-state):

| Pool | Reference cell | Applies to |
|---|---|---|
| fwd × no-cos | p5203-fwd-no-cos | cells 9, 10, 11, 12 |
| fwd × with-cos | p5203-fwd-with-cos | cells 1, 3, 5, 7 |
| rev × with-cos | p5203-rev-with-cos | cells 2, 4, 6, 8 |

**Three pools, not four.** There is no `no-cos × rev` cell in the
matrix (those were SKIP in the prior run), so no baseline is
needed for that arm.

**Per-pool baseline-capture procedure:**

1. Before the matrix runs (after the p5204 fix, before the first
   matrix cell), for each of the three pools above capture FIVE
   repeated instances of the reference cell at the same
   (port × dir × cos) setting, each 60 s × sampler = 12 blocks.
   5 × 12 = 60 baseline blocks per pool, satisfying #812 §11.3's
   `B_base ≥ 60` floor.
2. The pool is the "healthy" reference for all cells sharing its
   (dir × cos). This makes the Fisher-Pitman exchangeability
   assumption defensible: each cell's shape is compared against
   a baseline measured on the same traffic-direction, same-shaper
   regime.
3. Remaining cross-port heterogeneity within a pool (e.g. comparing
   p5201-fwd-with-cos at 0.95 Gbps to p5203-fwd-with-cos baseline
   at ~22 Gbps with CoS shaping differences) is handled by the
   I12 count-ratio band (§6 invariant I12). Within a single
   (dir × cos) pool the throughput span is tighter (max ~250×
   within no-cos-fwd vs ~240× within with-cos-fwd) and the
   shape-fraction statistic is more defensible than the Round-1
   single-pool design — but we still expect `p5201-*-with-cos`
   and `p5204-*-with-cos` to sit near or below the 0.05 I12 band
   and potentially be marked SUSPECT. Per-channel SUSPECT cells
   reduce the `k_v` denominator per §4.6 aggregation.

**Total baseline capture cost:** 3 pools × 5 runs × 60 s ≈ 15 min
iperf3 + 3 × 5 × 60 s overhead (setup + teardown) ≈ 15 min;
**30 min end-to-end per §3.5 table.**

### 4.4 Test statistic + null construction

Exactly per #812 §11.3, with `alternative='greater'` justified
inline (LOW-5 fix):

```python
from scipy.stats import permutation_test
for cell in cells:
    pool = baseline_pool_for(cell)   # per §4.3
    for v in ("D1", "D2"):           # D3 ejected, §4.2
        cell_T  = compute_per_block_stat(cell.samples, v)     # shape (12,)
        base_T  = compute_per_block_stat(pool.samples, v)     # shape (60,)
        res = permutation_test(
            data=(cell_T, base_T),
            statistic=lambda x, y: x.mean() - y.mean(),
            permutation_type='independent',
            n_resamples=10_000,
            alternative='greater',
            random_state=42,
        )
        cell.p_v[v] = res.pvalue
        cell.fire_v[v] = (res.pvalue <= 0.05)
```

- **α per cell per verdict = 0.05 one-sided.** Same as #812 §11.3.
- **`alternative='greater'` justification (LOW-5 fix).** The
  alternative encodes "the cell has MORE pathological-signal mass
  than a healthy same-(dir × cos) baseline." This is the pre-
  registered direction per #812 §11.3 line 1383-1385 — under a
  healthy baseline `T_D1,b^base` is small (mass concentrated in
  buckets 0-2) and `T_D2,b^base` is near zero (the `6..=9` factor
  is small), so any pathology pushes both statistics upward. A
  two-sided test would spend half its power on the "baseline is
  worse than the cell" direction, which is unmotivated given the
  healthy-baseline calibration.
- **N_perm = 10 000** with deterministic seed 42.
- **Two channels per cell × 12 cells = 24 statistics.** Round 1
  claimed 36 (three channels); Round 2 reduces to 24 because D3 is
  ejected from the classifier.
- **Aggregation:** `k_v ≥ 2 of 12` for each `v ∈ {D1, D2}`. Under
  the null, per-cell FP = 0.05, so
  `P[Binom(12, 0.05) ≥ 2] = 1 − 0.95¹² − 12 × 0.05 × 0.95¹¹ ≈ 0.118`
  per channel. Two channels × 0.118 ≈ 0.235 soft union bound.
  Findings.md reports BOTH `k_D1` and `k_D2` values whether or
  not they cross the gate.

**NO Bonferroni correction.** #812 §11.3 explicitly withdrew it.

### 4.5 Outcome → §8 decision tree

- **All `k_v < 2` AND original §4 A/B/C verdicts stay at
  `k_A < 2`, `k_B_cos < 2 of 4`, `k_C < 1` → H1 confirmed.**
  Verdict persists as D-dominant. Findings.md declares Phase B
  fairness done at the 0.79σ measurement floor, closes #786,
  deprioritizes #793.
- **`k_D2 ≥ 2` alone (with `k_D1 < 2`, B/C quiet) → H2 D2-signature.**
  Scope #793 Phase 4 against "per-worker reap-lag jitter under the
  C threshold." Specific follow-up: wire a reap-cadence telemetry
  probe (submit-rate vs reap-rate gap), and consider an MQFQ-side
  lag throttle measuring reap lag instead of (or in addition to)
  ring depth.
- **`k_D1 ≥ 2` alone (with `k_D2 < 2`, B/C quiet) → H2 D1-signature.**
  Scope #793 Phase 4 against "XSK submit→DMA latency inside AF_XDP."
  Follow-up includes checking the submit site for hidden kernel-
  side queueing on `sendto` and/or per-CPU NAPI affinity drift.
- **`k_D1 ≥ 2 AND k_D2 ≥ 2` simultaneously → H3 multi-channel.**
  Per §2 precedence rule. Findings.md writes up both signatures
  as a candidate new hypothesis tier, files a design-doc issue.
  NO direct Phase 4 scoping.
- **`k_D1 ≥ 2 OR k_D2 ≥ 2` AND also an exploratory out-of-family
  bucket mode (buckets 10-13 mass > 5 % anywhere) → H3.** Same
  action.
- **Exploratory D3 telemetry: bucket 14-15 mass > 1 % in ≥ 2
  cells → LEAD for next round** (wire `tx_pause` tap per #812 §12
  item 6). Does NOT feed the formal classifier; does NOT determine
  an H1/H2/H3 outcome on its own.
- **k_A ≥ 2 or k_B ≥ 2 of 4 (with-cos) firing NEW this round that
  did not fire prior** → revisit the prior findings doc; likely
  cluster-state drift; investigate before drawing any conclusion.

### 4.6 Classifier script specification — `test/incus/step1-histogram-classify.py`

**HIGH-6 fix.** Complete algorithm spec so the pipeline is
reviewable without reading code.

**Inputs (per cell):**
- `evidence/{baseline|with-cos|no-cos}/<slug>/flow_steer_cold.json`
  — cold snapshot (snapshot point 0 of 13).
- `evidence/.../flow_steer_samples.jsonl` — 12 during-run snapshots
  (points 1..12 of 13). Each line is the raw `{"type":"status"}`
  response plus `_sample_ts`.
- `evidence/.../iperf3.json` — for I12 cross-check.

**Inputs (global):**
- `evidence/baseline/<pool>/run{1..5}/flow_steer_{cold,samples}.*`
  — three baseline pools (fwd-no-cos, fwd-with-cos, rev-with-cos).
- `test/incus/requirements-step1.txt` — pins
  `scipy==<pinned>`, `numpy==<pinned>` for the capture host.

**Outputs (per cell):**
- `evidence/<slug>/hist-blocks.jsonl` — 12 lines, one per block `b`.
  Each line: `{"b": 0..=11, "count_delta": int, "buckets": [16
  int], "shape": [16 float], "tx_packets_delta": int}`.
- `evidence/<slug>/perm-test-results.json` — one JSON document:
  ```json
  {
    "cell": "p5201-fwd-with-cos",
    "pool": "fwd-with-cos",
    "python_version": "3.11.x",
    "scipy_version": "1.13.x",
    "numpy_version": "1.26.x",
    "seed": 42,
    "n_resamples": 10000,
    "B_cell": 12,
    "B_base": 60,
    "mde_sigma_80pct": 0.79,
    "invariants": {"I11": "PASS", "I12": "PASS", "I13": "PASS"},
    "channels": {
      "D1": {"p": 0.234, "fire": false, "stat_obs": 0.0012, ...},
      "D2": {"p": 0.048, "fire": true,  "stat_obs": 0.0004, ...}
    },
    "exploratory": {
      "bucket_14_15_mass_fraction": 0.00008,
      "out_of_family_bucket_10_13_max": 0.014,
      "bucket_mode_index": 2
    }
  }
  ```

**Outputs (global):**
- `evidence/summary-table.csv` — one row per cell, columns:
  cell, pool, verdict_abcd (from existing classifier),
  fire_D1, p_D1, fire_D2, p_D2, bucket_mode, bucket_14_15_pct,
  i11_pass, i12_pass, i13_pass, suspect_reason.

**Algorithm:**

```
for cell in 12 matrix cells + 3 baseline pools × 5 runs each:
    snaps_jsonl = load(flow_steer_samples.jsonl)   # 12 during
    snap_cold   = load(flow_steer_cold.json)       # 1 cold
    # Order: [cold, during1, ..., during12] → 13 snapshots.
    snaps = [snap_cold] + snaps_jsonl

    # Per-snapshot aggregation: sum histograms across bindings.
    # Rationale (Round 2 MED-4 justification):
    # - D1/D2 signatures per #812 §11.1 describe CELL-LEVEL shape
    #   shifts (submit→DMA / bimodal reap-lag). The user-visible
    #   throughput gap is a cell-level observable; a binding-level
    #   test would inflate multiplicity without changing the
    #   question being asked.
    # - Per-binding permutation would violate the exchangeability
    #   assumption within a block — bindings are not i.i.d. draws;
    #   they share a Rust worker, share the TX DMA queue, and are
    #   coupled by the MQFQ scheduler. Summing before the permutation
    #   removes the dependency structure the test assumes away.
    # - A per-binding breakdown IS exported via exploratory telemetry
    #   (§4.7) in the summary table — each cell's `per_binding_mass_
    #   share` column shows whether one binding dominates the signal,
    #   which catches the "one worker is broken" pattern the cell-
    #   level test might mask. Aggregate for the formal test; break
    #   out for the exploratory narrative.
    for s in snaps:
        s.hist_total = sum(b.tx_submit_latency_hist for b in
                           s.status.per_binding)   # [AtomicU64; 16]
        s.count_total = sum(b.tx_submit_latency_count for b in
                           s.status.per_binding)
        s.sum_ns_total = sum(b.tx_submit_latency_sum_ns for b in
                             s.status.per_binding)
        # I13 check per snapshot (wire-format consistency):
        assert sum(s.hist_total) == s.count_total,  "I13 fail"

    # Block deltas: 12 non-overlapping 5-s blocks.
    blocks = []
    for b in 0..=11:
        block = {
            "b": b,
            "count_delta": snaps[b+1].count_total - snaps[b].count_total,
            "buckets":     snaps[b+1].hist_total  - snaps[b].hist_total,  # elementwise
            "tx_packets_delta": snaps[b+1].tx_packets - snaps[b].tx_packets,
        }
        if block.count_delta > 0:
            block.shape = block.buckets / block.count_delta
        else:
            block.shape = [0.0] * 16    # will trip I11
        blocks.append(block)

    # I11 gate: per-block count floor.
    # Floor rationale (MED-4 fix): derived from shape-statistic
    # interval-width budget, not from single-bucket Poisson. See §6.
    if min(b.count_delta for b in blocks) < I11_FLOOR:
        cell.suspect = True
        cell.suspect_reason = "I11 count floor"

    # I12 gate: cell-vs-pool count ratio.
    pool = baseline_pool_for(cell)
    ratio = median_count(cell.blocks) / median_count(pool.blocks)
    if ratio < 0.05 or ratio > 20:
        cell.suspect = True
        cell.suspect_reason = "I12 count ratio"

    # Per-block statistics (§4.2):
    T_D1 = [mass(b.buckets[3..=6]) / b.count_delta if b.count_delta > 0 else 0
            for b in blocks]
    T_D2 = [(mass(b.buckets[0..=2]) / b.count_delta) *
            (mass(b.buckets[6..=9]) / b.count_delta)
            if b.count_delta > 0 else 0
            for b in blocks]
    # D3 exploratory only (no test):
    bucket_14_15_mass = sum(sum(b.buckets[14..=15]) for b in blocks) / \
                        max(1, sum(b.count_delta for b in blocks))

    # Permutation test (§4.4) against the pool:
    pool_T_D1, pool_T_D2 = build_pool_block_stats(pool)
    for v, cell_T, pool_T in [("D1", T_D1, pool_T_D1),
                              ("D2", T_D2, pool_T_D2)]:
        res = scipy.stats.permutation_test(
            (cell_T, pool_T),
            statistic=lambda x, y: x.mean() - y.mean(),
            permutation_type='independent',
            n_resamples=10_000,
            alternative='greater',
            random_state=42)
        cell.p_v[v] = res.pvalue
        cell.fire_v[v] = res.pvalue <= 0.05
```

**Version emission (HIGH-5 fix).** Every
`perm-test-results.json` MUST include `python_version`,
`scipy_version`, `numpy_version` top-level keys, populated from
`sys.version`, `scipy.__version__`, `numpy.__version__`. Reviewer
uses these to audit reproducibility across capture-host drift.

**Pool-block indexing.** Each pool's 60 baseline blocks come from
5 runs × 12 blocks/run, indexed `(run_id, b)` → flat index
`run_id × 12 + b`. `build_pool_block_stats` concatenates the 60
per-block values for each statistic into one 60-element vector
per channel.

**Determinism.** `random_state=42` into `scipy.stats.permutation_test`
fixes the Monte-Carlo partition sequence given the pinned SciPy
version. Reviewers re-running on the same pinned environment MUST
get bit-identical p-values.

### 4.7 Exploratory histogram-shape table

Descriptive telemetry reported alongside the formal verdict, NOT
feeding the classifier.

**4.7.1 Bucket-index-to-time-range reference (LOW-11 fix).**
Sourced from `userspace-dp/src/afxdp/umem.rs:178-181`
(`bucket_index_for_ns`):

| Bucket | Range (ns) | Range (µs / ms) |
|---:|---|---|
| 0  | `[0, 1024)` | `[0, 1) µs` |
| 1  | `[2^10, 2^11)` | `[1, 2) µs` |
| 2  | `[2^11, 2^12)` | `[2, 4) µs` |
| 3  | `[2^12, 2^13)` | `[4, 8) µs` |
| 4  | `[2^13, 2^14)` | `[8, 16) µs` |
| 5  | `[2^14, 2^15)` | `[16, 32) µs` |
| 6  | `[2^15, 2^16)` | `[32, 64) µs` |
| 7  | `[2^16, 2^17)` | `[64, 128) µs` |
| 8  | `[2^17, 2^18)` | `[128, 256) µs` |
| 9  | `[2^18, 2^19)` | `[256, 512) µs` |
| 10 | `[2^19, 2^20)` | `[512, 1024) µs` |
| 11 | `[2^20, 2^21)` | `[1, 2) ms` |
| 12 | `[2^21, 2^22)` | `[2, 4) ms` |
| 13 | `[2^22, 2^23)` | `[4, 8) ms` |
| 14 | `[2^23, 2^24)` | `[8, 16.78) ms` |
| 15 | `[2^24, ∞)`   | `≥ 16.78 ms` (saturation) |

Thus: `T_D1`'s buckets `3..=6` span `[4 µs, 64 µs)` —
**not** `[4 µs, 128 µs)` as Round-1 prose said. `T_D2`'s `6..=9`
factor spans `[32 µs, 512 µs)`. `T_D3` (exploratory) saturates at
`≥ 8 ms` (buckets 14..=15).

**4.7.2 Exploratory D3 telemetry.** Per cell:
`bucket_14_15_mass / total_mass` as a single fraction. Recorded in
`perm-test-results.json.exploratory.bucket_14_15_mass_fraction`
and `summary-table.csv`. No gate; LEAD if > 1 % in ≥ 2 cells (§4.5).

**4.7.3 Out-of-family bucket mode.** Per cell: argmax bucket index
across the summed cell-level histogram. If the argmax is any of
buckets 10-13 on ≥ 2 cells, that is an H3-candidate signal outside
the pre-registered D1/D2 channels (§2 H3 definition).

## 5. Verdict thresholds — re-applied from step1-plan §4

**Do not redefine X/Y/Z.** The A/B/C/D thresholds remain as
step1-plan §4.2 spells them out:

- **X (Verdict A):** `max(n_w) ≥ 9` OR `min(n_w) ≤ 0`. FP 0.064,
  per `test/incus/step1-rss-multinomial.py`.
- **Y (Verdict B indirect):** `max_f / trimmed_min_f ≥ 2.72`,
  per `test/incus/step1-rate-spread-analysis.py`.
- **B_park (Verdict B direct):** `Z_nocos = 10 parks/s` on no-cos,
  `Z_cos = 500 parks/s` on with-cos (calibration-gap placeholder).
- **Z (Verdict C):** `ring_w / 60 ≥ 50` events/s on a worker with
  `cpu_w < 85 %`. FP < 0.01.
- **D / D-escalate:** no A/B/C fires AND SUM within 2 Gbps of
  shaper max.
- **§4.6 aggregation:** `k_A ≥ 2`, `k_B ≥ 2 of 4 with-cos-fwd`,
  `k_C ≥ 1`. Unchanged.

**Two new thresholds for the histogram channel (D3 removed
from Round 1):**

- **D1/D2 per-cell fire rule:** cell-level Fisher-Pitman
  one-sided p-value `p_v ≤ 0.05` against the cell's
  per-pool baseline.
- **Aggregation gate:** `k_v ≥ 2 of 12` cells per channel
  `v ∈ {D1, D2}`.
- **FP math:** `P[Binom(12, 0.05) ≥ 2] = 0.118` per channel.

**"D1/D2 pattern fires" is defined as** `p_v ≤ 0.05` on the
cell AND cross-cell `k_v ≥ 2 of 12`. Single-cell `p_v ≤ 0.05`
without cross-cell corroboration is reported as a LEAD, not a
verdict.

## 6. Invariants — step1-plan §5 I1-I10 PLUS three new ones

Re-apply all ten step1-plan §5 invariants verbatim (I1–I10).
New invariants for histogram validity, re-derived per MED-4:

- **I11 — per-block count floor.** For each cell, each of the
  12 blocks MUST have `block.count ≥ I11_FLOOR` completions.
  MED-4 fix: the floor is derived from the classifier's actual
  statistical object, not from `sqrt(np)` on a single bucket.
  `T_D1,b` has form `(sum of 4 multinomial counts) / N`, with
  multinomial variance bounded above by
  `Var[T_D1,b] ≤ p(1-p)/N` (binomial bound). To hold the
  per-block one-σ noise on `T_D1,b` below 0.01 (an order of
  magnitude below the per-channel gate's step size) at `p = 0.1`
  (conservative): `sqrt(0.1 × 0.9 / N) ≤ 0.01 ⇒ N ≥ 900`. For
  `T_D2,b = p1 × p2` the delta-method variance is roughly
  `p2² Var[p1] + p1² Var[p2] ≤ 2 × p(1-p)/N` at `p ≤ 0.1`, so the
  same N ≥ 900 bound holds within a factor 2. We set
  **I11_FLOOR = 1000 completions per block** as a round-number
  operating threshold — well below Round-1's `25000`, which was
  over-tight and tied to the bad `sqrt(np)` derivation. The floor
  has slack: at `N = 1000, p = 0.1`, per-block σ ≈ 0.0095, so
  across B = 12 blocks the standard error of `mean(T_D1,b)` is
  `0.0095 / sqrt(12) ≈ 0.0027`. Cell fails I11 → marked SUSPECT,
  does NOT enter the permutation aggregation. Corrected per-block
  volume table (HIGH-1 arithmetic):
  - `p5203-fwd-no-cos` worst block: ~9.4 M completions — PASS.
  - `p5201-fwd-with-cos` worst block: ~0.4 M completions — PASS.
  - `p5204-fwd-with-cos` worst block: ~39 k completions — PASS.
- **I12 — cell-count vs pool-count ratio.** For each cell
  `median(block.count) / median(pool.block.count) ∈ [0.05, 20]`.
  Outside this band, the histogram-shape comparison is
  contaminated by absolute-count-driven rarity. Pool granularity
  is (dir × cos); inside-pool throughput spans after HIGH-2's
  per-pool baselines sit mostly inside the band for
  `p5202-*-with-cos` and `p5203-*-with-cos` but may trip for
  `p5201-*-with-cos` (0.041 under the no-cos-fwd baseline but
  ~0.043 under the with-cos-fwd baseline) and `p5204-*-with-cos`
  (< 0.01 either way). Findings.md must explicitly name any cell
  that trips I12 and report the fallback in §4.5 — a SUSPECT
  mark reduces the `k_v` denominator, not the floor.
- **I13 — histogram count-sum consistency.** Per #812 §5.2:
  `sum(tx_submit_latency_hist) == tx_submit_latency_count` on
  every snapshot. Violation indicates a #813 regression (wire
  format broken) — HALT the run, file an issue, do not continue.

## 7. Validation gates between steps

Ordered gate sequence:

1. **Pre-run gate:** p5204 config fix verified via smoke
   (`iperf3 -P 4 -t 5 -p 5204` SUM ≈ 100 Mbps with CoS live) OR
   explicit decision-to-proceed recorded in findings.md with the
   reduced-denominator math for §4.6. Neither gate = HALT before
   the first cell.
2. **Baseline-capture gate:** 5 × runs per pool × 3 pools each
   pass §5 I1-I10, §6 I13. If fewer than 3 of 5 runs in ANY
   pool pass, re-run that pool; H-STOP-5 on second failure.
3. **Per-cell gate:** §5 I1-I10 + §6 I11-I13. Any failure → cell
   marked SUSPECT; §4.6 aggregation rules handle the reduced
   denominator.
4. **Cross-cell aggregation gate:** after all 12 cells + all 3
   pools:
   - Per-channel `k_v` computed (§4.4).
   - `k_v ≥ 2` evaluated per §4.5.
   - Findings table in findings.md MUST include: per-cell `p_D1
     / p_D2`, per-cell bucket_14_15 mass fraction (exploratory),
     per-cell argmax bucket, verdict-letter column (A/B/C/D/D-esc),
     histogram-channel column (D1-fire / D2-fire / quiet), I11 /
     I12 / I13 pass/fail, and a one-sentence per-cell summary.
5. **Evidence-checked-in gate:** findings.md MUST reference
   `docs/pr/816-step1-rerun/evidence/` for every cited number;
   no hand-written numbers.

## 8. Decision tree — step1-plan §8 augmented

Re-use the existing §8 branches for A/B/C/D. Add the histogram
branch (D3 removed; H3 precedence rule from §2 applied):

- **H1 (D-dominant persists, all `k_v < 2`, AND no exploratory
  out-of-family bucket-mode argmax in 10-13 on ≥ 2 cells):**
  *"Phase B fairness done at the 0.79σ measurement floor. Remaining
  ~2.4 Gbps shortfall is not in the TX-completion path (histogram
  confirmed to the floor). D4 (RX coalescing) or upstream becomes
  the only remaining open direction."* → Close #786, deprioritize
  #793. The exploratory-OoF negation is required so this branch
  does NOT shadow the H3-OoF-only branch below (Round 3 MED fix).

- **H2 D1 (`k_D1 ≥ 2` AND `k_D2 < 2`, B/C quiet):**
  *"XSK submit→DMA latency elevated cross-cell."* → Scope #793
  Phase 4 against in-AF_XDP submit-path queueing / per-CPU NAPI
  drift / sendto kick regressions.

- **H2 D2 (`k_D2 ≥ 2` AND `k_D1 < 2`, B/C quiet):**
  *"Per-worker reap-lag jitter below the C threshold (bimodal
  histogram tail)."* → Scope #793 Phase 4 against reap-cadence
  telemetry + MQFQ shared V_min + lag throttle.

- **H3 multi-channel (`k_D1 ≥ 2 AND k_D2 ≥ 2` simultaneously):**
  *"Two pre-registered channels firing — plausibly shared upstream
  cause. Candidate new hypothesis tier."* → Write up in findings.md,
  file design-doc issue, do NOT scope Phase 4 from this round.

- **H3 out-of-family (any `k_v ≥ 2` plus exploratory bucket-mode
  argmax in 10-13 on ≥ 2 cells):**
  *"Pre-registered signal PLUS unexpected bucket-mode."* → Same
  H3 action: design-doc issue, no Phase 4.

- **H3 out-of-family only (all `k_v < 2` BUT exploratory
  bucket-mode argmax in 10-13 on ≥ 2 cells) — Round 2 MED-3 fix.**
  *"No pre-registered signal crosses the gate, but the exploratory
  histogram shape table shows mass concentrated at buckets 10-13
  on ≥ 2 cells — a new hypothesis tier the classifier does not
  name."* → H3 action: design-doc issue, no Phase 4. This branch
  makes the §2 definition "a mode the classifier does not name"
  reachable without requiring a simultaneous `k_v` fire. Without
  this branch a pure out-of-family signal would fall through to
  H1, which would be wrong.

- **Exploratory D3 LEAD (`bucket_14_15` fraction > 1 % on ≥ 2
  cells):** *"Saturation mass in bucket 14-15. LLFC candidate —
  ethtool tap not wired."* → Follow-up for #812 §12 item 6; do
  NOT scope Phase 4. Does NOT change the H1/H2/H3 outcome on its
  own (§4.5).

- **Original A/B/C verdicts fire newly (not in prior run):**
  Cluster state has drifted. HALT until drift is understood.

Step 1 re-run MUST NOT commit to Step 2 scope in findings.md
beyond the one-paragraph direction.

## 9. Rollback (N/A for measurement — what happens on SUSPECT / inconclusive)

Per step1-plan §7, no rollback for measurement work itself.

Handling of inconclusive outcomes:

- **Cell SUSPECT.** §5 I1-I10 / §6 I11-I13 failed. Cell excluded
  from `k_v` denominators; findings.md names the cell and the
  failing invariant.
- **Permutation test inconclusive** (p_v ≤ 0.05 on 1 cell only,
  no `k_v ≥ 2`). Report as a LEAD, not a verdict. Findings.md
  documents the single-cell fire with full histogram shape +
  context, flags as "awaiting corroboration in next round."
- **Permutation test returns `p = 1.0` and stat_obs = 0** on a
  cell where telemetry is otherwise healthy. HIGH-4 fix: this is a
  **legitimate `quiet` outcome for a cell whose per-block
  statistic is identically zero** (e.g. no blocks saw any mass in
  the target bucket range). Record as `quiet`, NOT as a halt
  condition. The only degenerate-null HALT is H-STOP-1 (I13
  violation) or per-cell verification that
  `tx_submit_latency_count > 0` on every during-run snapshot
  despite substantial `tx_packets` traffic (wire-format
  regression signature; checked in the script, §4.6).
- **N_valid < 8 cells** (more than 4 SUSPECT). Per step1-plan §7:
  drop the reverse cells first, re-run forward cells. If still
  < 8 valid, run is **failed** — findings.md documents the failure
  and the re-run is re-planned.

## 10. Non-negotiables

Per step1-plan §9, all of which carry unchanged:

- **Target cluster `loss:xpf-userspace-fw0` / `-fw1`. Forbidden:
  `bpfrx-fw0` / `bpfrx-fw1`.** Per
  `docs/development-workflow.md` §"Test target is the userspace
  cluster." Any evidence captured against the forbidden cluster
  is invalid.
- **Canonical CoS: scheduler-be 100 M / iperf-a 1 G / iperf-b
  10 G / iperf-c 25 G on forward direction.** Any deviation from
  `docs/pr/line-rate-investigation/full-cos.set` at run time is
  CONFIG-DIVERGENCE and must be resolved BEFORE the re-run
  (§3.2).
- **Zero per-packet measurement overhead.** The histogram reads
  are atomic loads from `[AtomicU64; 16]` per binding at snapshot
  time (#813 landed; #812 §3.4 overhead budget unchanged).
- **No fixes during Step 1.** The p5204 config fix is PRE-run
  (§3.2); once cell 1 starts capturing, no further cluster-state
  changes until findings.md is written.
- **Named thresholds.** §5 re-applies X/Y/Z/B_park from
  step1-plan; §5's new `p_v ≤ 0.05` + `k_v ≥ 2 of 12` are the
  only additions and both have derivations cited.
- **Reproducibility — HIGH-5 fix.** Permutation test is driven by
  `scipy.stats.permutation_test(..., random_state=42,
  n_resamples=10_000)` — deterministic given pinned SciPy.
  Implementation requirements:
  1. `test/incus/step1-histogram-classify.py` is committed in
     the same commit that lands this plan. The Implementor step
     of the workflow is responsible for materializing the script
     per §4.6; Architect has provided algorithmic spec only, not
     source.
  2. `test/incus/requirements-step1.txt` is committed in the
     same commit, pinning `scipy` and `numpy` exact versions.
  3. The script emits `python_version`, `scipy_version`,
     `numpy_version` into every `perm-test-results.json` per §4.6.
  4. If the capture-host environment cannot match the pinned
     versions, HALT the re-run and re-provision the host before
     continuing; a version drift invalidates the deterministic-
     seed guarantee.

## 11. Hard stops

HALT the re-run on any of:

- **H-STOP-1.** I13 (count-sum consistency) violation on any
  snapshot. Wire format broken, #813 regression.
- **H-STOP-2 — rewritten per MED-6.** Primary failover
  (step1-plan I4 / I9) detected mid-cell that invalidates the
  current cell's measurement (not a pre-run state check on which
  firewall holds primary). #815 has landed on master (verified
  `gh issue view 814` shows CLOSED), so fw1 is NOT a known-bad
  failover target and moving primary to fw1 mid-run is no longer
  a halt condition by itself. The halt fires on:
  - A mid-cell fabric flap (any RG state transition during the
    60-s capture window), OR
  - A fabric-integrity indicator failing (step1-plan I4 covers
    the fab0/fab1 ping sanity), OR
  - Primary-identity drift BETWEEN cells within the re-run
    (e.g. fw0 for cells 1-4, fw1 for cells 5-12) without
    operator acknowledgement — this is a measurement-integrity
    signal (different NIC, different CPU pinning), not a "fw1
    is bad" signal. Findings.md must record a separate-primary
    re-run as TENTATIVE on measurement grounds.
  Pre-run verification: cluster-status-pre.txt MUST capture
  current RG primary for fw0 and fw1; §7 gate 3 requires the
  same primary at cluster-status-post.txt. Drift → SUSPECT on
  that cell.
- **H-STOP-3.** CoS apply / remove leaves the cluster in a
  no-CoS state without a committed rollback. step1-plan §6
  step 10 HALT.
- **H-STOP-4.** Five or more consecutive cells fail §5 I1-I10.
- **H-STOP-5.** Baseline-capture (§4.3) fails — fewer than 3 of
  the 5 runs in ANY of the 3 pools pass §5 / §6 on their second
  attempt. Without all three baseline pools the permutation test
  cannot run for the cells in the affected pool.

## 12. Deferrals

Per `docs/development-workflow.md` §Plan: each deferral names
what is NOT done and why.

1. **Z_cos re-calibration on the with-cos half.** Still blocked
   on data provenance per step1-plan §8. This re-run DOES capture
   the data (park-rate deltas are in every status snapshot), so
   the Z_cos = mean + 2σ re-derivation can happen in findings.md
   inline. Any AFD / Phase 5 action remains gated per step1-plan
   §8 and #812 §10.
2. **D3 `tx_pause` channel — HIGH-3 fix; now fully ejected.**
   Per §4.2, D3 is no longer a formal classifier channel. Wiring
   `ethtool -S tx_pause` time-series into capture is #812 §12 item
   6 — separate follow-up PR. This re-run reports bucket-14/15
   mass as exploratory telemetry only; a LEAD fires only for the
   NEXT round to scope, not Phase 4.
   **Risk of deferring:** if LLFC really is driving the D-dominant
   shortfall, this re-run will not detect it (bucket-14/15 mass
   alone could be reap-stall, not LLFC; without `tx_pause`
   correlation we cannot disambiguate). Findings.md must note
   this limitation: "D3 channel not formally evaluated; a
   persistent bucket-14/15 signal is a LEAD for the next round."
3. **Per-flow histograms.** #812 §12 item 2 deferral stands.
4. **Prometheus export of the histogram.** #812 §12 item 1.
5. **HdrHistogram / dynamic bucket adaptation.** #812 §12 item 4.
6. **Bucket width re-cut for sub-µs resolution.** #812 §12 item 8.
7. **Histogram reset endpoint.** #812 §12 item 3.
8. **Recovery of 0.45σ MDE.** Per §4.1, tightening the floor below
   0.79σ requires either a 1-Hz sampler (rejected on
   measurement-of-the-measurer grounds) or cell-side repeats (2 ×
   60 s per cell, ~20 min of extra iperf3 time). Deferred to a
   future round gated on the current round's H1/H2/H3 outcome —
   if H1 fires at 0.79σ we would want a repeat run at 0.64σ
   before closing #786, which belongs in the next plan document.

## 13. Evidence layout

Under `docs/pr/816-step1-rerun/evidence/`, matched to the three
baseline pools and the existing `step1-evidence/<cos>/p<port>-<dir>/`
pattern:

```
docs/pr/816-step1-rerun/
    plan.md                             # this document
    codex-plan-review.md                # Codex Rounds 1+2
    findings.md                         # verdict doc, added after execution
    evidence/
        baseline/
            fwd-no-cos/
                run1/                   # p5203-fwd-no-cos instance 1
                    iperf3.json
                    flow_steer_cold.json
                    flow_steer_post.json
                    flow_steer_samples.jsonl
                    mpstat.txt
                    perf-stat.txt
                    ping-small.txt
                    ping-large.txt
                    ss-samples.jsonl
                    nic-counters-cold-*.txt
                    nic-counters-post-*.txt
                    cluster-status-pre.txt
                    cluster-status-post.txt
                    dmesg-tail.txt
                    verdict.txt
                run2/ … run5/
                baseline-blocks.jsonl    # 60 blocks for §4.3 fwd-no-cos pool
            fwd-with-cos/
                run1/ … run5/
                baseline-blocks.jsonl
            rev-with-cos/
                run1/ … run5/
                baseline-blocks.jsonl
        with-cos/
            p5201-fwd/                   # all files identical layout
                …                        # PLUS hist-blocks.jsonl + perm-test-results.json
                hist-blocks.jsonl
                perm-test-results.json
            p5201-rev/
            p5202-fwd/
            p5202-rev/
            p5203-fwd/
            p5203-rev/
            p5204-fwd/
            p5204-rev/
        no-cos/
            p5201-fwd/
            p5202-fwd/
            p5203-fwd/
            p5204-fwd/
    summary-table.csv                   # one row per cell: verdict + k_v + exploratory
```

The new `test/incus/step1-histogram-classify.py` (§4.6) produces
`hist-blocks.jsonl` and `perm-test-results.json` per cell, one
`baseline-blocks.jsonl` per pool, and `summary-table.csv` across
the matrix.

*End of Architect Round 2 revision. Awaiting Round 2 Codex hostile
review per `docs/development-workflow.md` §Phase 1.*
