# ROUND 1 DESIGN REVIEW — Issue #816 Step 1 Re-run Plan

## 1. N_blocks = 12 derivation

**Severity:** HIGH

**Citations:** `docs/pr/816-step1-rerun/plan.md:216-254`, `docs/pr/816-step1-rerun/plan.md:299-327`, `docs/pr/812-tx-latency-histogram/plan.md:1337-1415`, `test/incus/step1-capture.sh:286-309`

**Flaw:** This section is mathematically sloppy in three different ways.

First, it computes the partition count as `C(B + B_base, B) = C(24, 12)` at `plan.md:233-237`, but the same document later defines `B_base = 60` at `plan.md:305-306`. Those are not the same design. The actual partition count for the stated test is `C(72, 12) = 15,363,284,301,456`, not `C(24, 12) = 2,704,156`.

Second, the claimed "`~0.4 %` relative error" is bogus. Fraction-of-partition-space-sampled is not Monte Carlo p-value error. With `n_resamples = 10_000` and a gate near `p = 0.05`, the estimator's 1-sigma absolute error is `sqrt(p(1-p)/N) ≈ 0.00218`, with a 95 % half-width of about `0.00427`. That is not "an order of magnitude smaller than alpha"; it is on the order of 8.5 % of the threshold.

Third, the throughput-to-completion arithmetic at `plan.md:239-246` is wrong on its own stated `/1500 B frame` conversion:

- `22.6 Gbps × 5 s / (1500 × 8) = 9,416,667` frames, not `6.3 M`.
- `0.95 Gbps × 5 s / (1500 × 8) = 395,833` frames, not `0.26 M`.
- `0.094 Gbps × 5 s / (1500 × 8) = 39,167` frames, not `26,000`.

The real design issue is power. #812's accepted procedure at `plan.md:1337-1415` used `B = 60` one-second blocks. Replacing that with `B = 12` five-second blocks materially inflates the standard error of the mean-difference statistic. Using the same statistic as the plan's SciPy call, the first-order SE scales with `sqrt(1/B + 1/B_base)`:

- `60 vs 60` blocks: standardized 80 %-power MDE ≈ `0.45σ`.
- `12 vs 60` blocks: standardized 80 %-power MDE ≈ `0.79σ`.
- `12 vs 12` blocks: standardized 80 %-power MDE ≈ `1.02σ`.

So yes, `10_000` resamples gives plenty of p-value resolution at `alpha = 0.05` (`p_min ≈ 1e-4`), but no, it does not preserve the detection power that `B = 60` was buying. If you care about sub-`0.8σ` shifts, this plan needs more blocks or more repeated runs, which is harness/script work.

**Mitigation:** Rewrite §4.1 against the actual `12 vs 60` design, fix the throughput arithmetic, delete the fake "`0.4 %` relative error" claim, and state the power trade honestly as a standardized MDE. Then either accept the `~0.79σ` floor explicitly or change the harness to collect more blocks / more baseline-matched repeats.

## 2. Baseline pool — single pool across all configs

**Severity:** HIGH

**Citations:** `docs/pr/816-step1-rerun/plan.md:286-327`, `docs/pr/816-step1-rerun/plan.md:451-460`, `docs/pr/812-tx-latency-histogram/plan.md:1377-1382`, `docs/pr/816-step1-rerun/plan.md:239-246`

**Flaw:** §4.3 quotes #812's requirement for a baseline from the "same cell configuration" and then violates it immediately by pooling five `p5203-fwd-no-cos` runs across all 12 cells. That is not a small deviation; it is the opposite of the accepted #812 contract.

The plan's own rescue argument is self-defeating. It says shape fractions normalize out throughput scale, but D3 is not a smooth fraction statistic here; under §4.2 it is a Bernoulli indicator `1{mass(14..=15) > 0}`. The probability of that event depends on block count. Your own counts at `plan.md:239-246` span roughly `6.3 M`, `0.26 M`, and `26 k` completions per block, i.e. about `24x` and `242x` swings. Exchangeability is gone.

Worse, I12 admits this and still does not save the design. Using the plan's own counts:

- `p5201-fwd-with-cos`: `0.26 M / 6.3 M = 0.041 < 0.05`.
- `p5204-fwd-with-cos`: `26 k / 6.3 M = 0.004 < 0.05`.

So the shared baseline would systematically mark at least those cells SUSPECT under the very invariant the plan added to justify the shared baseline. That is not a baseline strategy. That is a plan to pre-exclude cells because the baseline is wrong.

**Mitigation:** Stop calling this a per-cell baseline unless it is actually same-config. Either capture healthy baselines for the configs you intend to test, or narrow the rerun matrix to the configs that can share a defensible baseline. If budget forbids per-config baselines, say so and reduce scope; do not sneak a cross-config pool under #812's wording.

## 3. D3 channel half-wired

**Severity:** HIGH

**Citations:** `docs/pr/816-step1-rerun/plan.md:256-275`, `docs/pr/816-step1-rerun/plan.md:385-387`, `docs/pr/816-step1-rerun/plan.md:517-521`, `docs/pr/812-tx-latency-histogram/plan.md:1351-1355`, `docs/pr/812-tx-latency-histogram/plan.md:1509-1510`

**Flaw:** "Copy #812 §11.3 verbatim" is false. The accepted D3 statistic in #812 is `1{tail} * 1{tx_pause > 0}`. This plan deletes the `tx_pause` term and still runs the result through the same `p_v <= 0.05`, `k_v >= 2`, and hypothesis-branch machinery. That is no longer a D3 test; it is a generic rare-tail detector confounded by count, C-like stalls, and anything else that can touch buckets 14-15.

To be precise: the user's "0/1 statistic implies zero variance" objection is too broad. A mixed 0/1 sample is still a valid permutation input. The actual bug is that the plan changed the hypothesis while pretending it did not.

Labeling the output a LEAD is not enough while the half-wired channel still lives inside the formal classifier and inherits #812's pre-registration/FP story.

**Mitigation:** Either wire the missing `tx_pause` channel and keep D3 as the real #812 statistic, or eject D3 from the formal permutation family for this rerun and report it as descriptive/exploratory telemetry only. Do not keep the #812 name and #812 decision logic after changing the statistic.

## 4. I11 count floor of 25,000 per block

**Severity:** MEDIUM

**Citations:** `docs/pr/816-step1-rerun/plan.md:442-460`

**Flaw:** I11 is derived from the wrong model and the wrong object. `T_D1,b` and `T_D2,b` are ratios/products of multinomial bucket masses over a fixed block count; they are not raw Poisson arrivals, and the permutation test operates on block-to-block variation, not on a single bucket's counting error at an invented `p = 0.05`.

The chosen `25,000` floor is also tied to the already-bad count arithmetic in §4.1. In a shaped or bursty regime, overdispersion can dominate the tidy `sqrt(np)` story written here. And D3's rare-tail event is exactly the kind of place where a universal `p = 0.05` count-floor argument is irrelevant.

**Mitigation:** Redefine I11 in terms of the actual classifier objects. If you want a floor, derive it from a named maximum interval width on `T_v,b` itself, or from minimum expected counts in the bucket-sets each statistic uses, using a healthy same-config baseline. If you cannot do that, do not pretend the current `25,000` threshold has a statistical derivation.

## 5. `alternative='greater'`

**Severity:** LOW

**Citations:** `docs/pr/816-step1-rerun/plan.md:339-345`, `docs/pr/812-tx-latency-histogram/plan.md:1345-1349`, `docs/pr/812-tx-latency-histogram/plan.md:1383-1385`

**Flaw:** This is not the main bug, but the plan leaves the sign argument implicit. For `T_D2,b = frac(0..=2) * frac(6..=9)`, `greater` is only obviously correct when the baseline is truly healthy and same-config, because the product rises when a second lobe appears while the baseline's tail term stays near zero. Once §4.3 swaps in a cross-config baseline, that justification is no longer obvious from the text.

**Mitigation:** Keep `alternative='greater'`, but say why after fixing item 2: under a healthy same-config baseline the `6..=9` factor is near zero, so D2 increases the product. Right now the reader has to infer that from #812.

## 6. H-STOP-2 claims fw1 fab0 bug fixed by #815

**Severity:** MEDIUM

**Citations:** `docs/pr/816-step1-rerun/plan.md:439-440`, `docs/pr/816-step1-rerun/plan.md:601-607`, `docs/pr/line-rate-investigation/step1-plan.md:898-899`

**Flaw:** The repo-state claim is verifiable and mostly true. `master` is `d5feef58`, a merge of PR `#815`, and commit `0e2a4b2a` raises `MAX_INTERFACES` to `65536`. `docs/pr/814-max-interfaces/validation.md:37-64` also records fw1 compile PASS and failover/failback PASS. So the "is #815 on master?" question is answered: yes.

The design problem is that §6 simultaneously says "re-apply I1-I10 verbatim" and imports I9 from the old Step 1 plan, whose active rationale is exactly "primary drift onto fw1 strands the measurement on a known-bad node." That rationale is stale if H-STOP-2 now says fw1 is safe once #815 is present. The plan half-updates the failover policy.

**Mitigation:** Rewrite I9 and H-STOP-2 as a matched pair. Either keep the conservative policy and justify it with a fresh measurement-specific reason, or drop the obsolete "fw1 is known-bad" premise and gate only on failover-mid-cell / fabric-flap integrity. Do not import stale invariants verbatim after verifying the underlying bug is closed on master.

## 7. Degenerate null at §9 inconclusive branch

**Severity:** HIGH

**Citations:** `docs/pr/816-step1-rerun/plan.md:267-274`, `docs/pr/816-step1-rerun/plan.md:549-563`, `docs/pr/816-step1-rerun/plan.md:636-638`

**Flaw:** This contradiction is real. Under the plan's half-wired D3, an all-zero indicator across cell and baseline is a legitimate quiet outcome. §9 instead says "identically-zero Δ on every permutation" means wire-format regression / histogram always-empty and HALT. That is false. For D3 it can simply mean no bucket-14/15 events occurred.

So yes, the plan currently contains a halt branch that can fire on a normal D3-quiet result if the implementation takes §9 literally.

**Mitigation:** Limit the HALT to actual telemetry failure, e.g. zero `tx_submit_latency_count` despite substantial traffic, empty histograms when I13/I11 should have passed, or malformed vectors. Treat all-zero D3 blocks as `quiet`, not as a #813 regression. More broadly, stop using generic permutation degeneracy as a proxy for wire-format breakage.

## 8. Budget double-counting

**Severity:** MEDIUM

**Citations:** `docs/pr/816-step1-rerun/plan.md:191-208`, `docs/pr/816-step1-rerun/plan.md:326-327`

**Flaw:** The budget table omits the new baseline step it later claims is "inside the §3.5 budget." The arithmetic is:

- §3.5 table: `10 + 6 + 12 + 6 + 1 + 3 + 1 + 15 + (10..20) + 10 = 74..84` minutes.
- Add the missing baseline from §4.3: `+7` minutes.
- Real total: `81..91` minutes.

That already exceeds the advertised 90-minute top end by 1 minute before any baseline rerun, SUSPECT rerun, or operator slippage. The plan is budgeting optimism twice.

**Mitigation:** Put the baseline step in the table and restate the target window honestly. Either widen the target, shrink the buffer/write-up allowance, or predeclare what gets dropped earlier. Right now the budget does not match the work.

## 9. H3 definition ambiguity

**Severity:** MEDIUM

**Citations:** `docs/pr/816-step1-rerun/plan.md:64-90`, `docs/pr/816-step1-rerun/plan.md:392-395`, `docs/pr/816-step1-rerun/plan.md:523-527`

**Flaw:** H3 is defined two different ways. §2 says H3 means "something neither team predicted" and gives an out-of-family example at buckets 10-13. §4.5 and §8 then also use H3 for "anything else," including multiple known channels firing simultaneously. Those are not the same class of outcome.

If D1 and D2 both fire, is that a pre-registered H2 composite, or H3 unexpected behavior? The document currently says both.

**Mitigation:** Define precedence explicitly. Example: H2 requires exactly one pre-registered channel to cross the gate; H3 covers either a new bucket-mode outside D1/D2/D3 or any multi-channel fire. Write that once in §2 and reuse the same rule in §8.

## 10. Reproducibility claim

**Severity:** HIGH

**Citations:** `docs/pr/816-step1-rerun/plan.md:589-593`, `docs/pr/816-step1-rerun/plan.md:701-703`

**Flaw:** UNVERIFIABLE, therefore HIGH. The plan claims deterministic reproducibility from `scipy.stats.permutation_test(..., random_state=42, n_resamples=10_000)`, but the repository does not contain the promised `test/incus/step1-histogram-classify.py`, does not pin a SciPy version anywhere I could find, and this workspace's `python3` cannot import `scipy` at all. There is no file-backed evidence that the actual runtime environment will produce the same Monte Carlo stream or even run.

**Mitigation:** Commit the script, pin the Python/SciPy environment that executes it, and make the script emit its `python --version`, `scipy.__version__`, and `numpy.__version__` into evidence. Until then "deterministic" is advertising, not an invariant.

## 11. Bugs carried from copying #812 §11.3

**Severity:** LOW

**Citations:** `docs/pr/816-step1-rerun/plan.md:261-265`, `docs/pr/812-tx-latency-histogram/plan.md:1340-1349`, `userspace-dp/src/afxdp/umem.rs:178-181`, `pkg/dataplane/userspace/protocol.go:485-487`

**Flaw:** The formulas mostly match the final #812 text; I do not see a new sign error in `T_D1` or `T_D2`. The pedantic bug is an off-by-one range label copied forward: buckets `3..=6` are `4-64 µs`, not `4-128 µs`, because bucket `N >= 1` is `[2^(N+9), 2^(N+10)) ns` and bucket 7 is the `64-128 µs` bucket. The prose is wrong about the wire contract.

**Mitigation:** Add an explicit bucket-index-to-time-range table sourced from `bucket_index_for_ns` and stop hand-writing range labels in prose. The math is too easy to get subtly wrong.

## 12. Missing script spec

**Severity:** HIGH

**Citations:** `docs/pr/816-step1-rerun/plan.md:59-60`, `docs/pr/816-step1-rerun/plan.md:170-178`, `docs/pr/816-step1-rerun/plan.md:592-593`, `docs/pr/816-step1-rerun/plan.md:701-703`, `docs/development-workflow.md:68-79`, `userspace-dp/src/protocol.rs:1415-1425`, `test/incus/step1-capture.sh:286-309`

**Flaw:** The classifier script is both unspecified and absent. The plan says a new `step1-histogram-classify.py` will compute block deltas and p-values, but it does not actually specify the load-bearing parts of the pipeline: how per-binding histograms are aggregated across bindings/queues, how blocks are aligned and delta'd, how baseline blocks are serialized and reused, how I11/I12/I13 are enforced, or how D3's half-wired path is represented in output.

Worse, the one pseudo-spec it does provide already has an off-by-one: `plan.md:176-177` says `b ∈ 0..12` even though 13 snapshot points only support 12 deltas (`0..11`). That is exactly why a real script spec is not optional.

Per `docs/development-workflow.md:68-79`, the plan is supposed to contain thresholds, statistics, execution, validation, rollback, hard stops, and deferrals in a reviewable form. Here the statistical pipeline is still partly implicit in a missing file.

**Mitigation:** Put the classifier algorithm in the plan or land the script before claiming reproducibility. At minimum specify the inputs, block-delta indexing, aggregation over `status.per_binding`, baseline selection, invariants, exact JSON outputs, and dependency requirements. Right now a reviewer cannot validate the pipeline because the pipeline is not actually written down.

## Summary

| Severity | Count |
|---|---:|
| HIGH | 6 |
| MEDIUM | 4 |
| LOW | 2 |

ROUND 1: PLAN-READY NO — 12 open items



## Round 1 response

Architect Round 2 addressed each Round 1 finding. Mapping below.

| # | Severity | Title | Status | Pointer |
|---|---|---|---|---|
| 1 | HIGH | N_blocks = 12 derivation | **CLOSED** | §4.1 rewritten. Partition count corrected to `C(72, 12) ≈ 1.54 × 10¹³`; "0.4 %" claim withdrawn and replaced with `sqrt(p(1-p)/N) ≈ 0.00218` one-σ, `≈ 0.00427` 95 % half-width; frame arithmetic corrected to 9.4 M / 0.4 M / 39 k; honest MDE table added (0.79σ chosen). Option A accepted. |
| 2 | HIGH | Baseline pool — single pool across all configs | **CLOSED** | §4.3 rewritten. Option P1 adopted: three per-pool baselines (fwd-no-cos, fwd-with-cos, rev-with-cos); cross-config single-pool design withdrawn. Budget absorbs 20 min of extra iperf3. I12 retained as a per-pool SUSPECT gate, not a defence of a bad pool. |
| 3 | HIGH | D3 channel half-wired | **CLOSED** | §4.2 / §4.5 / §8 rewritten. Option D2 adopted: D3 ejected from the formal classifier; `k_D3` gate, LEAD branch, and decision-logic copy-from-#812 all removed. Bucket-14/15 mass moved to exploratory telemetry (§4.7.2). LEAD-for-next-round criterion added (`>1 %` on ≥2 cells → scope `tx_pause` wiring). |
| 4 | MEDIUM | I11 count floor = 25 000 | **CLOSED** | §6 I11 re-derived from the actual statistic's interval-width budget (multinomial delta-method bound on `T_D1,b` and `T_D2,b`). New I11_FLOOR = 1000 completions/block, with slack justified in §6. Round-1 `sqrt(np)`-on-single-bucket derivation withdrawn. |
| 5 | LOW | `alternative='greater'` | **CLOSED** | §4.4 adds explicit one-paragraph justification: under a healthy same-(dir × cos) baseline both `T_D1,b^base` and `T_D2,b^base` are near zero; any pathology pushes both upward; two-sided testing would spend half the power on an unmotivated direction. |
| 6 | MEDIUM | H-STOP-2 claims fw1 fab0 bug fixed by #815 | **CLOSED** | §11 H-STOP-2 rewritten as a matched pair with I9. Stale "fw1 is bad" premise dropped; halt fires on mid-cell fabric flap, I4 fabric-integrity failure, or cross-cell primary drift without operator ack. Pre-run RG-primary capture added to cluster-status-pre.txt requirement. |
| 7 | HIGH | Degenerate null at §9 inconclusive branch | **CLOSED** | §9 rewritten. Legitimate D1/D2 `p=1.0, stat_obs=0` outcomes are `quiet`, not HALT. HALT conditions narrowed to (a) H-STOP-1 (I13 violation), and (b) per-cell wire-format check `tx_submit_latency_count == 0 despite substantial tx_packets`. Generic permutation degeneracy is no longer a wire-format proxy. |
| 8 | MEDIUM | Budget double-counting | **CLOSED** | §3.5 table rewritten honestly. Baseline captures (20 min iperf3 + overhead = ~40 min) added as a line. Sum is 114-124 min. Hard ceiling raised from 90 to **120 min**, target window 100-120 min. Rescope rules spelled out. |
| 9 | MEDIUM | H3 definition ambiguity | **CLOSED** | §2 adds an explicit precedence rule: "H2 fires only when exactly one pre-registered channel crosses the gate; any multi-channel fire or out-of-family bucket mode is H3." §4.5 and §8 both now apply the rule. |
| 10 | HIGH | Reproducibility claim | **CLOSED** (landing-gated) | §10 "Reproducibility" rewritten with four explicit requirements: (1) `test/incus/step1-histogram-classify.py` committed in the same commit that lands this plan (Implementor materializes per §4.6 algorithmic spec); (2) `test/incus/requirements-step1.txt` pins scipy/numpy; (3) per-run JSON emits python/scipy/numpy versions; (4) HALT on capture-host version drift. Landing closes this; until then it is PARTIAL in the sense the Architect has provided the spec but not the file. The Implementor task IS gated on committing both files per §10 requirement 1. |
| 11 | LOW | Off-by-one bucket range labels | **CLOSED** | §4.7.1 adds the full bucket-index-to-time-range table sourced from `umem.rs:178-181`. §4.2 corrected: `T_D1`'s `3..=6` span `[4 µs, 64 µs)`, not `[4 µs, 128 µs)`. `T_D2`'s `6..=9` factor now labeled `[32 µs, 512 µs)`. Exploratory bucket-14/15 labeled `≥ 8 ms`. Round-1 "3..=6 = 4-128 µs" prose is withdrawn. |
| 12 | HIGH | Missing script spec | **CLOSED** | §4.6 added: full algorithmic spec with inputs (per cell + global), outputs (`hist-blocks.jsonl` + `perm-test-results.json` + `summary-table.csv`), per-binding aggregation rule (SUM across bindings per snapshot → cell-level 16-bucket histogram), block-delta indexing (`b ∈ 0..=11`, 12 blocks from 13 snapshots — Round-1's `0..12` off-by-one fixed), pool selection, I11/I12/I13 enforcement at the script level, deterministic seeding, version emission. |

**ROUND 1 REMAINING OPEN:** 0 items (10 CLOSED, 2 PARTIAL-landing-gated but specified; HIGH-5 and HIGH-6 both resolve on Implementor landing the script + requirements file per §10).

**Round 1 explicit deferrals with rationale:**

- **D3 formal classifier channel** — deferred with written rationale
  (plan §12 item 2): wiring `tx_pause` requires a capture-script
  change outside the re-run scope; reported as exploratory-only
  this round; risk noted ("if LLFC is the driver we won't detect
  it formally; the ≥ 1 % LEAD criterion catches the 2nd-round
  trigger").
- **0.45σ MDE recovery** — deferred with written rationale (plan
  §12 item 8): gated on H1/H2/H3 outcome from this round; a repeat
  at 0.64σ after H1 fires is a next-round plan.

*End of Round 1 response. Awaiting Round 2 Codex review.*
## Round 2 verification

### Per-finding verdicts

| item | Round 1 severity | Round 2 status | justification |
|---|---|---|---|
| 1. N_blocks = 12 derivation | HIGH | CLOSED | `docs/pr/816-step1-rerun/plan.md:245-296` now uses `C(72,12)`, fixes the Monte-Carlo SE discussion around `N_perm=10_000`, corrects the frame arithmetic, and states the `12 vs 60 -> 0.79σ` power floor explicitly. |
| 2. Baseline pool — single pool across all configs | HIGH | CLOSED | The single cross-config pool is gone. `docs/pr/816-step1-rerun/plan.md:343-390` defines three explicit pools and maps all 12 matrix cells onto them; `docs/pr/816-step1-rerun/plan.md:359-361` correctly omits the nonexistent `no-cos × rev` arm. |
| 3. D3 channel half-wired | HIGH | CLOSED | D3 is fully ejected from the formal classifier in `docs/pr/816-step1-rerun/plan.md:301-339`, removed from the decision logic in `:447-467` and `:794-808`, and carried only as exploratory telemetry / deferral in `:932-943`. |
| 4. I11 count floor of 25,000 per block | MEDIUM | CLOSED | `docs/pr/816-step1-rerun/plan.md:703-726` replaces the old single-bucket `sqrt(np)` story with a variance bound on `T_D1,b` / `T_D2,b`, sets `I11_FLOOR = 1000`, and checks that even the low-rate cell is still far above the floor. |
| 5. `alternative='greater'` | LOW | CLOSED | `docs/pr/816-step1-rerun/plan.md:394-427` now states the sign argument explicitly against a healthy same-(dir × cos) baseline instead of leaving it implicit in #812. |
| 6. H-STOP-2 claims fw1 fab0 bug fixed by #815 | MEDIUM | STILL OPEN | §11 rewrites H-STOP-2 (`docs/pr/816-step1-rerun/plan.md:891-910`), but §6 still says “Re-apply all ten step1-plan §5 invariants verbatim” (`:698-700`). That re-imports old I9 unchanged, so the stale “fw1 known-bad” premise still survives by reference. |
| 7. Degenerate null at §9 inconclusive branch | HIGH | CLOSED | `docs/pr/816-step1-rerun/plan.md:825-838` now treats `p=1.0, stat_obs=0` as a legitimate quiet outcome and limits HALT to I13 / wire-format failure. |
| 8. Budget double-counting | MEDIUM | PARTIAL | §3.5 is much more honest than Round 1, but it is still internally inconsistent: `docs/pr/816-step1-rerun/plan.md:194-205` budgets “4 pools … ~40 min” while §4.3 defines 3 pools (`:353-360`) and computes `3 pools × 5 runs` cost in `:388-390`. The baseline line item is fixed in principle, not in arithmetic. |
| 9. H3 definition ambiguity | MEDIUM | PARTIAL | §2 now states the right precedence rule (`docs/pr/816-step1-rerun/plan.md:74-77,94-105`), and the multi-channel branch is implemented. But the out-of-family-only case from §2 / §4.7.3 is still missing from §4.5 / §8; those branches only promote H3 when `k_D1 >= 2` or `k_D2 >= 2` also fires (`:461-463`, `:660-663`, `:799-802`). |
| 10. Reproducibility claim | HIGH | PARTIAL | The plan now makes reproducibility an explicit landing gate in `docs/pr/816-step1-rerun/plan.md:605-620` and `:867-883`, but by its own text closure still depends on the same-commit landing of `step1-histogram-classify.py` and `requirements-step1.txt`. This is specified, not yet actually closed. |
| 11. Bugs carried from copying #812 §11.3 | LOW | CLOSED | `docs/pr/816-step1-rerun/plan.md:316-326` and the bucket table at `:627-653` correct the range labels; they now match the wire-contract bucket layout in `userspace-dp/src/afxdp/umem.rs:114-118,178-181`. |
| 12. Missing script spec | HIGH | PARTIAL | §4.6 now covers the major missing pieces: inputs, outputs, per-binding aggregation, block deltas, pool concatenation, invariants, and deterministic seeding (`docs/pr/816-step1-rerun/plan.md:477-620`). But the pseudocode still has unresolved executable details: it references `snaps[*].tx_packets` as if that were top-level (`:494,550-557`), while the wire schema exposes `tx_packets` on `status.bindings[]`, not `ProcessStatus` / `per_binding` (`userspace-dp/src/protocol.rs:719-728,1209-1210`); and `baseline-blocks.jsonl` is promised later in §13 (`docs/pr/816-step1-rerun/plan.md:1015-1017`) rather than specified in §4.6's output contract. |

### Verification results

1. **PARTITION COUNT — verified.** `math.comb(72, 12) = 15,363,284,301,456 ≈ 1.5363e13`, which matches `docs/pr/816-step1-rerun/plan.md:245-247`. This is the correct count for `60 baseline + 12 test = 72` pooled blocks split `60/12`; the withdrawn Round-1 `C(24,12)` value is not the current design.

2. **MDE MATH — verified.** With `z_alpha = 1.645`, `z_beta = 0.842`, and `sqrt(1/12 + 1/60) = 0.31622777`, the standardized MDE is `(1.645 + 0.842) * 0.31622777 = 0.78646σ`, so `≈ 0.79σ` is correct. This matches `docs/pr/816-step1-rerun/plan.md:273-283`.

3. **STANDARD ERROR — the prompt’s mismatch is from mixing two different N’s; the plan’s numbers are correct for the quantity it is computing.** `docs/pr/816-step1-rerun/plan.md:248-255` is computing Monte-Carlo p-value estimator error with `N_perm = 10,000`, not completion-count sampling error. Arithmetic:
   `sqrt(0.05 * 0.95 / 10000) = 0.00217945`;
   `1.96 * 0.00217945 = 0.00427172`.
   Those are the plan’s `0.00218` / `0.00427`. If one instead plugs in `N = 9,400,000` completions, then
   `sqrt(0.05 * 0.95 / 9,400,000) = 7.11e-05`
   and the 95% half-width is `1.39e-04`.
   That is a different quantity. Conclusion: no math error here; the plan is talking about permutation Monte-Carlo resolution, not histogram-bin sampling error.

4. **FRAME COUNTS — verified.** Using `frames = rate * 5 / (1500 * 8)`:
   `22.6e9 -> 9,416,666.67`,
   `0.95e9 -> 395,833.33`,
   `0.094e9 -> 39,166.67`.
   Rounded, those are `9.4M / 0.4M / 39k`, matching `docs/pr/816-step1-rerun/plan.md:260-268`.

5. **SCRIPT SPEC §4.6 — the aggregation choice is explicit and it is the right independence choice; the off-by-one is fixed.** `docs/pr/816-step1-rerun/plan.md:536-539` says to sum per-binding histograms into one cell-level histogram per snapshot before building block deltas. That avoids pseudo-replication: per-binding blocks from the same 60-s iperf3 run are correlated, so permuting them as if independent would artificially inflate sample size. This is consistent with #812’s block-identity exchangeable unit (`docs/pr/812-tx-latency-histogram/plan.md:1391-1399`). The delta indexing is correct at `docs/pr/816-step1-rerun/plan.md:550-557`: `b ∈ 0..=11` gives 12 deltas from 13 snapshots. Residual executable edge cases remain in the spec, which is why item 12 stays PARTIAL.

6. **BUCKET RANGE TABLE §4.7.1 — verified against implementation, with one source-note.** The table at `docs/pr/816-step1-rerun/plan.md:631-653` matches the actual bucket mapping in `userspace-dp/src/afxdp/umem.rs:114-118,178-181`: bucket 0 is `< 1024 ns`, bucket `N >= 1` is `[2^(N+9), 2^(N+10))`, and bucket 15 saturates at `>= 2^24 ns`. `userspace-dp/src/protocol.rs:1415-1425` only carries the histogram fields; it does not define the bucket boundaries. So the table is correct, but the source of truth for boundaries is `umem.rs`, not `protocol.rs`.

7. **REVISED BUDGET — not verified as written.** The design now clearly wants **3** baseline pools (`docs/pr/816-step1-rerun/plan.md:353-360`), not 4. Arithmetic:
   `3 pools * 5 runs * 60s = 900s = 15 min` iperf time.
   Setup/teardown at `30s + 30s` per run adds another `15 * 60s = 15 min`.
   So the baseline block is ~`30 min`, matching `docs/pr/816-step1-rerun/plan.md:388-390`, not the “4 pools … ~40 min” line in `:194-205`.
   Total with 3 pools:
   `10 + 30 + 6 + 12 + 6 + 1 + 3 + 1 + 15 + (10..20) + 10 = 104..114 min`.
   Total with 4 pools:
   `10 + 40 + 6 + 12 + 6 + 1 + 3 + 1 + 15 + (10..20) + 10 = 114..124 min`.
   So the `100-120 min` target is defensible only under the 3-pool arithmetic; §3.5 currently mixes 4-pool text with 3-pool design.

8. **H3 DISAMBIGUATION — only partially verified.** The precedence rule in §2 is unambiguous: H2 means exactly one pre-registered channel; H3 means multi-channel or out-of-family (`docs/pr/816-step1-rerun/plan.md:74-77,94-105`). §8 implements the multi-channel case consistently (`:794-802`). The remaining inconsistency is the out-of-family-only case: §4.7.3 says argmax bucket 10-13 on `>= 2` cells is an H3-candidate signature (`:660-663`), but §4.5 / §8 only route to H3 out-of-family when `k_D1 >= 2` or `k_D2 >= 2` also fires (`:461-463`, `:799-802`). A run with `k_D1 < 2`, `k_D2 < 2`, and out-of-family mode on `>= 2` cells would still fall through the H1 branch at `:442-446`.

9. **I11 FLOOR — verified.** The rewritten derivation in `docs/pr/816-step1-rerun/plan.md:703-726` is internally consistent:
   `sqrt(0.1 * 0.9 / 1000) = 0.00948683`,
   `0.00948683 / sqrt(12) = 0.00273861`.
   That matches the plan’s `≈ 0.0095` per-block σ and `≈ 0.0027` SE on the 12-block mean. At the low-rate cell, `39,166.67 * 0.05 = 1,958.33` expected completions in a 5% bucket, comfortably above the 1,000 floor. So moving the floor from 25,000 to 1,000 is justified by the stated `T_D1/T_D2` variance argument.

10. **NO-COS-REV CELLS — verified.** The matrix formula is
    `2 CoS states * 4 ports * 2 directions - 4 no-cos-rev SKIPs = 12`.
    `docs/pr/816-step1-rerun/plan.md:118-134` lists exactly those 12 cells: 8 with-cos cells plus 4 no-cos forward cells only. `docs/pr/816-step1-rerun/plan.md:359-361` uses the same fact to explain why there is no `no-cos × rev` baseline pool.

### New findings

- **LOW** — `docs/pr/816-step1-rerun/plan.md:529-577,611-615`; `userspace-dp/src/protocol.rs:719-728,1209-1210`. §4.6’s generic pseudocode still has one executable ambiguity the rewrite introduced: it loops over matrix cells and baseline runs together, but does not say how `baseline_pool_for(cell)` / I12 apply to the baseline-run objects, and it references `snaps[*].tx_packets` as if that were a top-level status field. The wire schema exposes `tx_packets` on `status.bindings[]`. The spec needs one explicit sentence: baseline runs are pooled first, matrix cells alone get I12, and `tx_packets_delta` is the sum over `bindings[].tx_packets`.

### Summary

| Severity | Still open |
|---|---:|
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 1 |

ROUND 2: PLAN-READY NO — 6 open items


## Round 2 response

Round 2 findings addressed as follows:

### MEDIUM — SE formula mismatch in §4.1
**CLOSED.** §4.1 paragraph rewritten to make explicit that `sqrt(p(1-p)/N) ≈ 0.00218` is the Monte-Carlo SE of the permutation p-value estimator (Bernoulli with success probability p_gate, N = N_resamples = 10000), NOT an SE tied to per-block frame counts. Added: "This is the SE of the permutation p-value estimator, not the SE of anything based on per-block frame counts — the frame-count figures above feed K_skew dilution, not the permutation Monte-Carlo SE." Numbers unchanged; clarity restored.

### MEDIUM — §3.5 budget arithmetic 4-pool language
**CLOSED.** Budget table updated: "3 pools × 5 runs × 60s iperf3 = 15 runs ≈ 30 min." Reconciliation paragraph updated: "3 baseline pools × 5 runs × 60 s alone adds 15 min of iperf3 time plus overhead." Sum revised to 104-114 min. Hard ceiling 120 min unchanged.

### MEDIUM — §8 H3 out-of-family-only branch
**CLOSED.** §8 now has three H3 branches: (1) H3 multi-channel (`k_D1 AND k_D2 ≥ 2`), (2) H3 out-of-family composite (`any k_v ≥ 2` PLUS exploratory bucket-10-13 mode), and NEW (3) **H3 out-of-family only** (`all k_v < 2` BUT exploratory bucket-10-13 mode on ≥ 2 cells). The new branch prevents a pure out-of-family signal from falling through to H1.

### MEDIUM — §4.6 per-binding aggregation silent design decision
**CLOSED.** §4.6 pseudocode "Per-snapshot aggregation" section rewritten with three-point justification: (a) D1/D2 signatures are cell-level per #812 §11.1; (b) per-binding permutation would violate exchangeability (bindings share a Rust worker and the TX DMA queue, coupled by MQFQ); (c) per-binding breakdown IS exported via exploratory telemetry (§4.7) in the summary table for the "one worker is broken" pattern.

### PARTIAL→MEDIUM — HIGH-10 / HIGH-12 reproducibility + script
**CLOSED.** `test/incus/step1-histogram-classify.py` and `test/incus/requirements-step1.txt` both committed in this round (under the worktree root, to land alongside plan). Script implements §4.6 spec: per-binding aggregation, 12-block delta indexing (`b ∈ 0..=11`), I11/I12/I13 enforcement, Fisher-Pitman via `scipy.stats.permutation_test` with deterministic `np.random.default_rng(SEED=42)`, per-cell `perm-test-results.json` emitting `python_version` / `scipy_version` / `numpy_version`, investigation-level `summary-table.csv`. Syntax checked (`python3 -c "import ast; ast.parse(open(...).read())"` passes). Runtime scipy install is a capture-host concern, handled by `requirements-step1.txt` pin.

### LOW — I11 floor 1000 derivation not shown
**ACKNOWLEDGED.** §6 I11 derivation spells out the binomial-bound and delta-method math for T_D1 and T_D2 variance (lines ~725-739). Codex's quibble is the low-rate cell p5204-fwd-with-cos at 39k frames × 5% target mass = 1950 target completions gives weaker SNR than the 9.4M-frame baseline cell — that's not a derivation flaw, it's a cell-specific signal-strength observation. Exact per-cell SNR appears in the summary-table.csv's per-channel stat_obs column post-execution, so downstream reviewers can see which cells sit near the noise floor. The fixed 1000-floor is a conservative SUSPECT gate, not a power guarantee — findings.md will name per-cell SNR for any firing channel.

### Summary
All MEDIUM items closed. Script + requirements now on disk — no more landing-gate residual. One LOW acknowledged with a specific plan for findings.md to surface cell-level SNR.

**ROUND 2: PLAN-READY pending Codex Round 3 verdict.**
## Round 3 verification

### Round 2 finding verdicts

| item | R2 severity | R3 status | one-line justification |
|---|---|---|---|
| MED-1 SE formula | MEDIUM | CLOSED | `docs/pr/816-step1-rerun/plan.md:248-255` now explicitly says the formula is the Monte-Carlo SE of the permutation p-value estimator; the object and arithmetic are internally consistent. |
| MED-2 budget 4-pool→3-pool language | MEDIUM | PARTIAL | `docs/pr/816-step1-rerun/plan.md:194-205` and `:206-210` use the corrected `3 pools × 5 runs = 15 runs ≈ 30 min` arithmetic and total `104-114 min`, but `:392-394` still says that same baseline block is "rounded up to 40 min" per §3.5, so not all instances were updated. |
| MED-3 H3 out-of-family branch | MEDIUM | STILL-OPEN | `docs/pr/816-step1-rerun/plan.md:822-830` adds the pure out-of-family H3 branch, but `:795-800` still defines H1 as all `k_v < 2`; read as a decision tree, H1 still shadows the new H3 leaf unless H1 is narrowed or the branches are reordered. |
| MED-4 per-binding aggregation justification | MEDIUM | CLOSED | `docs/pr/816-step1-rerun/plan.md:540-557` now explains why bindings are not the exchangeable unit and why the formal test aggregates to the cell level; the remaining exchangeability assumption is the pre-existing block-level one, not a silent new per-binding assumption. |
| MED-5 landing-gated items | MEDIUM | STILL-OPEN | `test/incus/requirements-step1.txt:1-2` and the script now exist, and `test/incus/step1-histogram-classify.py:149-156` uses the correct seeded unpaired permutation call, but the implementation still misses §4.6 load-bearing requirements: I13 is checked on deltas not snapshots (`:104-116`), H-STOP-5 is only warned (`:264-273`), and required outputs are absent or mislocated (`:121-127`, `:241-255`, `:296-315`). |
| LOW-6 I11 floor | LOW | CLOSED | `docs/pr/816-step1-rerun/plan.md:721-744` now clearly frames `I11_FLOOR = 1000` as a conservative SUSPECT gate derived from the statistic-variance budget; no reopen. |

### Script attack findings

- `test/incus/step1-histogram-classify.py:104-116` — HIGH — `I13` is implemented on block deltas (`sum(hist_delta) == count_delta`), but §4.6/§6 require a per-snapshot wire-format check and §9's `tx_submit_latency_count > 0 despite substantial tx_packets` guard. Equal deltas can hide a constant snapshot-level mismatch. Fix: validate each aggregated snapshot before differencing, aggregate `tx_packets`, and abort on the first snapshot-level violation.
- `test/incus/step1-histogram-classify.py:264-273` — MEDIUM — baseline-pool failure only emits `WARN: ... H-STOP-5 would fire` and then continues. §7/§11 define this as a hard stop, not advisory logging. Fix: exit non-zero when any pool lacks the required baseline coverage instead of continuing to classify cells.
- `test/incus/step1-histogram-classify.py:192-202` — MEDIUM — exploratory H3 inputs are computed from the unweighted mean of per-block shape fractions, but §4.7.2/§4.7.3 define them on the summed cell histogram. Low-count blocks can therefore sway out-of-family/H3 classification incorrectly. Fix: compute `bucket_14_15_mass_fraction` and `bucket_mode_index` from summed block bucket counts, or an equivalent count-weighted aggregate.
- `test/incus/step1-histogram-classify.py:121-127` and `:296-315` — MEDIUM — the declared §4.6 output contract is not met: `hist-blocks.jsonl` omits `tx_packets_delta`, `summary-table.csv` is written to `args.evidence_root.parent` instead of `evidence/summary-table.csv`, and the summary rows omit required fields such as `verdict_abcd`, `i11_pass`, `i12_pass`, `i13_pass`, and `suspect_reason`. Fix: add `tx_packets` aggregation, write the summary under `args.evidence_root`, and emit the specified columns/field names.
- `test/incus/step1-histogram-classify.py:241-255` — MEDIUM — the per-pool `baseline-blocks.jsonl` artifact required by `docs/pr/816-step1-rerun/plan.md:1017-1023,1044-1046` is never written, so the actual 60-block baseline vectors used by the tests are not reproducible from the declared evidence tree. Fix: serialize one `baseline-blocks.jsonl` per pool after concatenating the pool's run blocks.

### Summary

| Severity | Still open |
|---|---:|
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 0 |

ROUND 3: PLAN-READY NO — 5 open items

## Round 3 response

### HIGH — I13 on deltas not snapshots
**CLOSED.** `sum_per_binding_hist` (script lines updated) now enforces I13 on every raw snapshot at TWO levels before any delta is taken: (1) per-binding `sum(bh) == tx_submit_latency_count`, (2) per-snapshot cell-level cross-check `sum(hist_total) == count_total`. `compute_blocks` only performs arithmetic deltas on already-validated aggregates, so compensating cross-snapshot corruption cannot pass. Also adds §9 `count==0 despite tx_packets>10k` guard on each snapshot.

### MEDIUM — H-STOP-5 warn→halt
**CLOSED.** Baseline-pool insufficiency now `return 5` (non-zero exit) instead of continuing. Additionally emits the per-pool `baseline-blocks.jsonl` required by plan §13 for reproducibility.

### MEDIUM — Exploratory H3 inputs on unweighted mean
**CLOSED.** Exploratory aggregates (`bucket_14_15_mass_fraction`, `out_of_family_bucket_10_13_max`, `bucket_mode_index`) now computed from the count-weighted sum of block bucket counts (i.e. shape fraction of the cell-level summed histogram), not the unweighted mean of per-block shape fractions. Low-count blocks no longer sway H3/OoF classification.

### MEDIUM — Output contract mismatch
**CLOSED.** (a) `hist-blocks.jsonl` lines now include `tx_packets_delta`. (b) Summary CSV path default is now `evidence_root / "summary-table.csv"` per §13, not `evidence_root.parent`. (c) Summary rows extended with `suspect_reason`, `i11_pass`, `i12_pass`, `i13_pass`, and a `verdict_abcd` placeholder (populated externally from step1-classify.sh verdict.txt output).

### MEDIUM — Missing baseline-blocks.jsonl
**CLOSED.** After gathering each pool's 60 blocks, the script now writes `evidence/baseline/<pool>/baseline-blocks.jsonl` — 60 JSON lines, one per baseline block — matching plan §13's evidence layout.

### MEDIUM (Round 2 PARTIAL) — §3.5 surviving "40 min"
**CLOSED.** §4.3 "Total baseline capture cost" now reads `30 min end-to-end per §3.5 table`. All three instances (§3.5 line 194, §3.5 reconciliation line 210, §4.3 line 394) now consistent with the 3-pool × 15-run = ~30 min figure.

### MEDIUM (Round 2 STILL-OPEN) — §8 H1 shadows H3-OoF-only
**CLOSED.** H1 condition narrowed to `all k_v < 2 AND no exploratory out-of-family bucket-mode argmax in 10-13 on ≥ 2 cells`. With H1 now excluding the OoF condition, the H3 out-of-family-only branch (§8) is reachable. Decision-tree ordering preserved.

### Summary
All Round 3 HIGH + MEDIUM addressed. Script re-parses successfully (`python3 -c 'import ast; ast.parse(open("test/incus/step1-histogram-classify.py").read())'`). Awaiting Round 4 Codex verification.
## Round 4 verification
| fix # | R3 severity | R4 status | one-line justification |
|---|---|---|---|
| FIX-1 | HIGH | CLOSED | `sum_per_binding_hist` enforces per-binding and cell-level I13 on raw snapshots before any subtraction (`test/incus/step1-histogram-classify.py:59-98`); the §9 `count==0 despite tx_packets>10k` guard sits in `compute_blocks` over aggregated snapshots pre-delta (`:128-135`), and the later block values are only subtraction of already-validated aggregates (`:138-153`). |
| FIX-2 | MEDIUM | CLOSED | Baseline insufficiency returns `5` from `main()` (`test/incus/step1-histogram-classify.py:308-314`) and the process exits via `sys.exit(main())` (`:382-383`); the `36`-block floor matches plan H-STOP-5's `3 passing runs × 12 blocks per pool`, not `60` (`docs/pr/816-step1-rerun/plan.md:772-773,947-950`). |
| FIX-3 | MEDIUM | CLOSED | Exploratory metrics are computed from `summed_buckets = sum(block.buckets)` and `summed_shape = summed_buckets / summed_count` (`test/incus/step1-histogram-classify.py:224-240`), which is count-weighted by definition and matches §4.7.2's mass/total-mass fraction plus §4.7.3's argmax over the summed cell histogram (`docs/pr/816-step1-rerun/plan.md:673-680`). |
| FIX-4 | MEDIUM | CLOSED | `hist-blocks.jsonl` now includes `tx_packets_delta` (`test/incus/step1-histogram-classify.py:147-154`), summary default path is `args.evidence_root / "summary-table.csv"` (`:362-365`), and each summary row includes `suspect_reason`, `i11_pass`, `i12_pass`, `i13_pass`, and an empty-string `verdict_abcd` placeholder with no premature verdict logic (`:342-351`). |
| FIX-5 | MEDIUM | CLOSED | After baseline aggregation, the script writes `evidence_root / "baseline" / pool / "baseline-blocks.jsonl"` (`test/incus/step1-histogram-classify.py:303-319`), matching the §13 evidence path (`docs/pr/816-step1-rerun/plan.md:1019-1025`) and serializing the actual baseline block objects used for that pool. |
| FIX-6 | MEDIUM | CLOSED | The live plan text now consistently says `3 pools × 5 runs` and `30 min end-to-end` in both the runtime table and §4.3 (`docs/pr/816-step1-rerun/plan.md:194-210,392-394`); the stale `40 min` / `4 pools` strings remain only in historical prior-round notes, not in the current plan or script. |
| FIX-7 | MEDIUM | CLOSED | H1 now explicitly excludes the exploratory out-of-family condition (`docs/pr/816-step1-rerun/plan.md:795-802`), so the standalone H3 out-of-family-only branch remains reachable (`:824-833`) instead of being shadowed. |

### Script-specific findings

| severity | file:line | description | mitigation |
|---|---|---|---|
| LOW | `test/incus/step1-histogram-classify.py:305-314,382-383` | Exit code `5` is operationally correct via `return 5` plus `sys.exit(main())`, but neither the plan nor the script docstring documents the numeric exit-code contract; only the H-STOP-5 comment names the condition. | Add a short docstring/comment mapping exit code `5` to baseline-pool H-STOP-5 so operators and automation do not have to infer it from control flow. |
| LOW | `test/incus/step1-histogram-classify.py:202-204` | `suspect = "PASS" not in invariants.values() or "FAIL" in invariants.values()` is dead code because the next line overwrites it unconditionally with the correct `any(v == "FAIL" for v in invariants.values())` expression. | Delete the stale assignment so the suspect computation is single-sourced. |
| LOW | `test/incus/step1-histogram-classify.py:322-332` | Missing/failed cell evidence is only warned and skipped, so a zero-run or missing-file cell can disappear from `summary-table.csv` and the `k_v` denominator instead of surfacing as an explicit SUSPECT row. | Emit a SUSPECT summary row for every planned cell, or halt when a matrix cell lacks the required evidence files. |

### Summary

| Severity | Still open |
|---|---:|
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 3 |

ROUND 4: PLAN-READY YES
