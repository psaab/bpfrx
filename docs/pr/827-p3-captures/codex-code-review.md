# Code Review — PR #827 p3-captures

**Verdict: MERGE NO**

## Contract Checks (1-10)
1. PASS — `step1` enforces K0/K1 in `sum_per_binding_kick()` and K2/K3 in `compute_blocks()` before the block-emission loop, so no `tx_kick_*_delta` output is produced before those checks run (`test/incus/step1-histogram-classify.py:112-175`, `test/incus/step1-histogram-classify.py:211-257`).
2. PASS — `step3` uses `KICK_LAT_IN_NS=4096`, `KICK_LAT_OUT_NS=2048`, `RETRY_IN=1000`, `RETRY_OUT=100`, and the verdict path uses integer cross-multiplication in `t1_in_block()` / `t1_out_block()` rather than float division (`test/incus/step3-tx-kick-classify.py:45-48`, `test/incus/step3-tx-kick-classify.py:135-148`).
3. PASS — `elevated_blocks()` uses the 3rd-largest `T_D1` value as the threshold and includes all ties with `>=`, so the returned set is size `>= 3` when `len(T_D1) >= 3` (`test/incus/step3-tx-kick-classify.py:110-120`).
4. PASS — `step3` only opens `--hist-blocks` via `load_jsonl()`; there is no path in the file that opens `flow_steer_*` or any raw snapshot file (`test/incus/step3-tx-kick-classify.py:57-65`, `test/incus/step3-tx-kick-classify.py:377-386`).
5. FAIL — `t1_out_block()` checks `retry_delta >= RETRY_OUT` before `count_delta == 0`, so a no-kick block with high retry returns `False` instead of the required vacuous `True` (`test/incus/step3-tx-kick-classify.py:143-148`).
6. PASS — step1 emits exactly `tx_kick_count_delta`, `tx_kick_sum_ns_delta`, `tx_kick_retry_delta`, and `tx_kick_hist_delta`, and step3 reads those exact names (`test/incus/step1-histogram-classify.py:277-280`, `test/incus/step3-tx-kick-classify.py:79-85`).
7. PASS — step3 writes `--out`, sibling `.meta.json`, sibling `.diag.json`, and `tx-kick-by-block.jsonl`; there is no `verdict.txt` write path (`test/incus/step3-tx-kick-classify.py:392-439`).
8. PASS — the step3 CLI only defines `--hist-blocks`, `--cell`, and `--out`; there is no `--evidence-dir` flag (`test/incus/step3-tx-kick-classify.py:377-382`).
9. FAIL — the approved plan says test #5 should yield verdict `OUT`, but the checked-in test asserts `INCONCLUSIVE`; the implementation/test set is not aligned with the approved contract (`docs/pr/827-p3-captures/plan.md:322-324`, `test/incus/step3-tx-kick-classify_test.py:155-171`).
10. FAIL — test #19 does hit the hist-bucket monotonicity branch without retry/sum-ns short-circuiting, but not all 22 tests exercise their stated contract: test #2 cannot distinguish integer gating from float division because its fixture yields an exact 3000 ns mean, and test #5 does not implement the approved “verdict OUT” scenario (`test/incus/step1-histogram-classify_test.py:200-233`, `docs/pr/827-p3-captures/plan.md:311-314`, `docs/pr/827-p3-captures/plan.md:322-324`, `test/incus/step3-tx-kick-classify_test.py:95-113`, `test/incus/step3-tx-kick-classify_test.py:155-171`).

## Findings
- HIGH — `test/incus/step3-tx-kick-classify.py:143-148`: No-kick semantics are wrong relative to the approved contract. `t1_out_block()` returns `False` on `count_delta == 0` whenever `retry_delta >= 100`, because the retry guard short-circuits before the no-kick case. Concrete fix: move the `count_delta == 0` fast path ahead of the retry check, or otherwise encode the approved no-kick rule explicitly, then add a test with `count=0` and `retry>=100`.
- MED — `docs/pr/827-p3-captures/plan.md:322-324`, `test/incus/step3-tx-kick-classify_test.py:155-171`: Approved test #5 says “all others OUT; verdict OUT,” but the checked-in test asserts `INCONCLUSIVE`. That is a direct plan/test contradiction, not a reviewer interpretation gap. Concrete fix: either change the fixture so the outside-elevated witness still leaves every block in the OUT band, or update the approved plan before merge.
- MED — `docs/pr/827-p3-captures/plan.md:311-314`, `test/incus/step3-tx-kick-classify_test.py:95-113`: `test_large_u64_integer_gating` does not actually prove integer-space gating. The fixture sets the mean to exactly 3000 ns, so both integer comparison and float-division comparison land in the same `INCONCLUSIVE` bucket. Concrete fix: pick a `count` near/above `2^53` and a `sum_ns` whose true ratio sits just below or just above 2048 or 4096, so float rounding can change the verdict while integer cross-multiplication cannot.

## Summary
The core implementation is mostly aligned with the plan: step1 owns K0-K3 pre-delta, step3 uses the right thresholds and wire keys, reads only `hist-blocks.jsonl`, and emits the expected outputs and CLI surface. The merge blocker is the no-kick OUT semantics in `step3`, and the test suite is not at the same bar as the approved plan because one planned OUT-case test was checked in as `INCONCLUSIVE` and the large-u64 test does not actually pin the integer-math requirement. I could not execute `pytest` here because the `pytest` module is not installed in this environment.

## R2 Follow-up

**Verdict: MERGE YES**

- PASS — plan §4.3 is now consistent with the authoritative §4.4 formal definition: on `count_delta == 0`, only the latency side of OUT is vacuous, while `tx_kick_retry_delta < 100` still applies (`docs/pr/827-p3-captures/plan.md:180-190`, `docs/pr/827-p3-captures/plan.md:221-226`).
- PASS — R1 MED-1 is closed. Plan test #5 now matches the implementation's actual `INCONCLUSIVE` outcome, and the test body still checks the real contract: a rank-5 IN-shaped block must not become an IN witness merely by matching the thresholds (`docs/pr/827-p3-captures/plan.md:329-337`, `test/incus/step3-tx-kick-classify_test.py:193-223`).
- LOW — R1 LOW-1 is only partially closed. The updated test now honestly admits later in the docstring that the chosen fixture "cannot DISCRIMINATE between integer and float math here", but both the opening sentence of the docstring and the approved plan still describe it as a float-vs-integer disagreement case that the body does not actually realize (`test/incus/step3-tx-kick-classify_test.py:96-102`, `test/incus/step3-tx-kick-classify_test.py:123-151`, `docs/pr/827-p3-captures/plan.md:318-321`). This is a documentation/test-description issue, not a blocker, because the production code still uses integer cross-multiplication in the verdict path (`test/incus/step3-tx-kick-classify.py:135-148`).

R2 conclusion: the prior merge blockers are resolved. The remaining issue is low-severity wording drift around test #2; it should be renamed or the plan text should be softened to describe it as a large-value integer-path sanity check rather than a discriminating float-vs-integer proof, but that does not justify holding the PR.
