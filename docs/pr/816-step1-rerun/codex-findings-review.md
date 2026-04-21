# Codex Findings Review

Summary: 1 HIGH, 1 MEDIUM, 2 LOW. The core H3 call is supported by the machine-readable outputs: `summary-table.csv` does show `D1_fire=True` on 4 cells and `D2_fire=True` on 3 cells, `with-cos/p5202-fwd` and `with-cos/p5203-rev` are the only both-fire cells, and `with-cos/p5204-fwd` is correctly excluded as `suspect=true`, `suspect_reason="I12"` (`docs/pr/816-step1-rerun/summary-table.csv:2-13`, `docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/perm-test-results.json:19-29`, `docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/perm-test-results.json:19-29`, `docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/perm-test-results.json:12-29`). The blockers are elsewhere: the run knowingly violated the plan’s mandatory HALT on SciPy/Numpy pin drift, the A/B/C/D side of the pipeline is not reproducibly wired and already has a wrong aggregate in `findings.md`, and parts of the exploratory prose overclaim what the evidence shows.

## Findings

1. HIGH — The run is out of spec because it proceeded after a plan-mandated HALT on dependency drift.
The plan is explicit: if the capture host cannot match the pinned SciPy/Numpy versions, the rerun must stop before classification (`docs/pr/816-step1-rerun/plan.md:898-914`). The findings doc admits that exact failure and admits execution continued anyway on `scipy 1.16.3` / `numpy 2.3.5` (`docs/pr/816-step1-rerun/findings.md:14-23`), and the emitted evidence records those drifted versions in the actual result files (`docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/perm-test-results.json:4-6`). The “semantic equivalence” justification is not a substitute for the plan contract: the contract required a halt precisely because deterministic seeding was only promised against the pinned environment. Even if SciPy’s docs suggest legacy `random_state` handling is still accepted after 1.15, that does not upgrade this out-of-spec run into a reproducible one.
Mitigation: mark the current H3 result as tentative / non-accepting, provision the pinned environment, rerun the histogram classifier under the pinned versions, and regenerate `findings.md`, `summary-table.csv`, and all `perm-test-results.json` artifacts before accepting the verdict.

2. MEDIUM — The A/B/C/D column is externally backfilled rather than reproducibly generated from the rerun evidence, and that manual path has already produced a wrong aggregate.
`step1-capture.sh` writes a `PENDING` placeholder verdict (`test/incus/step1-capture.sh:453-454`). The new orchestrator copies that capture output into `docs/pr/816-step1-rerun/evidence/` immediately after capture, before any classifier run is encoded (`test/incus/step1-baseline-and-matrix.sh:26-35`). Meanwhile `step1-classify.sh` still hardcodes the old evidence root under `docs/pr/line-rate-investigation/step1-evidence` (`test/incus/step1-classify.sh:5-8,15`), and the histogram script admits `verdict_abcd` is only a placeholder “populated externally” (`test/incus/step1-histogram-classify.py:351`). That external/manual integration is already wrong in the published findings: `findings.md` reports `D=6`, `D-escalate=5` (`docs/pr/816-step1-rerun/findings.md:137-145`), but the committed summary rows are `D=5`, `D-escalate=6` (`docs/pr/816-step1-rerun/summary-table.csv:2-13`).
Mitigation: make `step1-classify.sh` accept an explicit evidence root, run it directly against `docs/pr/816-step1-rerun/evidence`, and generate the `verdict_abcd` column and letter-count rollup programmatically from the committed `verdict.txt` files instead of by external/manual backfill.

3. LOW — The suspect-cell JSON evidence is not valid JSON because it serializes `NaN`.
The plan’s output contract is “one JSON document” per cell (`docs/pr/816-step1-rerun/plan.md:499-523`). For the `I12` suspect cell, the committed artifact writes bare `NaN` tokens for `p` and `stat_obs` (`docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/perm-test-results.json:19-29`). Python’s stdlib will tolerate that, but strict JSON parsers will not. That is an avoidable portability failure in one of the evidence files reviewers are expected to consume directly.
Mitigation: emit `null` for unavailable numeric fields in suspect cells, or stringify them explicitly, and keep `suspect=true` plus `suspect_reason` as the machine-readable explanation.

4. LOW — The exploratory tail narrative overstates and inconsistently describes the affected-cell set.
The prose uses multiple incompatible descriptions of the same phenomenon: “0.15–0.33 mass fraction across 10 of 12 cells” (`docs/pr/816-step1-rerun/findings.md:54-58`), “10–33 % ... across BOTH no-cos and with-cos-reverse cells” (`docs/pr/816-step1-rerun/findings.md:201-203`), and “15–32 % of mass on 10 of 12 cells” (`docs/pr/816-step1-rerun/findings.md:235-237`). The machine-readable summary does not support that “10 of 12” affected-cell count: only nine rows show the mode-9/high-tail regime the prose is talking about (`docs/pr/816-step1-rerun/summary-table.csv:2-5,7,9-11,13`), while the three shaped forward rows are near-zero tail cases (`docs/pr/816-step1-rerun/summary-table.csv:6,8,12`). This does not overturn H3, but it does mean the narrative is looser than the evidence.
Mitigation: recompute the descriptive `b10-13` totals directly from `hist-blocks.jsonl`, publish one consistent count/range, and replace all three conflicting prose versions with that single computed statement.

## Verified

- `k_D1 = 4` and `k_D2 = 3` match the CSV exactly, so the plan-§8 H3 multi-channel gate is satisfied on the committed data (`docs/pr/816-step1-rerun/summary-table.csv:2-13`).
- `with-cos/p5202-fwd` and `with-cos/p5203-rev` are the only both-fire cells (`docs/pr/816-step1-rerun/summary-table.csv:8,11`, `docs/pr/816-step1-rerun/evidence/with-cos/p5202-fwd/perm-test-results.json:19-29`, `docs/pr/816-step1-rerun/evidence/with-cos/p5203-rev/perm-test-results.json:19-29`).
- `with-cos/p5204-fwd` is correctly marked `suspect=true`, `suspect_reason="I12"` and excluded from `k_v` (`docs/pr/816-step1-rerun/summary-table.csv:12`, `docs/pr/816-step1-rerun/evidence/with-cos/p5204-fwd/perm-test-results.json:12-29`).
- All three baseline pools do have 60 serialized blocks, and an independent scan of the raw snapshots found no I13 mismatches across 351 snapshots. The I13 two-level checks, count-weighted exploratory aggregation, and `H-STOP-5` code paths are still present in the classifier (`test/incus/step1-histogram-classify.py:83-97,123-126,218-240,305-314`).
- The Step 2 paragraph stays at direction level and explicitly refuses to scope #793 Phase 4 directly (`docs/pr/816-step1-rerun/findings.md:280-299`).
- The old LOW items do not affect this run’s outputs: `H-STOP-5` never fired, there were no skipped matrix cells, and the dead `suspect` assignment remains dead code only (`test/incus/step1-histogram-classify.py:202-204,305-314`).

## Open Items

1. Re-run the histogram classifier under the pinned SciPy/Numpy environment required by plan §10.
2. Make the A/B/C/D generation path reproducible against `docs/pr/816-step1-rerun/evidence` and regenerate the letter-count rollup from code, not manual backfill.
3. Fix the suspect-cell JSON serialization so all `perm-test-results.json` files are strict JSON.
4. Recompute and tighten the exploratory `b10-13` prose from the committed block artifacts.
