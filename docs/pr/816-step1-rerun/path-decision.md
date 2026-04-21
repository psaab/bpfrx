# #816 — Path-decision record (Round 1 findings review)

After Round 1 of two-angle findings review on commit `9f789d87`,
both reviewers (Codex correctness + methodology) returned MERGE NO.
Net findings: **6 HIGH** between the two reviews; **D1 signal on shaped
cells is robust, but the H3 multi-channel verdict, D2 channel
classification, and Z_cos figure are not supported by the data**.

This document records the two paths considered, the path chosen, and
what it would take to revisit the other path later.

## Path A — Revise findings.md to corrected H2-D1 verdict (CHOSEN)

### What it does

- Rewrite `findings.md` §1, §2, §4, §5, §7 to land the corrected verdict:
  **H2 D1 (XSK submit→DMA latency elevated cross-cell on shaped traffic)**
  per plan §8.
- Downgrade D2 from "fires" to "exploratory only — single-digit raw
  frame counts, degenerate baseline null."
- Strike the `Z_cos = 74,552 parks/s` figure and replace with the
  two-cluster summary `{line-rate: 0 parks/s; shaped: 19867-59624 parks/s
  (n=3)}`.
- Add baseline outlier subsection documenting `fwd-with-cos/run1` as a
  3.5× T_D1 outlier; report sensitivity analysis with run1 dropped.
- Add `stat_D1` and `stat_D2` columns to per-cell verdict table and to
  `summary-table.csv` so effect-size heterogeneity is visible.
- Reword Step 2 direction paragraph from single-mechanism "D4 reap-hold"
  guess to enumerated candidate mechanisms (a) submit→TX DMA stalls,
  (b) RX-side NAPI budget leakage, (c) scheduler descheduling between
  sendto and reap, (d) virtualization jitter, (e) iperf3 burstiness —
  with telemetry needed to discriminate.
- Fix the prose-vs-CSV letter-count mismatch (findings says D=6 / D-esc=5;
  CSV says D=5 / D-esc=6).
- Fix the suspect-cell JSON serialization (`NaN` → `null`).
- Document scipy version drift as an explicit deferral with risk
  statement; link to follow-up issue #817 (Path B).

### Why chosen

- The D1 stat_obs ≈ 0.9 signal is robust — won't flip on RNG reshuffle.
- All four methodology HIGHs (D2 degenerate null, H3 framing wrong,
  baseline outlier, Z_cos bimodality) are independent of scipy version.
- Codex's scipy-pin HIGH is a process-compliance finding, not a science
  finding. The science survives Path A.
- Path A unblocks the Phase 4 scoping decision (#793 — XSK submit→DMA
  latency) without another 45 min cluster execution.
- Cost: ~30 min architect revision + 2 review rounds.

### Risk

- The strict reproducibility contract (plan §10 req 4) was violated.
  Anyone re-deriving from the committed evidence must work under
  `scipy 1.16.3 / numpy 2.3.5`, not the originally-pinned versions.
  Documented as deferral with link to #817.
- D2 downgrade is a judgment call — the Fisher-Pitman test did fire at
  α=0.05; downgrading it requires explicit "the test fired but the
  effect size is below mechanistic significance" framing. Borderline
  whether this is "ejecting D2 from the formal classifier" (a plan-
  contract change) or "describing what the data showed" (a findings
  judgment). Path A treats it as the latter.

## Path B — Re-run under pinned scipy 1.13.1 / numpy 1.26.4 (DEFERRED)

### What it does

- Provision capture host with Python 3.11 + pinned scipy/numpy per
  `test/incus/requirements-step1.txt`.
- Re-run `test/incus/step1-histogram-classify.py` against the existing
  evidence tree (no new captures needed — the histogram analysis is
  pure post-processing).
- Diff new `perm-test-results.json` against committed (1.16.3) outputs.
- Update findings.md and `summary-table.csv` if any verdict-relevant
  numbers changed.

### Why deferred (not chosen)

- Path A captures most of the value at much lower cost.
- D1 stat_obs ≈ 0.9 won't move on a RNG reshuffle.
- All non-RNG findings (HIGH-M2 baseline outlier, HIGH-M3 Z_cos
  bimodality, HIGH-M4 H3 conflation) need the same Path A revision
  regardless of scipy version.
- Path B is environment provisioning + pure recompute — appropriate
  follow-up work, not a blocker for the science.

### Tracking

Filed as **issue #817** ("Step 1 #816 reproducibility: re-run under
pinned scipy 1.13.1 / numpy 1.26.4 (Path B)"). Acceptance criteria
documented in the issue body.

### When to come back to Path B

- If the next round of work (Step 2 design doc per plan §8 H2 D1
  branch, or the actual Phase 4 scoping under #793) needs to re-derive
  thresholds from #816 evidence — the strict-pin discipline matters
  more for derived calibration values than for verdict signs.
- If a future plan introduces a tighter-α gate (e.g. α=0.01 instead
  of 0.05) that puts more weight on the Monte-Carlo p-value precision.
- If `p5203-rev-with-cos D2 = 0.0465` (within MC 95% half-width of
  the gate) becomes load-bearing for any decision — at that point the
  exact RNG stream matters and the pinned re-run is the right answer.

## Other paths considered and rejected

### Path C — Re-run the entire 12-cell matrix from scratch under pinned scipy

- Cost: full matrix re-execute (~45 min capture + 15 min analysis) plus
  pinned-environment provisioning.
- Benefit over Path A+B: would also catch any captures that were
  themselves contaminated by the "out-of-spec" framing (none observed).
- Rejected: Path A + Path B (deferred) achieves the same end at lower
  cost. Captures were valid; only the analysis-side determinism is in
  question.

### Path D — Discard the run, re-plan with stricter D2 threshold

- Cost: another full plan-review cycle (4 rounds last time) plus
  re-execution.
- Benefit: cleaner pre-registered D2 threshold (e.g. require ≥ 100
  frames in b0-2 per block).
- Rejected: throws away the genuine D1 finding for an iterative tweak
  to a channel that the data already shows is bogus. Path A's
  "downgrade D2 to exploratory + name the threshold problem in
  findings" preserves the D1 result and feeds the threshold lesson
  into the next round's plan.

## What this enables

- Path A's revised findings.md unblocks Phase 4 scoping under #793 with
  a concrete direction: investigate the submit→DMA path on shaped
  traffic cells.
- Path B (deferred) ensures the strict-reproducibility option remains
  open if the next round needs it.
- Both paths together avoid the "throw away the result, restart" outcome
  while honoring the methodology critique.

## Decision log

- **Decided:** Path A.
- **Decided by:** human + Claude collaboration on 2026-04-21.
- **Tracking issue for Path B:** #817.
- **Next action:** dispatch architect agent to revise findings.md per
  Path A spec; then two-angle review Round 2.
