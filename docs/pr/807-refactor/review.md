# PR #807 review — docs refactor into `docs/pr/<pdr>/` + remaining-gaps

**MERGE YES** (with two minor nits; neither blocks merge since this is a pure docs move.)

## Scope verified

- 51 files, 405 insertions, 0 deletions. All moves (0-line diffs) except:
  - `docs/pr/README.md` — new index (41 lines)
  - `docs/pr/line-rate-investigation/remaining-gaps.md` — new content (196 lines)
  - `docs/pr/line-rate-investigation/full-cos.set` — new canonical CoS config (48 lines)
  - `docs/pr/800-workers-queues/investigation.md` — new content recovered from
    branch (120 lines), declared in commit body.
- Merge-SHA citations in `docs/pr/README.md` all verify on master:
  `f37597ec` (#796), `50acc495` (#797), `019c3db6` (#803), `3d2d63a4` (#804).
- All moved files accessible at new paths; `docs/pr/` listing matches PR table
  (6 subdirs + README.md).

## 1. Layout convention — SOUND

`docs/pr/<scope>/` with standard filenames (`plan.md`, `codex-review.md`,
`go-review.md`, `rust-review.md`, `systems-plan-review.md`, `validation.md`,
`evidence/`) gives one obvious home per durable artifact. README
distinguishes PR-scoped artifacts from feature-design docs that stay at
`docs/` root. Good.

One minor asymmetry: `785-phase3/` uses the *issue* number prefix while
`797-d3/`, `803-tunables/`, `804-instrumentation/` use the *PR* number.
This is because #796 is "PR #796 for phase 3 of issue #785" and calling
the dir `796-phase3` would lose the #785 context. Acceptable, but worth
noting in README if it recurs. Not a blocker.

## 2. `remaining-gaps.md` sanity check

**Accurate against master PR history.** The four merged-PR citations
(#796, #797, #803, #804) and two closed-without-code issues (#799, #800)
all match `git log --oneline`.

**Unsourced "best-measured" table — MINOR NIT.** The three rows:

| cell | cited value | closest committed evidence        |
|------|-------------|-----------------------------------|
| 5201 FWD mean | 22.94 | knobs-on summary says 19.82       |
| 5201 REV mean | 20.66 | knobs-on summary says 18.21       |
| 5203 FWD mean | 22.80 | knobs-on summary says 22.89 (OK)  |

The p5201 FWD/REV numbers are ~3 Gbps above the committed
`docs/pr/803-tunables/evidence/knobs-on/summary.txt`. They may come from
post-#804 runs or from an external capture not yet committed. The doc
gives no pointer. Traceability would improve if the table cited the run
(evidence dir, commit SHA, or "captured 2026-04-21 on
`loss-userspace`"). Not wrong — just unreproducible. Recommend a
follow-up "evidence provenance" note; does not block merge.

The p5201-rev retransmit count of 29736 does reconcile with
`docs/pr/803-tunables/evidence/baseline-knobs-off/p5201-rev-2.json`, so
at least one cell is traceable.

**H-FWD/H-REV hypothesis list.** Each hypothesis carries the "evidence
available now" and "why still open" — exactly the discipline the
engineering-style doc asks for. Matches the plan's §Hypotheses table.

## 3. 8-port validation matrix

The README in the PR body says "8-port" but strictly it's **4 ports ×
2 directions = 8 runs**. The matrix text in `remaining-gaps.md` is
correct and clear about this.

**Exhaustive for the stated CoS config?** Yes, for the committed
`full-cos.set`:

- Ports 5201/5202/5203 match explicit filter terms 0/1/2 → iperf-a/b/c
  classes → scheduler-iperf-{a,b,c} at 1.0G/10.0G/25.0G `exact`.
- Port 5204 has NO explicit term. It falls through term 3 (no `from`
  clause) → `best-effort` class → `scheduler-be` at 100m `exact`.

So 5204 exercises the default-class path — **good**, because it covers
the "catch-all → best-effort" leg that the other three ports skip. The
matrix is exhaustive for this config.

**96% threshold.** Reasonable for TCP over 25G-class shaping:
- 0.96 × 1G = 0.96 Gbps (TCP overhead + shaper burst jitter)
- 0.96 × 10G = 9.6 Gbps
- 0.96 × 25G = 24 Gbps
- 0.96 × 100M = 96 Mbps

25G line is ~24.2 Gbps after IPG/preamble; 24 Gbps leaves ~0.8 Gbps for
shaper discipline overhead + TCP control-plane. For the tightest shaper
(5204 → 100M best-effort), 96 Mbps is stringent given TCP slow-start
on 60 s duration — reasonable. No objection.

**Retransmits ≤ 100 / 60 s.** Tight but not unreasonable for a
non-congested 25G path with shapers. Matches the "target unmet"
framing — the current 2683/29736 retransmits are 27×/297× over budget,
which is a real gap not a spec tweak.

**CoV gate.** "Not regressed vs the Phase 3 baseline on that shaper"
is ambiguous — Phase 3 baseline numbers aren't cited here. If the
captured 0.21 % / 1.50 % / 1.20 % are the new reference, that should be
stated. Minor.

## 4. `full-cos.set`

48 lines; byte-identical to the `delete .../ set .../` form the user
specified. Structure:

- Purge 3 stanzas up front (safe re-apply).
- 4 forwarding-classes on queues 0/4/5/6 (queues 1/2/3/7 unassigned —
  hardware-permissible).
- 4 schedulers with `transmit-rate exact` (strict-policing semantics,
  not weighted).
- 1 scheduler-map binding FC → scheduler.
- reth0.80 bound to that scheduler-map + 25G shaping-rate (aggregate
  cap below the physical 25G link, leaves no headroom — intentional
  for the test).
- `bandwidth-output` filter with 4 terms (3 dst-port matches + 1
  catch-all).
- Filter applied `reth0 unit 80 family inet filter output`.

No IPv6 filter applied — if CoS is also a goal for the v6 twin of this
test, that would be a gap. Not flagged as in-scope here, so fine.

Minor style note: terms 0/1/2 have `then count <name>` but term 3
doesn't. Consistency suggests adding `then count best-effort` in
term 3 so per-class byte counts are visible for all four classes. Not
a correctness issue — CoS queue counters exist independently — just
nicer for validation readout.

## 5. Dangling references in moved files

**Five hits, all in review docs (historical records):**

- `docs/pr/797-d3/go-review.md` references `docs/785-d3-validation.md`
  and `docs/785-d3-pr-review.md` (no longer exist; the validation doc
  was renamed to `docs/pr/797-d3/validation.md`).
- `docs/pr/797-d3/codex-review.md` same.
- `docs/pr/797-d3/validation.md:141` references
  `docs/785-phase4-options.md` (doesn't exist on master either — this
  is a pre-existing stub, not introduced by the move).
- `docs/pr/803-tunables/evidence/repro-matched-5run.sh` hardcodes
  `docs/801-evidence/baseline-knobs-off/` / `docs/801-evidence/knobs-on/`
  as output dirs. If someone re-runs this script verbatim, it'll emit
  under `docs/801-evidence/` which no longer exists. **This is the one
  path rewrite that would actually break a workflow**, not just cross-
  reference.
- `docs/pr/803-tunables/go-review.md` references
  `docs/801-evidence/runs/` and `docs/785-801-pr-review.md`.
- `docs/pr/line-rate-investigation/plan.md` references
  `docs/line-rate-investigation-plan-review.md` and
  `-systems.md` (renamed to `codex-plan-review.md` and
  `systems-plan-review.md` in the same dir).
- `docs/pr/line-rate-investigation/codex-plan-review.md` and
  `systems-plan-review.md` reference `docs/line-rate-investigation-plan.md`
  (renamed to `plan.md` in same dir).

**Recommendation:** the review MDs are historical records — leaving
them is defensible (the PR body calls this out). BUT:

- `repro-matched-5run.sh` has operational impact — update the two
  output paths to `docs/pr/803-tunables/evidence/` so a fresh rerun
  lands in the right place. **One-line fix.**
- Optionally a `plan.md` header could note "reviewer docs at
  `codex-plan-review.md` and `systems-plan-review.md` in this dir"
  so the stale `docs/...` refs inside don't confuse a reader.

Neither blocks the merge — they're cleanup in the next round.

## 6. Files that SHOULD have moved but didn't

- `docs/pr/785-umbrella/cross-worker-drr-retrospective.md` and
  `docs/pr/785-umbrella/perf-fairness-plan.md` stay at `docs/` root. **Correct per
  the README convention** — these are multi-PR retrospectives /
  parent-plans for issue #785 (spans #796 and #797), not single-PR
  adversarial review cycles. Feature-design-doc class. No move
  needed.

Nothing else at `docs/` root uses the `<NNN>-` PR-prefix pattern except
those two.

## 7. README.md convention

**Right level of detail.** Three sections: subdirectory table,
conventions, when-to / when-not-to. Explicitly excludes single-commit
cleanups and feature design docs. Cites merge SHAs for the four merged
PRs. Clear.

Minor suggestion: add one sentence on the #796/#797 issue-vs-PR
numbering asymmetry noted in §1 above. Non-blocking.

## Summary

Pure docs move, no code surface touched. The five dangling-reference
hits are inside historical review docs (intentional per PR body) plus
one script (`repro-matched-5run.sh`) whose hardcoded output path is a
genuine follow-up. The "best-measured" table in `remaining-gaps.md` is
unsourced — traceability nit for the next iteration.

**Verdict: MERGE YES.** The refactor is coherent, the new
`remaining-gaps.md` is an honest "gap to target" post-mortem, the
validation matrix is well-defined for the stated CoS config, and
`full-cos.set` is a usable canonical artifact. Follow-ups (script
paths, source provenance for best-measured, optional `then count
best-effort` in term 3) can land in a subsequent commit.
