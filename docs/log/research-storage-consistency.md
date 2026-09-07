# Consistent research storage and completed-review archive

- **Timestamp**: 2026-09-06 18:20 UTC
- **Request**: Remove active `/tmp` write instructions. Use
  `/var/tmp/deep-review-reports/` for initial final-report publication and
  `/var/tmp/deep-review-work/` for all new workspaces/worktrees and scratch.
  The follow-up request adds `/var/tmp/deep-review-finished/` for completed
  deep-review sources and their research results, including deduplication history.
- **Cause**: Previous changes preserved standalone and legacy research defaults,
  added mixed-device `/tmp` staging, and left plan worktrees in `.claude/worktrees`.
  Those were active exceptions, not merely compatibility reads.
- **Files / actions**: Updated the research entrypoint, research storage and plan
  references, deep-review entrypoint/storage/shared contract, and review-triage.
  General, external-review, deep-review, legacy, mixed-input and planning modes
  now share the same output/work roots. Removed alternate staging fallbacks.
  Added `deep-review/references/finished-archive.md`. Extended
  `scripts/review-dedup-check.py` and `scripts/test_review_storage.py` to scan
  active, finished and legacy report roots even when cached indexes are stale.
- **Compatibility**: Existing `/tmp` artifacts remain readable for history,
  deduplication and sequence selection. New results for legacy/out-of-root inputs
  go to the reports root with the original source location recorded. Sources are
  not copied into discovery storage. In-root sources initially retain adjacent
  `report-<filename>` results; source/model identity and immutable snapshots remain
  intact. Input mount identity no longer controls the publication destination.
- **Archival contract**: After required claim reviews, verified publication and
  enabled filing/tagging complete, move the exact source/result set to the flat
  finished root with unchanged basenames/bytes. Completed unresolved research is
  distinct from a missing reviewer or blocked filing and from a fixed defect.
  Shared repository/per-report locks and a persistent relocation ledger coordinate
  verified staging, create-if-absent archive publication, and removal of only the
  exact unchanged originals after the entire destination set verifies. Interrupted
  moves resume from verified state; this is not an atomic multi-file rename.
  Completed legacy originals may be removed only through this procedure. Remote
  originals stay remote while their completed local results are archived, with
  that exception recorded. Already-archived sources/results remain in place on
  re-research. Shared aggregates wait for all their inputs to finish.
- **Deduplication**: Deep-review and triage consult archived originals and their
  result/issue ledgers without queuing finished history as fresh work. Archived
  sequence numbers remain reserved. Immutable initial publication paths resolve
  through verified relocation records. The scanner supplies title-match leads,
  not final identity, issue-status or corrective-scope decisions.
- **Preserved**: Automatic validated-defect filing, Codex + AGY + Claude SMR
  adversarial gates, expertise, provenance, all 21 finding fields and manual
  implementation approval. Native skill metadata and the research authority,
  expertise and filing blocks are unchanged; deep-review's discovery/expertise
  block and shared schema/completion block are unchanged.
- **Validation**: All 18 hermetic storage tests pass. Running those tests against
  the pre-change scanner in memory produces only the expected archive-coverage
  failures, including both stale-index cases. All 29 local Markdown references
  resolve; `git diff --check` passes. The stock skill validator passes for all
  three skill entrypoints using isolated copies under the work root, removing
  only unsupported Claude `user_invocable`/`user-invocable` metadata in the two
  compatibility copies. Native metadata was separately compared with HEAD.
- **Independent checks**: Read-only reviewers checked the final design and ten
  archival routing/recovery scenarios. Their feedback clarified the remote-source
  exception and qualified legacy-preservation wording. These are instruction
  decision checks, not live archival execution or empirical review-quality tests.
- **Skill guidance**: Skill-creator kept detailed archival mechanics in a routed
  reference and required meaningful scanner regressions and independent workflow
  checks while preserving review/filing intent. Temporary validation copies are
  artifacts only; the reusable scanner tests remain in the repository.
- **Scope**: Implementation and validation did not move existing reports or
  worktrees, change watcher schedules, or file issues. Only skill/helper/test/log
  edits and owned validation copies were produced; no live archive operation or
  provider-based three-way research run was executed.
- **Publication request**: The user subsequently requested commit and push.
  Re-ran all 18 storage tests and the whitespace check before publication; keep
  the unrelated untracked `.antigravitycli/` directory outside this commit.
