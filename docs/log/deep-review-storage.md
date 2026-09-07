# Deep-review storage layout

- **Timestamp**: 2026-09-06 00:08 UTC
- **Request**: Use `/var/tmp/deep-review-reports/` for completed reports and
  `/var/tmp/deep-review-work/` for worktrees and all named working artifacts,
  superseding the initially requested split between `/tmp` and `/var/tmp`.
- **Files / actions**: Updated deep-review, its shared contract and new
  `references/report-storage.md`, review-triage, and `scripts/review-dedup-check.py`.
  Worktrees, drafts, manifests, logs, evidence and task-local build/temp/cache
  output stay in unique owned work runs; shared indexes, markers and locks stay
  outside those disposable runs beneath the work root.
- **Compatibility**: Preserve legacy root-`/tmp` reports, results, markers and
  cached indexes as read-only history. New triage outputs also use the new roots.
  Dedup scans the new and legacy report roots even when an older cache exists.
  Keep source finding identity and model attribution; do not move old artifacts
  or create duplicate compatibility aliases. Coordinate old filing workers before
  changing mutex paths; an old live lock must never be moved or deleted.
- **Scope**: Skill-creator guidance kept this a storage change. Specialist
  expertise, evidence/disposition rules and report naming remain intact. The
  superseded cross-filesystem publication implementation was removed; both new
  roots support the existing same-filesystem create-if-absent publication protocol.
  Standalone research report/workspace paths are unchanged. No existing reports,
  worktrees, watcher schedules, GitHub issues or live environments were modified.
  These skill documents are the affected workflow documentation; no firewall
  product README changes are needed.
- **Validation**: Five focused checks passed: a cached legacy index cannot hide
  new reports; cached/scanned entries do not duplicate title rows; invalid cached
  JSON does not suppress discovery; both issue-index roots remain readable; all
  specialist profiles and 21 finding fields are unchanged. Command:
  `python3 -B /var/tmp/deep-review-work/storage-validation.LqpE6VliSU/check_storage.py`.
- **Validation**: Native metadata is unchanged, five local links resolve, and
  `git diff --check` passed. Stock skill validation passed triage directly and an
  exact deep-review copy omitting only its preserved Claude invocation field.
  Confirmed both new roots share device 2050 and exercised actual hard-link
  publication plus refusal of existing file, directory and symlink targets.
  Removed only the owned publication-test artifact from the reports directory;
  its draft and test evidence remain in the owned storage-validation work run.
- **Limits**: This checks the documented layout, scanner behavior and local
  publication primitives, not an external watcher configuration or a live GitHub
  filing/lock migration. No automatic relocation or deletion of old user artifacts.

## Durable validation follow-through

- **Request / actions**: Preserve the useful temporary `check_storage.py` checks
  in `scripts/test_review_storage.py` and document the repeatable command in the
  storage reference. The test module imports its sibling scanner relative to its
  own path and replaces filesystem reads/discovery with in-memory fixtures.
  Neither the original temporary script nor its workspace is a dependency.
- **Coverage**: New and legacy reports/indexes, a stale cache hiding a fresh
  report, duplicate title rows, corrupt or missing indexes/reports, empty roots,
  both issue-index roots and fresh-report matching through the public helper.
  The one-time comparison of expertise/schema against HEAD remains the earlier
  change audit, not a self-comparison regression test that becomes vacuous after
  committing. `make selftest` discovers the new file through `scripts/test_*.py`.
- **Validation**: All nine tests pass directly from the checkout, by absolute
  path from `/var/tmp`, and via `python3 -B -m unittest discover -s scripts
  -p test_review_storage.py -v`. Running the same fixtures against the
  pre-change scanner from `c097b3e15` in memory produces expected assertion
  failures for new-root discovery, corrupt-index fallback, stale-cache matching
  and current issue-index inclusion, with no harness errors. Full `make selftest`
  and firewall suites were not run for this scoped workflow change.
- **Publication**: Publish on `skills/deep-review-storage`, not directly to
  `master`, to preserve the repository's PR requirement for code changes.
