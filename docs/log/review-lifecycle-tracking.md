# Repeat-safe deep-review and research lifecycle

- **Date**: 2026-09-06.
- **Request**: Update deep-review/research to use the agreed storage paths and
  record what has been researched so a future loop can avoid duplicate work.
- **Gap**: Storage and archival instructions existed, but research allocated a
  fresh run and promised a fresh report before deciding whether the same source
  and required work had already been completed. Archive locations and title
  indexes did not supply an intake/recovery contract for interrupted research.
- **Files/actions**: Added the shared
  `.claude/skills/deep-review/references/review-lifecycle.md`; updated both skill
  entrypoints, their storage references, the shared contract, finished-archive
  instructions, and review-triage. Kept the prior uncommitted origin-attribution
  corrections intact. No executable helper or running loop was introduced.
- **Paths**: New source/result publication stays under
  `/var/tmp/deep-review-reports/`. Working files and shared progress stay under
  `/var/tmp/deep-review-work/`. Completed source/result sets stay under
  `/var/tmp/deep-review-finished/`. Legacy `/tmp` artifacts remain history and
  explicitly scoped inputs, never new output or implicit alternate queue roots.
- **Progress contract**: Per-source versioned JSON at
  `state/reviews/<canonical-report-digest>.json` records source hash/aliases,
  original discovery identities, scoped attempt requirements, actual reviewers
  and evidence revisions, claim checkpoints, outputs, issue/tag state, blockers
  and archive-ledger references. Completed attempt history stays immutable.
  Processing state is separate from finding disposition or remediation status.
- **Repeat/resume decisions**: Matching completed intake returns the existing
  assessment without a new run, report or reviewer dispatch. Weaker triage cannot
  satisfy research's three-way gate; newly enabled filing resumes valid evidence
  subject to freshness checks. Busy and unchanged-blocked work is skipped.
  Missing/corrupt state is reconciled against actual history, not reset to fresh
  work. Finalization resumes missing tags/publication/archive steps; changed
  dependencies invalidate only affected checkpoints. Explicit revalidation
  preserves the source key and obeys requested fresh-pass requirements.
- **Coordination**: All processing claims are nonblocking, including single-input
  intake; actual contention wins over saved status. Sorted processing claims
  precede repository/per-report filing locks. Overlapping multi-input claims
  release on contention. Retained task identities and resume history prevent
  orphaned reviewer tasks from being blindly submitted again. The existing
  relocation ledger remains the proof of archival; lifecycle status is not a
  substitute. Historical consumers require compatible coordination before a
  concurrent loop is enabled.
- **Independent checks**: A read-only design reviewer identified and verified
  fixes for single-input claim contention, historical result run IDs, and missing
  later triage snapshot naming. A separate evaluator exercised 12 synthetic
  repeat/resume/recovery/authority scenarios and found no remaining instruction
  contradiction. These were decision evaluations, not executed filing, state
  recovery, publication or live-review workflows.
- **Validation**: All 18 existing hermetic storage tests pass; all 39 local
  Markdown references resolve; `git diff --check` passes. Stock metadata
  validation passes for all three skill entrypoints using owned copies under
  `/var/tmp/deep-review-work/review-lifecycle-validation.wry2E85yMn/`, removing
  only unsupported Claude invocation metadata for compatibility. Native metadata,
  research authority/expertise, deep-review's discovery/expertise block and the
  complete shared schema/completion block remain unchanged. These checks do not
  establish that a future loop or filesystem-lock implementation has been tested.
- **Skill guidance**: Skill-creator kept the reusable lifecycle in one routed
  reference and required independent decision checks while retaining the user's
  specialist, adversarial validation, automatic filing and origin-credit intent.
- **Scope**: Only local skill/log edits and owned validation copies. No existing
  reports, worktrees, GitHub issues/labels, consuming checkouts, schedules or
  processing registry entries were changed. No commit, push, PR or merge was
  performed for these updates; publication and activation remain separate work.
