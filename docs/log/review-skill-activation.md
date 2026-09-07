# Activate the current review skills in consuming checkouts

- **Timestamp**: 2026-09-07 03:31:06 UTC
- **Action**: Synchronized the current deep-review, research and review-triage
  bundle from `/home/ps/git/kimi-xpf` into the two verified consumers:
  `/home/ps/git/bpfrx` and `/home/ps/git/muse-xpf`. The source includes
  the pending provenance and review-lifecycle changes; it is not just the
  committed storage revision.
- **Cause**: Both consumers still instructed new report publication and scratch
  allocation under `/tmp`. Updating or pushing the skills branch did not update
  these checkout-local skill copies.
- **Scope**: Only the three named skills, their referenced Markdown files,
  `scripts/review-dedup-check.py`, `scripts/test_review_storage.py`, and this
  action log. Verified the destination scope was clean and contained no
  symlinks before editing. Preserved unrelated files and existing branches.
- **Storage contract**:
  - New reports: `/var/tmp/deep-review-reports/`.
  - Scratch, worktrees, progress state and coordination:
    `/var/tmp/deep-review-work/`.
  - Completed source/result pairs: `/var/tmp/deep-review-finished/`.
  - Legacy `/tmp` artifacts remain reconciliation inputs, never destinations
    for new output or staging.
- **Workflow preserved**: Original per-claim source/model attribution, the
  research three-pass adversarial gate and validated-issue filing policy,
  repeat-safe lifecycle intake and completed-review reconciliation.
- **Validation**:
  - All 13 bundle/helper/test files are byte-identical in all three checkouts.
  - All 39 local Markdown references resolve in each checkout.
  - `python3 -B scripts/test_review_storage.py`: 18 tests passed in each
    checkout. These hermetic tests cover deduplication across active, finished
    and legacy roots, stale indexes, and derivative exclusion; they do not
    execute a real research run, archiver, filing workflow or processing loop.
  - `git diff --check` passed in each checkout.
  - Audited remaining `/tmp` references: historical compatibility, explicit
    migration/reconciliation and prohibitions on new writes only.
- **Activation boundary**: Files on disk are updated. Already-running model
  sessions can retain old loaded instructions and must explicitly reload the
  updated skills and references or start a fresh session. No claim is made
  about other hosts, other checkouts or cached prompts.
- **Publication and data**: No commit, push, merge, branch switch, GitHub issue
  mutation, report relocation, or live firewall operation was performed.
- **Local file edit**: Created this action log; preserved the pending canonical
  skill and action-log changes from the preceding work.

## Validation of the /var/tmp storage contract (muse-xpf)

- **Timestamp**: 2026-09-07 05:11:32 UTC
- **Action**: Validated the committed /var/tmp storage contract in this
  checkout, found the identical bundle already on origin/master
  (`ddd270ade`, #9356), and withdrew the redundant local commit.
- **Detail**: Re-derived the bundle revisions of
  `.claude/skills/deep-review/SKILL.md`,
  `.claude/skills/deep-review/references/review-contract.md` and
  `scripts/review-dedup-check.py` for comparison; all seven
  skill/script files compared byte-identical to the pushed bundle, so
  the local commit was dropped instead of pushed. Edit made in the
  dedicated `muse-xpf-skill-log` worktree, not the control checkout.
- **Validation**:
  - `python3 -B scripts/test_review_storage.py`: 18 tests pass
    (14 failed against the pre-bundle dedup helper).
  - `git diff --check`: clean.
  - Audited every `/tmp` reference in the deep-review skill: legacy
    reads, migration coordination, and explicit never-write rules
    only. All local Markdown cross-references resolve.
- **File(s)**: `docs/log/review-skill-activation.md` (this note only).
