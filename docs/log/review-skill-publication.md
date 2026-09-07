# Publish the review workflow changes

- **Date**: 2026-09-06 (America/Los_Angeles).
- **Request**: Commit and push the pending deep-review/research updates to the
  public repository, not only the locally activated consuming checkouts.
- **Target**: `psaab/xpf`, verified public through GitHub. Publish branch
  `skills/deep-review-storage` and open its missing pull request against `master`;
  do not push code directly to the default branch or merge without authorization.
- **Action**: Prepare the pending provenance, repeat-safe lifecycle and activation
  records for publication. Include only the named skill/reference files and
  task action logs. Preserve unrelated `.antigravitycli/` state and the local
  consumer checkout changes. This log is the only new documentation edit in the
  publication step; the preceding logs retain their historical local-only scope.
- **Validation**: Re-ran `python3 -B scripts/test_review_storage.py`: 18 tests
  passed. `git diff --check` passed. The preceding activation check verified all
  13 skill/helper/test files byte-for-byte across the three checkouts and all
  39 local Markdown references. The independent lifecycle/provenance decision
  evaluations and their limitations are recorded in the preceding task logs.
- **Base audit**: Refreshed `origin/master` and the remote skills branch. The
  feature branch is based on an older default-branch revision: the two-tree
  diff therefore includes unrelated upstream additions absent from that base.
  The merge-base diff contains only the review skills, storage dedup helper,
  hermetic tests and their action logs. These upstream changes are not intended
  deletions; preserve them when integrating the pull request.
- **Boundaries**: No firewall runtime changes or live deployments are part of
  this publication. No existing report or GitHub issue attribution is repaired
  by publishing skill instructions. A public feature branch/PR is distinct from
  a merge to `master`; already-running sessions must reload updated instructions.
