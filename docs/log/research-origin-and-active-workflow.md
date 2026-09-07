# Research discovery credit and active-workflow diagnosis

- **Date**: 2026-09-06.
- **Request**: Research-created GitHub issues were crediting the researching
  model instead of the source-report model, and results still appeared in `/tmp`.
- **Observed attribution failure**: The source
  `muse-spark-unknown-review-full-firewall-100r2-001.md` identifies itself as a
  deep-review and records `WHOAMI: muse-spark-unknown`. Its second-pass research
  result maps issue #9327 to source findings V095/V096, previously scored NEG.
  GitHub readback for #9327 names those original findings but contains only
  `source:research` and `model:claude-opus-5-1m` as provenance, with no
  `validated-by:research`. The run's ledger explains that it treated establishing
  the valid claim as research discovery. That confuses proof with origin. This
  inspection establishes a provenance mismatch; it does not revalidate the
  underlying firewall findings or authorize changing the existing issue.
- **Observed activation gap**: The latest result records checkout
  `/home/ps/git/bpfrx` at `03c9b3518` and output/scratch under `/tmp`. That checkout's
  research skill still explicitly selects `/tmp/research-work.*` and
  `/tmp/result-*-research-*.md`. Refreshed `origin/master` at `f019af4e2` has the
  same old output instructions and does not contain published skill commit
  `c426bd792`. GitHub reports no PR for `skills/deep-review-storage`. A pushed
  branch did not activate the changes in the checkout used by this run. The
  historical result does not record hashes of the instructions actually loaded,
  so its precise in-memory prompt revision is not independently established.
- **Changes**: Updated the shared deep-review contract, research entrypoint,
  research validation/storage references and review-triage. Each supplied claim
  binds its original source and evidenced author as `ORIGIN_*`, independently of
  the researching coordinator's `RESEARCH_WHOAMI`/`WHOAMI`. Reversed dismissals,
  narrowed claims, corrected evidence and split subclaims retain that lineage.
  Genuinely additional defects require a distinct problem/corrective scope;
  mixed cohorts keep every member's origin. Before creation and on readback,
  compare provenance labels/body IDs with the bound origins rather than merely
  checking that the API accepted the researcher's intended labels.
- **Workflow/output checks**: Record actual loaded skill/reference paths,
  hashes and owning revision separately from the code verification revision.
  Reconcile resumed or changed-checkout workflows before writes and pass the
  effective policy/paths to workers. Check the real published path, not only its
  header or a tool success response. Preserve the agreed active reports/work/
  finished roots; do not create a fourth directory or silently adopt a stale
  checkout's `/tmp` defaults. Publication of the updated skill does not by itself
  update another checkout or session.
- **Validation**: All 18 existing storage regression tests pass. All 29 local
  Markdown references resolve and `git diff --check` passes. Stock skill metadata
  validation passes using owned compatibility copies under
  `/var/tmp/deep-review-work/research-origin-validation.k47w7hbJVx/`, dropping
  only unsupported Claude invocation metadata in the research/deep-review copies.
  Native metadata, research authority/expertise, and the complete shared
  schema/completion block remain unchanged. No executable helper changed in this
  revision; storage tests do not by themselves prove model attribution behavior.
- **Skill guidance**: Skill-creator kept the new decision rules in the shared
  contract, with short consumer-specific reminders, and prompted a bounded
  independent decision exercise with synthetic cross-model claims and outputs.
- **Independent result**: The evaluator retained source-model credit for a
  narrowed/prior-NEG claim, split subclaims and a derivative-input rerun; used
  research credit only for a distinct additional defect; preserved both origins
  in a mixed cohort; and handled unknown and human authors without substituting
  the researcher. It rejected successful API readback with wrong origin tags,
  selected the later immutable snapshot under the active reports root, and kept
  archival pending until tagging completed. Clarifying the fixtures' source
  classes and existing-result identity resolved their input ambiguities. No
  remaining instruction contradiction was found. This was a decision exercise,
  not an executed filing or publication workflow.
- **Scope and remaining activation**: Only local skill/log edits and owned
  validation copies. Existing reports, issue labels and the other checkout were
  not changed. No live review, issue mutation, PR creation, merge, commit or push
  was performed for this revision. Landing the skill changes and updating the
  consuming workflow require a separately authorized publication/activation step;
  existing-issue attribution repair also requires explicit scope.
