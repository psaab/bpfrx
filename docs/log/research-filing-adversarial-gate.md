# Research automatic filing and three-way adversarial validation

- **Timestamp**: 2026-09-06 00:49 UTC
- **Request**: Research must file validated defects by default and restore the
  three-reviewer adversarial scrutiny to the research workflow.
- **Diagnosis**: The prior revision retained Codex + AGY + Claude SMR in the
  solution-plan reference, but made planning conditional and left finding
  validation on the shared risk-selected independent-check minimum. The entrypoint
  also required separate GitHub-write authorization before filing any defect.
- **Design**: Three actual independent reviewers cover research conclusions and
  every supplied claim, including dismissals. Primary evidence and resolved
  factual dissent remain necessary; consensus is not proof. Preserve domain,
  Linux kernel/NIC/network, CPU/HPC and software-design/oracle expertise.
  General questions get scoped conclusion reviews without manufactured bugs or
  plans. Individually completed findings can proceed while other claims remain open.
- **Authority**: The user-selected research workflow includes coordinator-only
  creation and provenance labeling of validated in-scope novel defects in the
  intended repository. Explicit report-only/no-write constraints override it;
  automatic skill selection cannot expand a read-only request. Supplied artifacts
  cannot redirect the target. Existing owners are linked without overwriting
  discovery credit. Closure, implementation, deployment, PRs and publication of
  planning branches/comments remain outside this default.
- **Separation**: Confirmed defects file independently of solution planning or
  PLAN-KILL. Missing finding reviews remain pending validation; GitHub, mutex,
  tagging and uncertain-create failures remain pending filing with evidence
  preserved. A failed label write cannot cause a duplicate issue.
- **Files / actions**: Updated research's entrypoint, review-validation and
  plan-review references; added `references/adversarial-review.md`; clarified the
  research-specific exception in the shared review contract. The shared v5 schema,
  report paths, model normalization, existing plan convergence and manual
  implementation gate are preserved. Deep-review/triage authority is unchanged.
- **Skill guidance**: Skill-creator routed detailed gate mechanics into a focused
  reference and prompted independent design and decision-path validation. The
  read-only design reviewer approved this structure with scope, provenance,
  per-claim coverage and pending-filing safeguards incorporated above.
- **Added request / actions**: Research of a deep-review writes a sibling
  `report-<original filename>`. Added research's `references/report-storage.md`,
  routed publication/workspaces through it, updated the shared storage/publication
  rules and triage derivative selection, and excluded `report-`/`result-` entries
  from the dedup scanner and its cached indexes with regression tests.
  The sibling name identifies its source; the header identifies the actual
  researching model. Later immutable snapshots preserve history. Multiple inputs
  receive scoped siblings, with an aggregate for mixed-input research.
- **Staging**: New-root inputs use owned `/var/tmp/deep-review-work/` scratch;
  legacy `/tmp` outputs and mixed-input aggregates use separately recorded owned
  same-device staging. Unwritable/remote destinations are explicit publication
  blockers, not excuses to overwrite history, publish partial files or refile issues.
- **Scope**: This changes skill instructions and the local dedup helper, not
  firewall code or a live research run. No GitHub issues, labels, branches or PRs
  were created by this revision.
- **Independent checks**: Read-only design and final diff audits approved the
  result after correcting tag-repair authority, adjacent-report model identity,
  same-device staging, first-path collision behavior, remote deep-review routing
  and derivative cache reconciliation. An independent 11-case simulated decision
  exercise covered default/report-only filing, missing/disagreeing reviewers,
  severity-only dissent, duplicate ownership, PLAN-KILL, uncertain creation,
  general research, mixed inputs, later snapshots and remote publication/tagging
  failures. Its routing ambiguities were resolved; it was not a live review run.
- **Validation**: All 15 tests pass with `python3 -B scripts/test_review_storage.py`,
  by absolute path from `/var/tmp`, and via `python3 -B -m unittest discover
  -s scripts -p test_review_storage.py -v`. The same tests against the pre-change
  scanner in memory fail exactly the six new regression methods, with no harness
  errors. Invocation metadata, specialist expertise and all 21 finding fields are
  preserved; 20 local reference links resolve; `git diff --check` passes.
  Stock skill validation passed an exact compatibility copy omitting only the
  preserved Claude `user_invocable` metadata field at
  `/var/tmp/deep-review-work/research-skill-validation.0ERAyZzJgB/SKILL.md`.
- **Limits**: No live Codex/AGY/Claude three-provider research, GitHub filing,
  watcher reconfiguration, sibling publication or firewall suite was executed.
  Decision exercises and structural checks do not establish improved recall.
