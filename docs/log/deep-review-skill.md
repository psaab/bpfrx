- **Timestamp**: 2026-09-05 UTC
  - **Action**: Revised deep-review and review-triage around a shared evidence contract after the maintainer's review and request to commit/push. Prioritize consequential behavior across subsystem boundaries, include validation infrastructure and shipped artifacts in scope, separate impact from confidence/verification, and preserve actionable fix acceptance criteria.
  - **File(s)**: `.claude/skills/deep-review/SKILL.md`, `.claude/skills/deep-review/references/review-contract.md`, `.claude/skills/review-triage/SKILL.md`.
  - **Action**: Replaced checkout/model-specific triage assumptions with repository/revision provenance. Made review modes explicit, recent-fix windows independent of tip movement, and run allocation/publication/cleanup safe for concurrent campaigns. Preserved report/watcher filename compatibility and the explicit disposition trail.
  - **Documentation**: This is a workflow-documentation change; firewall behavior and module/operator contracts are unchanged.
  - **Validation**: `git diff --check`; native YAML frontmatter checks for both skills; both Markdown links and six repository references resolved. The Codex skill validator passed review-triage directly and deep-review on a temporary copy omitting only its existing Claude-specific `user-invocable` field, which was checked separately as boolean true. The stock validator does not accept that field; the source skill preserves it.
  - **Validation**: Exercised the documented `ln -T` publication on temporary reports: initial publication succeeded, an existing final and an existing directory were both refused, and the original report/sentinel remained intact. These checks used only owned temporary paths.
  - **Validation**: Coordinator decision walkthrough covered the cases below. This is instruction review, not an independent agent evaluation, empirical defect-recall measurement, or live firewall validation.

| Case | Required result under both skills |
| --- | --- |
| Established supported-behavior defect | MATERIAL with bounded impact, evidence and fix acceptance criteria |
| Candidate disproved by its actual guard | NEG in the reasoned disposition log, excluded from findings |
| Potentially severe issue needing unavailable lab evidence | NEEDS_VALIDATION with potential impact and a named next check |
| Green test using the wrong or stale artifact | VOID execution evidence; no unearned verification |
| Evidence file unchanged but a supporting validator changed | Recheck the dependency and claim at the pinned comparison revision |
| Incomplete fix under a closed issue | Residual with explicit owner/follow-up recommendation, not automatic DUP/FIXED |
| Report from a different or unresolved repository | Reconcile provenance; no automatic fabrication judgment |
| Fix merged but absent from an in-scope release | FIXED in source with delivery/backport milestone still outstanding |
