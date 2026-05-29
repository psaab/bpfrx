# #1630 cause-1 credit carry — reviewer task IDs

Branch: `fix/1630-cause1-credit-carry` (off origin/master)
PR: (filled after `gh pr create`)

4-way code review seats:
- **Claude SMR**: `docs/pr/1630-cause1-credit-carry/claude-smr-code-r1.md`
- **Codex**: (task-id filled after dispatch)
- **AGY**: (task-id filled after dispatch)
- **Copilot**: formal `@copilot review` on the PR (poll for the review)

Merge gate: 4-of-4 MERGE-READY + scoped Gate-1 (100m/1g ≥95% SOLO) +
full smoke matrix + `make test-failover`. 3-of-4 allowed only with a
documented Codex/Copilot-infra-blocked exception
(feedback_codex_infra_must_retry).
