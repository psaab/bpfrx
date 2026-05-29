# #1630 cause-1 credit carry — reviewer task IDs

Branch: `fix/1630-cause1-credit-carry` (off origin/master)
PR: #1650
Head SHA: 3662ecbde

4-way code review seats (all addressed):
- **Claude SMR**: `docs/pr/1630-cause1-credit-carry/claude-smr-code-r1.md` — MERGE-READY
- **Codex**: direct companion task (fresh, session a8c1b014). 1 Major + 1 Medium (floored-boundary), both FIXED in 4a2b998f7.
- **AGY**: `review-mpqel5m5-2skf6n` — MERGE-READY across 6 axes, no findings.
- **Copilot**: formal `copilot-pull-request-reviewer` review on PR #1650 — same boundary Major (fixed) + plan.md doc nit (fixed 7e6f7115f).

Cluster validation: scoped Gate-1 SOLO v4 100m 95.0% / 1g 95.3% PASS;
`make test-failover` 13/0. cause-2 resolved-as-physics → `Closes #1630`.

Merge gate: 4-of-4 MERGE-READY + scoped Gate-1 (100m/1g ≥95% SOLO) +
full smoke matrix + `make test-failover`. 3-of-4 allowed only with a
documented Codex/Copilot-infra-blocked exception
(feedback_codex_infra_must_retry).
