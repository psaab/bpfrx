# Plan-reviewer ledger — #3075 / #3395 stable-id research

Three research reviewers per the /research contract: Claude SMR + Codex + AGY.
(Copilot joins only at /engineer time on the code PR.)

| Reviewer | Round | ID / location | Verdict |
|---|---|---|---|
| Claude SMR | r1 | `claude-smr-plan-r1.md` | NEEDS-REVISION |
| Claude SMR | r2 | `claude-smr-plan-r2.md` | PLAN-READY |
| AGY | r1 | agent `ad7b57a4eac3787f8`; AGY job `rescue-mr0w8dqr-1ut9yh` (exit 0); verbatim in `agy-plan-r1.md` | NEEDS-REVISION → all items folded into v2 (PLAN-READY-equivalent) |
| Codex | r1 | agent `a9e1a225b759186a7` (codex-rescue) | INFRA-BLOCKED |

## Codex infra-block (documented retries)

Per `feedback_codex_infra_must_retry`, Codex was attempted and retried:
1. Initial dispatch (agent `a9e1a225b759186a7`) — returned "The task is running.
   I'll wait for it to complete" with no synchronous verdict.
2. Resume via SendMessage requesting a concrete verdict or an explicit
   infra-block confirmation — returned "The Codex task is still running and
   actively reading source files."

Two attempts, no usable synchronous verdict (the documented codex-companion
result-fetch-drop pattern). Proceeded 2-of-3 (Claude SMR + AGY), which converged.
AGY alone would not have been enough; SMR + AGY both reached PLAN-READY.

## Note on a mis-targeted AGY sibling job

The MCP `agy_adversarial_review` git-diff default produced a sibling job
`adversarial-review-mr0wcll0-pk94mc` that reviewed a DIFFERENT worktree
(`.claude/worktrees/2387-research`, the #2387 VRF SessionKey plan). That output
was discarded as off-target. The canonical AGY review (`rescue-mr0w8dqr-1ut9yh`)
read THIS plan's file content directly and verified against the 3075-3395 source
— recorded verbatim in `agy-plan-r1.md`. (Companion-points-at-wrong-checkout
hazard; the file-content-not-git-diff route is the reliable one.)
