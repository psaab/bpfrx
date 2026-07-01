# Reviewer ID ledger — #3612 appid precedence divergence

Three plan reviewers (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer; it joins the quad at /engineer time on the code PR.

| Round | Reviewer   | Task/Job ID            | Verdict        | Doc |
|-------|------------|------------------------|----------------|-----|
| r1    | Claude SMR | (in-conv)              | PLAN-READY     | claude-smr-plan-r1.md |
| r1    | AGY        | ac3e8e989222da3a8      | PLAN-READY     | agy-plan-r1.md |
| r1    | Codex      | task-mr1uyd5f-m6qis0   | INFRA-BLOCKED  | (unretrievable: `result`="No job found"; codex-rescue forward-only; 1 fetch attempt + coordinator retry) |

Convergence: 2-of-3 PLAN-READY (Claude SMR + AGY), Codex infra-blocked per the
/research Codex-infra exception (AGY alone is never enough; here Claude SMR + AGY
both PLAN-READY). PATH A. Full 4-way incl. Codex + Copilot at /engineer on the
code PR.
