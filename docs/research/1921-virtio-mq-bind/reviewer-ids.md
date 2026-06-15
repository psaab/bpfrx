# #1921 virtio-MQ forwarding — reviewer ledger

## Plan review round 1 (plan @ 96eee9025)
| Reviewer | ID | Verdict |
|---|---|---|
| Claude SMR | claude-smr-plan-r1.md | PLAN-NEEDS-MINOR (F1 driver-agnostic pin) |
| Codex | task-mqfnykhy-2jfzzu | PLAN-KILL (armed != bind success; gate diagnosis wrong) |
| AGY | adversarial-review-mqfnzlwk-gu7f3v | PLAN-NEEDS-MAJOR (stale-socket, ethtool race, fabric/VF, watchdog) |

r1 outcome: NOT converged. Codex correctly refuted the central enable-gate
chain (verified: helpers.rs:487 `armed = armed && registered`, a request flag).
Plan rewritten to v2.

## Plan review round 2 (plan @ <pending>)
| Reviewer | ID | Verdict |
|---|---|---|
| Claude SMR | (this rewrite authored the corrections) | pending re-attest |
| Codex | <pending> | pending |
| AGY | <pending> | pending |
