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

## Plan review round 2 (plan @ cdd7a1bcd)
| Reviewer | ID | Verdict |
|---|---|---|
| Codex | task-mqftf67e-wfs37n | PLAN-NEEDS-MAJOR (stale gate text in §5; min() contradiction; watchdog claim wrong; tighten Phase-0 ctrl instr) |
| AGY | adversarial-review-mqftflub-s27we1 | INFRA-TIMEOUT (job ran, result never captured; r1 findings already folded) |
| Claude SMR | authored v3 corrections | n/a |

r2 outcome: Codex KILL->NEEDS-MAJOR (progress). All 4 Codex findings addressed in
v3. AGY r2 infra-timed-out -> re-dispatch fresh in r3.

## Plan review round 3 (plan @ 239d95501)
| Reviewer | ID | Verdict |
|---|---|---|
| Codex | task-mqftqa63-k6xzr9 | PLAN-NEEDS-MAJOR (effective_rx_queues vs global-min uniform planner; 2 stale-text spots) |
| AGY | adversarial-review-mqftqp2j-zyq5ff | PLAN-NEEDS-MINOR (CONFIRMED EBUSY root cause: rebind double-stop bypasses 500ms quiesce, rebind.rs:16 + teardown.rs:14-46) |

r3 outcome: AGY confirmed the EBUSY-loop root cause in code (high value). Codex's
blocker = the planner is global-min UNIFORM (helpers.rs:745, test
main_tests.rs:609-631), so effective_rx_queues must be a uniform target + RSS
constrain, not per-interface. v4 resolves both + scrubs stale gate text.

## Plan review round 4 (plan @ <pending>)
| Reviewer | ID | Verdict |
|---|---|---|
| Codex | <pending> | pending |
| AGY | <pending> | pending |
