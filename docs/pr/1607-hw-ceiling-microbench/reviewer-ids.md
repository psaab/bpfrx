# Reviewer task IDs for #1607

## Plan review round 1 (commit d777741a85b48bf68fc50b16a87b755f918da078)

- Codex: `task-mpoiptnt-dmw8n0` (dispatch tool-use id `toolu_01ACNLB5iChPEqGmepeFSZRT`) — PLAN-KILL
- Antigravity: `adversarial-review-mpoiqabw-y5s6ga` (dispatch tool-use id `toolu_01NkgULjzaFqnCfu7RfvbEuk`) — PLAN-KILL
- Claude SMR: `docs/pr/1607-hw-ceiling-microbench/claude-smr-plan-r1.md` — PLAN-NEEDS-MAJOR

## Plan review round 2 — v2 (commit c97343fff)

- Codex: `task-mpoklpy1-tkrdqd` (lost — re-dispatch as task-mpokqxeq-lv5w6w)
- Antigravity: `adversarial-review-mpoklpnn-a24rwz` — PLAN-KILL (4 axes + 2 hazards)
- Claude SMR: `docs/pr/1607-hw-ceiling-microbench/claude-smr-plan-r2.md` — PLAN-READY-WITH-NIT (RETRACTED — missed axis 1)

## Plan review round 3 — v2 patched (commit 0b6eec937)

- Codex: `task-mpoky7lt-5xx6oz` (lost to infra)
- Antigravity: `adversarial-review-mpoky7be-bsku4m` — PLAN-NEEDS-MAJOR (3 axes + 1 hazard)
- Claude SMR: `docs/pr/1607-hw-ceiling-microbench/claude-smr-plan-r3.md` — PLAN-READY (retracted, see r4)

## Plan review round 4 — v2-r3 (commit e64103b8a)

- Codex: `task-mpol9qvc-a60wf4` (lost to infra; retried as `task-mpolbsvu-mpanqp` also lost)
- Antigravity: `adversarial-review-mpol9qlh-ivlrgr` — PLAN-NEEDS-MAJOR (4 axes)
- Claude SMR: `docs/pr/1607-hw-ceiling-microbench/claude-smr-plan-r4.md` — PLAN-READY (retracted, see r5)

## Plan review round 5 — v2-r4 (commit-pending)

- Claude SMR: `docs/pr/1607-hw-ceiling-microbench/claude-smr-plan-r5.md` — PLAN-READY for narrowed scope (plan + flooder CLI skeleton ONLY; counters AND runner AND measurement all deferred to #1611 / #1612 — see r5 correction note added post-AGY code-review-r1 axis 5)
- Codex: not dispatched (infra repeatedly losing tasks this session)
- Antigravity: not dispatched (4 consecutive rounds productive; r5 would be diminishing returns vs current narrowed scope)

## Code review round 1 — PR #1613 (commit 3b7b361bb)

- Claude SMR: `docs/pr/1607-hw-ceiling-microbench/claude-smr-code-r1.md` — CODE-READY
- Antigravity: `adversarial-review-mpomv4o9-bwph0u` — CODE-NEEDS-MINOR (axis 4 leftover plan §6 + axis 5 SMR r5 doc claim discrepancy)
- Codex: `task-mpomv4zm-bxhsd5` (5th infra loss this session) / `task-mpomvkmw-pb85x6` retry (also lost)
- Copilot: triggered via `@copilot review` PR comment; pending
