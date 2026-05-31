# #1713 reviewer task IDs

## Plan review (round 1)
- Codex: background task `bqe72n8c2` (isolated CODEX_COMPANION_SESSION_ID) — PLAN-NEEDS-MINOR
- AGY: `adversarial-review-mptac8cu-fhtcux` — PLAN-READY
- Claude-SMR: in-conversation — PLAN-READY

Plan v2 (commit after this) addresses Codex minors: resolved.conf ordered-search
rationale, precise de-dup guard (`domainName != "" && d == domainName`),
DNS+domain-name / DNS+domain-search ordering tests.
