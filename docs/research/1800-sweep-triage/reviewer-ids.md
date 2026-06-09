# #1800 sweep-triage — plan-review task IDs

Plan: docs/research/1800-sweep-triage/plan.md, branch research/1800-sweep-triage

## Round 1 (plan v1 `758f35ea3`)
- Codex: `task-mq77b8i5-7zftgs`
- AGY: `adversarial-review-mq77b8r3-ftrvfe`
- Claude SMR: claude-smr-plan-r1.md — PLAN-NEEDS-MINOR (U2 needs failover gate; §5.5 premise must be stated+verified; U6 interactions resolve-in-plan or downgrade to Option B)

## Round 1 outcome
- Codex `task-mq77b8i5-7zftgs`: **PLAN-NEEDS-MAJOR** — U6 split per-path; U10 too late + monotonic-ns + KVM overclaim; U5a FormatSet-corpus not hand-table; U8 Background-root invariant; U11 Option B preferred; U7 migration + broader audit; U9 stronger test; parallelism matrix.
- AGY `adversarial-review-mq77b8r3-ftrvfe`: **PLAN-NEEDS-MAJOR** — NEW defects: performAutoRollback persist hole + RestartHeartbeat no-peer-grace; companion wall-clock sites (hbSuppressStart, GARP); U7 strict-path-only validation (Load() boot safety); U6 reject-A-globally (reconciled via split); U9 recovery-only verified sufficient; U11 no-pair-reader verified.
- Claude SMR: **PLAN-NEEDS-MINOR** — U2 failover gate; §5.5 premise; U6 resolve-in-plan.
- All folded into v2 `48d1a023c`.

## Round 2 (plan v2 `48d1a023c`)
- Codex: `task-mq77o1nn-edtbnt`
- AGY: `adversarial-review-mq77o1xw-5gryre`
- Claude SMR: claude-smr-plan-r2.md — **PLAN-READY**
