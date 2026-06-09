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

## Round 2 outcome
- Codex `task-mq77o1nn-edtbnt`: **PLAN-NEEDS-MINOR** — PrivateRGElection default-on means heartbeat owns promotion (window widening = explicit trade only; coordinated restart suppression REQUIRED); CommitConfirmed ordering invariant; U8 option-identity diff; Q3 tree-level FormatSet sanity; Q4 sanitize-with-warning; Q5 no pair reader → U11 DEFER.
- AGY `adversarial-review-mq77o1xw-5gryre`: returned **PLAN-NEEDS-MAJOR** but all four "critical gaps" verifiably re-raise r1 items already present in the v2 text (citations point at main checkout, not the worktree) — treated as STALE per the verify-reviewer-claims rule; useful nuance (U11 A-shape preference) recorded in §5.7. r3 re-anchored with quote requirements.
- Claude SMR: **PLAN-READY**.
- Codex r2 folded into v2.1 `ff86057ae`.

## Round 3 (plan v2.1 `ff86057ae`)
- Codex: `task-mq77zu6y-5crxzh` (fold-fidelity confirmation)
- AGY: `adversarial-review-mq77zugr-1hwb7z` (re-anchored to worktree file with quote requirement)
- Claude SMR: claude-smr-plan-r3.md — **PLAN-READY**

## Round 3 outcome — CONVERGED PLAN-READY (v2.2 `57a5f8989`)
- Codex `task-mq77zu6y-5crxzh`: **PLAN-READY** — "Findings: none. The v2.1 folds are faithful." (one editorial nit, folded)
- AGY `adversarial-review-mq77zugr-1hwb7z`: **PLAN-NEEDS-MINOR** — engaged with the worktree text this round. Verified-new items ALL folded into v2.2: nested-CommitConfirmed rollback-target defect (store.go:879-880, REAL), SyncApply retry discipline, U8 lease-loop invariant, U11 Option-B lock-ordering point, atomic.Value tip. Its two additional wall-clock claims (startedAt heartbeat.go:373; transfer windows failover.go:845-863) were verified FALSE — direct time.Time comparisons retain Go's monotonic reading — recorded as audited-safe in §5.6.
- Claude SMR: **PLAN-READY** (claude-smr-plan-r3.md).
- Convergence basis: Codex READY + SMR READY + AGY MINOR-conditions-closed (every verified item folded; false claims documented with code evidence).
