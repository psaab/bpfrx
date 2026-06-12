# #1873 reviewer task-id ledger

| Round | Reviewer | Task id | Verdict |
|---|---|---|---|
| 1 | Claude SMR | (in-conversation) claude-smr-plan-r1.md | PLAN-NEEDS-REVISION (R1 config-domain assignment) |
| 1 | Codex | task-mqa4p6jy-k0oi3a (first dispatch task-mqa4mj62-tndk1i lost in shared runtime, never registered) | PLAN-NEEDS-REVISION (3 MAJOR: collision probing, eligibility determinism, live-validation gaps) |
| 1 | AGY | adversarial-review-mqa4memd-n0t6xo | PLAN-NEEDS-REVISION (CRITICAL slow-path plaintext leak refutes v1 fail-safe claim; eligibility gates; GRE-origin staleness) |
| 2 | Claude SMR | (in-conversation) claude-smr-plan-r2.md | PLAN-NEEDS-REVISION (R-C cold-path rescope; R-B groups union) |
| 2 | Codex | task-mqa5478t-h5yale | PLAN-NEEDS-REVISION (R-C must be slow-path-boundary invariant; full caller enumeration) |
| 2 | AGY | adversarial-review-mqa540ex-4eud0g | PLAN-NEEDS-REVISION (retry_pending_neigh plaintext MAJOR; Q1-Q8 ratified) |
| 3 | Claude SMR | (in-conversation) claude-smr-plan-r3.md | PLAN-READY-conditional, then SELF-RETRACTED anti-blanket argument (wg_control.rs:592) |
| 3 | Codex | task-mqa5gfj5-ceos57 | PLAN-READY (ratified conditional gate on refuted premise — superseded by v4) |
| 3 | AGY | adversarial-review-mqa5g6f6-abtkjf | PLAN-NEEDS-REVISION (verified admin-down plaintext trace kills conditional gate; netlink/oper-state revisions REJECTED as superseded by blanket) |
| 4 | Claude SMR | (in-conversation) claude-smr-plan-r4.md | PLAN-READY |
| 4 | Codex | task-mqa5sc25-bz2mkx | PLAN-READY |
| 4 | AGY | adversarial-review-mqa5s52d-b8j1xm | PLAN-READY |

Converged: PLAN-READY 3-of-3 at round 4 on plan v4 (blanket R-C gate).

## PR #1882 code review

| Round | Reviewer | Task id | Verdict |
|---|---|---|---|
| code-1 | Copilot | (review requested) | COMMENTED — quota limit, retry 1 documented |
| code-1 | Claude SMR | claude-smr-code-r1.md | MERGE-READY after self-found MAJOR fix 73f61b1db797 (reverse-only purge) |
| code-1 | AGY | adversarial-review-mqa9m9r0-p48whc (timed out) → retry adversarial-review-mqa9u6b2-lq3y1y | MERGE-READY at 73f61b1db797 |
| code-1 | Codex | task-mqa9mk6f-2etcct | MERGE-NEEDS-MAJOR (re-owned-id publication window) → fixed in 8909f3ac0e70 (purge-before-store + defer + rotation barrier) |
| code-2 | Copilot | (review re-requested at 70206ae04 — retry 2; retry 3 requested before round-2 push) | COMMENTED — quota limit |
| code-2 | AGY | review-mqaam2as-a3fgqq (job state under gemini state/1873-engineer-0721a2dc90c4f2cd/) | needs-attention (2 med 2 low, no verified counter-example) — mediums superseded by the r2 redesign; low (engine-Arc pin) FOLDED |
| code-2 | Codex | task-mqaaoq6a-6afsma | MERGE-NEEDS-MAJOR (1: private fabric-overlay Arc defeats the rotation barrier, worker/loop_body/mod.rs:617; 2: 250ms timeout fail-open) → fixed in 140f310bd (structural owner check: stored egress_ifindex vs row logical_ifindex at re-resolve + both encap builders; new-appearance purge arm; defer/barrier deleted) |
| code-2 | Claude SMR | claude-smr-code-r2.md | Confirmed both Codex findings; found+fixed the write-back erasure (gated resolution must PRESERVE stale egress_ifindex) and the first-apply purge guard; MERGE-READY pending Codex r3 ratification |
