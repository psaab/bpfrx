# PR #1862 (#1760 W-lite watch repair) — reviewer ledger

## Research convergence (branch research/1760-reverse-key-v2 @ 97612480ee22)
- r1: Codex task-mq912xff-4iym1m (MINOR), AGY adversarial-review-mq90z9rb-438t86 (KILL), SMR MINOR
- r2: Codex task-mq91i26m-ke7g4c (MAJOR), AGY adversarial-review-mq91hvda-u43zjb (MAJOR), SMR self-corrected MAJOR
- r3: Codex task-mq923td0-p9fu4m (MINOR) -> confirm task-mq92cre3-67e0k5 (READY); AGY adversarial-review-mq923k3r-44j692 (READY); SMR READY

## Code review (PR #1862)
- Copilot: 4 documented attempts, all "quota limit" (auto + 2 explicit requests) -> 3-of-4 fallback per feedback_codex_infra_must_retry
- Codex: r1 task-mq935xbo-96x2zt (NEEDS-CHANGES x4) -> r2 task-mq93puor-wkb43g (NEEDS-CHANGES, DNAT-vs-direct) -> r3 task-mq93zkkb-gmey13 (NEEDS-CHANGES, ext-IP corner) -> r4 task-mq9495k7-53gz6n (NEEDS-CHANGES, SharedPromote churn) -> r5 task-mq94hky1-wpanh3 (MERGE-READY, no findings)
- AGY: r1 adversarial-review-mq934b1x-n4b3xh (MERGE-READY; F1 counter-claim refuted by source) -> r2 adversarial-review-mq93pm4w-xbq0z3 (MERGE-READY) -> final adversarial-review-mq94nusk-ha5g1h (MERGE-READY on c8de0cc267a6)
- Claude SMR: claude-smr-code-r1.md (MERGE-READY + final addendum; self-caught harness preflight bug)
