# #1921 virtio-MQ forwarding — reviewer ledger

## Plan review round 1 (plan @ 96eee9025)

| Reviewer | ID | Verdict |
|---|---|---|
| Claude SMR | claude-smr-plan-r1.md | PLAN-NEEDS-MINOR (F1 MAJOR: driver-agnostic channel pin) |
| Codex | task-mqfnykhy-2jfzzu | pending |
| AGY | adversarial-review-mqfnzlwk-gu7f3v | pending |

Copilot joins at /engineer on the implementation PR.

## Notes
- Ring-mismatch "Bug 1" self-refuted during drafting (queueCountFromBindings
  tracks bound set; bootstrap qc=1 write is Enabled=0).
- Validation venue: virtio multi-queue repro (NOT loss mlx5, which can't repro)
  + loss cluster for mlx5 regression.
