# Reviewer task IDs — #1615

## Plan-review round 1

- Codex: task-mpoxm6fp-0uzenc → sandbox infra (BLOCKED); retries task-mpoxp8g2-wz3ed6 (BLOCKED), task-mpoxrqw7-v2jwj0 (BLOCKED), task-mpoxt7ed-srhb1t (final, NEEDS-MAJOR with embedded files)
- AGY:   adversarial-review-mpoxmejg-u7jhya (NEEDS-MAJOR)
- Claude SMR: claude-smr-plan-r1.md (NEEDS-MINOR — MAJOR-1..5 + MINOR-1..4)

## Plan-review round 2 (plan v2)

- Codex: task-mpoxxoi2-lcj5po (NEEDS-MAJOR)
- AGY:   adversarial-review-mpoxxv31-f1ylaj (NEEDS-MINOR)
- Claude SMR: claude-smr-plan-r2.md (PLAN-READY)

## Plan-review round 3 (plan v3)

- Codex: task-mpoyqsg3-kz70ue (NEEDS-MAJOR — 6 doc-consistency findings)
- AGY:   adversarial-review-mpoyqyps-lt2o4w (NEEDS-MINOR — 3 findings)
- Claude SMR: claude-smr-plan-r3.md (PLAN-READY)

## Plan-review round 4 (plan v4)

- Codex: task-mpoyufgg-ccq66o (NEEDS-MINOR — 2 doc-consistency, scrubbed)
- AGY:   adversarial-review-mpoyum3e-qx87bl (PLAN-READY w/ 4 minor impl follow-ups)
- Claude SMR: claude-smr-plan-r4.md (PLAN-READY)

## Code-review round 1 (PR #1617)

- Codex: task-mpozrxtm-sf58du (sandbox-blocked) → task-mpozvst1-yue27n (CODE-KILL: dangling pointer + warmup + deadline)
- AGY:   adversarial-review-mpozs5n6-lzryzj (NEEDS-MAJOR: AGY-impl-1 dangling pointer, AGY-impl-2 Send safety doc)
- Claude SMR: claude-smr-code-r1.md (MERGE-READY — but missed the dangling pointer; humbled)
- Copilot: @copilot review triggered

## Code-review round 2 (PR #1617 after r1 fixes)

- Codex: task-mpp04elk-moz9oh (MERGE-READY)
- AGY:   adversarial-review-mpp04lix-hs4f0o (MERGE-READY)
- Claude SMR: claude-smr-code-r2.md (MERGE-READY — all 4 r1 findings fixed)
- Copilot: 2nd formal review on commit 4efdac9f — 4 inline comments: 3 real + 1 false-positive on dangling pointer

## Code-review round 3 (PR #1617 after Copilot r2 fixes)

- Codex: (no re-review needed — doc + drop() fix doesn't touch threading)
- AGY:   (no re-review needed — same)
- Claude SMR: claude-smr-code-r3.md (MERGE-READY — 3 of 4 Copilot fixed + 1 false-positive rebutted)
- Copilot: re-review triggered post-8b9de5783; no 3rd formal review submitted (Copilot bot inferred no new substantive change)
