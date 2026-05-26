# Reviewer task IDs — #1440 header serialization consolidation

Per `feedback_codex_session_loss_continuation`: long-running agents
lose Codex session state; record task-ids here so continuations can
fetch by id.

## Plan-review rounds

| Reviewer | Round | Task ID | Verdict |
|----------|-------|---------|---------|
| Codex    | v1 plan | task-mpmyvnpm-ge5fua | PLAN-NEEDS-MAJOR |
| Gemini   | v1 plan | task-mpmywy00-x8qvzg | failed (ACP) |
| Gemini   | v1 plan retry | task-mpmz0n67-gs2r0s | PLAN-KILL (incl. unauthorized writes; reverted) |
| AGY      | v1 plan | adversarial-review-mpmyx4kr-8zsdfx | PLAN-NEEDS-MAJOR |
| Claude SMR | v1 plan | (in-conversation) | PLAN-NEEDS-MINOR |
| Codex    | v2 plan | task-mpmzjv9c-j03mii | infra-blocked |
| Gemini   | v2 plan | task-mpmzkffq-rjpk0l | failed (ACP) |
| AGY      | v2 plan | adversarial-review-mpmzkcpk-avm6d9 | PLAN-NEEDS-MINOR |
| Codex    | v2.1 plan | task-mpmzzzlp-njggey | PLAN-NEEDS-MAJOR |
| Gemini   | v2.1 plan | task-mpn00gsr-mi5kf0 | **PLAN-READY** |
| Codex    | v2.2 plan | task-mpn06yi9-kftqfa | infra-blocked |
| Codex    | v2.2 plan retry | task-mpn08gur-xwvor4 | infra-blocked (rolled off) |
| Codex    | v2.2 plan retry 2 | task-mpn0mxxt-lxsudl | infra-blocked (rolled off) |

## Code review (PR #1579 head a8023a54)

| Reviewer | Task ID | Verdict |
|----------|---------|---------|
| Codex    | task-mpn1fuxe-dmzola | (pending) |
| Gemini   | task-mpn1ge1a-nvqsto | (pending) |
| AGY      | adversarial-review-mpn1ggzg-5i6ari | (pending) |
| Copilot  | gh pr review (auto) | (pending) |
