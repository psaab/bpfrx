# Reviewer task IDs — #1540 REST API split

Track Codex / Gemini / Antigravity task-ids round-by-round so that
long-running sessions or harness restarts can resume by fetching
results by id rather than re-dispatching.

## Plan review

| Round | Reviewer | Task ID | Verdict | Notes |
|-------|----------|---------|---------|-------|
| 1     | Codex    | (foreground task on 5ed3fdd3) | PLAN-NEEDS-MINOR | 4 items: config_handlers.go→config.go, newCollector→metrics_descriptors.go + parseMemInfoKB→metrics_system.go, tighten api.go scope (move policyActionStr/screenChecks/protoName/configCommitResponse out), atomic-move + build cadence. All folded. |
| 1     | AGY      | review-mpmuqzeo-dgl1z7 | PLAN-NEEDS-MINOR | 5 items: config_handlers.go→config.go, match* helpers in security.go (already), newCollector→metrics_descriptors.go, parseMemInfoKB→metrics_system.go, per-file build cadence. All folded. |

## Implementation review

| Round | Reviewer | Task ID | Verdict | Notes |
|-------|----------|---------|---------|-------|
| 1     | Codex    | (foreground task on b34ddc09) | MERGE-NEEDS-MINOR | doc-drift only: plan.md stale against landed shape; canary + retirement README pkg/api/api.go blurb mentioned protoName but it's in sessions.go. Folded in 860bf5f5. |
| 1     | AGY      | review-mpmv8agw-9avq5l | MERGE-READY | Independent 110-function byte-comparison; Collect-path allocation audit clean; canary/docs path-set parity verified. |
| 1     | Copilot  | gh PR #1564 (b34ddc09) | COMMENTED (8 inline) | 4 doc-drift folded in 860bf5f5; 4 pre-existing `net.InterfaceByName(ifName)` Junos-name lookups filed as #1565 (pre-existing on master at 936b076d, NOT introduced by pure-code-motion #1540). |
| 1     | Claude SMR | in-conversation | MERGE-READY | Independent 110-function byte-comparison vs base 936b076d via Python AST-block extractor; all 69 handlers.go blocks, all 34 metrics.go blocks, all 10 handlers_sessions.go blocks byte-identical in new files. |
| 2     | Codex    | (foreground task on 860bf5f5) | MERGE-NEEDS-MINOR | 2 remaining doc-drift findings in this PR's own plan.md + reviewer-ids.md (stale v1 open-questions section, reviewer-ids round-1 marked pending). Folded in next commit. |
