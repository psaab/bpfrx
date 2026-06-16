# #1917 increment B — code-review reviewer ledger

PR: https://github.com/psaab/xpf/pull/1933
Branch: engineer/1917b-inplace-upgrade

## Plan-review (research phase, already converged PLAN-READY v4)
See docs/research/1917b-inplace-upgrade-mechanism/ for plan-review ids.

## Code-review (this PR — 4-way: Codex + AGY + Claude SMR + Copilot)

| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | 019ed12a-9a64-7800-86b6-aeea042e3f7a | r1 | NEEDS-REVISION (3 Critical + 2 High + 1 Medium) |
| AGY | adversarial-review-mqgtwgjy-7dc77o | r1 | NEEDS-REVISION (1 Critical + 2 High) |
| Claude SMR | in-conversation | r1 | NEEDS-REVISION (concurred with Codex/AGY) |
| Copilot | (formal PR review) | r1 | (pending) |

### Round-1 findings + resolution (commit 6fc77fba9)
- Codex Critical#1 (rollback leaves stale FLIPPED journal) — FIXED: rollback journals ROLLINGBACK + clears on success; resume handler.
- Codex Critical#2 (restoreDBSnapshot crash window destroys DB) — FIXED: stage+fsync before move-aside + recovery branch.
- Codex Critical#7 / AGY Critical (drain parser keyed on text FormatStatus never emits — dead on live cluster) — FIXED: rewrote to gRPC + chassis-cluster-information topic, real-format-validated parsers.
- Codex High#2 (stale FLIPPED not recovered) — FIXED: stale-target recovery starts a half-cut FLIPPED/STARTED.
- Codex High#5 (interactive ISSU hard-errors non-TTY) — FIXED: gRPC SystemAction.
- Codex High#6 / AGY (HA proto not actually compared) — FIXED: compare local vs peer HA protocol version lines.
- Codex Medium / AGY (LocalPrimary/DrainComplete substring bugs) — FIXED by the per-RG Local-state rewrite.
- Codex Medium (HelperHealthy ignores --unit) — FIXED: NewSystem(unit).
- AGY Critical (cluster-setup secondary grep never matches) — FIXED: grep real "Local state: Secondary".

### Round 2 (verify fixes)
| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | (pending) | r2 | (pending) |
| AGY | (pending) | r2 | (pending) |
