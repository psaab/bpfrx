# #1922 PR-2 — SAFE-BOOTSTRAP daemon (Items 2-4 + 1b) — reviewer task IDs

Branch: `engineer/1922-pr2-bootstrap` (off origin/master with PR-1/Item-1a merged).
Plan: `git show origin/research/1922-safe-bootstrap-daemon:docs/research/1922-safe-bootstrap-daemon/plan.md`

## Engineer-time resolutions (documented per the plan)

- **OQ-B (first-commit gate scope):** RESOLVED blunt. `commitAndApply`
  refuses ANY plain first commit in bootstrap mode with guidance to use
  `commit confirmed <minutes>`. The confirmed-commit path is the escape
  hatch; no separate `commit no-confirm` form is introduced (avoids the
  reflexive-lockout foot-gun the plan flagged). Day-0 path bypasses (resolves
  NOT-bootstrap before any interactive session).
- **OQ-C (lifeline detection):** RESOLVED ladder = active IPv4 default route,
  else active IPv6 default route, else refuse-and-stay-bootstrap (console).
  Recorded by PCI+MAC. Multi-homed/policy-routed mgmt is the operator-override
  residual via `system management-interface`.
- **OQ-D (protected set):** RESOLVED auto-exempt-from-claim (skip the
  unmanaged strip), normal mgmt-zone policy still applies. Explicit non-fxp0
  `system management-interface` narrows fxp0 off the auto-protection.
- **Lifeline-identification path:** PCI bus address is the primary key (MAC
  tiebreaker), resolved to current name at reconcile time. The
  `system management-interface` typed leaf is the operator override; its
  config-mode `set` grammar is DEFERRED (default-route signal is the primary
  no-config path).

## Reviewers

| Reviewer | Task ID | Round | Verdict |
|---|---|---|---|
| Codex | bvo39rwsi (r1) / 019ed26c-5f23-7d91-9015-15433bb64d78 (r2) | r1→r2 | r1 NEEDS-CHANGES (2 release-blockers) → **r2 MERGE-READY** |
| AGY | adversarial-review-mqh69wa0-bkp0t6 (r1) / adversarial-review-mqh6o06z-wfmlzb (r2) | r1→r2 | r1 NEEDS-CHANGES (1 CRITICAL) → r2 pending |
| Claude SMR | n/a | r1 | reviewed (concerns checked; no new blockers beyond the two below) |
| Copilot | n/a (gh add-reviewer) | r1 | pending formal review |

## Round-1 findings folded (commit 640de42e6)

Both Codex and AGY independently found the SAME root cause — an empty config
tree compiles to a NON-nil `*config.Config` — from two angles; both fixes are
required for a post-first-commit-rollback box to stay bootstrap across restart:

1. **AGY r1 CRITICAL — predicate ordering.** `computeBootClass` checked
   `hasActiveConfig` before `everCommitted`; the empty rolled-back tree
   compiles non-nil → misclassified normal. FIX: check `!everCommitted`
   first. Test: `post-rollback-restart-empty-compiled`.
2. **Codex r1 release-blocker — degraded-retry marker loss.** The #1799
   persist-retry loop re-wrote `committed=1`, losing the never-committed
   marker on a failed-then-healed first-commit-rollback write. FIX:
   `persistMarkerCommitted` field feeds the retry loop the correct bit.
   Test: `TestFirstCommitRollbackDegradedRetryKeepsNeverCommitted`.

Codex r2 verified both resolved + no new findings → MERGE-READY. Findings
1/2/5/6 from Codex r1 confirmed BENIGN (HA-guard logs-not-bootstraps; dp
construct/suppress/exit/teardown lifecycle correct; protected-set parser
grammar intentionally deferred; cli.go rollback hook is fallback-only).
