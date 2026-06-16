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
| AGY | adversarial-review-mqh69wa0-bkp0t6 (r1) / adversarial-review-mqh6o06z-wfmlzb (r2) | r1→r2 | r1 NEEDS-CHANGES (1 CRITICAL) → **r2 MERGE-READY** (2 Low folded) |
| Claude SMR | n/a | r1 | reviewed — route-detect semantics, bootstrapFromFile-not-gated, exit-startup writer guard, gate-race-benign all checked; no new blockers |
| Copilot | n/a (gh add-reviewer) | r1 | pending formal review |

## Round-2 (AGY) low-severity findings folded (commit after r2)

- **AGY r2 Low — applyConfigLocked nil cfg.** Added an explicit top-level
  `if cfg == nil { return nil }` guard (no production caller passes nil; the
  bootstrap-exit block and the historical cfg.Warnings deref made the
  contract ambiguous).
- **AGY r2 Low — extractPCIAddr OOB.** `len(p) >= 10` could index `p[10]`
  out of bounds on a 10-char component; hardened to `>= 11` (a PCI address is
  >= 12 chars). Pre-existing code, hardened now that the lifeline path calls it.

## Live validation (loss userspace cluster)

- Deploy to loss:xpf-userspace-fw0/fw1 (worktree binary, hash-verified): both
  nodes boot NORMAL (node-id + day-0 import → everCommitted → not bootstrap).
  Zero `entering BOOTSTRAP` log lines — the regression-safe path holds.
- `show chassis cluster status`: healthy HA, node0 primary / node1 secondary,
  RG0+RG1 Monitor-failures None, takeover/transfer ready, peer version
  exchanged (heartbeat live).
- test-connectivity (cluster): LAN→WAN iperf3 IPv4 TCP PASS, IPv6 TCP PASS,
  cross-zone + RETH VIP v4/v6 + mtr paths PASS. (heartbeat/fabric direct-ICMP
  + external-IPv6-internet failures are env/topology artifacts, not
  forwarding-path regressions — protocol heartbeat verified live above.)
- make test-failover: see PR thread.

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
