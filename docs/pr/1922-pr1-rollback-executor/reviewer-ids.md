# #1922 PR-1 (Item 1a) — reviewer task IDs

PR: https://github.com/psaab/xpf/pull/1935
Branch: engineer/1922-pr1-rollback-executor

## Quad review

- **AGY (adversarial-review):** `adversarial-review-mqh45kuh-79gi56`
  - result: `~/.claude/plugins/data/agy-claude-code-agy/state/jobs/adversarial-review-mqh45kuh-79gi56.result.md`
- **Codex (hostile):** `task-mqh46o4f-rccrbz` (dispatched via codex-rescue background agent abb9cf970dd85a74d).
- **Claude SMR (hostile, in-conversation):** see below.
- **Copilot:** requested via `gh pr edit 1935 --add-reviewer Copilot`; awaiting formal review.

## Verdicts

### Round 1

- **Codex** `task-mqh46o4f-rccrbz` — NEEDS-CHANGES. Critical: first
  commit-confirmed timeout passes nil into applyConfigLocked (fresh store
  has compiled==nil; PromoteRollback returns (nil,true)) → panic. High:
  standalone CLI (commitConfirmedFn==nil) lost dataplane re-apply. Med:
  serialization tests pass under a TryAcquire-skip; no real timer
  cardinality test. Low: false lock-order comment. Atomicity / guard
  preservation / registration ordering checklist confirmed correct.
- **Copilot** (copilot-pull-request-reviewer) — 2 inline comments, both
  the same Critical (first-commit nil deref + misleading doc).
- **Claude SMR** — verified registration ordering (executor wired at
  daemon init before gRPC/HTTP servers start), no-regression on cli.New
  (sole caller is daemon_run.go with SetCommitFns wired), applyConfigLocked
  re-applies syslog (superset of old CLI reloadSyslog). Concurred with the
  Codex Critical.
- **AGY** — first MCP dispatch ran in the main-checkout cwd (empty diff);
  re-dispatched against the worktree diff.

All r1 findings addressed in f8e16e1 (daemon nil-guard + standalone-cli
store executor + total==2 + timer-fire-once test via shared fireConfirmTimer
+ corrected lock-order comment).

### Round 2 (re-review of f8e16e1 / cc0a1a78b)

- **Codex** `task-mqh4p3z8-qe9b7o` — **MERGE-READY**. All 5 checks PASS
  (nil-deref closed on all paths incl. fallback; no standalone/daemon
  double-registration; tests catch TryAcquire-skip + drive real
  fireConfirmTimer; timer extraction lock-safe; no deadlock/torn-state;
  corrected comment matches code). No new findings.
- **AGY** (agy-rescue agent) — **MERGE-READY**. All 6 hunt categories
  verified clean (lock order, nil-deref, lost-wakeup/double-fire/stale-gen,
  double-registration, torn state, #1817/#1799 preservation). Severity:
  None.
- **Claude SMR** — MERGE-READY.
- **Copilot** — r1 findings (both = the Critical) addressed; re-requested
  on HEAD.

### Live gate

Service-mode gRPC `commit confirmed 1` (delete lan->wan allow-all,
unconfirmed) on loss:xpf-userspace-fw0: mid-window forwarding BLOCKED,
post-timeout store reverted (policy back) AND dataplane re-applied
(forwarding restored). Journal: "commit confirmed timed out, configuration
rolled back". v4+v6+reverse forwarding sanity 0% loss. Deployed hash
verified == local.
