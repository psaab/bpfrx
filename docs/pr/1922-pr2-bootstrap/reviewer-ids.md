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
| Codex | (pending) | r1 | (pending) |
| AGY | (pending) | r1 | (pending) |
| Claude SMR | n/a | r1 | (pending) |
| Copilot | n/a | r1 | (pending) |
