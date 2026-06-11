No blocking findings.

The three Codex r2 requirements are adequately specified in v3:

- Auto-rollback is now daemon-owned and serialized under `applySem` across store promotion plus apply, with the hook shape deferred but the invariant explicit: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md:575).
- `enterBootstrapMode` is now an explicit cleanup path: networkd cleanup with lifeline and rename persistence semantics, FRR/VRRP clear, dataplane/helper detach-stop, and bootstrap suppression reassertion: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md:697). The helper-resurrection rationale is grounded; the exact `ensureProcessLocked` line is slightly lower than the cited `manager.go:641`, but it is the same apply block and not a plan issue.
- The dependency matrix now includes the missing auth/syslog/archive/diagnostic execs: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md:212).

The AGY r2 fixes are folded without conflicting with the Codex r2 asks: the lifeline record is PCI-keyed and resolved to the current name during reconcile, which composes with persistent renames; rollback from first commit preserves never-committed state rather than writing committed-empty, and section 9 adds serialization, predicate-stability, and PCI-keyed lifeline tests: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md:617), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md:595), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md:846).

PLAN-READY

Codex session ID: 019eb8fb-3409-7283-b261-e13c67561b8b
Resume in Codex: codex resume 019eb8fb-3409-7283-b261-e13c67561b8b
