# Codex plan-review r2 — task-mq8l6s4h-rdekdo

PLAN-NEEDS-REVISION

1. **[High] Publish-skip/no-bump is not safe after a successful route publish followed by a failed FIB bump.**

Plan §4.3 says: “the actuator bumps FIB generation **only when `published`**” and “a skipped publish means the helper already has these exact routes — no re-resolution needed” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:323). §7 repeats: “skipping the bump cannot strand a flow on stale routes” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:501).

Counterexample: `PublishRouteOverlaySnapshot` updates `lastSnapshot` and `lastSnapshotHash` after a successful `apply_snapshot` at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dataplane/userspace/manager.go:857) and [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dataplane/userspace/manager.go:866). The daemon then calls `BumpFIBGeneration()` at [daemon_ipmon.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_ipmon.go:186). But `BumpFIBGeneration` logs and suppresses control-message failure at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dataplane/userspace/manager.go:1092), returning only `uint32`.

So this ordering is possible:

1. route overlay B publishes successfully;
2. `lastSnapshotHash` advances to B;
3. `bump_fib_generation` fails;
4. a later same-content actuation is hash-skipped and, under v2, will not retry the bump.

That can strand existing cached flow routes. A failed `apply_snapshot` itself is safe because hash/state do not advance, but a failed bump after a successful publish is not covered. The plan needs either a bump error contract/pending-bump retry state, or a rule that duplicate skips still bump when the previous bump after this route content was not confirmed.

2. **[Low] The v2 survey still contains the v1 false lease-delete model.**

Plan §3 still says: “Lease record deleted ONLY on client stop (`ctx.Done` branches of both run loops...)” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:90). That contradicts the actual cleanup owner: `finishClient` runs as a defer on every client goroutine exit and deletes `m.leases[key]` at [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:274) and [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:294).

§4.3 correctly fixes this, but the survey is still stale and will mislead implementors/reviewers. Update the survey row to say `finishClient` is the terminal cleanup owner; the inline `ctx.Done` deletes are redundant/pre-existing.

The constructor-arg hook has bounded caller fallout: current `rg` shows one production caller plus two tests. The `Renew` transient is now honestly documented and matches the cancel → `finishClient` → `Start` sequence. The management-interface rejection matches the daemon’s `fxp*`/`fab*`/`em*` management VRF binding classes.