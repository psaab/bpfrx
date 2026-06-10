# Codex plan-review r1 — task-mq8jm9hz-g87plf

Verdict + findings (rawOutput):

PLAN-NEEDS-REVISION

1. **[High] Missed lease-delete mutation site: `finishClient` is the real cleanup owner.**

Plan §4.3 says: “The lease-delete paths — the `ctx.Done()` branches of `runDHCPv4` / `runDHCPv6`...” and “`removeLeaseAndNotify(key)` replaces the four inline delete sites” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:236). That is contradicted by code: every DHCP client goroutine defers `m.finishClient` at [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:251), and `finishClient` deletes `m.leases[key]` at [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:294). Reconcile explicitly waits for `finishClient` cleanup at [reconcile.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/reconcile.go:133).

Verified counterexample: after T2 failure, v4 breaks back to fresh DORA at [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:699). If the client is then cancelled while `doDHCPv4` is in progress, the loop returns via [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:601) without hitting the inline delete branches; only `finishClient` removes the lease. If the hook is only wired into the four inline delete sites, the ipmon route can remain stale until some unrelated actuation. The helper must cover `finishClient`, not just the `ctx.Done` branches.

2. **[High] Same-content gateway churn is not cheap: duplicate publish still bumps FIB generation.**

Plan §4.3 claims same-gateway re-actuation is cheap because “`PublishRouteOverlaySnapshot`’s content-hash skip plus `frr-reload.py`’s diffing” handle it at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:270). §12 Q3 then treats the broad gate as acceptable on that basis at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:562).

The userspace publisher does skip duplicate `apply_snapshot` and returns `nil` at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dataplane/userspace/manager.go:846). But the daemon interface returns only `error` at [daemon_ipmon.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_ipmon.go:40), and the actuator unconditionally calls `BumpFIBGeneration()` after any nil publish result at [daemon_ipmon.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_ipmon.go:180). That bump sends a control request at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dataplane/userspace/manager.go:1092).

So a same-content aggregate hook still invalidates flow route caches and emits a bump. Fix the return contract to distinguish “published” vs “skipped”, or make the engine/hook gate compare resolved gateway state before actuating.

3. **[Medium] “The hook itself never blocks” is false under the proposed resolver placement.**

Plan §4.3 says: “The hook itself never blocks: it takes `Engine.mu` briefly...” at [plan.md](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/docs/research/1844-dhcp-nexthop/plan.md:272). But `ActiveOverlay()` holds `Engine.mu` for the whole overlay build at [ipmon.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/ipmon/ipmon.go:213), and `Status()` also calls `activeOverlayLocked()` under that same mutex at [ipmon.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/ipmon/ipmon.go:275). The proposed resolver calls `LeaseFor`, which takes `dhcp.mu` at [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:540).

I do not see a deadlock if the hook fires outside `dhcp.mu`, but the non-blocking claim is wrong. Update the invariant and add a contention test around `Status()` / `ActiveOverlay()` / gateway hook.

**Open Questions**

1. Spelling: ratify `next-hop <ifd>.<unit>`. Current schema already treats `next-hop` as one free-form arg at [schema.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/config/schema.go:1196), and compiler stores the raw token at [compiler_services.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/config/compiler_services.go:345). Parse by last dot, require exact configured interface + unit, then require `unit.DHCP`. No extra tunnel rejection unless DHCP itself rejects those units globally.

2. Lease expiry: keep-last-known is defensible but must be explicit. T2 failure does not delete the lease at [dhcp.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go:699), and FRR DHCP route collection keeps using stored leases at [daemon_flow.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_flow.go:28). I would not add expiry timers in this PR.

3. Gate sufficiency: not sufficient as written because of finding 2. Aggregate `func()` is acceptable only if duplicate overlay results do not bump FIB generation.

4. v4-only: justified. `RouteSnapshot` has no device field at [protocol.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dataplane/userspace/protocol.go:499), while FRR DHCP v6 routes need `Interface` and render it at [config_render.go](/home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/frr/config_render.go:203). Do not pull v6 into this PR.

5. Hook shape: aggregate is fine after the above fixes. Per-key would help avoid unrelated churn, but the bigger required fix is knowing whether the resolved overlay actually changed before bumping FIB.