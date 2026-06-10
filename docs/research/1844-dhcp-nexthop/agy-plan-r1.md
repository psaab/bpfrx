I will start by checking the list of files in the workspace and locate `docs/research/1844-dhcp-nexthop/plan.md`. Let's use `view_file` to read this plan.
I will search for the plan file using `run_command` to list all files matching `plan.md` in the workspace.
I will run `git log` and search for files matching `1844` or `plan.md` in the commit history or filesystem to see if it was added or is in a specific revision.
I will search for any commits or files related to `1844` or `dhcp-nexthop` in git to locate the plan.md document.
I will run a command to show the file contents of `docs/research/1844-dhcp-nexthop/plan.md` from the `research/1844-dhcp-nexthop` branch.
I will retrieve the first 250 lines of the plan using `head` on `git show`.
I will retrieve the next chunk of the plan file (from line 250 onwards) using `tail` or a line range.
I will read the very beginning of the plan file to make sure I haven't missed any text.
I will run `git log` to see if the branch `origin/engineer/1827-ipmon-pr1` exists.
I will run `git status` to see the current check out state of this worktree.
I will run `git diff` to see what changes are currently in the working directory before making any branch adjustments.
I will check if there are any local modifications in the directories `pkg/ipmon`, `pkg/dhcp`, `pkg/daemon`, and `pkg/config` relative to `origin/engineer/1827-ipmon-pr1`.
I will view the `pkg/ipmon/ipmon.go` file using `view_file`.
I will run `find` to locate the `ipmon.go` and `dhcp.go` source files in the repository.
I will run a command to list all files in the `origin/engineer/1827-ipmon-pr1` commit that match `ipmon`.
I will list the active git worktrees using `git worktree list` to see if there is one configured for the `1827-ipmon` branch.
I will view `pkg/ipmon/ipmon.go` inside the worktree for the base branch `d18071d5c` located at `/home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2`.
I will view the next chunk of `pkg/ipmon/ipmon.go` from line 150 to 300.
I will view the remaining lines (300 to 491) of `pkg/ipmon/ipmon.go`.
I will view the `pkg/dhcp/commit.go` file in the base worktree to check the current lease commitment code structure and see if there are hooks.
I will look for the lease deletion sites in `pkg/dhcp/dhcp.go` to understand how leases are managed during context cancellation/client stops. Let's use `grep_search` to find `delete(m.leases` or similar in `pkg/dhcp/dhcp.go`.
I will view lines 280 to 310 of `pkg/dhcp/dhcp.go` around the first lease deletion site.
I will view lines 640 to 690 of `pkg/dhcp/dhcp.go` to see the delete sites in the DHCP run loop.
I will search for occurrences of `finishClient` to see where it is invoked.
I will view lines 240 to 280 of `pkg/dhcp/dhcp.go` to see the structure of the client runner and its defer block.
I will view the beginning and end of `runDHCPv4` to see all exit paths of the loop. Let's use `grep_search` to find `func (m *Manager) runDHCPv4` first.
I will view lines 570 to 630 of `pkg/dhcp/dhcp.go` to see the setup and start of the DHCPv4 run loop.
I will view lines 625 to 645 of `pkg/dhcp/dhcp.go` to see the transition from successful acquisition to the renewal cycle.
I will view lines 690 to 730 of `pkg/dhcp/dhcp.go` to see the end of the renewal cycle in DHCPv4.
I will search for `scheduleRecompile` or other callbacks in `pkg/dhcp/dhcp.go` to see how callbacks are implemented and if they require lock protection.
I will view lines 1310 to 1360 of `pkg/dhcp/dhcp.go` to see the registration and invocation patterns for callbacks.
I will search for `onAddressChange` in `pkg/dhcp/dhcp.go` to see where it is set and read.
I will search for the initialization of `dhcp.Manager` in `pkg/daemon` to see if `SetGatewayChangeHook` is called during startup or dynamically.
I will view lines 105 to 135 of `pkg/daemon/daemon_dhcp.go`.
I will search for `type PreferredRoute` in the config package to see the struct fields at the base commit.
I will view lines 310 to 330 of `pkg/config/types_system.go` to see the structure of `PreferredRoute`.
I will search for `buildDHCPClientSpecs` in the codebase to verify how interface names and lease keys are derived.
I will view lines 14 to 50 of `pkg/daemon/daemon_dhcp.go` to see how DHCP client lease interface names are derived.
I will search for `LinuxIfName` to find its definition.
I will view lines 1 to 30 of `pkg/config/types.go` to see the definition of `LinuxIfName`.
I will search for the definition of the interfaces config structures in `pkg/config/types.go`.
I will view lines 1 to 50 of `pkg/config/types_interfaces.go` to see the structure of interfaces and units configuration.
I will view lines 50 to 90 of `pkg/config/types_interfaces.go`.
I will search for `UnitConfig` in the config package to see if it is a defined type.
I will view lines 480 to 520 of `pkg/dataplane/userspace/protocol.go` to inspect the `RouteSnapshot` structure.
I will view the contents of `pkg/daemon/daemon_ipmon.go` in the base worktree to check how the overlay is consumed and actuated.
I will view the remaining lines (150 to 255) of `pkg/daemon/daemon_ipmon.go`.
I will view lines 320 to 360 of `pkg/config/types_system.go` to see the structure of `RouteOverlayEntry`.
I will search for `validateIPMonitoringStrict` in the codebase to see how next-hop config validation is currently performed.
I will view lines 370 to 430 of `pkg/config/compiler_services.go` to see the current ip-monitoring validation checks.
I will search for `LeaseFor` in `pkg/dhcp/dhcp.go` to see the locking structure.
I will view lines 535 to 555 of `pkg/dhcp/dhcp.go` to inspect the `LeaseFor` method.
I will search for `onDHCPAddressChange` to see how address changes are handled.
I will view lines 70 to 100 of `pkg/daemon/daemon_dhcp.go` to see what locks are acquired during `onDHCPAddressChange`.
I will search for `preferred-route` parsing in the configuration package.
I will view lines 280 to 330 of `pkg/config/compiler_services.go` to inspect the compilation logic of preferred routes.
I will view lines 331 to 370 of `pkg/config/compiler_services.go` to see the rest of `compilePreferredRoutes`.
# Adversarial Plan Review: DHCP-learned next-hops for preferred routes (#1844)

## Verdict: `PLAN-NEEDS-REVISION`

The plan provides the correct core winner-resolution architecture (pre-winner-selection in-engine resolution) and correctly identifies the IPv6 wire-protocol blocking constraint. However, it contains a critical notification leak during interface teardown/link failures, an API-level concurrency data race, and an invalid type compilation blocker. 

---

## Pressure-Test of the Section 12 Open Questions

1. **Spelling Ratification (Q1):** The `<ifd>.<unit>` spelling carries no parser ambiguity because Junos/Linux interface naming conventions do not overlap with valid IP representations. In the degenerate case of an interface named `1.2.3` and unit `4`, configuring `next-hop 1.2.3.4` will parse as the IP literal `1.2.3.4` instead of the interface—this is an acceptable, minor constraint. Tunnel interfaces (e.g., `st0.0`) configured with `family inet dhcp` require no special rejection; if they support DHCP and resolve, they are valid routing targets.
2. **Lease-Expiry Withdrawal (Q2):** Keeping the stale gateway matches the manager's behavior of keeping the expired IP address on the interface on T2 failure ([pkg/dhcp/dhcp.go:699-701](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/dhcp/dhcp.go#L699-L701)). Both behaviors violate RFC 2131 §4.4.5. While route parity is acceptable for now, route withdrawal must be coupled to address withdrawal when the manager is eventually corrected.
3. **Gate Sufficiency (Q3):** The gate is sufficient. Debounce (1 s) and throttle (3 s) in the engine run loop ([pkg/ipmon/ipmon.go:415-424](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/ipmon/ipmon.go#L415-L424)) coalesce transient delete-then-commit flaps (e.g. client restart), and unchanged lease renewals do not fire the hook because of the `prev.Gateway != lease.Gateway` guard in `commitLease`. Caching resolved gateways is unnecessary.
4. **v4-Only Cut (Q4):** Fully justified. Since `RouteSnapshot` has no device/interface field ([pkg/dataplane/userspace/protocol.go:499-506](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/dataplane/userspace/protocol.go#L499-L506)), conveying IPv6 link-local next-hops (`fe80::...`) without interface scope is impossible without breaking wire-protocol and Rust dataplane changes.
5. **Hook Shape (Q5):** The aggregate `func()` is correct. The engine's resolution scan is O(N) over small policy sets and is fast enough to make key-based delta parsing a waste of complexity.

---

## Numbered Findings

### 1. [Critical] Missed Hook Fire Site in `finishClient` (Silent Routing Blackhole)
* **Plan Section:** §4.3 (trigger) & §9 (testing: "delete-site helper fires on client stop")
* **File & Line Reference:** [pkg/dhcp/dhcp.go:295](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/dhcp/dhcp.go#L295) (`delete(m.leases, key)`)
* **Evidence/Rationale:** The plan states: *"One helper `removeLeaseAndNotify(key)` replaces the four inline delete sites so a future fifth site cannot forget the hook."* However, it completely ignores the actual fifth lease deletion site inside the deferred cleanup helper `finishClient`. If a client terminates due to max attempts reached, link-down/abort, or admin disable, `finishClient` removes the lease from `m.leases` but the gateway change hook is NEVER fired. The engine will never recompute the overlay, leaving the stale gateway active in the dataplane and creating a silent blackhole.
* **Remedy:** The `removeLeaseAndNotify(key)` helper must also be invoked inside `finishClient` (outside `m.mu` protection).

### 2. [Medium] Data Race on Hook Invocation due to Mutable Setter API
* **Plan Section:** §4.3 (wiring) & §11 (Fork 2 Path A: `SetGatewayChangeHook` API)
* **File & Line Reference:** [pkg/daemon/daemon_dhcp.go:119-124](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/daemon/daemon_dhcp.go#L119-L124)
* **Evidence/Rationale:** The plan proposes exposing `SetGatewayChangeHook(hook func())` on the manager. Because the manager is created lazily at configuration runtime, and the client goroutines read the hook pointer concurrently (outside `m.mu` to prevent deadlock), calling `SetGatewayChangeHook` on an active manager introduces a data race.
* **Remedy:** Pass the gateway change hook directly as an immutable constructor argument to `dhcp.New(...)` (analogous to `onAddressChange` at [pkg/dhcp/dhcp.go:116](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/dhcp/dhcp.go#L116)).

### 3. [Medium] Type Discrepancy in Plan's Derived Helper Signature
* **Plan Section:** §4.1 (compile check #5)
* **File & Line Reference:** [pkg/config/types_interfaces.go:44](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/config/types_interfaces.go#L44) (`type InterfaceUnit struct`)
* **Evidence/Rationale:** The plan defines the signature of the shared helper as `config.DHCPLeaseIfName(ifName string, unit *UnitConfig) string`. No `UnitConfig` type exists in `pkg/config`. The actual type is `InterfaceUnit`.
* **Remedy:** Modify the helper signature to accept `*InterfaceUnit`.

### 4. [Low] Stale Lease and Gateway Retention on T2 Rebind Failure
* **Plan Section:** §12 Q2 & §8 ("Stale next-hop | MED | Re-acquisition window keeps last-known gateway...")
* **File & Line Reference:** [pkg/dhcp/dhcp.go:699-701](file:///home/ps/git/bpfrx/.claude/worktrees/eng-1827-pr2/pkg/dhcp/dhcp.go#L699-L701)
* **Evidence/Rationale:** When T2 rebind fails, the lease expires but the address and lease record remain in `m.leases` and on the interface during re-acquisition. While this matches the manager's address behavior, keeping an expired lease violates RFC 2131 §4.4.5.
* **Remedy:** Parity is accepted, but document that if `pkg/dhcp` is eventually fixed to comply with RFC 2131, the route overlay must align and withdraw the preferred route when the address is removed.
