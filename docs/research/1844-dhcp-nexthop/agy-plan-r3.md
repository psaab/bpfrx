I will read the design/implementation plan file, [docs/research/1844-dhcp-nexthop/plan.md](file:///home/ps/git/bpfrx/docs/research/1844-dhcp-nexthop/plan.md), to examine the requested sections and invariants.
I will locate the plan file in the repository using a shell command.
I will run a git command to list all files changed between the base commit `d18071d5ccb2719f6739c6352fb3d951c4615a7b` and `HEAD` to see where the plan file is.
I will search for any documentation files matching "dhcp" in the repository.
I will run a command to list any files matching `1844` anywhere in the repository or git database.
I will list the active git worktrees to see if the branch or worktree for research-1844-dhcp is active.
I will read the plan file from the `research-1844-dhcp` worktree.
I will examine `pkg/daemon/daemon_run.go` to verify the pointer-stability precedent and check how `d.rpm` and `NoDataplane` are currently managed in the codebase.
I will read the contents of [pkg/daemon/daemon_run.go](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go) around line 600 to see where managers like `d.rpm` and `d.ipmon` are created.
I will search for `NoDataplane` in `pkg/daemon/daemon_run.go` to see where the dataplane initialization is gated.
I will read the contents of [pkg/daemon/daemon_run.go](file:///home/ps/git/bpfrx/pkg/daemon/daemon_run.go) around line 240 to see where `d.ipmon` and `d.rpm` are set up.
I will search for `ipmon` in `pkg/daemon/daemon_run.go` to see where `d.ipmon` is initialized.
I will search for `ipmon` in the `pkg/daemon/` directory to see where it is created and held.
I will run a shell command to list files in the `pkg/daemon` directory to see what files are present.
I will search for occurrences of `ipmon` in the `pkg/daemon` directory of the `research-1844-dhcp` worktree to locate where `ipmon` is set up.
I will read the contents of [pkg/daemon/daemon_run.go](file:///home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_run.go) around line 244 in the `research-1844-dhcp` worktree to inspect how `d.ipmon` and `d.dhcp` are configured.
I will search for `d.dhcp` inside `pkg/daemon/daemon_run.go` of the `research-1844-dhcp` worktree to see the current initialization logic.
I will search for `d.dhcp` inside `pkg/daemon/daemon_dhcp.go` of the `research-1844-dhcp` worktree to understand how it is currently used and verify the proposed design.
I will view the DHCP reconciliation logic in `pkg/daemon/daemon_dhcp.go` to see the current lazy-initialization code.
I will view lines 100-112 of `pkg/daemon/daemon_dhcp.go` in the worktree to see the initial guards in `reconcileDHCPClients`.
I will search for `resolveDHCPNextHop` in the worktree to see if it is already partially defined, referenced, or tested.
I will search for `finishClient` in `pkg/dhcp/dhcp.go` of the `research-1844-dhcp` worktree to confirm the lease lifecycle details.
I will view the `finishClient` logic in `pkg/dhcp/dhcp.go` in the worktree to verify the description in Section 3.
I will search for `applySem` in `daemon_ipmon.go` of the `research-1844-dhcp` worktree to understand how route actuation is synchronized.
I will search for stop/cancel client logic in `pkg/dhcp/dhcp.go` in the worktree to see if any synchronous waits happen on client termination under `applySem`.
I will read `pkg/dhcp/reconcile.go` around line 133 in the worktree to check if client cancellation blocks synchronously.
I will search for the closure of the `done` channel in `pkg/dhcp/dhcp.go` in the worktree.
I will view lines 240-270 of `pkg/dhcp/dhcp.go` in the worktree to trace the defer order of `close(dc.done)` and `finishClient`.
I will view `pkg/dhcp/commit.go` in the worktree to see how `commitLease` currently updates the lease and where the hook should fire.
I will view `pkg/daemon/daemon_ipmon.go` around line 160-200 in the worktree to inspect the current routes-only actuator logic.
I will search for other occurrences of `BumpFIBGeneration` in the `pkg/daemon` directory of the `research-1844-dhcp` worktree to see how general FIB bumps are triggered during full configuration applies.
I will search for `BumpFIBGeneration` in `pkg/dataplane/userspace/manager.go` in the worktree to see what it actually does.
I will view the `BumpFIBGeneration` implementation in `pkg/dataplane/userspace/manager.go` in the worktree.
I will view lines 1066-1096 of `pkg/dataplane/userspace/manager.go` in the worktree to see how the bump control message is sent and how errors are logged.
I will read the next 20 lines of `pkg/dataplane/userspace/manager.go` in the worktree to see the end of the `BumpFIBGeneration` function.
I will search for `PublishRouteOverlaySnapshot` in `pkg/dataplane/userspace/manager.go` in the worktree.
I will view the `PublishRouteOverlaySnapshot` function in `pkg/dataplane/userspace/manager.go` to see how it computes content changes.
I will view lines 866-875 of `pkg/dataplane/userspace/manager.go` in the worktree to see the end of `PublishRouteOverlaySnapshot`.
I will search for `ipmonActiveOverlay` in `pkg/daemon/daemon_apply.go` in the worktree to see how the single capture hardening is applied.
I will read the lines around the two reads of `d.ipmonActiveOverlay()` in `pkg/daemon/daemon_apply.go` in the worktree to understand how they should be captured once.
I will read lines 730-745 of `pkg/daemon/daemon_apply.go` in the worktree to view the second `d.ipmonActiveOverlay()` call.
I will search for `reconcileDHCPClients` in the test files of the worktree to see if any tests rely on the lazy initialization of `d.dhcp`.
I will view the test setup in `pkg/daemon/dhcp_reconcile_test.go` to see how the daemon is constructed in tests.
I will read the test implementation of `TestReconcileDHCPClientsCommitLifecycle` in the worktree.
I will search for any other test files using `d.dhcp` directly or indirectly in the `pkg/daemon` directory of the worktree.
I will view the `RouteSnapshot` struct in `pkg/dataplane/userspace/protocol.go` of the worktree to verify the wire contract shape constraint.
I will view the `buildDHCPClientSpecs` function in `pkg/daemon/daemon_dhcp.go` of the worktree to see how lease key derivation currently maps to interface units and VLAN IDs.
# Verdict: PLAN-READY

The v2.3 plan successfully folds all recommendations from prior review rounds (AGY r2, Codex r2, and SMR r2). The design is robust, deadlock-free, and contains no new logic holes.

---

### 1. Eager Initialization & Pointer Stability (§4.3, §4.6, §7)
- **Race Elimination:** Creating the DHCP manager eagerly in `Run` (beside `d.ipmon` and `d.rpm`), gated on `!NoDataplane`, makes `d.dhcp` a write-once/read-only pointer. This completely eliminates Go data races with concurrent CLI/gRPC reads and `resolveDHCPNextHop` calls.
- **Pruning & Safety:** Removing the lazy-creation branch from [reconcileDHCPClients](file:///home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_dhcp.go#L108) is clean: the existing `NoDataplane` early-return guards against nil dereferences in config-only mode, and the resolver retains its own `d.dhcp` nil-check.

### 2. Lease Lifecycle survey correction (§3, §4.3)
- **Lease Removal site:** Section 3 and Section 4.3 correctly locate the hook's second fire site in [finishClient](file:///home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/dhcp/dhcp.go#L281). Since `finishClient` is the terminal cleanup defer on every exit path, this guarantees that client cancellation, max-retransmission exits, or link-local aborts will withdraw the route from the overlay snapshot, preventing blackholes.

### 3. Pending-FIB-Bump Retry (§4.3, §4.6)
- **Resilience:** The addition of the `pendingFIBBump` flag (mutated only under `applySem`) and updating `routeOverlayPublisher` interfaces to return errors/status guarantees that transient control message failures do not strand flow cache routes on stale gateways.
- **Safety:** The `lastSnapshotHash` is only updated after a successful `apply_snapshot`, so a failed publish cannot poison the duplicate-skip logic.

### 4. Lock & Thread Safety Verification
- **Acyclic Lock Hierarchy:** The lock order `applySem` $\rightarrow$ `Engine.mu` $\rightarrow$ `dhcp.Manager.mu` is strictly preserved. Since both hook fire sites in `pkg/dhcp` (`commitLease` and `finishClient`) release `dhcp.mu` before invoking the callback, there is no reverse coupling.
- **Test Compatibility:** Existing daemon-level tests in `dhcp_reconcile_test.go` explicitly mock and set `d.dhcp = mgr` beforehand, meaning they remain green despite the removal of lazy-initialization logic.
