### Verdict: PLAN-NEEDS-REVISION

All Round 1 folds have been successfully verified against the codebase (including `finishClient` unconditional defer, constructor injection, interface-typed metrics/UnresolvedRoutes, and same-content/FIB-gen gating). However, two new, related holes have been identified in the lazy initialization design of `d.dhcp`.

---

### Hostile Review Findings (New Holes)

#### Finding 1: Concurrent Read/Write Data Race on `d.dhcp`
* **Context:** `d.dhcp` is lazily initialized on the main thread inside `applyConfigLocked` -> `reconcileDHCPClients` ([pkg/daemon/daemon_dhcp.go:119-124](file:///home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_dhcp.go#L119-L124)):
  ```go
  if d.dhcp == nil {
      dm, err := dhcp.New(stateDir, d.onDHCPAddressChange, ...)
      d.dhcp = dm
  }
  ```
* **Risk:** The `d.resolveDHCPNextHop` resolver callback runs on the engine loop's goroutine concurrently (outside `applySem`) and reads `d.dhcp` without synchronization. Concurrently, CLI status and gRPC query handlers (e.g. `show system dns` / `show routing`) read `d.dhcp` from their respective request handler goroutines.
* **Consequence:** This constitutes a Go data race. A race detector (under `go test -race`) will flag this, and it violates the codebase's strict memory-safety invariants.

#### Finding 2: Startup Initialization Order Hazard in `applyConfigLocked`
* **Context:** In `applyConfigLocked`, the ip-monitoring active overlay is captured and pushed to the dataplane cache at step 1.95 ([pkg/daemon/daemon_apply.go:446](file:///home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_apply.go#L446)):
  ```go
  setter.SetRouteOverlay(d.ipmonActiveOverlay())
  ```
  However, the lazy initialization of `d.dhcp` in `reconcileDHCPClients` is not evaluated until step 3 ([pkg/daemon/daemon_apply.go:837](file:///home/ps/git/bpfrx/.claude/worktrees/research-1844-dhcp/pkg/daemon/daemon_apply.go#L837)).
* **Consequence:** On the very first startup `applyConfig`, `d.dhcp` is guaranteed to be `nil` when the overlay is built. Any interface-typed preferred routes will resolve to `ok=false` and be skipped in the initial snapshot, even if they are dynamically about to be configured in the same commit.

---

### Recommendation to Address Findings
Eagerly initialize the DHCP manager `d.dhcp = dhcp.New(...)` in `daemon_run.go:244` alongside `d.ipmon`, rather than lazily. This guarantees:
1. The `d.dhcp` pointer is write-once during boot and read-only afterwards (eliminating the data race).
2. The manager is fully constructed and ready to resolve next-hops before the first `applyConfig` evaluates the overlay.
