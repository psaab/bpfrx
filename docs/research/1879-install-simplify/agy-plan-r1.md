### 1. [High] Unconditional interface renaming at daemon startup (lockout hazard)
* Evidence: 
  * [pkg/daemon/daemon_run.go:210](file:///home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/daemon_run.go#L210)
  * [pkg/daemon/linksetup.go:48](file:///home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/linksetup.go#L48)
* Details: `enumerateAndRenameInterfaces` runs unconditionally at daemon start as long as `!d.opts.NoDataplane` is true. It renames every PCI NIC it discovers by bus order without checking for the presence of a committed configuration or checking whether the interface carries the active management session. Without a dedicated guard or bootstrap mode (which currently does not exist in the codebase), this creates an immediate lockout hazard on first start.

### 2. [Critical] Commit-confirmed rollback is not applied in the daemon process
* Evidence: 
  * [pkg/configstore/store.go:909](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L909)
  * [pkg/configstore/store.go:975-983](file:///home/ps/git/bpfrx/pkg/configstore/store.go#L975-L983)
  * [pkg/cli/cli.go:281](file:///home/ps/git/bpfrx/pkg/cli/cli.go#L281)
* Details: When a commit confirmed times out, `performAutoRollback` is executed within the daemon's `store` instance and reads `s.centralRollbackFn`. However, `SetCentralRollbackHandler` is never called in `pkg/daemon` (it is only called in `pkg/cli/cli.go` on the CLI's own store instance). Thus, the daemon's rollback timer will trigger but will not execute any callback to apply the reverted configuration to the dataplane, routing, or network interfaces.

### 3. [Critical] Rollback to empty/bootstrap config brings down the management interface
* Evidence: 
  * [pkg/dataplane/compiler_iface.go:1128-1149](file:///home/ps/git/bpfrx/pkg/dataplane/compiler_iface.go#L1128-L1149)
  * [pkg/networkd/networkd.go:353](file:///home/ps/git/bpfrx/pkg/networkd/networkd.go#L353)
* Details: During configuration compilation/apply, any interface not defined in the configuration is treated as "unmanaged." In `compiler_iface.go:1134-1149`, the daemon immediately brings down these unmanaged interfaces and strips them of all non-link-local IP addresses. Additionally, `networkd.go:353` writes `.network` files with `ActivationPolicy=always-down`. If a rollback to an empty/bootstrap configuration is triggered, the management lifeline interface (such as `fxp0`) will be treated as unmanaged and disabled, resulting in a permanent lockout.

### 4. [Medium] Postinst-gate honesty caveat and cleanup discrepancy are accurate
* Evidence: 
  * [test/incus/cluster-setup.sh:727](file:///home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/cluster-setup.sh#L727)
  * [test/incus/cluster-setup.sh:761-763](file:///home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/cluster-setup.sh#L761-L763)
  * [test/incus/cluster-setup.sh:786-787](file:///home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/cluster-setup.sh#L786-L787)
* Details: The honesty caveat is accurate. The deploy test script copies the new binary to `/tmp/xpfd.preflight` and runs `verify-dataplane` before touching the running daemon or replacing the binary. The package upgrade flow replaces the on-disk binary first, making the postinst check weaker. Furthermore, the test script calls `xpfd cleanup` before replacing the binary to clear map state, whereas the package upgrade only performs a restart without a full cleanup.

### 5. [Low] Depends: frr and Recommends: strongswan-swanctl/kea-dhcp are correct
* Evidence: 
  * [pkg/frr/vtysh.go:66](file:///home/ps/git/bpfrx/pkg/frr/vtysh.go#L66)
* Details: The daemon shell-outs route through `systemctl reload frr` inside `vtysh.go`. Without `frr` installed, applying routing configuration fails. Hence, `Depends: frr` is correct as a hard dependency. IPSec and Kea DHCP are feature-optional (configured at runtime), so `Recommends` is appropriate.

### 6. [Low] Recommended Path D ordering is correct
* Evidence: 
  * [docs/research/1879-install-simplify/plan.md:403](file:///home/ps/git/bpfrx/.claude/worktrees/1879-research/docs/research/1879-install-simplify/plan.md#L403)
* Details: Implementing the native `.deb` package first (M1) establishes the definitive file placement and dependency closure. The image-bake script (M2) can then consume the `.deb` directly, which eliminates duplication of placement logic and ensures clean in-place updates. This is optimal for a single-maintainer, no-CI repo.

PLAN-NEEDS-REVISION: 1. Register the daemon's reconcile callback using `SetCentralRollbackHandler` in the daemon process so rolled-back configurations are actually applied to the running dataplane and routing engine. 2. Exempt the protected management interface from the always-down/unmanaged stripping policy so rollback to an empty or bootstrap config does not disable it. 3. Adjust the M1 cost estimate to honestly account for the daemon-side changes required for the new bootstrap-mode logic and rename guard.
