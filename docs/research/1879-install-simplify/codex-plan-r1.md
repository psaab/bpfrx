I could not fetch `gh issue view 1879 --comments` because network is blocked in this session, so I did not independently verify the issue comments or the cited deep-research report. This review is based on the plan and repo evidence.

**Findings**

1. **SAFE-BOOTSTRAP rollback is not proven and has a concrete counterexample.**  
   The plan says first takeover can reuse `CommitConfirmed` and rollback will restore the bootstrap lifeline. But `CommitConfirmed` saves `confirmPrevCfg = s.compiled`; on a fresh node `Load()` leaves `compiled` nil when there is no active config ([store.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/configstore/store.go:109)). Auto-rollback only calls the apply callback when `prevCfg != nil` ([store.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/configstore/store.go:1151)). So first confirmed commit from no committed config can roll back store state without reconciling networkd or restoring a lifeline.

2. **The claimed “bootstrap mode / takeover not armed” does not exist today.**  
   On daemon start, after load/bootstrap, `Run()` unconditionally calls `enumerateAndRenameInterfaces` when dataplane is enabled ([daemon_run.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/daemon_run.go:149)). That function assigns vSRX-style names to all PCI NICs ([linksetup.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/linksetup.go:27)), writes `.link` files, brings the interface down, renames it, and brings it back up ([linksetup.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/linksetup.go:317)). The bootstrap fxp0 network is DHCP-only ([linksetup.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/linksetup.go:288)). Static remote management can still be locked out before any commit-confirmed safety net exists.

3. **The no-committed-config gate is definable, but the plan has not defined it tightly enough.**  
   The daemon first loads the DB, then imports text config via `bootstrapFromFile()` if there is no active DB config ([daemon_run.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/daemon_run.go:135), [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/daemon_apply.go:27)). A correct predicate must distinguish absent DB, empty active DB, corrupt DB, successful preseeded `xpf.conf`, and failed preseed import. “No committed config” is not safe as a loose English condition.

4. **The postinst verifier gate is weaker than the #1869 invariant and cannot be the primary upgrade safety mechanism.**  
   The current cluster deploy verifies the new temporary binary before stopping the old daemon or replacing installed binaries ([cluster-setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/cluster-setup.sh:711), [cluster-setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/cluster-setup.sh:727), [cluster-setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/cluster-setup.sh:765)). `verify-dataplane` itself is correctly exposed and exits nonzero on verifier failure ([main.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/cmd/xpfd/main.go:46)). But a Debian `postinst` runs after unpack, so the disk binary has already been swapped. Debian docs support the plan’s `#DEBHELPER#` token/restart ordering and compat 13 restart-after-upgrade semantics, but that only makes this a last-chance gate, not equivalent to #1869. The supported HA upgrade path must make `xpf-upgrade` or equivalent verify-before-unpack primary.

5. **Dependency classification is partly correct but incomplete.**  
   `Depends: frr` is justified: the daemon writes `/etc/frr/frr.conf` and reloads FRR via systemd/vtysh ([manager.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/frr/manager.go:520)). `strongswan-swanctl`, Kea, and chrony as `Recommends` is policy-plausible because they are feature-specific, though the daemon really execs `swanctl` ([ipsec.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/ipsec/ipsec.go:31)) and manages Kea units/files ([dhcpserver.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/dhcpserver/dhcpserver.go:75)). But the plan omits other real runtime tools: `ethtool`, `ip`, `nft`, `networkctl/systemd-networkd`, `systemctl`, and feature dependencies for SSH/syslog/user management. Debian Policy 7.2 requires this matrix to match whether xpf “will not operate at all” or only loses optional features.

6. **Path C costing is too optimistic and the Incus export story is not verified.**  
   `setup.sh` is a useful in-guest provisioning recipe, but it is not 80% of a shippable qcow2 product. It installs build tools, enables unstable kernel repos, installs `linux-image-amd64` from unstable, and tunes GRUB ([setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/setup.sh:280), [setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/setup.sh:283), [setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/setup.sh:300)). It also initializes Incus storage as `dir` when possible ([setup.sh](/home/ps/git/bpfrx/.claude/worktrees/1879-research/test/incus/setup.sh:73)), so “root disks are qcow2 under the hood” is not a dependable recipe. Shipping an image also needs sealing, cloud-init/network ownership, exact kernel pin/removal of unstable tracking, signing, size validation, and boot testing outside Incus.

7. **HA rolling upgrade assumptions are under-specified.**  
   The helper is version-coupled to the daemon through a Unix control socket and explicit protocol version ([protocol.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/dataplane/userspace/protocol.go:10)); single-package install can handle same-node coupling. But HA has peer software/protocol fields ([manager.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/cluster/manager.go:119)) and explicit mismatch handling ([daemon_ha_userspace.go](/home/ps/git/bpfrx/.claude/worktrees/1879-research/pkg/daemon/daemon_ha_userspace.go:902)). The plan assumes N-1/N config and protocol compatibility without making it a release policy or a required mixed-version test.

8. **Path D ordering is defensible, but only if Path C immediately consumes the deb.**  
   Deb first, image second, installer third is the right build dependency order for a single maintainer because the image should install the same package artifact. But the plan must not let the operator-pinned qcow2 requirement become an indefinite “after packaging” item; Path C needs a concrete spike and acceptance test in M2.

**Required Changes**

1. Specify SAFE-BOOTSTRAP as an actual daemon mode: no PCI rename, no link down/up, no networkd takeover, no AF_XDP attach until an explicit first confirmed takeover succeeds.

2. Redesign first confirmed rollback so nil/bootstrap previous config still triggers reconciliation and restores the management lifeline, with tests for DHCP and static management.

3. Define the exact no-committed-config predicate across absent DB, empty DB, corrupt DB, preseeded `xpf.conf`, and failed bootstrap import.

4. Make verify-before-unpack the primary supported upgrade mechanism for HA; document postinst verification as a secondary dpkg guard, including half-configured recovery and unattended-upgrades behavior.

5. Replace the dependency section with a complete runtime dependency matrix tied to actual execs and degraded feature behavior.

6. Rework Path C into a verified image pipeline: publish/export/convert mechanics, storage-driver assumptions, cloud-init/network sealing, exact kernel policy, signing, size budget, and non-Incus qcow2 boot validation.

7. Add HA mixed-version acceptance criteria: daemon/helper same-package guarantees, `/usr/local` migration hazards, peer protocol compatibility, and N-1/N config compatibility tests.

8. Expand the open questions to include the missing gate predicate, rollback nil-callback hole, stale local binaries, package half-configured recovery, Incus export spike, unstable kernel removal, and HA compatibility policy.

PLAN-NEEDS-REVISION
