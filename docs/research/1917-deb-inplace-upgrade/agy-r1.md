I will start by listing the available permissions to understand the workspace structure and where the repository files are located.
I will list the contents of the `/home/ps/.gemini/antigravity-cli/worktrees` directory to see if that is where the repository resides.
I will run a quick command to print the working directory using `/home/ps` as the base directory.
I will search for `plan.md` under `/home/ps` to locate the repository root.
I will search for any directory or file containing `1917-deb-inplace-upgrade` under `/home/ps` to locate the target repository.
I will run `git status` in the `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade` directory to confirm it's our repository and target workspace.
I will read the proposed upgrade plan located at `docs/research/1917-deb-inplace-upgrade/plan.md` to understand its details.
I will find all Go files in the repository to make sure I have their exact paths.
I will find all Go files containing `configstore` or `cluster` in their path to locate the configuration storage and cluster/HA logic.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/dataplane/userspace/process.go` to examine the helper's lifecycle, the execution command, how `m.proc` is managed, and how XSKMAP is cleared.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/dataplane/userspace/manager.go` to check the fields of `Manager` and see if `proc` or other properties suggest any support for re-attaching.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/dataplane/verify_userspace_shim.go` to check the verifier gating for the kernel version and how the embedded shim is validated.
I will search for `6.18` in the repository to see where the kernel version requirement is defined or checked.
I will run a grep command in the workspace to find references to `6.18`.
I will view `pkg/configstore/db.go` to see the structure of configuration database management, how marshaling is performed, and if there are any version fields.
I will check the status of my background task searching for `6.18`.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/cluster/heartbeat.go` to inspect the heartbeat payload and checks, focusing on where the software version is populated and if/how it's checked.
I will search for `HAProtocolVersion` and `SoftwareVersion` in the `pkg/cluster` files to see where they are processed and check if any decisions are gated by them.
I will view `pkg/cluster/peer_state.go` to see the logic for version checks, mismatch detection, and how decisions are affected.
I will search for usage of `HAProtocolVersionMismatch` across the repository to see what is gated on a protocol mismatch.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/daemon/daemon_ha_userspace.go` around line 900 to see how the HA protocol mismatch gates transfer readiness or role elections.
I will view `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/cluster/status.go` to confirm that the `SoftwareVersion` is only surfaced in status output and never gates actual operations or state transitions.
I will check the grep task status to see if any matches were found for `6.18`.
I will terminate the running grep task to avoid unnecessary resource usage since it matched large generated files.
I will run a command to find Python and script files in the repository.
I will run a targeted search in `scripts/image/bake.py` for references to the kernel version floor or pinning.
I will view `scripts/image/bake.py` around line 200 to see the exact shell logic for the kernel floor check.
I will view lines 241 to 280 of `scripts/image/bake.py` to inspect how files were copied in previously.
I will view lines 150 to 194 of `scripts/image/bake.py` to check the actual files copied in during the bake.
I will search for any files containing `upgrade` in the repository to see if `xpf-upgrade` or related upgrade tools already exist.
I will search for the communication protocol or ports used between cluster nodes to see how sync and failover coordination are handled.
I will run a grep command to see where `ForceSecondary` or failover requests are handled in gRPC API and CLI.
I will view `pkg/cluster/failover.go` around line 118 to check how `ForceSecondary` operates.
I will search for `Reset` in `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/cluster/failover.go` to see the logic for restoring the node back to primary.
I will view lines 148 to 190 of `/home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/cluster/failover.go` to understand how the failover is cleared and election resumes.
I will write the complete, evidence-backed adversarial review report to the artifact directory.
PLAN-NEEDS-REVISION

### Blocking Items

1. **Debhelper auto-restart hazard in `postinst`**
   The plan does not address how to prevent the default Debian packaging toolchain (`dh_installsystemd`) from automatically appending a `systemctl try-restart xpfd.service` code block to the end of the generated `postinst` script on package upgrade. Without overriding this behavior, any `apt upgrade xpf` on an active HA node will trigger an immediate daemon restart, causing a full dataplane cycle and traffic cut even if the custom `postinst` script refuses to flip the live symlink. 
   * **Resolution:** The package rules (`debian/rules`) must explicitly configure `dh_installsystemd` with `--no-restart-on-upgrade`.

2. **GRUB fallback mechanism for the verify-gated kernel channel**
   Section §6.7 states that the candidate kernel is installed "unbooted" and `verify-dataplane` is run against it. However, the BPF verifier is a kernel-space component. Loading a BPF collection spec via `ebpf.NewCollection` ([verify_userspace_shim.go:L113](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/dataplane/verify_userspace_shim.go#L113)) queries the *currently running kernel*. Thus, the verification requires booting the candidate kernel.
   * **Resolution:** The plan must design a one-time boot GRUB fallback mechanism (e.g. using `grub-reboot` to boot the candidate kernel once, and automatically falling back to the old boot default if a boot-watchdog script or the verifier fails) to prevent a verifier failure on the candidate kernel from permanently bricking the node.

3. **Non-atomic Config-DB state-manifest writes**
   Writing the new version metadata to a separate `.configdb/manifest.json` file while writing the configuration to `active.json` ([db.go:L45](file:///home/ps/git/bpfrx/.claude/worktrees/1917-deb-inplace-upgrade/pkg/configstore/db.go#L45)) creates a crash-consistency gap. A power cut between writing these two files will leave the configuration database in a mismatched state.
   * **Resolution:** The manifest metadata must be stored inside the same file (either wrapped in a parent JSON envelope or prefixed as a plaintext header for encrypted configurations) to ensure single-file atomic renames via `fsatomic`.

4. **Bootstrapping of the upgrade command**
   During a rolling upgrade, when `apt upgrade` installs version N+1, it only stages the new files under `/usr/local/lib/xpf/<new-version>`. The active `/usr/local/sbin/xpf-upgrade` symlink still points to the old version N, which may lack the protocol handling or orchestration code required by version N+1.
   * **Resolution:** The plan must explicitly mandate executing the newly staged orchestrator binary from `/usr/local/lib/xpf/<new-version>/xpf-upgrade` to drive the rolling cut-over, rather than the active symlink path.

***

Detailed analysis, code walks, and architectural justifications are documented in [adversarial_review.md](file:///home/ps/.gemini/antigravity-cli/brain/cd31d3a1-8551-4d90-9756-4a1d258dfa93/adversarial_review.md).
