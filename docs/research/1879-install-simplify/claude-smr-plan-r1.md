# Claude SMR hostile plan review — #1879 round 1

Reviewer: Claude (domain SMR: this codebase's daemon
bootstrap/linksetup/configstore; plus packaging + appliance
distribution). Plan reviewed at `3820eac16`
(docs/research/1879-install-simplify/plan.md, DRAFT v1).

Stance: hostile. I verified plan claims against the repo before
crediting them. Findings below are ordered by severity; each cites
file evidence.

## S0 (CRITICAL to the plan's premise) — commit-confirmed auto-rollback does NOT re-apply to the dataplane/networkd when xpfd runs as a service

The plan's SAFE-BOOTSTRAP keystone is "first takeover gated by
commit-confirmed ... rollback restores the bootstrap state". Verified
counter-evidence: `Store.performAutoRollback`
(pkg/configstore/store.go:1102-1156) reverts the store and persists,
then calls `s.centralRollbackFn` — but that handler is registered in
exactly ONE place: inside the interactive shell's `Run()`
(pkg/cli/cli.go:289 `c.store.SetCentralRollbackHandler(...)`), which
only executes when `isInteractive()` is true
(pkg/daemon/daemon_run.go:1054). Under systemd — i.e. every install
path this plan creates — the daemon never registers a central
rollback handler. A `commit confirmed` issued through the remote
`cli` (gRPC) that times out rolls back the configstore but NEVER
re-applies the rolled-back config to networkd/dataplane: the
lockout-inducing config keeps running. The auto-rollback safety net
the plan relies on is, today, a no-op precisely in the deployment
mode the plan targets.

Required: the plan must list, as an explicit M1b prerequisite work
item, registering a daemon-side central rollback handler wired to
`d.applyConfig` (the same full-reconcile path the embedded CLI
prefers per the comment at pkg/cli/cli.go:284-288), plus a
service-mode rollback test. Credit: the lead surfaced in AGY's r1
trace; verified here against the worktree.

## S1 (HIGH) — "bootstrap mode" is referenced as if it exists; it does not, and its cost is not in the estimate

The SAFE-BOOTSTRAP section and Path C first-boot contract both lean on
"xpfd runs in bootstrap mode: ... dataplane takeover NOT armed". No
such mode exists. `enumerateAndRenameInterfaces()`
(pkg/daemon/linksetup.go:48) runs unconditionally at daemon start and
renames every PCI NIC regardless of config presence; nothing in
`cmd/xpfd/main.go` or the daemon run path branches on
"no committed config". The plan's M1 cost ("~3-5 focused days" for
Path A) covers the debian/ skeleton but M1 explicitly bundles "Path A
.deb **+ SAFE-BOOTSTRAP daemon changes**" — the daemon-side work (a
new startup mode, the rename guard, the lifeline writer, the
first-commit gate, schema leaf, tests, and the mandatory
`make test-failover` gate for any daemon-startup change) is plausibly
1-2 weeks by itself.

Required: define bootstrap mode concretely (which subsystems start:
sshd is out of scope/system-owned, gRPC/REST binds, CLI, networkd
writes limited to the lifeline file; dataplane load skipped or
config-only), list the daemon touchpoints, and split the M1 cost into
M1a (.deb alone, current daemon behavior — additive, low risk) and
M1b (SAFE-BOOTSTRAP) with honest per-part estimates. State which can
ship without the other and what the interim safety posture is.

## S2 (HIGH) — commit-confirmed rollback can itself cut off management unless the protected designation lives outside the rolled-back config

The plan: first takeover requires `commit confirmed`; non-confirmation
rolls back to "the empty/bootstrap config". But the project's
documented unmanaged-interface policy is "Interfaces not in the config
are brought down and marked `ActivationPolicy=always-down`"
(CLAUDE.md, pkg/networkd behavior). A rollback to an empty config,
naively applied, brings down every interface — including the
management lifeline. Separately, the proposed protected-interface
mechanism is a config leaf (`system management-interface`) — which is
itself part of the tree being rolled back; a chicken-and-egg.

Required: pin the mechanism. The protected set enforced by the
networkd reconcile path must be the union of (a) the config leaf when
present, (b) the default `fxp0`, and (c) the lifeline-recorded
interface from first start — with (b)/(c) effective even when the
active config is empty or absent. State explicitly that rollback's
target state is "bootstrap state with lifeline `.network` intact",
and add the rollback-restores-lifeline test to §9 as a named
must-pass (the plan gestures at this — "riskiest reconciliation in
the design" — but does not specify where the designation lives, which
is the actual safety property).

## S3 (MED) — postinst gate: unstated dpkg failure-mode consequences, and an unreconciled cleanup discrepancy

(a) A failing postinst leaves the package half-configured, which
blocks ALL subsequent apt/dpkg operations (`dpkg --configure -a`
re-runs and re-fails) until the operator remediates. On a box with
unattended-upgrades this turns a verifier REJECT into a wedged apt.
Acceptable, but the plan must say it and document the remediation
(`apt install xpf=<old>` re-runs cleanly).

(b) The dh restart snippet does stop→start with NO `xpfd cleanup` in
between, whereas `cluster-setup.sh deploy_vm()` deliberately runs
`xpfd cleanup` between stop and binary replacement
(test/incus/cluster-setup.sh:~790). `pkg/dataplane/loader.go:1160`
says Cleanup "fully tears down the dataplane — use when
decommissioning, not during normal restarts", implying the package
restart path is fine without it — but then the test deploy's cleanup
call is either legacy-migration hygiene or load-bearing for binary
upgrades, and the plan must state which is authoritative for the
supported upgrade path (and why a plain unit restart after a binary
swap is sufficient).

## S4 (MED) — postinst verify-dataplane has no CPU discipline; the cluster pre-flight grew one for a reason

The deploy pre-flight runs the verify walk under
`nice -n 19 taskset -c <complement-of-worker-CPUs>` because a REJECT
walk costs ~17s of one core (test/incus/cluster-setup.sh:725-763,
with the false-reject fallback subtlety). The plan's postinst sketch
runs `xpfd verify-dataplane` bare — on a live HA node mid-upgrade this
can land on AF_XDP worker cores. Either adopt the same
nice/best-effort-taskset discipline in postinst (the script logic is
portable) or state explicitly that the supported apt path accepts a
transient one-core blip and quantify it.

## S5 (MED) — Path C ignores that cloud-init is itself a network manager

Basing the image on Debian genericcloud gets cloud-init for day-0
`write_files`, but cloud-init also generates and applies network
configuration (ENI/netplan/networkd) for detected NICs on first boot —
i.e. a second actor renaming/claiming interfaces under xpfd's
takeover and potentially fighting the lifeline `.network`. The image
must ship with cloud-init network configuration disabled
(`network: {config: disabled}`) or scoped to fxp0 only, and the plan
should say so; otherwise the first-boot contract in C.2 is not
guaranteed. Add to §5-C and to the open questions.

## S6 (LOW) — path migration from /usr/local

Every existing install (test VMs, any hand-installed host) has
`/usr/local/sbin/xpfd` + `/usr/local/sbin/cli`; the .deb installs to
`/usr/sbin` + `/usr/bin`. PATH precedence on Debian puts /usr/local
first — a stale old binary silently shadows the packaged one (this
exact failure class is documented project memory:
feedback_cli_binary_path). postinst should detect and warn/remove
`/usr/local/sbin/{xpfd,cli,xpf-userspace-dp}`; the plan's bpfrxd
migration analogue in deploy scripts shows the precedent.

## S7 (LOW) — hosting-limit claims need one verification pass

"GitHub Releases has a 2 GiB per-file cap" and the ~600 MB-1 GiB
sealed-image estimate are stated without verification; GH Pages apt
repos also have soft size limits relevant to M3. One bake + measure
during M2 settles it; mark these as assumptions-to-verify rather than
facts.

## What I checked and did NOT find broken

- The #1869/#1864 characterization matches the repo
  (cluster-setup.sh:705-770 ordering invariant; pkg/dataplane/README.md
  guard layers; `verify-dataplane` exit codes in cmd/xpfd/main.go).
- CommitConfirmed exists end-to-end with the #1799 persist-failure
  hardening (pkg/cli/cli_config.go:213-240, configstore tests) — the
  plan's reuse claim is sound.
- The Depends/Recommends mapping matches what the daemon actually
  touches (frr.conf managed section + `systemctl reload frr` hard;
  strongswan/kea/chrony rendered-at-runtime optional).
- Helper/daemon coupling: xpfd spawns the helper itself
  (pkg/dataplane/userspace/process.go), so a single-unit restart does
  cycle both — invariant 6 holds as written.
- The "setup.sh is ~80% of the recipe" claim is fair, and the plan
  correctly subtracts the build-toolchain and test-package install
  (test/incus/setup.sh:281) from the bake.
- Path D ordering (deb → image → installer) is right: C consuming A's
  deb avoids re-implementing file placement at bake time, and B is
  pure sugar over A. I see no credible argument for C-first.

## Verdict

PLAN-NEEDS-REVISION — required changes:

0. Add the service-mode central-rollback-handler gap (S0) as a named
   M1b prerequisite with a service-mode rollback test.
1. Define bootstrap mode + daemon touchpoints; split M1a/M1b costs
   honestly (S1).
2. Pin where the protected-mgmt designation lives so rollback cannot
   remove it; name the rollback-restores-lifeline test (S2).
3. State postinst failure-mode consequences (wedged apt /
   unattended-upgrades) + reconcile the cleanup-on-upgrade
   discrepancy (S3).
4. Add CPU discipline (or an explicit accepted-blip statement) to the
   postinst gate (S4).
5. Address cloud-init network-config conflict in Path C (S5).
6. (Minor) /usr/local shadowing migration + mark hosting limits as
   assumptions (S6, S7).

No PLAN-KILL: the architecture reuses the right primitives and the
honest-scope framing is genuine; the gaps are specification holes, not
direction errors.
