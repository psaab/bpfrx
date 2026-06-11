# #1879 — Simplify xpf installation: plan of action

## 1. Status

PLAN-READY v3 — converged round 3: Claude SMR PLAN-READY + Codex
PLAN-READY (`task-mqa4cu0t-nhlc2g`) + AGY PLAN-READY
(`adversarial-review-mqa4ce8t-mz62do`). Awaiting manual approval via
`/engineer 1879`.

v3 was produced after round-2 adversarial review (Claude SMR r2 +
Codex `task-mqa42upr-3bwhh1` + AGY `adversarial-review-mqa42d7b-7umru1`,
all PLAN-NEEDS-REVISION on v2's new mechanisms). v3 changes: the
lifeline record is keyed by PCI address (not interface name — AGY r2
Critical, rename-survival); rollback-from-bootstrap persists the
no-committed-config state so the predicate survives restarts (AGY r2
High); auto-rollback is specified as a daemon-owned transaction
holding `applySem` across store promotion AND apply (Codex r2-1,
atomicity contract); entering bootstrap mode is an explicit cleanup
sequence (`enterBootstrapMode`), not a plain empty-config apply
(Codex r2-2 + SMR N2); dependency matrix extended with the
auth/syslog/diagnostic execs (Codex r2-3); renames-persist semantics
stated (SMR N1); OQ-7 gate-scope note (SMR N3).

v2 (round-1 union): the two verified commit-confirmed service-mode
holes became named M1b prerequisite fixes; bootstrap mode specified
with an exact gate predicate; protected-mgmt designation moved
outside the rolled-back config; verify-before-unpack promoted to
primary HA upgrade command; dependency matrix grounded in actual
execs; Path C costing corrected (no qcow2-under-the-hood, no "80%"
claim); HA mixed-version policy + tests; open questions expanded.

Research-only branch `research/1879-install-simplify`. No production
code is touched by this plan document.

## 2. Issue framing

Installing xpf on a fresh machine is an expert-only, many-step affair:
four artifacts copied by hand (`xpfd`, `cli`, `xpf-userspace-dp`,
`xpfd.service`), undeclared external dependencies (FRR hard, strongSwan
and Kea feature-optional, systemd-networkd assumed, kernel >= 6.18 for
the shim verifier paths), an implicit first-boot bootstrap with real
lockout risk (xpfd renames and takes over ALL interfaces at startup),
and upgrade/rollback knowledge scattered across `test/incus/*` scripts
and tribal memory. #1879 asks for one reviewable plan that gets a fresh
Debian host to a running, management-reachable xpf in one or two
commands, with upgrades and rollback equally boring.

The issue lists four candidate directions (A native .deb, B installer
script, C prebuilt appliance image, D hybrid) and explicitly does NOT
pre-decide. The operator pinned one research requirement: deep coverage
of the Juniper vSRX prebuilt-qcow2 model and what promoting
`test/incus/setup.sh` provisioning into an image-bake pipeline would
take (direction C) — xpf is a vSRX clone and the standalone test-VM
provisioning is a strong starting point for an image recipe.

A web-sourced, adversarially-verified deep-research report is attached
to the issue (2026-06-11 comment). Its verified findings are treated as
citable inputs here and referenced as "[report]".

## 3. Honest scope/value framing

This is operator-experience and safety work, not performance work.
The win is measured in: (a) commands from fresh host to running
firewall (today: ~15 manual steps incl. dependency hunting; target: 1-2);
(b) lockout incidents on first install (today: structurally possible —
`enumerateAndRenameInterfaces()` renames the management NIC at first
daemon start; target: structurally prevented); (c) upgrade safety
(today: scp + restart with the #1869 pre-flight only in the *test*
deploy script; target: the same gate in the supported install path).

What this plan does NOT claim:

- It does not make xpf hardware-portable. AF_XDP line-rate behavior
  remains coupled to NIC driver + kernel (mlx5/i40e native XDP vs iavf
  generic). Packaging cannot fix that; pre-flight checks can only
  *report* it.
- It does not create release/CI infrastructure the project doesn't
  have. Every path below is costed for a no-CI, single-maintainer
  project; anything that presupposes a build farm (VyOS-style A/B
  squashfs) is explicitly deferred, per [report].
- A container image is NOT a viable shortcut: the claim that
  containerization sidesteps kernel-version gating was REFUTED 0-3 in
  the verification panel [report] — a containerized AF_XDP dataplane
  still depends on the host kernel >= 6.18 and host NIC drivers. cRPD
  can ship as a container because it is control-plane-only; xpf cannot.
- The safety half (M1b) is NOT small. Round-1 review established that
  the auto-rollback mechanism the design leans on is broken in service
  mode today (§4.6); fixing it plus building bootstrap mode is daemon
  work with the standard `make test-failover` gate, costed separately
  below.

If reviewers conclude the operator-experience gain is too small to
justify the churn — or that the project should stay test-script-only
until there are external users — PLAN-KILL is an acceptable verdict.

## 4. What's already shipped / partially batched

The plan composes with (and must not regress) the following existing
mechanisms:

1. **`test/incus/setup.sh provision_instance()`** — the de-facto
   in-guest provisioning recipe: Debian 13 base, sysctls
   (`bpf_jit_enable`, v4/v6 forwarding, `accept_ra=0`), package set
   (frr, strongswan + swanctl, kea-dhcp4/6, chrony, tcpdump, iproute2,
   ...), kernel from Debian unstable via pinning (to get >= 6.18),
   `init_on_alloc=0` GRUB tweak + reboot, `systemctl enable frr`,
   chrony pool-source neutering + `/etc/chrony/sources.d` for
   xpfd-managed servers. Caveats for image reuse: it also installs a
   *build* toolchain (clang, llvm, golang, build-essential,
   setup.sh:281) that a shipped image must not include, and it leaves
   the unstable apt source + kernel pin enabled (setup.sh:285-298) —
   acceptable in a long-lived test VM, unacceptable tracking state in
   a shipped appliance.
2. **`test/incus/cluster-setup.sh deploy_vm()/deploy_rolling()`** — the
   de-facto upgrade runbook: #1869/#1864 `verify-dataplane` pre-flight
   ordering invariant (push new binary to temp path, verify against
   the live kernel verifier BEFORE any stop/cleanup/replace; REJECT
   aborts with the old dataplane untouched; CPU discipline:
   `nice -n 19` + best-effort `taskset` to the complement of AF_XDP
   worker cores, cluster-setup.sh:725-763), graceful stop →
   `xpfd cleanup` → replace → `systemctl enable --now`, rolling order
   secondary-first-then-primary with a sync wait. The #1878 lock-cell
   (`with-cluster.sh`) serializes deploys on the shared cluster.
3. **`xpfd verify-dataplane` subcommand** (`cmd/xpfd/main.go:53`) —
   exit 0 PASS / 3 verifier REJECT / 1 other; loads the embedded shim
   through the real kernel verifier, anonymous maps, no pins, no
   attach.
4. **#1864 pinned-toolchain story** (`pkg/dataplane/README.md`) — the
   shim object `userspace_xdp_bpfel.o` is git-tracked and go:embed'd
   into xpfd; `make build` is toolchain-independent. This is the single
   most packaging-friendly property the project has: **the deployable
   artifact set is three static binaries + one unit file**, with
   CGO_ENABLED=0 for both Go binaries.
5. **First-boot bootstrap in the daemon** (`pkg/daemon/linksetup.go`) —
   `enumerateAndRenameInterfaces()` (linksetup.go:48) renames PCI NICs
   to vSRX names by bus order (idx 0 → fxp0; cluster: idx 1 → em0),
   writes `.link` files, cycles the link down/up on rename
   (linksetup.go:318), and `writeBootstrapFxp0Network()`
   (linksetup.go:291) drops a DHCP-only `.network` for fxp0 if absent.
   It is called **unconditionally** from `daemon.Run()` when the
   dataplane is enabled — this is both the asset (image first-boot
   works today) and the hazard (it fires at first start and
   down/up-cycles + renames the NIC carrying your SSH session, with
   no static-address preservation).
6. **`commit confirmed <minutes>`** — implemented in the configstore
   and CLI (`configstore.CommitConfirmed`, `pkg/cli/cli_config.go`;
   #1799 hardened the persist-failure path). **Round-1 review found
   two service-mode holes that make it unusable as a takeover safety
   net today**:
   - `SetCentralRollbackHandler` is registered in exactly one place —
     inside the interactive shell's `Run()` (pkg/cli/cli.go:289),
     which only executes when xpfd runs on a TTY
     (`isInteractive()`, daemon_run.go). Under systemd, a confirm
     timeout rolls back the store + persists but **never re-applies
     the rolled-back config** to networkd/dataplane/FRR.
   - `performAutoRollback` calls the handler only when
     `prevCfg != nil` (pkg/configstore/store.go:1151). On a fresh
     node, `Load()` leaves `compiled` nil, so the **first** confirmed
     commit — exactly the case this plan gates — rolls back store
     state with no reconciliation at all (Codex r1 finding 1).
   Both are named prerequisite fixes in M1b (§5 SAFE-BOOTSTRAP step
   0). The plan still reuses commit-confirmed rather than inventing a
   new mechanism — but it no longer claims the mechanism works
   off-the-shelf.
7. **HA version-awareness already exists**: the helper control
   protocol carries an explicit version
   (pkg/dataplane/userspace/protocol.go:10) and the cluster manager
   tracks peer software/protocol fields with explicit mismatch
   handling (pkg/cluster/manager.go:119,
   pkg/daemon/daemon_ha_userspace.go:902). The rolling-upgrade story
   builds on this instead of assuming compatibility (§5 HA).
8. **`make install`** — installs xpfd + cli to $(PREFIX) but not the
   helper or the unit; incomplete as a supported path, but evidence the
   intent existed.
9. **Version stamping** — `git describe` LDFLAGS already embed
   version/commit/build-time; the .deb version derives from the same
   source of truth.

## 5. Concrete design — path options

### Path A — policy-correct native Debian package (`xpf` .deb)

The artifact: one binary package `xpf` (arch amd64) built with the `dh`
sequencer at **debhelper-compat (= 13)**. Debian 13 (trixie) ships
debhelper 13.x; compat 13 gets `dh_installsystemd` auto-generated
maintainer-script snippets and `--restart-after-upgrade` semantics by
default [report].

Contents:

```
/usr/sbin/xpfd                      (CGO_ENABLED=0 Go)
/usr/sbin/xpf-userspace-dp          (Rust, --release)
/usr/bin/xpf-cli + /usr/bin/cli -> xpf-cli   (see OQ-6)
/usr/sbin/xpf-upgrade               (verify-before-unpack wrapper — PRIMARY upgrade command)
/lib/systemd/system/xpfd.service    (productized variant of test/incus/xpfd.service)
/usr/share/doc/xpf/...              (changelog, copyright, README.Debian with runbooks)
```

**Runtime dependency matrix** (grounded in what the daemon actually
execs — `grep exec.Command pkg/ cmd/`: systemctl ×10, ip ×3,
chronyc ×3, vtysh ×2, swanctl ×2, ethtool ×2, ps, journalctl,
timedatectl, ss, nft, networkctl; plus netlink syscalls that need no
binary):

| Tool / service | Debian package | Level | Failure mode if absent |
|---|---|---|---|
| frr (`vtysh`, `systemctl reload frr`, managed frr.conf section) | `frr` | **Depends** | routing config apply fails; core function broken |
| systemd + networkd + `systemctl`/`networkctl`/`journalctl`/`timedatectl` | `systemd` (networkd included on Debian) | **Depends** (effectively satisfied everywhere; the real assertion is *networkd is the active network manager* — a runtime check, not metadata; OQ-3) | interface management broken |
| `ip`, `ss` | `iproute2` (Priority: important) | **Depends** (explicit, costs nothing) | link/route/diag ops fail |
| `nft` | `nftables` | **Depends** | the nft-rendered paths fail at apply |
| `ethtool` | `ethtool` | **Depends** | RSS indirection (D3) + ntuple paths fail on mlx5 |
| `swanctl` (`pkg/ipsec/ipsec.go:31`) | `strongswan-swanctl` | Recommends | IPsec features error at commit/use; rest unaffected |
| Kea units/files (`pkg/dhcpserver/dhcpserver.go:75`) | `kea-dhcp4-server`, `kea-dhcp6-server` | Recommends | DHCP-server feature unavailable |
| `chronyc` + sources.d | `chrony` | Recommends | NTP management feature unavailable |
| `ps` | `procps` (essential-adjacent) | — (present on any Debian) | diagnostics only |
| `useradd`, `chpasswd` (login/root-auth config, `pkg/daemon/daemon_system.go:714,784`) | `passwd` (Essential: yes on Debian) | — (declared for completeness; no metadata needed) | system login config fails |
| `id`, `chown`, `tail` | `coreutils` (Essential) | — | n/a |
| `systemctl restart rsyslog` (syslog file destinations, `daemon_system.go:644`) | `rsyslog` | Recommends | syslog-to-file feature degraded (journal still captures) |
| `scp` (flow-archival transfer, `daemon_flow.go:345`) | `openssh-client` | Recommends | archival transfer feature unavailable |
| `ping`, `traceroute` (API/gRPC diagnostics, `pkg/api/system.go:126`, `pkg/grpcapi/server_diag.go:141`) | `iputils-ping`, `traceroute` | Recommends (ping), Suggests (traceroute) | operational diag RPCs degraded |

Policy reasoning per Debian Policy §7.2 [report]: Depends = "will not
operate at all / postinst needs it"; Recommends = "found together in
all but unusual installations" — the OPNsense configd precedent
[report] validates the existing xpf design: the **daemon** renders
companion configs at runtime; the package must NOT write
frr/strongswan/kea config in postinst. Degraded behavior for each
Recommends is a documented feature-absence, not a crash (matching
today's runtime behavior where the daemon reports the exec failure at
apply time).

Conffile/state handling:

- `/etc/xpf/` is **not** shipped as conffiles. `xpf.conf` is
  operator/machine state (like `/etc/frr/frr.conf`), not a package
  default. Ship nothing under `/etc/xpf`; `postinst` does
  `mkdir -p /etc/xpf` (0750). `postrm purge` removes it. The
  configstore DB (`/etc/xpf/.configdb`) and `node-id` are never
  package-managed. This sidesteps the conffile-prompt-on-upgrade trap
  entirely.
- `xpfd.service` IS a normal packaged file (in /lib, not /etc), so
  upgrades replace it cleanly; operator overrides go in
  `/etc/systemd/system/xpfd.service.d/*.conf` drop-ins (document the
  CPUAffinity recipe from docs/712-cpu-pinning-recipe.md as a drop-in
  example).

**Upgrade mechanism — two tiers (revised per round 1):**

- **PRIMARY (and the only supported path for HA nodes):
  `xpf-upgrade`**, a shipped wrapper that preserves the full #1869
  ordering invariant: fetch/locate the candidate .deb → `dpkg-deb -x`
  to a temp dir → run the extracted binary's `verify-dataplane` under
  `nice -n 19` + best-effort `taskset` to the complement of the
  AF_XDP worker cores (porting the proven CPU-discipline logic from
  cluster-setup.sh:725-763, including the offline-CPU
  false-reject guard) → only on PASS, `apt install ./xpf_<ver>.deb`.
  REJECT aborts with the old binary still installed AND the old
  process still running — full #1869 strength.
- **SECONDARY (last-chance dpkg guard): the postinst gate.** dh's
  `--restart-after-upgrade` snippet (compat-13 default) restarts in
  postinst; our check precedes the `#DEBHELPER#` token:

```sh
# debian/xpf.postinst (sketch)
if [ "$1" = "configure" ] && [ -n "$2" ]; then   # upgrade, not fresh install
    if ! nice -n 19 /usr/sbin/xpfd verify-dataplane; then
        echo "xpf: new dataplane object REJECTED by the running kernel verifier." >&2
        echo "xpf: NOT restarting xpfd; the old daemon process keeps forwarding." >&2
        echo "xpf: recover with: apt install xpf=<previous-version>  (see README.Debian)" >&2
        exit 1   # package left half-configured; old PROCESS still runs
    fi
fi
#DEBHELPER#
```

  Stated consequences (not hidden): (a) dpkg has already replaced the
  on-disk binary by postinst time — a crash/reboot before remediation
  boots the rejected binary, which lands in config-only mode
  (management-reachable, not forwarding; the daemon survives a shim
  load failure). (b) A failed postinst leaves the package
  half-configured, which **blocks all subsequent apt/dpkg operations**
  (`dpkg --configure -a` re-runs and re-fails) until the operator
  installs the previous version — on a box with unattended-upgrades
  this wedges apt, which is the intended attention-forcing behavior
  but must be documented with the one-line recovery. (c) The bare
  postinst run gets `nice -n 19` but not the taskset complement (no
  helper-PID discipline guaranteed in maintainer-script context);
  the accepted cost is up to ~17s of one low-priority core on a
  REJECT walk — `xpf-upgrade` is the path that carries the full
  discipline.
- **Cleanup-on-upgrade**: the package restart path runs stop→start
  with NO `xpfd cleanup`, intentionally. `dataplane.Cleanup()` is
  documented as decommissioning-only ("not during normal restarts",
  pkg/dataplane/loader.go:1160-1162); the cleanup call in
  `deploy_vm()` is bpfrxd-era migration hygiene plus
  belt-and-braces for dev builds, not a binary-upgrade requirement.
  §9 includes an explicit upgrade-without-cleanup test to convert
  this from assertion to verified contract; if it fails, postinst
  gains a guarded `xpfd cleanup` between the dh-generated stop and
  start (mechanism exists, decision is test-driven).
- **/usr/local migration**: every existing install has
  `/usr/local/sbin/{xpfd,cli}` (+ helper), which shadow /usr/sbin
  binaries in PATH (documented failure class:
  feedback_cli_binary_path). postinst detects and removes (with a
  log line) `/usr/local/sbin/xpfd`, `/usr/local/sbin/cli`,
  `/usr/local/sbin/xpf-userspace-dp`, `/usr/local/sbin/bpfrx*` —
  mirroring the deploy scripts' bpfrxd migration block.
- Kernel >= 6.18 gating: deb metadata cannot express kernel minimums
  [report]. Three layers: (1) `preinst` warning when
  `uname -r` < 6.18 (warn, don't fail — chroot/image bakes run
  maintainer scripts under the build host's kernel; OQ-2); (2) daemon
  startup already fails the shim load on old kernels → config-only
  mode with a clear log; (3) `xpfd verify-dataplane` documented as
  the definitive check.
- Rollback: `apt install xpf=<old-version>` with versioned .debs kept
  in the repo/dist directory. Document; no new mechanism.

Build/release mechanics for a no-CI project: `debian/` directory in
tree + a `make deb` target (`dpkg-buildpackage -us -uc -b`). Signing/
hosting: a static apt repo via `reprepro`/`aptly` on GitHub Pages /
Releases, signed with a maintainer GPG key — the Tailscale trust-model
endpoint (signed-by apt source) without CI [report]. Hosting can be
deferred (Path A is useful with bare .deb artifacts attached to GitHub
Releases on day one). Repo/Pages size limits are assumptions-to-verify
during M3, not facts.

Rust note: `cargo build --release` for the helper happens on the
maintainer's machine as today; the .deb packages the resulting binary.
Debian-archive-grade source packaging (dh-cargo + Go vendoring) is NOT
attempted; the .deb is a **binary distribution vehicle**, stated
openly in debian/README.source.

**Cost (split per round 1): M1a (.deb alone, daemon behavior
unchanged) ~3-5 focused days** — debian/ skeleton, dependency matrix,
postinst gate + migrations, xpf-upgrade wrapper, unit productization,
manual test matrix on the standalone VM. M1a is shippable without M1b
but is labeled expert-preview until M1b lands (it makes installation
easier without yet making first-boot safe; the README states this).
Risk: LOW — additive; test scripts untouched.

### Path B — Tailscale-style `install.sh`

A single POSIX-sh script following the verified Tailscale structure
[report]: distro detection (Debian 13+ only at first; refuse others
with a clear message), installs the GPG keyring to
`/usr/share/keyrings/xpf-archive-keyring.gpg`, writes a `signed-by`
apt source, `apt-get install xpf`, then **prints** the next step and
exits. All logic wrapped in `main()` called at file end
(truncated-pipe safety, per the Tailscale script).

The non-negotiable property (issue + [report]): the script NEVER
activates the dataplane. Ending message:

```
xpf installed. The daemon is running in bootstrap mode and has NOT
taken over any network interfaces.
Next: designate the protected management interface and commit your
first configuration:
  xpf-cli
  > configure
  > set system management-interface <iface>
  > ... interfaces / zones / policies ...
  > commit confirmed 5
```

Hard dependency: Path B requires Path A's .deb **and** a signed apt
repo — it is sugar over A, not an alternative artifact. A variant that
scp's raw binaries was considered and rejected: it would re-create
today's four-loose-artifacts problem with a bow on it.

**Cost: ~1-2 days** once A + repo hosting exist. Risk: LOW. Defer
until there is at least one external operator who asks for it.

### Path C — vSRX-style prebuilt qcow2 appliance image (operator-pinned)

#### C.1 What vSRX itself does (the model to clone)

Distribution: Juniper publishes vSRX (vSRX 3.0) as hypervisor-specific
prebuilt images — `.qcow2` for KVM, OVA/VMDK for VMware, plus
marketplace images (AWS AMI, Azure). The KVM flow is: download
qcow2 → `virt-install` (or virsh define with a libvirt XML) with
CPU/RAM minimums and N virtio/SR-IOV vNICs → boot. Everything is
baked: Junos kernel, RE control plane (rpd — FRR's analogue), the
flowd/vFP dataplane, all libraries. There is no dependency matrix
because there is nothing to install — the image IS the dependency
closure. This is precisely the property that kills xpf's "undeclared
externals" problem at the root, and the ONLY complete answer to the
kernel >= 6.18 requirement (the kernel ships inside the artifact).

Interface contract: the **first vNIC is always fxp0**, out-of-band
management; subsequent vNICs map to revenue ports ge-0/0/0..n in
attach order. xpf already clones this exact convention in
`assignName()` (idx 0 → fxp0, PCI bus order) — xpf's daemon was
*designed* for the appliance-image model; the test VM proves the
first boot works unattended.

Day-0 configuration, in increasing automation order (all of which vSRX
supports and xpf should mirror):

1. **Console wizard / factory default**: vSRX boots a factory-default
   config — fxp0 DHCP, root login on console, management reachable.
   xpf equivalent: bootstrap mode (fxp0 DHCP via the lifeline writer,
   CLI on console) — M1b's bootstrap mode IS the factory-default
   state.
2. **Config-drive / CD-ROM day-0 file**: vSRX on KVM/OpenStack accepts
   a bootstrap Junos config supplied on an attached ISO/config-drive,
   applied on first boot. xpf equivalent: first-boot logic that, when
   the no-committed-config predicate (§SAFE-BOOTSTRAP) holds, probes
   for a labeled volume / cloud-init NoCloud seed containing
   `xpf.conf` (+ optional `node-id`), copies it in, and lets the
   normal commit-on-boot path run. A day-0-provisioned config is an
   explicit operator artifact, so it bypasses the first-commit
   confirm gate (the operator chose the config before boot; there is
   no interactive session to lock out — stated as a deliberate
   semantic, OQ-8).
3. **cloud-init user-data**: vSRX cloud images consume user-data
   carrying Junos config. xpf equivalent: base the image on Debian
   genericcloud (cloud-init preinstalled); a `write_files` stanza
   dropping `/etc/xpf/xpf.conf` is sufficient with zero xpf-side
   code. **Required sealing decision (round-1 S5): cloud-init is
   itself a network manager** — it generates and applies network
   config for detected NICs on first boot, i.e. a second actor
   fighting xpfd's takeover and the lifeline `.network`. The image
   ships with cloud-init network configuration disabled
   (`/etc/cloud/cloud.cfg.d/99-xpf.cfg`: `network: {config:
   disabled}`), keeping datasources for write_files/user-data only.

Upgrade semantics (the part the operator asked about): vSRX supports
both (a) in-place Junos package upgrade (`request system software
add`) inside the VM, and (b) **replace-image**: deploy a new VM from
the new qcow2, carry the configuration over, swap traffic. In cloud
deployments and HA pairs, (b) is the norm — config is small,
declarative, and version-portable, so the VM is cattle. xpf's
analogue maps cleanly:

- (a) in-place = `xpf-upgrade` / `apt upgrade xpf` inside the
  appliance **iff the image consumes Path A's .deb** — one more
  reason image-bake sits on top of the deb, not parallel to it.
- (b) replace-image = deploy new VM, copy `/etc/xpf/xpf.conf` (+
  `node-id`; text config alone is sufficient and more
  version-portable than `.configdb`), swap. For HA pairs this is
  *exactly* `deploy_rolling()` at VM granularity: replace the
  secondary VM, wait for session sync, fail over, replace the
  primary. Kernel + userspace move as one atomic, tested unit — the
  decisive operator argument for C over A-alone.
- VyOS-style A/B squashfs-with-rollback is the gold standard [report]
  but presupposes image-build infra and a boot-loader story;
  explicitly deferred. Replace-image + hypervisor snapshots gives 80%
  of the rollback value for ~0 engineering.

#### C.2 xpf image-bake pipeline (promoting setup.sh — honestly)

Round-1 corrections adopted: `setup.sh provision_instance()` is a
strong **in-guest provisioning recipe**, not "80% of a shippable
image". What it provides: package set, sysctls, kernel acquisition,
GRUB tuning, service enablement. What a shippable image additionally
needs (none of which exists): build-toolchain exclusion, removal of
the unstable apt source + pin after kernel install (a shipped
appliance must not track unstable; pin the exact installed kernel
package, prefer trixie-backports when it carries >= 6.18 — OQ-2),
sealing (machine-id truncate, ssh host-key removal, cloud-init clean
+ network-config disable, apt clean, log purge, free-space zeroing),
factory-default state (`rm -rf /etc/xpf/*`, xpfd enabled), image
extraction/conversion, signing, size budget, and boot validation
OUTSIDE incus.

Pipeline shape:

```
build host                          bake VM (incus, local)
──────────                          ─────────────────────
make deb        ────────────────►   incus launch images:debian/13 xpf-bake --vm
                                    ├─ provision-lib.sh: sysctls, GRUB, kernel policy
                                    ├─ apt install ./xpf_<ver>_amd64.deb
                                    │    (pulls Depends; Recommends pull strongswan/kea/chrony)
                                    ├─ remove unstable source + re-pin exact kernel
                                    ├─ seal (checklist above)
                                    └─ incus stop
                                              │ export
                              raw/qcow2 root disk extracted from the
                              incus VM export, then:
                              qemu-img convert -O qcow2 → xpf-<ver>.qcow2
                                              ├── minisign/GPG detached signature
                                              └── incus image tarball (incus users)
```

Storage-driver correction (Codex r1 finding 6): under the common
`dir` storage pool (which setup.sh itself creates, setup.sh:74), incus
VM root disks are **raw** block files, not qcow2 — the plan does not
assume qcow2-under-the-hood anywhere; `qemu-img convert` from
whatever the export contains is the explicit, driver-independent
step. M2 starts with a half-day **spike** validating the full
export→convert→virt-install boot loop on a clean KVM host (no incus)
before any further investment; the spike's acceptance test is the M2
gate (Codex r1 finding 8: the operator-pinned path gets a concrete
spike, not an indefinite "after packaging" slot).

Implementation shape: `scripts/bake-image.sh` sharing provisioning
logic with `test/incus/setup.sh` via a sourced
`test/incus/provision-lib.sh` (promote, don't fork — the test env and
the bake cannot drift; the refactor must be behavior-preserving for
the test env, §9).

First-boot contract of the shipped image (the vSRX clone):

1. vNIC #1 (lowest PCI bus) → fxp0, DHCP — existing
   `enumerateAndRenameInterfaces()` + lifeline writer.
2. No committed config (predicate, §SAFE-BOOTSTRAP) → bootstrap mode:
   management reachable (ssh on fxp0 DHCP address + hypervisor
   console), CLI available, takeover NOT armed.
3. Day-0 config via console, NoCloud seed, or config-drive (C.1).
4. Credentials: no default password. Console (always available on a
   hypervisor) root login per Debian default policy + cloud-init
   ssh-key injection for headless; OQ-4.

Honest costs unique to C: image hosting (GitHub Releases per-file
limit and the sealed-image size — assumptions-to-verify in the M2
spike; a compressed sealed Debian-13 qcow2 plausibly lands well under
1.5 GiB but this is measured, not asserted); signing (minisign — the
VyOS-validated lightweight choice [report]); a rebuild cadence for
Debian security updates baked into the image (document "the image is
a bootstrap artifact; apt handles security updates in place" to avoid
a re-bake treadmill); test matrix (virt-install/KVM + incus at
minimum, labeled accordingly).

**Cost: ~2-3 weeks** (spike ½ day; provision-lib refactor + bake
script ~1 week; sealing + first-boot + day-0 validation ~1 week;
signing/docs the rest), ASSUMING the M1a .deb exists. Risk: MEDIUM —
sealing and foreign-hypervisor first-boot have long-tail gotchas
(machine-id, NIC enumeration on real hardware, console= kernel args);
bounded by the spike-first ordering.

### Path D — staged hybrid (recommended)

Sequencing, each stage independently shippable and valuable:

- **M1a — Path A .deb** (~3-5 days): the artifact every other path
  consumes. Shippable alone as expert-preview.
- **M1b — SAFE-BOOTSTRAP daemon work** (~1-2 weeks incl. the two
  commit-confirmed prerequisite fixes, bootstrap mode, lifeline
  writer, gate predicate, tests, `make test-failover`): the
  highest-safety-leverage item [report ranks the TNSR/Junos
  composite #3]; must land before any path is *promoted* beyond
  expert-preview — making it easier to install a foot-gun is negative
  progress.
- **M2 — Path C image bake consuming the M1a .deb** (~2-3 weeks,
  spike-gated): operator-pinned priority; the only complete kernel
  >= 6.18 answer.
- **M3 — Path B install.sh + signed apt repo** (~1-2 days + repo
  setup): deferred until external demand.

M1a and M1b can proceed in parallel (disjoint surfaces: debian/ tree
vs pkg/daemon + pkg/configstore). This is the issue's direction D made
concrete; it matches the [report] ranking (deb #1 ROI, installer #2,
safety #3, image deferred — the deferral overridden for xpf by the
operator's appliance use-case, with the M2 spike as the
cheap-falsification step).

### SAFE-BOOTSTRAP (load-bearing, common to all paths)

Threat: first daemon start on a remote box renames ALL PCI NICs
(`enumerateAndRenameInterfaces()` runs unconditionally from
`daemon.Run()` when the dataplane is enabled), cycles links down/up
during rename (linksetup.go:318), writes a DHCP-only fxp0 bootstrap
`.network` (no static-address preservation), and — once a config is
applied — brings unconfigured interfaces down and strips their
addresses (`compiler_iface.go:1128-1149`, networkd
`ActivationPolicy=always-down`). If the management NIC is not idx 0,
or its addressing was static, or DHCP re-acquisition fails post-
rename, the operator is locked out. Today this is mitigated only by
convention (test VMs are wired so mgmt is idx 0 / DHCP).

Design (TNSR protected-mgmt + Junos commit-confirmed, composed with
the existing fxp0 bootstrap). Step 0 is prerequisite plumbing; steps
1-4 are the mechanism.

0. **Prerequisite fixes (the two round-1 holes, hardened per round
   2 — M1b items 1-2):**
   - **Auto-rollback becomes a daemon-owned, applySem-serialized
     transaction** (Codex r2-1). A plain callback wired to
     `d.applyConfig` is NOT sufficient: `performAutoRollback`
     mutates `s.active`/`s.compiled` BEFORE invoking the callback
     (store.go:1114→1146), and `d.applyConfig` only holds `applySem`
     around the apply — a concurrent commit could interleave between
     store promotion and rollback apply, leaving store=new-commit
     while kernel=rollback, violating the repo's commit→apply
     atomicity contract (pkg/daemon/apply_serialize_test.go,
     pkg/configstore/README.md §serialization). M1b therefore gives
     the daemon ownership of the whole rollback transaction: the
     confirm timer fires into a daemon-registered executor that
     acquires `d.applySem` FIRST, then performs store promotion +
     reconcile apply inside the same critical section (exact
     configstore hook shape — executor callback vs promote-deferral —
     is an /engineer-phase decision; the plan-level requirement is
     "promotion and apply are atomic under applySem", with a
     serialization test alongside apply_serialize_test.go). The
     interactive shell's existing handler reduces to TTY
     notification.
   - **The `prevCfg == nil` (first-commit) case rolls back to
     bootstrap state via `enterBootstrapMode` (step 4a), not via a
     normal apply of an empty tree** — and it **persists the
     no-committed-config state** (AGY r2 finding 2): the rollback
     must NOT write an empty *committed* tree to the configstore,
     or a daemon restart after rollback would classify
     committed-empty → NOT-bootstrap and perform a full takeover on
     an empty config. Mechanism: the store distinguishes
     "never-successfully-committed" from "operator committed empty"
     (a committed-generation marker / absence of an active record —
     /engineer picks the representation, constrained by the #1799
     persist-failure semantics which must be preserved). With these
     fixes, "commit confirmed" becomes a real safety net in service
     mode; without them it is a placebo (round-1's central verdict).
1. **Protected management interface designation** (TNSR model
   [report]). New config leaf `system management-interface <name>`
   (schema: `pkg/config/schema.go` setSchema; default `fxp0`). The
   **enforced protected set** is the union of: (a) the leaf value
   when present, (b) the default `fxp0`, and (c) the
   lifeline-recorded interface from first start (persisted at
   `/etc/xpf/lifeline-interface`, written by step 2) — with (b)/(c)
   effective even when the active config is empty, absent, or rolled
   back. **The lifeline record is keyed by PCI bus address (+ MAC as
   tiebreaker for non-PCI NICs), NOT by interface name** (AGY r2
   Critical): a name-keyed record goes stale the moment the takeover
   renames the device (e.g. recorded `eth1` becomes `em0`), silently
   dropping it from the protected set exactly when rollback needs
   it. Protected-set evaluation resolves the recorded PCI address to
   the device's *current* name at reconcile time. Enforcement lives in the networkd reconcile + unmanaged-
   interface strip paths (compiler_iface.go:1128-1149 and the
   `.network` writer): a protected interface is never marked
   always-down, never address-stripped, never bound into the
   dataplane. This placement — outside the config tree — is what
   makes rollback-to-bootstrap safe (round-1 S2/AGY-3): the
   designation cannot be removed by the very rollback it protects.
   Commit-check policy for zone-assigning the protected interface:
   OQ-1.
2. **Lifeline preservation at first start.** When the
   no-committed-config predicate holds (below), before any rename:
   xpfd identifies the interface carrying the current IPv4/IPv6
   default route (detection details OQ-5) and records its PCI bus
   address + MAC to `/etc/xpf/lifeline-interface` (name-independent,
   step 1). If that interface is the one that
   would become fxp0 (idx 0): snapshot its *current* addressing into
   the bootstrap `.network` — `Address=`/`Gateway=`/`DNS=` lines when
   static, plain DHCP when DHCP — so the rename's link cycle restores
   the same reachability (this replaces today's DHCP-only
   `writeBootstrapFxp0Network()`). If the default-route interface
   would NOT become fxp0: **no rename, no link cycle, no takeover of
   anything** — log loudly, stay in bootstrap mode, require the
   operator to either re-wire or set `system management-interface` +
   commit. Diff surface: one guard before the rename loop in
   `enumerateAndRenameInterfaces()` + the lifeline-aware bootstrap
   writer.
3. **Bootstrap mode, defined** (this mode does not exist today —
   round-1 S1/Codex-2; it is new M1b work): active when the
   no-committed-config predicate holds. In bootstrap mode the daemon:
   runs the gRPC/REST/CLI control surfaces as normal; performs NO PCI
   rename (beyond the lifeline-gated step 2 path), NO link down/up
   cycles, NO networkd takeover writes (except the lifeline
   `.network`), NO AF_XDP attach / dataplane load, NO FRR managed-
   section writes. Exit from bootstrap mode happens exactly once, at
   the first successful confirmed commit (step 4), which then runs
   the full normal startup reconcile (rename, networkd, dataplane).
   **No-committed-config predicate** (round-1 Codex-3), exact:
   bootstrap mode iff the configstore has no active committed
   config after `Load()` + `bootstrapFromFile()` resolve. The five
   cases: absent `.configdb` + no `xpf.conf` → bootstrap; absent DB +
   preseeded `xpf.conf` that imports cleanly → NOT bootstrap (this is
   every existing test/cluster deploy — zero behavior change); absent
   DB + `xpf.conf` import FAILURE → bootstrap + loud error (today:
   daemon runs with empty config and takes over interfaces anyway —
   strictly worse); empty active DB where the empty tree was a real
   operator commit → NOT bootstrap (they meant it; the protected set
   still shields mgmt); never-successfully-committed (including the
   post-rollback-from-first-commit state, which persists as
   no-committed-config per step 0 — AGY r2 finding 2) → bootstrap;
   corrupt DB → bootstrap + loud error, never takeover-on-garbage.
   The committed-empty vs never-committed distinction requires the
   step-0 committed-generation marker. The predicate is computed
   once at startup and on rollback-to-bootstrap, and is stable
   across daemon restarts (a restart after a timed-out first commit
   stays in bootstrap mode).
4. **First takeover gated by commit-confirmed** (Junos model; reuses
   `configstore.CommitConfirmed` after step-0 fixes). When the
   current mode is bootstrap, a plain `commit` of an interface-owning
   config is refused with guidance: `first commit on this system must
   be 'commit confirmed <minutes>' (interface takeover can cut off
   management; the system rolls back automatically unless
   confirmed)`. On confirm-timeout, the daemon-owned rollback
   transaction (step 0) executes `enterBootstrapMode` (4a). Escape
   hatch `commit no-confirm` for console installs; day-0-provisioned
   configs (image path C.1) bypass the gate by design — the
   predicate already resolves NOT-bootstrap before the first
   interactive session exists. Gate scope (interface-claiming commits
   vs any first commit): OQ-7. Note the gate is precisely "first
   commit on a fresh system", not "first takeover": an operator who
   exits bootstrap via `commit no-confirm` of a trivial config gets
   no gate on later interface-claiming commits — consistent with
   Junos, where commit-confirmed is operator discipline after day 0
   (SMR r2 N3).

4a. **`enterBootstrapMode` — an explicit cleanup sequence, not a
   plain apply of an empty tree** (Codex r2-2 + SMR r2 N2). A failed
   first takeover leaves real state behind: xpf networkd files,
   FRR managed-section content, VRRP instances, a running helper
   with AF_XDP sockets, and renamed NICs. A normal
   `applyConfig(empty)` is the wrong tool — the userspace apply path
   ensures the helper process exists
   (pkg/dataplane/userspace/manager.go:641), i.e. it would
   *resurrect* the dataplane bootstrap mode promises not to run.
   The sequence, in order: (1) remove xpf-written `.network`/`.link`
   takeover files EXCEPT the lifeline `.network` and the `.link`
   files (see renames-persist below), `networkctl reload`; (2) clear
   the FRR managed section (pkg/frr ApplyFull clears on empty
   content, manager.go:211) and remove VRRP instances
   (pkg/vrrp/manager.go:207 removes undesired instances); (3) stop
   the dataplane helper / detach AF_XDP (the inverse of startup
   load; exact teardown call audited at /engineer time — any
   subsystem that cannot shrink to zero gets its residue enumerated
   and accepted explicitly); (4) re-assert bootstrap-mode
   suppressions for the remainder of the daemon's lifetime.
   **Renames persist deliberately**: kernel NIC names and `.link`
   files are NOT reverted by rollback (reverting would link-cycle a
   degraded box for cosmetic benefit); post-rollback bootstrap state
   = renamed NICs + lifeline `.network` (matching the post-rename
   name via the PCI-keyed record) + zero config-driven claims. T1's
   assertions are therefore reachability- and claims-based, never
   name-restoration-based (SMR r2 N1).
5. **Composition with packaging**: the .deb/install.sh/image never
   decide takeover — they install + enable a daemon whose *own* gate
   is the predicate above. The safety property lives in exactly one
   place (the daemon) and holds identically for apt installs, image
   first boot, and the test scripts (which pre-seed config + node-id
   and therefore never enter bootstrap mode — no test-flow
   regression).

### HA-pair rolling upgrade, per path

- Invariant (all paths): **verify-dataplane gates every upgrade**
  before the running dataplane is disturbed (#1869). Order:
  secondary first, wait for session sync, then primary —
  `deploy_rolling()` is the reference implementation. On HA nodes the
  supported command is `xpf-upgrade` (full verify-before-unpack);
  bare `apt upgrade` is documented as the degraded path with the
  postinst last-chance gate.
- **Mixed-version policy (round-1 Codex-7), stated as release
  policy**: (a) daemon + helper always ship and restart as one
  package/unit — same-node coupling is structural (xpfd spawns the
  helper, pkg/dataplane/userspace/process.go; control protocol
  version pkg/dataplane/userspace/protocol.go:10). (b) Across the
  pair, release N must interoperate with N-1 for: session-sync,
  config-sync, heartbeat, and VRRP — the cluster already carries
  peer software/protocol fields and explicit mismatch handling
  (pkg/cluster/manager.go:119, daemon_ha_userspace.go:902); the
  policy makes "mismatch = degrade gracefully + alarm, never split-
  brain" a tested contract instead of an accident. (c) Text
  `xpf.conf` from N-1 must commit cleanly on N (de-facto true —
  precedent: the #1525 reject machinery retained one release cycle
  precisely for stored-config rolling upgrade; now written down).
  Acceptance test: one mixed-version soak (N-1 primary / N
  secondary, session sync + failover) on the LOCAL legacy cluster
  before tagging a release — manual, documented in the release
  runbook (docs/upgrade-policy.md, new).
- Path A: runbook in README.Debian + docs/upgrade-policy.md: node1
  `xpf-upgrade ./xpf_N.deb`, verify `show chassis cluster status`
  sync, then node0. apt never coordinates across nodes — and should
  not; CLI-orchestrated ISSU stays out of scope.
- Path C: replace-image per node in the same order; config carry-over
  via `/etc/xpf/xpf.conf` + `node-id`. The new VM joins as secondary,
  syncs sessions, takes over (~60 ms VRRP failover budget unchanged),
  then the peer is replaced. Kernel upgrades ride along atomically —
  the unique win of this path.
- Path B: identical to A (it installs A's deb).

## 6. Operator-facing surface preservation

(API-preservation analogue for an ops-surface plan.)

- `make build` / `build-ctl` / `build-userspace-dp` / `make install`
  unchanged. `make deb` and `make image` are additive.
- `test/incus/setup.sh` and `cluster-setup.sh` flows keep working
  unchanged; the provision-lib refactor must be behavior-preserving
  for the test env (same packages, same sysctls, same kernel pin).
  The cluster deploy keeps its push-binaries model (it deploys
  unreleased build artifacts; packaging is irrelevant there) and its
  #1878 lock-cell + #1869 preflight exactly as-is.
- Daemon: hosts WITH a committed or cleanly-preseeded config (every
  existing deployment, all test VMs, the cluster) resolve
  NOT-bootstrap and see no behavior change from SAFE-BOOTSTRAP other
  than the protected-set exemption (which only *prevents* downing
  fxp0/designated mgmt — a strict safety widening; flagged for
  reviewer scrutiny in OQ-1). The takeover gate and lifeline logic
  apply only on the bootstrap-predicate path.
- `xpfd verify-dataplane`, `xpfd cleanup`, `version` subcommands
  unchanged (postinst + xpf-upgrade become new callers).
- CLI grammar: additive leaves only (`system management-interface`;
  possible `commit no-confirm` — OQ-1/OQ-7).

## 7. Hidden invariants the change must preserve

1. **#1869 ordering invariant**: nothing may stop/replace a working
   dataplane before the new object passes the live kernel's verifier.
   `xpf-upgrade` preserves it fully; the postinst path is a
   documented, weaker last-chance guard (old process keeps running;
   disk already swapped) — never presented as equivalent.
2. **Interface lifeline**: at no point between "fresh boot" and
   "first confirmed commit" may the management path depend on an
   un-renamed kernel NIC name or an address the daemon is about to
   remove. The lifeline `.network` survives `networkctl reload`,
   daemon restarts, and rollback-to-bootstrap.
3. **Protected-set enforcement is config-independent**: the
   designation (leaf ∪ fxp0 ∪ lifeline-record) must be effective
   under empty, absent, corrupt, and rolled-back configs — it lives
   in the reconcile code path, not (only) in the config tree.
4. **RETH `.link` semantics** (`MACAddress=` vs `OriginalName=`,
   `ensureRethLinkOriginalName()`), `KeepConfiguration=static` VIP
   preservation, and the FPC-7 node-1 naming must be untouched — the
   SAFE-BOOTSTRAP diff is confined to the bootstrap-predicate path
   and the fxp0 bootstrap writer.
5. **Shim artifact discipline (#1864)**: the .deb embeds whatever
   `userspace_xdp_bpfel.o` is tracked in git; `make deb` must NOT run
   `make generate`. Pin-bump procedure unchanged.
6. **Config-only-mode survivability**: daemon startup with a rejected
   shim must keep yielding a management-reachable config-only daemon
   (the floor under the postinst weakening).
7. **Helper/daemon version coupling**: xpfd and xpf-userspace-dp ship
   and restart as a unit (single .deb, single service restart);
   nothing in the plan may let apt restart one without the other.
8. **Rollback semantics elsewhere unchanged**: the step-0 handler
   registration must not alter HA SyncApply, the #1817 confirmGen
   guard, or the #1799 persist-failure behavior in configstore.
9. **Cluster test env hygiene**: nothing in this plan touches the
   shared loss cluster; image-bake experiments and mixed-version
   soaks run on local incus only.
10. **No new hot-path code**: entirely control-plane/packaging work;
    zero dataplane-loop changes.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (existing deployments) | MED | M1b touches daemon startup, configstore rollback, and the unmanaged-interface strip path. Mitigations: the bootstrap predicate resolves NOT-bootstrap for every existing deployment (explicit case matrix, §5); the protected-set change is a strict safety widening; `make test-failover` gates the daemon changes; the five-case predicate gets unit tests. The round-2 serialization hazard (store promotion vs concurrent commit) is addressed by design — the rollback transaction owns applySem across promotion + apply — and carries a dedicated test |
| Lockout / safety regression | LOW (net improvement) | The plan's purpose; riskiest sub-items are the synthesized-bootstrap rollback target and the lifeline static-snapshot writer — both carry named must-pass tests |
| Packaging correctness | MED | dpkg maintainer-script edge cases (half-configured recovery, purge vs remove, masked service, unattended-upgrades) — bounded by the manual test matrix; no CI to catch drift |
| Image first-boot portability | MED | sealing, cloud-init network ownership, NIC enumeration on real hardware, console args; bounded by the spike-first M2 gate and the KVM/incus-only validation label |
| Architectural mismatch | LOW | All mechanisms reuse existing primitives (commit-confirmed + fixes, verify-dataplane, linksetup, provision script); no new daemons, no new state stores |
| Scope creep | MED-HIGH | Classic packaging rabbit holes (source-package purity, A/B images, repo automation, cloud-init modules, ISSU) fenced in §10; reviewers should police re-entry |

## 9. Test plan

- **Unit/Go** (`make test`, 30 packages green): schema test for
  `system management-interface`; linksetup tests for the lifeline
  writer (static snapshot vs DHCP pass-through), the
  default-route-not-idx-0 refusal, and the NOT-bootstrap fast path;
  five-case predicate test (absent DB±xpf.conf, failed import, empty
  active vs never-committed, corrupt DB); configstore/daemon tests
  for the daemon-owned rollback transaction: a
  rollback-vs-concurrent-commit serialization test alongside
  apply_serialize_test.go (store promotion + apply atomic under
  applySem), the `prevCfg==nil` → enterBootstrapMode path
  (service-mode, no TTY), restart-after-timed-out-first-commit stays
  bootstrap (predicate stability), PCI-keyed lifeline resolution
  across a rename; first-commit confirm-gate test.
- **Named must-pass integration tests** (standalone incus VM):
  (T1) *rollback-restores-lifeline*: first `commit confirmed 1` with
  a deliberately broken config, do not confirm → after timeout,
  management reachable on the lifeline address, bootstrap `.network`
  intact, daemon in bootstrap mode; run twice: DHCP mgmt and static
  mgmt. (T2) *upgrade-without-cleanup*: package upgrade via restart
  (no `xpfd cleanup`) → dataplane loads, sessions resume; converts
  the §5 cleanup assertion into contract.
- **Package matrix (standalone incus VM, fresh Debian 13)**: fresh
  install → bootstrap mode, fxp0 DHCP, ssh reachable, dataplane not
  armed; first `commit confirmed` + confirm → takeover, traffic;
  `xpf-upgrade` with good .deb → PASS, restart, sessions resume;
  `xpf-upgrade` with the preserved #1864 incident object → REJECT,
  nothing replaced; bare `apt upgrade` with bad object → postinst
  FAIL, old process forwarding, `apt install xpf=<old>` recovers and
  un-wedges dpkg; remove vs purge; preinst kernel warning on 6.12;
  /usr/local shadow removal verified.
- **Image (M2)**: spike acceptance first (export→convert→virt-install
  boot on clean KVM, no incus); then bake → first-boot contract (fxp0
  DHCP, console login, NoCloud day-0 seed applied, cloud-init network
  config confirmed disabled); replace-image upgrade with config
  carry-over on the standalone topology.
- **HA**: `make test-failover` for any commit touching daemon
  startup/linksetup/configstore (standing rule); rolling-upgrade
  runbook + one mixed-version (N-1↔N) soak rehearsed on the LOCAL
  legacy cluster (`CLUSTER_ENV=`), never the shared loss cluster.
- **No-regression for test env**: `make test-vm && make test-deploy`
  end-to-end after the provision-lib refactor; cluster deploy
  unchanged by inspection (it doesn't consume provision-lib).

## 10. Out of scope (explicitly)

- VyOS-style A/B squashfs image upgrades with boot-level rollback
  (deferred until release infra exists [report]).
- Container/Docker distribution (refuted as a kernel-gating
  workaround [report]; no demand).
- Debian-archive-grade source packaging (dh-cargo/Go vendoring,
  lintian-clean source uploads); the .deb is a binary vehicle.
- Cloud marketplace images (AMI/Azure) and an xpf cloud-init module;
  NoCloud/config-drive day-0 only.
- CLI-orchestrated ISSU (`request system software ...` driving the
  rolling upgrade across the pair).
- Automated apt-repo publishing pipelines; repo updates stay a manual
  maintainer action.
- Any change to the shared loss-cluster deploy flow.
- Migrating hosts from ifupdown/NetworkManager to networkd
  automatically (OQ-3 records the refuse-and-instruct position).

## 11. Open questions for adversarial review

1. **Protected-interface semantics**: should `system
   management-interface` *refuse* zone assignment of the protected
   interface at commit-check (strict Junos fxp0 fidelity:
   out-of-band, not zone-assignable), or auto-exempt it from
   dataplane claim while allowing mgmt-zone policy treatment? And is
   the protected-set union (leaf ∪ fxp0 ∪ lifeline-record) too wide —
   e.g. a box that legitimately repurposes fxp0 as a revenue port?
2. **Kernel delivery on Debian 13**: trixie ships 6.12; the test env
   pins from unstable. For the .deb path, is "document
   trixie-backports/unstable kernel as a prerequisite + preinst
   warning" acceptable, or does the kernel dependency effectively
   make Path C the ONLY supported non-expert path — and should the
   plan say so more bluntly? For the image: pin-exact-kernel vs track
   backports — which is the right freshness/stability trade?
3. **systemd-networkd assertion**: on a stock Debian netinst,
   ifupdown may own the mgmt NIC. Bootstrap mode currently
   refuses-and-instructs rather than migrating. Is refuse right, and
   what is the exact detection (networkctl state? presence of
   /etc/network/interfaces stanzas for the lifeline iface)?
4. **Image credentials**: no-default-password + console login +
   cloud-init keys for headless. Does this survive the
   bare-metal-restore / no-console deployment case, or does the image
   need an OPNsense-style deterministic first-boot identity after
   all?
5. **Lifeline detection heuristic**: default-route interface is the
   proposed signal. Multi-homed hosts, v4/v6 split default routes,
   and policy-routed mgmt are ambiguous. Is "v4 default route, else
   v6 default route, else refuse takeover" sufficient, or must the
   detection also consider the interface of the active SSH session
   (`SSH_CONNECTION` is unavailable to a daemon; ss-based peer-addr
   matching is fragile)?
6. **`cli` binary name**: `/usr/bin/cli` is hopelessly generic for a
   system package (and /usr/local shadowing already bit us —
   feedback_cli_binary_path). Proposed: `xpf-cli` + compat symlink.
   Right call? Drop the symlink entirely?
7. **First-commit gate scope**: confirm-required for any first commit
   (blunt, simple) vs only interface-claiming first commits (precise,
   more logic, risk of holes — e.g. a commit that re-addresses but
   does not rename the mgmt NIC)? The plan currently says blunt-with-
   `no-confirm`-escape; is the escape hatch itself the hole?
8. **Day-0 bypass semantics** (Path C): a preseeded `xpf.conf`
   bypasses the confirm gate by design (predicate resolves
   NOT-bootstrap). An operator who fat-fingers the day-0 config locks
   the appliance at first boot with no rollback armed. Acceptable
   (console always exists on a hypervisor; vSRX behaves the same), or
   should first-boot-from-day-0 ALSO arm a one-shot confirm window
   that auto-confirms on any successful mgmt-plane login?
9. **Half-configured wedge policy**: is wedging apt on a postinst
   verifier REJECT (attention-forcing) the right default for
   unattended-upgrades environments, or should xpf ship an apt.conf.d
   snippet excluding itself from unattended-upgrades on HA nodes?

Reviewers: each of these is individually invitable to PLAN-KILL the
relevant sub-path; §3 stands — if the verdict is that a
single-maintainer project should not carry a packaging+image surface
at all yet, PLAN-KILL is acceptable.
