# #1879 — Simplify xpf installation: plan of action

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR,
3-way per /research protocol; Copilot joins at /engineer time).

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
provisioning is already ~80% of an image recipe.

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

If reviewers conclude the operator-experience gain is too small to
justify the churn — or that the project should stay test-script-only
until there are external users — PLAN-KILL is an acceptable verdict.

## 4. What's already shipped / partially batched

The plan composes with (and must not regress) the following existing
mechanisms:

1. **`test/incus/setup.sh provision_instance()`** — the de-facto
   appliance recipe: Debian 13 base, sysctls
   (`bpf_jit_enable`, v4/v6 forwarding, `accept_ra=0`), package set
   (frr, strongswan + swanctl, kea-dhcp4/6, chrony, tcpdump, iproute2,
   ...), kernel from Debian unstable via pinning (to get >= 6.18),
   `init_on_alloc=0` GRUB tweak + reboot, `systemctl enable frr`,
   chrony pool-source neutering + `/etc/chrony/sources.d` for
   xpfd-managed servers. Caveat: it also installs a *build* toolchain
   (clang, llvm, golang, build-essential) that a shipped image must not
   include.
2. **`test/incus/cluster-setup.sh deploy_vm()/deploy_rolling()`** — the
   de-facto upgrade runbook: #1869/#1864 `verify-dataplane` pre-flight
   ordering invariant (push new binary to temp path, verify against
   the live kernel verifier BEFORE any stop/cleanup/replace; REJECT
   aborts with the old dataplane untouched), graceful stop →
   `xpfd cleanup` → replace → `systemctl enable --now`, rolling order
   secondary-first-then-primary with a sync wait. The #1878 lock-cell
   (`with-cluster.sh`) serializes deploys on the shared cluster.
3. **`xpfd verify-dataplane` subcommand** (`cmd/xpfd/main.go`) — exit 0
   PASS / 3 verifier REJECT / 1 other; loads the embedded shim through
   the real kernel verifier, anonymous maps, no pins, no attach.
4. **#1864 pinned-toolchain story** (`pkg/dataplane/README.md`) — the
   shim object `userspace_xdp_bpfel.o` is git-tracked and go:embed'd
   into xpfd; `make build` is toolchain-independent. This is the single
   most packaging-friendly property the project has: **the deployable
   artifact set is three static binaries + one unit file**, with
   CGO_ENABLED=0 for both Go binaries.
5. **First-boot bootstrap in the daemon** (`pkg/daemon/linksetup.go`) —
   `enumerateAndRenameInterfaces()` renames PCI NICs to vSRX names by
   bus order (idx 0 → fxp0; cluster: idx 1 → em0), writes `.link`
   files, and `writeBootstrapFxp0Network()` drops a DHCP `.network`
   for fxp0 if absent. This is both the asset (image first-boot works
   today) and the hazard (it fires unconditionally at first start and
   renames the NIC carrying your SSH session).
6. **`commit confirmed <minutes>`** — already implemented end-to-end
   (`configstore.CommitConfirmed`, `pkg/cli/cli_config.go`; #1799
   hardened the persist-failure path). The SAFE-BOOTSTRAP design below
   reuses it rather than inventing a new rollback mechanism.
7. **`make install`** — installs xpfd + cli to $(PREFIX) but not the
   helper or the unit; incomplete as a supported path, but evidence the
   intent existed.
8. **Version stamping** — `git describe` LDFLAGS already embed
   version/commit/build-time; a .deb version can be derived from the
   same source of truth.

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
/usr/bin/cli                        (CGO_ENABLED=0 Go; see naming OQ-6)
/lib/systemd/system/xpfd.service    (productized variant of test/incus/xpfd.service)
/usr/share/doc/xpf/...              (changelog, copyright, runbooks)
```

`debian/control` dependency mapping (Debian Policy §7.2 reasoning per
[report]):

- `Depends: frr` — routing is core function; xpfd owns a managed
  section of `/etc/frr/frr.conf` and calls `systemctl reload frr`;
  daemon malfunction without it is structural. Policy: Depends gates
  configuration, which is what we want.
- `Recommends: strongswan-swanctl, kea-dhcp4-server, kea-dhcp6-server,
  chrony` — feature-optional companions "found together in all but
  unusual installations"; installed by default by apt, removable for
  minimal installs without breaking the package. The OPNsense configd
  precedent [report] validates the existing xpf design: the **daemon**
  renders companion configs at runtime; the package must NOT write
  frr/strongswan/kea config in postinst.
- `Depends: systemd, systemd-resolved | systemd (<< 256)` — see OQ-3;
  systemd-networkd is part of the systemd package on Debian, so this is
  mostly a documentation/assertion problem, not a metadata one.

Conffile/state handling:

- `/etc/xpf/` is **not** shipped as conffiles. `xpf.conf` is
  operator/machine state (like `/etc/frr/frr.conf`), not a package
  default. Ship nothing under `/etc/xpf`; `postinst` does
  `mkdir -p /etc/xpf` (0750). `dpkg -P` (purge) removes the dir only if
  the operator confirms via `postrm purge` convention. The configstore
  DB (`/etc/xpf/.configdb`) and `node-id` are never package-managed.
  This sidesteps the classic conffile-prompt-on-upgrade trap entirely.
- `xpfd.service` IS a normal packaged file (in /lib, not /etc), so
  upgrades replace it cleanly; operator overrides go in
  `/etc/systemd/system/xpfd.service.d/*.conf` drop-ins (document the
  CPUAffinity recipe from docs/712-cpu-pinning-recipe.md as a drop-in
  example).

Service lifecycle (all auto-generated by dh at compat 13):

- First install: `systemctl enable xpfd` + start. **BUT see
  SAFE-BOOTSTRAP below — the first start must come up in
  bootstrap/no-takeover mode, which is a daemon behavior, not a
  packaging behavior.** The package never decides takeover; the daemon
  does, based on whether a committed config exists.
- Upgrade: `--restart-after-upgrade` (compat-13 default) — old daemon
  keeps running while new files unpack; restart happens in postinst.
  This minimizes dataplane downtime [report] and gives us the hook
  point for the verify-dataplane gate:

```sh
# debian/xpf.postinst (sketch; dh snippet ordering: our code runs
# before the auto-generated restart snippet because dh inserts
# #DEBHELPER# where we place it)
if [ "$1" = "configure" ] && [ -n "$2" ]; then   # upgrade, not fresh install
    if ! /usr/sbin/xpfd verify-dataplane; then
        echo "xpf: new dataplane object REJECTED by the running kernel verifier." >&2
        echo "xpf: NOT restarting xpfd; the old daemon process keeps forwarding." >&2
        echo "xpf: see /usr/share/doc/xpf/README.Debian (#1864 recovery runbook)." >&2
        exit 1   # leaves package half-configured; old PROCESS still runs
    fi
fi
#DEBHELPER#
```

  Honest caveat (must be stated, not hidden): unlike
  `cluster-setup.sh deploy_vm()`, dpkg has **already replaced the
  on-disk binary** by postinst time. The old *process* keeps
  forwarding, but a crash/reboot before remediation boots the rejected
  binary — which lands in config-only mode (the daemon survives a shim
  load failure), management-reachable but not forwarding. This is
  strictly weaker than the test-script ordering invariant and strictly
  stronger than today's "no gate at all" for any non-test install. The
  full-strength pre-replace gate is only achievable with apt hooks or
  by doing upgrades through a wrapper (`xpf-upgrade` script that
  downloads the .deb, extracts the binary to /tmp, runs
  verify-dataplane, then `apt install ./xpf.deb`) — proposed as a
  shipped-but-optional convenience script in this path.
- Kernel >= 6.18 gating: deb metadata cannot express kernel minimums
  [report]. Three layers: (1) `preinst` warning when
  `uname -r` < 6.18 (warn, don't fail — chroot/image builds run preinst
  under the build host kernel; see OQ-2); (2) daemon startup already
  fails the shim load on old kernels → config-only mode with a clear
  log; (3) `xpfd verify-dataplane` documented as the definitive check.
- Rollback: `apt install xpf=<old-version>` with versioned .debs kept
  in the repo/dist directory. Document; no new mechanism.

Build/release mechanics for a no-CI project: `debian/` directory in
tree + a `make deb` target (`dpkg-buildpackage -us -uc -b`, or
sbuild when reproducibility matters). Signing/hosting: a static apt
repo via `reprepro` or `aptly` published on GitHub Pages / Releases,
signed with a maintainer GPG key — this is exactly the Tailscale
trust model endpoint (signed-by apt source) without any CI [report].
Hosting can be deferred (Path A is useful with bare .deb artifacts
attached to GitHub Releases on day one).

Rust note: `cargo build --release` for the helper happens on the
maintainer's machine as today; the .deb packages the resulting binary.
A full source-build via debian/rules (dh-cargo + Go module vendoring)
is NOT attempted — Debian-archive-grade source packaging is a
multi-week rabbit hole for zero operator benefit here. The .deb is a
**binary distribution vehicle**, stated openly in debian/README.source.

**Cost: ~3-5 focused days** (debian/ skeleton, postinst gate, unit
productization, docs, manual test matrix fresh/upgrade/remove/purge on
the standalone VM). Risk: LOW — additive; test scripts untouched.

### Path B — Tailscale-style `install.sh`

A single POSIX-sh script following the verified Tailscale structure
[report]: distro detection (Debian 13+ only at first; refuse others
with a clear message), installs the GPG keyring to
`/usr/share/keyrings/xpf-archive-keyring.gpg`, writes a `signed-by`
apt source, `apt-get install xpf`, then **prints** the next step and
exits. All logic wrapped in `main()` called at file end (truncated-pipe
safety, per the Tailscale script).

The non-negotiable property (issue + [report]): the script NEVER
activates the dataplane. Ending message:

```
xpf installed. The daemon is running in bootstrap mode and has NOT
taken over any network interfaces.
Next: designate the protected management interface and commit your
first configuration:
  cli
  > configure
  > set system management-interface <iface>
  > ... interfaces / zones / policies ...
  > commit confirmed 5
```

Hard dependency: Path B requires Path A's .deb **and** a signed apt
repo to exist — it is sugar over A, not an alternative artifact. A
variant that scp's raw binaries was considered and rejected: it would
re-create today's four-loose-artifacts problem with a bow on it.

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
externals" problem at the root.

Interface contract: the **first vNIC is always fxp0**, out-of-band
management; subsequent vNICs map to revenue ports ge-0/0/0..n in
attach order. xpf already clones this exact convention in
`assignName()` (idx 0 → fxp0, PCI bus order) — meaning xpf's daemon
was *designed* for the appliance-image model; the test VM proves the
first boot works unattended.

Day-0 configuration, in increasing automation order (all of which vSRX
supports and xpf should mirror):

1. **Console wizard / factory default**: vSRX boots a factory-default
   config — fxp0 DHCP, root login on console, management reachable.
   Operator logs in on the hypervisor console and configures. xpf
   equivalent: bootstrap mode (fxp0 DHCP via
   `writeBootstrapFxp0Network()`, sshd + `cli` on console) — this
   exists today, minus the explicit "factory default" framing and the
   takeover gate.
2. **Config-drive / CD-ROM day-0 file**: vSRX on KVM/OpenStack accepts
   a bootstrap Junos config supplied on an attached ISO/config-drive,
   applied on first boot. xpf equivalent: a tiny first-boot unit (or
   logic in xpfd startup) that, when `/etc/xpf/xpf.conf` is absent,
   probes for a labeled volume / `/dev/sr0` / cloud-init NoCloud seed
   containing `xpf.conf`, copies it in, and lets the normal
   commit-on-boot path run.
3. **cloud-init user-data**: vSRX cloud images consume user-data
   carrying Junos config on AWS/Azure/OpenStack. xpf equivalent: base
   the image on Debian genericcloud (cloud-init preinstalled);
   a `write_files` stanza dropping `/etc/xpf/xpf.conf` (+ optional
   `node-id`) is sufficient with zero xpf-side code; an xpf cloud-init
   module is gold-plating and out of scope.

Upgrade semantics (the part the operator asked about): vSRX supports
both (a) in-place Junos package upgrade (`request system software
add`) inside the VM, and (b) **replace-image**: deploy a new VM from
the new qcow2, carry the configuration over, swap traffic. In cloud
deployments and HA pairs, (b) is the norm — config is small,
declarative, and version-portable, so the VM is cattle. xpf's
analogue maps cleanly:

- (a) in-place = `apt upgrade xpf` inside the appliance **iff the
  image consumes Path A's .deb** — one more reason image-bake should
  sit on top of the deb, not parallel to it.
- (b) replace-image = deploy new VM, copy `/etc/xpf/xpf.conf` (+
  `node-id`, + optionally `.configdb` for rollback history — text
  config alone is sufficient and more robust across versions), swap.
  For HA pairs this is *exactly* `deploy_rolling()` at VM granularity:
  replace the secondary VM, wait for session sync, fail over, replace
  the primary. The kernel-upgrade problem (new kernel for new verifier
  features) is ONLY solvable on this path — apt can upgrade xpfd but a
  running appliance's kernel bump needs a reboot anyway; replace-image
  makes kernel + userspace one atomic, tested unit. This is the
  decisive operator argument for C over A-alone.
- VyOS-style A/B squashfs-with-rollback is the gold standard [report]
  but presupposes image-build infra and a boot-loader story; explicitly
  deferred. Replace-image + hypervisor snapshots gives 80% of the
  rollback value for ~0 engineering.

#### C.2 xpf image-bake pipeline (promoting setup.sh)

Recipe = `provision_instance()` minus test-isms, as a repeatable bake:

```
build host                          bake VM (incus, local)
──────────                          ─────────────────────
make build build-ctl                incus launch images:debian/13 xpf-bake --vm
make build-userspace-dp             ├─ provision: sysctls, GRUB init_on_alloc=0
make deb        ────────────────►   ├─ kernel >= 6.18 (trixie-backports or unstable pin — OQ-2)
                                    ├─ apt install ./xpf_<ver>_amd64.deb   (pulls frr; Recommends pull strongswan/kea/chrony)
                                    ├─ NO build toolchain, NO test packages (iperf3, golang, clang...)
                                    ├─ bake-time: systemctl enable xpfd; rm /etc/xpf/* (factory default)
                                    ├─ seal: truncate machine-id, clear ssh host keys,
                                    │        cloud-init clean, apt clean, zero free space
                                    └─ incus stop; incus export / image extract
                                              │
                                              ├── xpf-<ver>.qcow2          (KVM/virt-install)
                                              └── incus image tarball      (incus users)
```

Implementation shape: `scripts/bake-image.sh` sharing provisioning
logic with `test/incus/setup.sh` (refactor the common steps into a
sourced `test/incus/provision-lib.sh` so the test env and the bake
cannot drift — this is the "promote, don't fork" requirement from the
issue). Incus VM root disks are qcow2 under the hood; `incus image
export` + `qemu-img convert` produces a standalone qcow2 bootable via
virt-install. Alternative bakers (debos, Packer/qemu, vmdb2, FAI) were
considered: all add a new tool dependency; incus is already the
project's mandatory tooling and the bake is then literally "the test
VM, sealed". Choose incus.

First-boot contract of the shipped image (the vSRX clone):

1. vNIC #1 (lowest PCI bus) → fxp0, DHCP — guaranteed by existing
   `enumerateAndRenameInterfaces()` + `writeBootstrapFxp0Network()`.
2. No config present → xpfd runs in bootstrap mode: management
   reachable (ssh on fxp0 DHCP address + hypervisor console), CLI
   available, **dataplane takeover NOT armed** (SAFE-BOOTSTRAP below).
3. Day-0 config via console, NoCloud seed, or config-drive (C.1).
4. Default credentials: document `xpf`/`xpf` console login with forced
   password change, or SSH-key-only via cloud-init — OQ-4.

Honest costs unique to C: image hosting (GitHub Releases has a 2 GiB
per-file cap — a sealed, zeroed, compressed Debian-13 qcow2 should land
~600 MB-1 GiB, fits, but must be verified); image signing (minisign
or GPG detached sigs — minisign is the VyOS-validated lightweight
choice [report]); a rebuild cadence for Debian security updates baked
into the image (document "the image is a bootstrap artifact; apt
handles security updates in place" to avoid promising a re-bake
treadmill); and a test matrix (virt-install/KVM + incus at minimum).

**Cost: ~1-2 weeks** for the bake script + provision-lib refactor +
seal/first-boot validation + virt-install doc + signing, ASSUMING the
.deb exists (without it, bake-time file placement re-implements
packaging badly). Risk: MEDIUM — image sealing and first-boot-on-
foreign-hypervisor have long-tail gotchas (machine-id, predictable
NIC enumeration on non-virtio hardware, console= kernel args).

### Path D — staged hybrid (recommended)

Sequencing, each stage independently shippable and valuable:

- **M1 — Path A .deb + SAFE-BOOTSTRAP daemon changes.** The .deb is
  the artifact every other path consumes; safe-bootstrap is the
  highest-safety-leverage item [report ranks it #3 with TNSR/Junos
  precedent] and must land *before* any path makes installation easy —
  making it easier to install a foot-gun is negative progress.
- **M2 — Path C image bake consuming the M1 .deb** (operator-pinned
  priority; also the only complete answer to kernel >= 6.18).
- **M3 — Path B install.sh + signed apt repo** (deferred until
  external demand; repo hosting can land earlier if M1 wants it).

This is the issue's direction D made concrete; it matches the
[report] ranking (deb #1 ROI, installer #2, safety #3, image deferred
— with the deferral overridden for xpf by the operator's appliance
use-case and by setup.sh already being 80% of the recipe).

### SAFE-BOOTSTRAP (load-bearing, common to all paths)

Threat: first daemon start on a remote box renames ALL PCI NICs
(`enumerateAndRenameInterfaces()` runs unconditionally), brings
unconfigured interfaces down with `ActivationPolicy=always-down`, and
replaces addressing with xpf-managed `.network` files. If the
management NIC is not idx 0, or its addressing was static, or DHCP
re-acquisition fails post-rename, the operator is locked out. Today
this is mitigated only by convention (test VMs are wired so mgmt is
idx 0 / DHCP).

Design (TNSR protected-mgmt + Junos commit-confirmed, composed with
the existing fxp0 bootstrap):

1. **Protected management interface designation** (TNSR model
   [report]). New config leaf `system management-interface <name>`
   (schema: `pkg/config/schema.go` setSchema; default `fxp0`). The
   designated interface is host-managed: xpfd never binds it into the
   dataplane, never marks it always-down, never strips its addresses.
   Today fxp0 gets this treatment by convention; the leaf makes it
   explicit, configurable (e.g. a box where mgmt must be a ge- port),
   and enforceable at commit-check (refuse a config that assigns the
   protected interface to a security zone... or auto-exempt; OQ-1).
2. **Lifeline preservation at first start.** Before the first rename
   pass on a host with NO committed config, xpfd records the interface
   carrying the current default route (and/or an established SSH
   session — detection heuristic, OQ-5). If that interface is the one
   becoming fxp0: instead of writing the DHCP-only bootstrap
   `.network`, snapshot its *current* addresses/gateway into the
   bootstrap `.network` (`KeepConfiguration=static` + explicit
   `Address=`/`Gateway=` when the address was static; plain DHCP when
   it was DHCP). If the default-route interface would become a ge-
   port (i.e. NOT idx 0), **do not rename/claim anything**: log
   loudly, stay in bootstrap mode, require the operator to either
   re-wire or set `system management-interface` + commit. This changes
   `writeBootstrapFxp0Network()` from write-DHCP-if-absent to
   write-lifeline-if-absent, and adds one guard before the rename loop
   in `enumerateAndRenameInterfaces()` — a small, testable diff.
3. **First takeover gated by commit-confirmed** (Junos model; reuses
   `configstore.CommitConfirmed`, zero new rollback machinery). On a
   host with no previously-committed config, a plain `commit` of the
   first interface-owning config is refused with guidance:
   `first commit on this system must be 'commit confirmed <minutes>'
   (interface takeover can cut off management; the system rolls back
   automatically unless confirmed)`. Rollback restores the empty/
   bootstrap config → daemon reverts `.link`/`.network` state on
   rollback apply (the existing apply path already reconciles networkd
   files from config; verify the reverse transition cleanly restores
   the lifeline `.network` — this is the riskiest reconciliation in
   the design and gets a dedicated test). Escape hatch
   `commit no-confirm` for console/bench installs where lockout is
   impossible. (Naming/Junos-fidelity: OQ-1.)
4. **Composition with packaging**: the .deb/install.sh/image never
   decide takeover — they install + enable a daemon whose *own* gate
   is "no committed config ⇒ bootstrap mode, lifeline preserved".
   This keeps the safety property in exactly one place (the daemon)
   and makes it hold identically for apt installs, image first boot,
   and today's test scripts (which pre-seed a config and node-id, and
   therefore skip bootstrap mode entirely — no test-flow regression).

### HA-pair rolling upgrade, per path

- Invariant (all paths): **verify-dataplane gates every upgrade**
  before the running dataplane is disturbed (#1869). Order:
  secondary first, wait for session sync, then primary —
  `deploy_rolling()` is the reference implementation.
- Path A: documented runbook (`README.Debian` + docs/): node1
  `apt upgrade xpf` (postinst gate runs on node1's kernel), verify
  `show chassis cluster status` sync, then node0. apt never
  coordinates across nodes — and should not; a later
  `request system software in-service-upgrade`-style CLI orchestration
  is listed out-of-scope.
- Path C: replace-image per node in the same order; config carry-over
  via `/etc/xpf/xpf.conf` + `node-id`. The new VM joins as secondary,
  syncs sessions, takes over (~60 ms VRRP failover budget unchanged),
  then the peer is replaced. Kernel upgrades ride along atomically —
  the unique win of this path.
- Path B: identical to A (it installs A's deb).
- Config compatibility across versions is the silent prerequisite for
  rolling anything: the project already maintains stored-config
  rolling-upgrade compatibility (e.g. the #1525 retained reject
  machinery "kept for one release cycle to preserve the
  operator-friendly migration message for stored-config rolling
  upgrade") — the plan adds a stated policy: text `xpf.conf` from
  release N-1 must commit cleanly on N (this is already de-facto true;
  write it down in docs/engineering-style.md or a new
  docs/upgrade-policy.md).

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
- Daemon: hosts WITH a committed config (`/etc/xpf/.configdb` active
  or pre-seeded `xpf.conf` — i.e. every existing deployment and all
  test VMs) see no behavior change from SAFE-BOOTSTRAP; the takeover
  gate and lifeline logic only apply on the no-committed-config path
  (plus the new opt-in `system management-interface` leaf).
- `xpfd verify-dataplane`, `xpfd cleanup`, `version` subcommands
  unchanged (postinst becomes a new caller of verify-dataplane).
- CLI grammar: additive leaves only (`system management-interface`;
  possible `commit no-confirm` — OQ-1).

## 7. Hidden invariants the change must preserve

1. **#1869 ordering invariant**: nothing may stop/replace a working
   dataplane before the new object passes the live kernel's verifier.
   The deb postinst approximation (old process keeps running; disk
   already swapped) must be documented as a *known weakening* with the
   wrapper-script remedy, never silently presented as equivalent.
2. **Interface lifeline**: at no point between "fresh boot" and
   "first confirmed commit" may the management path depend on an
   un-renamed kernel NIC name or an address that the daemon is about
   to remove. The lifeline `.network` must survive `networkctl reload`
   and daemon restarts (bootstrap files are only superseded by
   committed config).
3. **RETH `.link` semantics** (`MACAddress=` vs `OriginalName=`,
   `ensureRethLinkOriginalName()`), `KeepConfiguration=static` VIP
   preservation, and the FPC-7 node-1 naming must be untouched by any
   linksetup edit — the SAFE-BOOTSTRAP diff is confined to the
   no-config first-start path and the fxp0 bootstrap writer.
4. **Shim artifact discipline (#1864)**: the .deb embeds whatever
   `userspace_xdp_bpfel.o` is tracked in git; `make deb` must NOT run
   `make generate`. Pin-bump procedure unchanged.
5. **Config-only-mode survivability**: daemon startup with a rejected
   shim must keep yielding a management-reachable config-only daemon
   (this is the floor under the postinst weakening).
6. **Helper/daemon version coupling**: xpfd and xpf-userspace-dp ship
   and restart as a unit (single .deb, single service restart) — the
   control-socket protocol is not cross-version stable and nothing in
   the plan may let apt restart one without the other.
7. **Cluster test env hygiene**: nothing in this plan touches the
   shared loss cluster; image-bake experiments run on local incus
   only.
8. **No new hot-path code**: this is entirely control-plane/packaging
   work; zero dataplane-loop changes.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (existing deployments) | LOW-MED | SAFE-BOOTSTRAP touches `linksetup.go` first-start path; gated on "no committed config" so existing nodes skip it, but the gate predicate itself must be airtight (a false "no config" on a live node would refuse renames/freeze takeover → MED until the predicate test exists) |
| Lockout / safety regression | LOW (improves it) | The plan's purpose; riskiest sub-item is commit-confirmed rollback restoring the lifeline `.network` correctly |
| Packaging correctness | MED | dpkg maintainer-script edge cases (failed postinst leaves half-configured package; purge vs remove; service masked by operator) — bounded by manual test matrix, no CI to catch drift |
| Image first-boot portability | MED | machine-id/ssh-key sealing, non-virtio NIC enumeration order on real hardware, console access assumptions; mitigated by shipping C after A and labeling the image KVM/incus-validated only |
| Architectural mismatch | LOW | All mechanisms reuse existing primitives (commit-confirmed, verify-dataplane, linksetup, provision script); no new daemons, no new state stores |
| Scope creep | MED-HIGH | The classic packaging rabbit holes (source-package purity, A/B images, apt repo automation, cloud-init modules) are explicitly fenced out in §10; reviewers should police re-entry |

## 9. Test plan

- **Unit/Go**: schema test for `system management-interface`;
  linksetup tests for the lifeline writer (static snapshot vs DHCP
  pass-through), the no-config rename guard, and the
  committed-config-present fast path (existing-deployment no-op);
  configstore test for first-commit-requires-confirmed gating.
  `make test` (30 packages) green.
- **Package matrix (standalone incus VM, fresh Debian 13)**:
  fresh install → bootstrap mode, fxp0 DHCP, ssh reachable, dataplane
  not armed; first `commit confirmed` + confirm → takeover, traffic;
  deliberate non-confirm → auto-rollback restores management;
  upgrade with good binary → postinst gate PASS, restart, sessions
  resume; upgrade with the preserved #1864 incident object →
  postinst gate FAIL, old process still forwarding, package
  half-configured, `apt install xpf=<old>` recovers;
  remove vs purge semantics; preinst kernel warning on a 6.12 kernel.
- **Image (M2)**: bake → virt-install on a clean KVM host + incus
  launch; first-boot contract (fxp0 DHCP, console login, day-0
  config-drive seed applied); replace-image upgrade with config
  carry-over on the standalone topology.
- **HA (only after M1 code changes, standard gate)**: `make
  test-failover` must pass for any commit touching daemon
  startup/linksetup (project standing rule); rolling-upgrade runbook
  rehearsed once on the LOCAL legacy cluster (`CLUSTER_ENV=`), not the
  shared loss cluster.
- **No-regression check for test env**: `make test-vm && make
  test-deploy` end-to-end after the provision-lib refactor.

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

## 11. Open questions for adversarial review

1. **Protected-interface semantics**: should `system
   management-interface` *refuse* zone assignment of the protected
   interface at commit-check, or auto-exempt it from dataplane claim
   while still allowing it in a (mgmt) zone for policy purposes?
   Junos fxp0 is fully out-of-band (not zone-assignable) — is strict
   Junos fidelity right here, and is `fxp0` the correct default value
   given bullet SAFE-BOOTSTRAP-2 handles the "mgmt is not idx 0"
   case by refusing takeover rather than by remapping names?
2. **Kernel delivery on Debian 13**: trixie ships 6.12; the test env
   pins linux-image from unstable. For the .deb path, is "document
   trixie-backports/unstable kernel as a prerequisite + preinst
   warning" acceptable, or does the kernel dependency effectively
   force Path C (image with the right kernel baked) to be the ONLY
   supported non-expert path — and should the plan say so more
   bluntly?
3. **systemd-networkd assertion**: xpfd assumes networkd is the
   network manager. On a stock Debian server netinst, ifupdown may own
   eth0. Should the daemon's bootstrap mode actively migrate the
   lifeline interface from ifupdown/NetworkManager to networkd
   (riskier, more magic), or refuse takeover until the operator
   converts (safer, more friction)? The current plan implies the
   latter without stating the detection mechanism.
4. **Image default credentials**: vyos/vyos-style documented default
   login vs cloud-init-only SSH keys. A documented default password on
   a firewall image is a CVE-magnet; console-only first login with
   forced change is the proposed middle ground — is that defensible,
   and does it survive the headless-server (no console) deployment
   case?
5. **Postinst gate honesty**: is the "old process keeps running but
   disk binary already swapped" weakening of the #1869 invariant
   acceptable for the supported path, or must M1 ship the
   `xpf-upgrade` wrapper (verify-before-unpack) as the *primary*
   documented upgrade command, demoting bare `apt upgrade` to the
   degraded path?
6. **`cli` binary name collision**: `/usr/bin/cli` is hopelessly
   generic for a system package (and `/usr/local/sbin/cli` shadowing
   already bit us — feedback_cli_binary_path). Rename to `xpf-cli`
   with a `cli` symlink? Pure-additive but touches docs/muscle memory
   everywhere.
7. **First-commit gate scope**: should commit-confirmed-required apply
   only when the candidate config changes interface claims (precise
   but more logic), or to any first commit (blunt but simple)? Blunt
   risks annoying bench installs; precise risks a hole (e.g. a config
   that doesn't *rename* but re-addresses the mgmt NIC).

Reviewers: each of these is individually invitable to PLAN-KILL the
relevant sub-path; §3 stands — if the verdict is that a
single-maintainer project should not carry a packaging+image surface
at all yet, PLAN-KILL is acceptable.
