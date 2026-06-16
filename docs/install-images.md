# xpf appliance images (#1879 Path C)

vSRX-style prebuilt-image distribution: one bootable root disk, built
offline, carrying everything xpf needs — the LATEST Ubuntu release
(operator policy: always the newest — 26.04 today, discovered at bake
time), a >= 6.18 kernel (the AF_XDP shim's verifier floor; 26.04 ships
7.0), FRR, strongSwan, Kea, chrony, systemd-networkd, and the xpf
binaries (`xpfd`, `cli`, `xpf-userspace-dp`) with their systemd units.
There is no dependency matrix to install and no kernel hunt: the image
IS the dependency closure.

Two deliverables, same root disk:

| Artifact | Consumer | Deploy command |
|---|---|---|
| `dist/xpf-<ver>.qcow2` | libvirt/KVM, plain QEMU | `virt-install --import --disk path=...` |
| `dist/xpf-<ver>.incus-metadata.tar.gz` + the same qcow2 | incus (VM) | `incus image import <meta> <qcow2> --alias xpf-appliance` |
| `dist/SHA256SUMS` | both | `sha256sum -c` |

## Bake

```bash
make image            # = python3 scripts/image/bake.py
```

Build-host requirements: the normal xpf build toolchain (Go, cargo),
`libguestfs-tools`, `qemu-utils`, `curl`, `xorriso` (for config
drives), and incus for the validation gate. `/dev/kvm` access makes
the bake fast; the script self-raises `RLIMIT_MEMLOCK` via sudo when
needed (qemu's io_uring).

Pipeline (offline — the image is never booted to provision it):

1. `make deb` (#1917 increment A). This runs `make build build-ctl
   build-userspace-dp` via `debian/rules`, so the #1864 pinned-toolchain
   contract holds — `make build` embeds the git-tracked shim object and
   the bake never runs `make generate` — then packages the freshly built
   binaries into the `xpf` Debian package (binary set staged under
   `/usr/local/share/xpf/staged`). The bake installs that `.deb` instead
   of copying raw binaries.
2. Discover the LATEST Ubuntu release from the upstream listing
   (`XPF_BASE_RELEASE` pins one), then fetch + SHA256-verify the
   official Ubuntu *server cloudimg*. Upstream owns partitioning and
   the UEFI/BIOS bootloader.
3. `virt-resize` the root partition into an 8 GiB work disk
   (`XPF_IMAGE_DISK_SIZE` overrides).
4. `virt-customize` offline: runtime package set (the #1879 plan §5
   dependency matrix; no build toolchain), the cloudimg's reduced
   `linux-virtual` kernel replaced by `linux-generic` (full driver set
   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
   with in-bake asserts that the kernel meets the >= 6.18 verifier
   floor and the extra-modules tree is present, purge of cloud-init
   (a competing network manager), snapd, and the virtual-kernel
   metapackages, systemd-networkd + resolved enabled, FRR + chrony
   enabled (default NTP pools neutered; xpfd manages
   `sources.d/xpf.sources`), sysctls, `init_on_alloc=0` (via an
   `/etc/default/grub.d` drop-in — Ubuntu cloud images override
   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
   The package's `postinst` stages the binary set, creates the live
   `/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` symlinks
   into the staging path, and enables `xpfd` + `xpf-day0-config` (so the
   bake no longer hand-copies binaries/units or runs `systemctl enable
   xpfd`). The incus-agent loader is still copied in and enabled
   directly. A plain `apt upgrade xpf` only refreshes the staging path
   and never restarts xpfd (`dh_installsystemd --no-stop-on-upgrade` + a
   `needrestart` blacklist); the verified in-place cut-over is a separate
   increment.
5. `virt-sysprep` seal: machine-id, ssh host keys, logs, tmp files,
   bash history, package caches, random seed; `/etc/xpf` factory-empty.
6. Export compressed qcow2 + incus metadata tarball + SHA256SUMS.
7. **Validation gate** (default on): the image is imported into local
   incus and the FULL first-boot matrix runs — factory boot (fxp0
   DHCP, sshd posture via `sshd -T`, -generic kernel flavor + full
   driver set check) with `xpfd verify-dataplane` IN-GUEST against
   the image's own kernel, plus the valid- and invalid-day-0-drive
   scenarios. A failure fails the bake — the image must never ship a
   verifier-failing shim (#1864/#1869 discipline). Use
   `--skip-validate` only for iteration; such artifacts are not
   publishable.

Each bake also writes `dist/xpf-<ver>.manifest` recording the exact
inputs (base image URL + release + verified SHA256, git commit, bake
date/host kernel). Bakes are not bit-reproducible (the base tracks
the newest upstream release unless `XPF_BASE_RELEASE` pins one); the
manifest is the traceability record.

Full first-boot matrix (run after a bake, or standalone):

```bash
python3 scripts/image/validate.py --qcow2 dist/xpf-<ver>.qcow2 \
    --metadata dist/xpf-<ver>.incus-metadata.tar.gz all
```

> **Deploying at scale?** `docs/deploy-quickstart.md` +
> `examples/deploy/README.md` are the operator runbook: the positional
> naming contract, the Python deployer (`scripts/deploy/xpf-deploy.py`
> — YAML-driven, incus/libvirt, builds the day-0 drive in-process),
> validated standalone/HA example definitions, SR-IOV/passthrough, and
> the fleet pattern. The sections below are the raw mechanics it builds
> on. (`scripts/image/make_config_drive.py` shown here is the image
> bakery's config-drive tool; the Python deployer builds drives
> in-process too.)

## Deploy quickstart — incus

```bash
incus image import dist/xpf-<ver>.incus-metadata.tar.gz \
    dist/xpf-<ver>.qcow2 --alias xpf-appliance

# Optional day-0 config drive (see below):
python3 scripts/image/make_config_drive.py -o day0.iso my-xpf.conf

incus init xpf-appliance xpf1 --vm -c limits.cpu=4 -c limits.memory=4GiB
incus config device add xpf1 day0 disk source=$PWD/day0.iso
incus start xpf1
```

The image carries the incus-agent loader (inert outside incus), so
`incus exec xpf1 -- cli` works immediately. Add revenue NICs as extra
devices before start; vNIC order maps to vSRX names (below).

## Deploy quickstart — libvirt/KVM

```bash
virt-install --name xpf1 --memory 4096 --vcpus 4 \
    --import --disk path=xpf-<ver>.qcow2 \
    --disk path=day0.iso,device=cdrom \
    --network bridge=br-mgmt --network bridge=br-trust \
    --osinfo ubuntu26.04 --noautoconsole
```

Plain QEMU works the same way (`-drive file=xpf-<ver>.qcow2`
`-cdrom day0.iso`); the image boots UEFI or BIOS.

## First-boot contract (vSRX parity)

| vSRX | xpf image |
|---|---|
| First vNIC is fxp0 (OOB mgmt), rest map to ge-0/0/N in attach order | Identical: `enumerateAndRenameInterfaces()` assigns fxp0 / em0 (cluster) / ge-X-0-N by PCI bus order |
| Factory default: fxp0 DHCP, root console login, no password | Identical: fxp0 DHCP bootstrap; root login on the hypervisor console with empty password; sshd refuses empty/root-password auth |
| Day-0 config: ISO with `juniper.conf` at the root, attached as CD-ROM | ISO (or any volume labeled `xpf-config`) with `xpf.conf` at the root — `juniper.conf` accepted as an alias; optional `node-id` file (`0`/`1`) for cluster members |
| Bad day-0 config: boots factory-default | Identical, but stricter: the config is validated with the REAL commit-check gate (`xpfd check-config`) BEFORE install; a REJECT logs loudly and the system stays factory-default |
| Day-0 applied once | Applied at most once: stamped after success; never clobbers an existing config (`.configdb` or preseeded `xpf.conf`). A REJECTED medium does not stamp — fix the config and reboot to retry while the system is still factory-default |

Day-0 loader specifics (`scripts/image/xpf-day0-config`, oneshot unit
`Before=xpfd.service`):

- Probes volumes labeled `xpf-config` (any filesystem) plus any ISO9660
  medium. Mounted `ro,nosuid,nodev,noexec`; only the two fixed
  filenames at the volume root are considered; 4 MiB size cap;
  validation under timeout. Nothing on the medium is executed.
- On PASS the config is installed as `/etc/xpf/xpf.conf` (mode 0600 —
  it may carry credential material) and xpfd's normal
  bootstrap-from-file import commits it at startup. No second config
  ingestion mechanism exists.
- Failures never block the boot: the unit is ordering-only (no
  `Requires=`), the script always exits 0, and `TimeoutStartSec`
  backstops a hung mount. Fallback is always the factory bootstrap.

Build a config drive:

```bash
python3 scripts/image/make_config_drive.py [-n 0|1] [-o day0.iso] my-xpf.conf
```

When an `xpfd` binary is present, the builder runs the same
commit-check and refuses to build an ISO the appliance would reject.

## Credentials / security posture

- No default password over the network, ever. The root password is
  empty: login works on the hypervisor console only. The image pins
  this explicitly — `/etc/ssh/sshd_config.d/10-xpf-factory.conf` sets
  `PermitRootLogin prohibit-password` + `PermitEmptyPasswords no`
  (not relying on distro defaults), and the validation harness
  asserts the effective `sshd -T` output.
- Headless/SSH access comes from the day-0 config (`system
  root-authentication`, `system login user ...`) — set credentials
  there, or use the console once and `commit` a config.
- The image ships no ssh host keys, no machine-id, no logs; both are
  regenerated per-instance at first boot.
- Verify artifacts with `sha256sum -c dist/SHA256SUMS`. (Detached
  signing — minisign — is a follow-up; see the #1879 deferred list.)

## Upgrades

The vSRX "replace-image" model: deploy a new VM from the new image,
copy `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` on cluster members),
swap traffic. The text config is the portable artifact — not
`.configdb`. For HA pairs this is `deploy_rolling()` at VM granularity:
replace the secondary, wait for session sync, fail over, replace the
primary. Kernel + userspace move as one tested unit.

In-place binary upgrades inside a running appliance follow the #1869
ordering invariant: push the new `xpfd` to a temp path, run
`xpfd verify-dataplane` there FIRST, and only on PASS stop/replace
(see `test/incus/cluster-setup.sh deploy_vm()` for the reference
implementation). A native .deb + `xpf-upgrade` wrapper is the M1a
follow-up, not part of this deliverable.

## Recovery

- Lost mgmt connectivity after a bad commit: use the hypervisor
  console (`incus console xpf1` / `virsh console xpf1`), log in as
  root, run `cli`, `configure`, `rollback 1`, `commit`.
- Unbootable/maimed instance: this is cattle — redeploy from the image
  and re-apply your config (day-0 drive or copy `xpf.conf` in).
- Day-0 config rejected at first boot: `journalctl -u xpf-day0-config`
  shows the commit-check error verbatim. Fix the config, rebuild the
  ISO, reboot — the system is still factory-default, so the loader
  retries.
- Pre-flight any config on the build host:
  `xpfd check-config [-node-id 0|1] my-xpf.conf` (exit 0 PASS / 2
  reject).

## Validation

`docs/image-validation.md` is the full validation runbook: Tier 1
(automated first-boot gate via `scripts/image/validate.py` — boot,
single ≥6.18 kernel, in-guest `verify-dataplane`, day-0 valid/invalid),
Tier 2 (standalone forwarding + SNAT, manual), and Tier 3 (HA pair
forwarding + failover, manual). Tier 1 gates the bake; Tiers 2–3 push
real traffic and prove the image actually routes.

## What the image does NOT solve

AF_XDP line-rate behavior remains coupled to the NIC driver exposed to
the VM (mlx5/i40e native XDP vs virtio vs iavf-generic) — see
`CLAUDE.md` "XDP on SR-IOV Interfaces". The image guarantees the
kernel side (>= 6.18, verifier-passing shim, `init_on_alloc=0`);
passthrough/VF topology is the operator's hypervisor decision.
