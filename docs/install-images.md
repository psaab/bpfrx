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
| `dist/xpf-<ver>.SHA256SUMS` (+ `.minisig`) | both | minisign-verified, per-file (#1924) |

> **Signed distribution (#1924):** the bake emits a per-version, minisign-signed
> checksum manifest. Fetch + verify from a trusted signed source instead of
> copying files by hand — `xpf-deploy.py fetch --version <ver> --image-url
> $XPF_IMAGE_BASE_URL` downloads, verifies the exact bytes against the signed
> manifest, and imports. The one-command `install.sh` + signed apt repo are the
> package path. See `docs/distribution.md`.

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
   (`XPF_IMAGE_DISK_SIZE` overrides). This is the *floor* size: an
   operator who provisions a larger root disk gets the extra space
   automatically via the first-boot root auto-grow (#1925, see
   "First-boot root auto-grow" below).
4. `virt-customize` offline: runtime package set (the #1879 plan §5
   dependency matrix; no build toolchain), the cloudimg's reduced
   `linux-virtual` kernel replaced by `linux-generic` (full driver set
   — mlx5/i40e for passthrough NICs live in `linux-modules-extra`)
   with in-bake asserts that the kernel meets the >= 6.18 verifier
   floor and the extra-modules tree is present, **the kernel held
   (`apt-mark hold`) + excluded from unattended-upgrades so an apt run
   cannot move the verifier floor out from under the gated shim .o
   (#1930) — kernel bumps go through the verify-gated LANE-1 channel, not
   background apt; a `needrestart` blacklist keeps an apt run from
   restarting xpfd mid-transaction**, purge of cloud-init
   (a competing network manager), snapd, and the virtual-kernel
   metapackages, systemd-networkd + resolved enabled, FRR + chrony
   enabled (default NTP pools neutered; xpfd manages
   `sources.d/xpf.sources`), sysctls, `init_on_alloc=0` (via an
   `/etc/default/grub.d` drop-in — Ubuntu cloud images override
   `GRUB_CMDLINE_LINUX_DEFAULT` there), and `apt-get install ./xpf.deb`.
   The package's `postinst` always stages the binary set into
   `/usr/local/share/xpf/staged`, then sets up the live
   `/usr/local/sbin/{xpfd,cli,xpf-userspace-dp,xpf-day0-config}` symlinks
   (normally through `versions/current`; see the fallback below) and
   enables `xpfd` + `xpf-day0-config` (so the bake no longer hand-copies
   binaries/units or runs `systemctl enable xpfd`). This bake is a FIRST
   install, so it takes the seed path. The four postinst behaviors are
   version-dependent (`$2` is the previously-configured version, empty on
   first install) — the full split is:

   - **First install (#1964 seed)** — `postinst` runs `xpfd seed-runtime`
     (`pkg/upgrade/runtime`), which copies `staged/*` into
     `/var/lib/xpf/versions/<ver>/`, points `versions/current -> <ver>`,
     and repoints each `/usr/local/sbin/*` symlink THROUGH
     `versions/current`. This is what a fresh bake gets: a real, immutable
     rollback target before the first in-place upgrade can ever stop the
     daemon. `versions/` is maintainer-script-managed runtime state, never
     in dpkg's file list, so dpkg only ever writes `staged/`.
   - **Direct-staged fallback** — if `seed-runtime` FAILS, `postinst`
     prints a warning and points the sbin symlinks straight at
     `staged/*` so the daemon still launches (degraded: the next upgrade
     takes the legacy-migration `preinst` path). This is the ONLY case
     where the live symlinks point into the staging path.
   - **Clustered upgrade (stage-only)** — on an upgrade where
     `/etc/xpf/node-id` is present, `postinst` STAGES only and does NOT
     cut. A clustered node is cut solely by `xpfd upgrade --rolling`,
     which sequences a controlled per-node drain so the cluster keeps
     forwarding.
   - **Standalone upgrade (verified cut-over)** — on an upgrade with no
     `node-id`, `postinst` publishes the staged generation and invokes
     `xpfd upgrade`, the verified, atomic, rollback-capable
     STOP->FLIP->START cut to the staged version (kernel verify gate, then
     a unit `ExecStart` pinned to the concrete version so a respawn never
     resolves a mismatched helper).

   The incus-agent loader is still copied in and enabled directly. The
   verified in-place cut-over is owned by the package itself; see
   `docs/in-place-upgrade.md` for the full state machine.
5. `virt-sysprep` seal: machine-id, ssh host keys, logs, tmp files,
   bash history, package caches, random seed; `/etc/xpf` factory-empty.
6. Export compressed qcow2 + incus metadata tarball + the per-version
   `xpf-<ver>.SHA256SUMS` manifest, minisign-signed to
   `xpf-<ver>.SHA256SUMS.minisig` when `XPF_SIGN_SECKEY` (a path) is set
   (#1924). An unsigned dev bake warns "not publishable"; `make dist-publish`
   refuses it.
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
manifest is the traceability record. The manifest ALSO records the
staged binary's compile-time protocol versions (`ha_protocol_version`,
`ha_protocol_min_compat`, `session_sync_protocol_version`,
`configdb_*_version`, from `xpfd protocol-versions`); the #1930 LANE-2
mixed-base HA gate (`xpf-deploy.py image-roll`) reads these to decide —
without booting the image — whether a rolling image-replace can preserve
sessions across the mixed-base window or must replace both nodes at once.
See `docs/in-place-upgrade.md` (Kernel / OS upgrade lanes) for the full
LANE-1/2/3 decision rule and the state-carry contract.

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

## First-boot root auto-grow (#1925)

The image ships an 8 GiB root disk (`XPF_IMAGE_DISK_SIZE`). When you
deploy onto a larger disk — `incus init ... -d root,size=40GiB`,
`qemu-img resize`, or a bigger libvirt volume — the extra space is
unallocated GPT free space and `/` cannot use it until the root
partition + filesystem are grown. The appliance does this **once, on
first boot, automatically**:

- `scripts/image/xpf-grow-root.service` (oneshot, `RemainAfterExit`,
  `ConditionPathExists=!/etc/xpf/.root-grown`) runs early — ordered
  `After=systemd-remount-fs.service` and `Before=local-fs.target
  xpfd.service xpf-day0-config.service` — so `/var` is full-size before
  xpf stages its versioned runtime (#1964) or writes the config DB. It
  stamps `/etc/xpf/.root-grown` on success and never runs again.
- `scripts/image/xpf-grow-root` resolves the device backing the live
  root mount from `findmnt /` (bus-agnostic — `vda`/`sda`/`nvme0n1pN`),
  then `growpart <disk> <partnum>` followed by `resize2fs <rootdev>`.
  On an exact-bake-size deploy both are no-ops (`growpart` returns
  `NOCHANGE` when there is no trailing free space; `resize2fs` is a
  no-op when the fs already fills the partition), and the script never
  blocks the boot — every failure path is non-fatal.

This restores exactly what the stock cloudimg's cloud-init
`growpart`/`resizefs` modules did before the bake purged cloud-init —
a known-good, expected-of-every-cloud-image behavior — using the tools
already in the image (`cloud-utils-growpart` + `e2fsprogs`).

**Why `growpart`/`resize2fs` and not `systemd-repart`:** they can only
*grow a partition's end into adjacent free space* and *grow* an ext4
filesystem. They cannot create, reformat, shrink, or move a partition
by construction — there is no `Format=`/`CopyBlocks=` knob to mis-set.
That is the smallest possible data-loss surface, deliberately chosen
over `systemd-repart` (which would also add a runtime package to a
minimized image).

**Why this is safe for the #1930 A/B kernel channel:** the LANE-1 A/B
"slots" are **directories inside the single ESP partition**
(`/boot/efi/EFI/xpf-A`, `xpf-B`) plus the `/etc/grub.d/09_xpf`
`$cmdpath` selector — they are NOT separate GPT partitions, and kernels
live in `/boot`. The root partition is the **physically last partition**
in the canonical Ubuntu cloudimg layout, so growing it into trailing
free space cannot touch the ESP (and the A/B dirs, selectors, and
shim/grub it holds), the BIOS-boot or `/boot` partitions, or any
partition *number* — `growpart` only edits the selected partition's
end and never renumbers. The grow signs nothing and does not alter the
ESP, so the Secure Boot posture and the kernel promote/rollback channel
are untouched. (If a future bake change ever added a trailing partition
*after* root, this "grow the last partition" assumption would need
revisiting.)

Validation: `scripts/image/validate.py d` (also part of `all`) boots a
baked image under local incus with a 20 GiB root disk and asserts the
root partition + filesystem grew past the 8 GiB floor, the grow is
idempotent across a reboot, the ESP stays mounted, and `verify-dataplane`
still passes; a control instance at the exact bake size proves the grow
is a clean no-op.

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
- Verify artifacts with their minisign-signed per-version manifest
  (#1924): `xpf-deploy.py fetch` verifies the exact bytes against
  `xpf-<ver>.SHA256SUMS` + `.minisig`, or verify manually with
  `minisign -V -p scripts/dist/xpf-image.pub -m xpf-<ver>.SHA256SUMS
  -x xpf-<ver>.SHA256SUMS.minisig` then check each file's hash. The signed
  apt repo + `install.sh` are the package path — see `docs/distribution.md`.

## Upgrades

The vSRX "replace-image" model: deploy a new VM from the new image,
copy `/etc/xpf/xpf.conf` (+ `/etc/xpf/node-id` on cluster members),
swap traffic. The text config is the portable artifact — not
`.configdb`. For HA pairs this is `deploy_rolling()` at VM granularity:
replace the secondary, wait for session sync, fail over, replace the
primary. Kernel + userspace move as one tested unit.

In-place binary upgrades inside a running appliance follow the #1869
ordering invariant: copy the new binaries into a versioned runtime dir,
run `xpfd verify-dataplane` against the staged version FIRST, and only on
PASS stop/flip/start. The `xpf` package owns this verified cut path: a
plain `apt install ./xpf.deb` (or `apt upgrade xpf`) stages the new
binaries and then runs the cut itself — `xpfd upgrade` on a standalone
node, or stage-only (cut deferred to `xpfd upgrade --rolling`) on a
clustered node. There is no separate `xpf-upgrade` wrapper. See
`docs/in-place-upgrade.md` for the full state machine and rollback
contract (`test/incus/cluster-setup.sh deploy_vm()` exercises it).

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
