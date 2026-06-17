# Plan of action — #1943: Realign standalone test env to production parity (Ubuntu 26.04)

- **Issue:** #1943 — Test env drift: standalone test VM is Debian 13 but
  production is Ubuntu 26.04.
- **Revision:** r2 (addresses AGY r1 + Claude SMR r1; Codex r1 pending fold-in)
- **Branch:** `research/1943-ubuntu-test-env-parity`
- **Scope class:** TEST-ENV / TOOLING only. No production source code is touched.
- **Skill:** `/research` — STOP at PLAN-READY. No PR, no implementation.

---

## 1. Problem statement

The production appliance image (`scripts/image/bake.py`) is built on **Ubuntu
26.04** server cloudimg (auto-discovered latest, `XPF_BASE_RELEASE`-pinnable;
ships a stock kernel >= 6.18, the AF_XDP shim verifier floor). The deploy gate
`scripts/dist/install.sh` accepts the whole Debian family but enforces kernel
>= 6.18.

The in-lab test environments, however, are **Debian 13**:

- `test/incus/setup.sh:28-29` — `IMAGE_VM=IMAGE_CT="images:debian/13"` for the
  standalone `xpf-fw` VM (`make test-vm`).
- `test/incus/cluster-setup.sh:85-86` — `IMAGE_VM/IMAGE_CT` default
  `images:debian/13` for the HA cluster.
- `CLAUDE.md:69` — `make test-vm  # Create Debian 13 VM …`.

Because Debian 13 (trixie) ships a kernel below the 6.18 verifier floor, both
setup scripts perform a **Debian-unstable kernel-pinning dance**
(`setup.sh:287-300`, `cluster-setup.sh:132-165`): add `deb …/debian unstable`,
pin `linux-image-amd64`/`linux-headers-amd64` to `a=unstable` at priority 990,
`apt install`, then reboot into the new kernel.

This drift is what bit #1930: the A4 verify-gated kernel boot channel
(Secure-Boot shim→grub→MOK chain, A/B ESP slots, `grub-reboot` one-shot promote
/rollback) **could not be validated on the Debian-13 test VM** — it had to be
exercised on a one-off Ubuntu 26.04 UEFI VM stood up by hand. The production
boot path lives in `scripts/image/{grub.d/09_xpf, xpf-uefi-slots,
xpf-kernel-promote*}` and is Ubuntu/shim-specific; the Debian test VM cannot
faithfully reproduce it.

## 2. Goal / success criteria

1. `make test-vm` provisions an **Ubuntu 26.04** standalone VM matching
   `bake.py`'s *release* (Ubuntu-family parity via the linuxcontainers
   `images:ubuntu/26.04` stream — NOT byte-identical to the
   cloud-images.ubuntu.com base; byte-fidelity boot-path validation uses the
   baked qcow2, Path V2). Version-pinnable via `XPF_BASE_RELEASE`, default
   `26.04` (a deliberate reviewed value, not silent auto-latest — see §6.1).
2. The Debian-unstable kernel dance is **removed where Ubuntu 26.04 already
   satisfies the >= 6.18 floor** (verified, not assumed), with a hard floor
   assertion retained so the VM fails loudly if the base ever ships < 6.18.
3. Package install lines use **Ubuntu package names** (delta vs Debian:
   `linux-image-amd64`/`linux-headers-amd64` → `linux-generic`/
   `linux-headers-generic`; `golang` availability; everything else identical).
4. `CLAUDE.md` "Test Environment (Incus VM)" + the `make test-vm` comment +
   any Debian-13 references are updated to Ubuntu 26.04.
5. A **UEFI Secure-Boot-capable** standalone test VM profile exists, so #1930
   A4 boot-path work (one-shot promote/rollback over shim→grub→MOK + A/B ESP
   slots) is live-validatable in-lab without a hand-rolled VM. (The HW-watchdog
   early-hang case stays bench/manual — incus/qemu OVMF can't guarantee a
   warm-reset-surviving HW watchdog; this is explicitly out of scope.)
6. No production code changes; `scripts/dist/install.sh` already accepts Ubuntu
   (confirmed §4), so nothing in the shipped product assumes Debian.

## 3. Confirmed facts (from code walk + live incus probe)

- **No production Debian assumption.** `grep -rn` over `pkg/ cmd/ scripts/`
  found the only distro gate in `scripts/dist/install.sh:75`:
  `case "${ID} ${ID_LIKE}" in *debian*|*ubuntu*) : ;;` — Ubuntu passes. The real
  gate is kernel >= 6.18. **Production is distro-agnostic within Debian-family.**
- **`images:ubuntu/26.04` and `images:ubuntu/26.04/cloud` exist** on the
  `images:` (linuxcontainers) remote, both VIRTUAL-MACHINE and CONTAINER
  variants (live probe 2026-06-17: `Ubuntu resolute amd64`, fingerprints
  `235d4bc96c24` / `1d612ab4dddd`). So `incus launch images:ubuntu/26.04 …`
  works today.
- **incus 6.21**, qemu driver present → OVMF/Secure-Boot VMs supported.
- **`loss:` remote** (where the cluster runs) is configured and reachable.
- `bake.py` ships `linux-generic` and HARD-ASSERTS newest kernel >= 6.18
  (`bake.py:233-242`); `docs/install-images.md:5-6` states "26.04 ships [a
  >= 6.18 kernel]". This is the lever for dropping the kernel dance.
- bake.py uses `virt-install --osinfo ubuntu26.04`
  (`docs/install-images.md:153`).

## 4. Open question that must be answered IN the first impl step (gating)

**Does `images:ubuntu/26.04` (the linuxcontainers cloudimg) ship a stock kernel
>= 6.18 out of the box?** `docs/install-images.md` asserts this for the
*Ubuntu cloud-images.ubuntu.com* base bake.py uses, and 26.04 stock is 6.18+,
but the `images:` (linuxcontainers) build is a *different* image stream and must
be empirically confirmed with `incus launch images:ubuntu/26.04 probe --vm` +
`uname -r` before deleting the kernel dance. **If it ships < 6.18**, fall back
to Path-K2 (§7). This is a HARD GATE: the implementer runs the probe first and
the chosen kernel path follows the measurement, not the assumption.

## 5. Affected files (test-env / tooling only)

| File | Change |
|------|--------|
| `test/incus/setup.sh` | env-overridable `IMAGE_VM/IMAGE_CT` → Ubuntu 26.04; pkg renames (+`linux-modules-extra-generic`, `linux-tools-generic`, `bind9-host`; −`golang`); drop kernel-install dance but KEEP grub-apply reboot; `security.secureboot` in `xpf-vm` profile; optional `XPF_BASE_IMAGE`/baked-qcow2 path for A4 |
| `test/incus/cluster-setup.sh` | same image + pkg + kernel changes (if C1 — Path-C §7); already uses `${IMAGE_VM:-…}` pattern |
| `CLAUDE.md` | "Test Environment (Incus VM)" section + line 69 + any Debian-13 refs → Ubuntu 26.04 + `XPF_BASE_RELEASE` pin + SB note |
| `docs/install-images.md` | (optional) cross-link the baked-image test-VM path for A4 validation |
| `docs/research/1943-ubuntu-test-env-parity/plan.md` | this doc (research branch only) |

No `.go`, `.rs`, `proto`, or shipped-`scripts/dist`/`scripts/image` source is
edited. (`scripts/image/bake.py` is already Ubuntu — it is the *reference*, not
a change target.)

## 6. Detailed change design (recommended path)

### 6.1 Image base + version pinning (setup.sh)
Replace the two hardcoded constants with an env-pinnable selector that mirrors
bake.py's `XPF_BASE_RELEASE` contract:

```sh
XPF_BASE_RELEASE="${XPF_BASE_RELEASE:-26.04}"          # pinned default (reviewed bump)
IMAGE_VM="${IMAGE_VM:-images:ubuntu/${XPF_BASE_RELEASE}/cloud}"   # env-overridable (cluster pattern)
IMAGE_CT="${IMAGE_CT:-images:ubuntu/${XPF_BASE_RELEASE}/cloud}"
```

(Use the `${IMAGE_VM:-…}` cluster-setup.sh pattern — Codex r1 #6 — so the image
is genuinely env-overridable for pinning a different *Ubuntu* release. This is
NOT a Debian fallback path; see §10.)

Rationale for a **pinned default `26.04`** rather than auto-latest-discovery:
bake.py auto-discovers because the production image must track the operator's
"always newest" policy; the *test* VM must instead match **whatever release
production was last baked at**, which is a deliberate, reviewed bump — not a
silent track of the newest Ubuntu the day you run `make test-vm`. Pinning to
`26.04` keeps test == prod and makes the next bump a one-line reviewed diff.
(Path-V alternative in §7 discusses auto-latest + qcow2-import.)

Use the `/cloud` variant (cloud-init enabled) to match bake.py's cloudimg base
as closely as the linuxcontainers stream allows.

### 6.2 Kernel path (conditional on §4 probe)
If the probe shows `images:ubuntu/26.04` ships >= 6.18 (expected):
**delete** the Debian-unstable repo + pin + `linux-image-amd64` install. Replace
with a hard assertion mirroring bake.py:

```sh
kver=$(incus exec "$INSTANCE_NAME" -- uname -r)
# fail loudly if base regressed below the AF_XDP verifier floor
dpkg --compare-versions "${kver%%-*}" ge 6.18 || die "base kernel $kver < 6.18"
```

**KEEP the reboot step (AGY r1 #2 — HIGH).** Removing the kernel *install* does
NOT remove the need for a reboot: the `init_on_alloc=0` grub change (below)
only takes effect after a reboot. If the reboot is dropped, the VM runs all
subsequent tests with `init_on_alloc=1` → the ~20% virtio-net XDP CPU
regression the tuning exists to avoid. So the kernel-install dance is deleted
but a single grub-apply reboot is retained (or the existing reboot loop is kept
and simply not preceded by a kernel install).

The `init_on_alloc=0` grub tuning stays, but switches from the Debian
`sed /etc/default/grub` form (`setup.sh:303`) to the **grub.d drop-in** form
that bake.py uses (`bake.py:78-87` `GRUB_DROPIN`, written to
`/etc/default/grub.d/99-xpf.cfg`). On the official cloud-images.ubuntu.com base,
`/etc/default/grub.d/50-cloudimg-settings.cfg` re-sets
`GRUB_CMDLINE_LINUX_DEFAULT`, so a sed on `/etc/default/grub` is silently lost
— hence the drop-in. **GATE (SMR F1):** the linuxcontainers `images:ubuntu/26.04`
stream is a DIFFERENT build than cloud-images.ubuntu.com and may not carry the
same `50-cloudimg-settings.cfg` override; §8 must confirm `init_on_alloc=0`
actually reaches `/proc/cmdline` after the chosen mechanism on the *actual* V1
image. The grub.d drop-in form is the safe superset either way (it appends, it
doesn't fight an override), so default to it.

### 6.3 Package names (setup.sh:281, cluster-setup.sh:459)
Delta Debian→Ubuntu for the test-tooling install line:
- `linux-image-amd64 linux-headers-amd64` → `linux-headers-generic` (headers
  for the running `-generic` kernel; the image already has the kernel).
- **ADD `linux-modules-extra-generic`** (AGY r1 #1 — HIGH). Ubuntu splits NIC
  drivers (`mlx5_core`, `i40e`, `ixgbe`) into `linux-modules-extra`, NOT the
  base kernel package. Both test envs need physical PCI passthrough
  (`setup.sh` WAN/loss PF) or SR-IOV VFs (`cluster-setup.sh` mlx5 VFs). Without
  `linux-modules-extra`, those interfaces never bind → total test failure.
  bake.py already HARD-ASSERTS this dir exists (`bake.py:227-228`,
  `…/drivers/net/ethernet/mellanox`); the test VM must install the package the
  baked image gets via `linux-generic`. Mirror bake.py's assertion as a
  provisioning check.
- `linux-perf` → `linux-tools-generic` (the Ubuntu equivalent for the running
  kernel; `linux-perf` is Debian-only).
- **DROP `golang`** (AGY r1 #5 + SMR F5). The VM never compiles Go — `make
  build` runs on the HOST and `test-deploy` pushes the binary
  (`setup.sh:376-401`). `golang` is ~500 MB of pure provisioning waste. Also
  re-examine `build-essential clang llvm libbpf-dev` — these were for the
  legacy in-VM eBPF build deleted in #1476; if nothing in-VM compiles BPF now,
  drop them too (probe-confirm at impl; conservative default is to keep clang
  for ad-hoc debugging but drop golang for certain).
- **`host` → `bind9-host`** (Codex r1 #3). The Debian `host` binary ships in
  `bind9-host` on Ubuntu resolute. Either rename, or drop (it's a debug
  convenience; `getent`/`resolvectl` cover most needs).
- Cluster-only extras present in `cluster-setup.sh:459`: `frr-pythontools`,
  `ethtool` — both exist on Ubuntu with identical names (confirm in simulate).
- Everything else (`tcpdump iproute2 iperf3 bpftool frr strongswan
  strongswan-swanctl kea-dhcp4-server kea-dhcp6-server chrony mtr-tiny pciutils
  curl wget ripgrep`) exists on Ubuntu 26.04 with identical names.
- **Validation (MANDATORY before merge, Codex r1 #3):** §8 step-2 runs
  `apt-get install --simulate` against the **exact full standalone list AND the
  exact full cluster list** on the probe VM — not a spot-check. Every rename
  (`linux-headers-generic`, `linux-modules-extra-generic`, `linux-tools-generic`,
  `bind9-host`, golang dropped) is confirmed to resolve. Do not assume any name.

### 6.4 UEFI Secure-Boot profile + the A4 substrate reality (revised r2)

**Critical correction from the production code walk:** the #1930 A4 channel is
implemented in `pkg/upgrade/kernel_run.go` and its `preflight()` (`:140-200`)
requires, on the *running system*:
- `IsUEFI()` true,
- `EfibootmgrOK()` (efibootmgr present + can R/W NVRAM),
- BOTH A/B boot slots already registered (the first-boot registration oneshot
  `xpf-uefi-slots` must have run),
- `GrubSubmenuDisabled()` (`GRUB_DISABLE_SUBMENU` + `/etc/grub.d/09_xpf`),
- watchdog status (D1 strict vs D2 best-effort).

The promote mechanism is **`efibootmgr --bootnext <inactive-slot>`** (one-shot
BootNext that the firmware clears before launch), **NOT** `grub-reboot` /
`GRUB_DEFAULT=saved`. The plan's r1 wording ("grub-reboot one-shot") was wrong;
the canonical mechanism is BootNext + the A/B ESP slot dirs staged by bake.py
(`bake.py:322-377`: `xpf-uefi-slots`, `09_xpf`, two fixed A/B ESP slot dirs each
carrying signed shim+grub).

**Consequence:** a plain `images:ubuntu/26.04` cloud VM does NOT contain the
A/B-slot substrate, `09_xpf`, or the `xpf-uefi-slots` registration oneshot —
those are baked by `bake.py`. Therefore the A4 promote/rollback chain can only
be **faithfully** validated on a VM booted from the **baked qcow2 (Path V2)**,
not on a vanilla cloud VM with Secure-Boot merely toggled on. A vanilla SB VM
proves only "OVMF + shim→grub→kernel boots and the AF_XDP shim still loads under
Secure-Boot" — useful, but it is NOT the A4 channel test.

So the secureboot work splits into two distinct deliverables:
1. **SB on the default/standalone VM** (`security.secureboot` explicit in the
   `xpf-vm` profile) — proves shim→grub→kernel + AF_XDP-shim-under-SB. Cheap,
   prod-faithful posture. This is Path-SB1.
2. **A baked-image boot-path VM** (Path V2) — `incus image import` the
   `bake.py` output qcow2, launch it, and exercise the real A4
   BootNext promote/rollback. This is the only thing that actually closes the
   #1930 "validate A4 in-lab" gap. Document it as `make test-vm-baked` (or a
   `XPF_BAKED_IMAGE=<path>` toggle in setup.sh).

**incus secureboot knob:**
```sh
# in create_vm_profile YAML config:
config:
  security.secureboot: "true"   # OVMF + shim signature enforcement (prod posture)
```

**EFI varstore lifecycle footgun (AGY r1 #4 + SMR F4 — MEDIUM):** incus VM EFI
vars persist across *soft reboots* (so a single BootNext one-shot survives the
candidate boot — A4 works within one VM lifetime). BUT `make test-destroy &&
make test-vm` deletes the instance's nvram/varstore on the host, wiping any
enrolled MOK and the registered A/B Boot#### entries. The plan must:
- Document that A4 boot-path runs happen within ONE VM lifetime (don't
  destroy/recreate mid-test), and
- The baked-image VM's `xpf-uefi-slots` first-boot oneshot re-registers the A/B
  slots on each fresh provision, so a recreate self-heals the slot entries; only
  manually-enrolled MOK keys (if any) need re-enrollment. Confirm in §8 whether
  the baked image's shim is signed by a key already in the OVMF default DB
  (Canonical/MS) — if so, no per-cycle MOK enrollment is needed at all. SB1 uses
  the distro-signed shim, so MOK enrollment is likely a non-issue; verify.

Decision on profile shape: Path-SB1 (single SB-on profile) — see §7.

### 6.5 CLAUDE.md
- Line 69: `make test-vm  # Create Ubuntu 26.04 VM with FRR, strongSwan`.
- "Test Environment (Incus VM)" section: note Ubuntu 26.04 parity with bake.py,
  the `XPF_BASE_RELEASE` pin, and the secureboot toggle for boot-path work.
- Sweep for any other "Debian 13" / "Debian-13" strings (grep found only
  line 69 in CLAUDE.md; re-sweep at impl).

## 7. Multiple Path Options (where the design branches)

### Path-V — image source (HOW to get Ubuntu 26.04)
- **V1 (RECOMMENDED): `images:ubuntu/26.04/cloud` from linuxcontainers.**
  Zero new infra, available today, cloud-init enabled. Risk: a *different*
  image stream than cloud-images.ubuntu.com (the bake.py base) — kernel/package
  baseline may differ slightly. Mitigated by the §4 kernel probe + §6.2 floor
  assertion.
- **V2: import the baked production qcow2 as an incus image.** Maximum fidelity
  (literally the shipped appliance), exercises the real boot path natively, no
  package/kernel drift at all. Cost: requires a fresh `bake.py` run (libguestfs,
  RLIMIT_MEMLOCK, ~minutes) before every `make test-vm` refresh, and the baked
  image enables Secure-Boot + factory posture (empty root pw, console-only)
  which complicates `incus exec`-based provisioning the test scripts rely on.
  **Best for boot-path validation; too heavy as the default dev VM.**
- **V3: thin cloud-images.ubuntu.com cloudimg via `incus image import` of the
  upstream `.img`.** Exactly bake.py's base, but needs a download+import step
  the scripts don't have today.
- **Recommendation:** V1 for the default `make test-vm`. **V2 is REQUIRED (not
  optional) for any #1930 A4 boot-path validation** — the A/B-slot substrate
  (`09_xpf`, `xpf-uefi-slots`, A/B ESP dirs) and the BootNext promote mechanism
  exist only in the baked image; a vanilla SB cloud VM cannot exercise A4
  (confirmed via `pkg/upgrade/kernel_run.go` preflight + `bake.py:322-377`).
  V1 + SB1 proves only "shim→grub→kernel boots + AF_XDP shim loads under SB."

### Path-K — kernel (conditional, §4-gated)
- **K1 (RECOMMENDED if probe >= 6.18): delete the Debian-unstable dance**,
  keep a floor assertion. Simplest; test == prod kernel provenance.
- **K2 (fallback if probe < 6.18): Ubuntu mainline/HWE kernel.** Add the Ubuntu
  mainline-PPA or `linux-generic-hwe-26.04` install instead of the Debian
  unstable repo. Strictly worse than K1; only if V1's stream lags.

### Path-C — cluster realignment scope
- **C1 (RECOMMENDED): realign BOTH standalone and cluster** to Ubuntu 26.04 in
  the same work. The cluster `cluster-setup.sh` has the identical Debian-13
  image + kernel dance; leaving it Debian creates a *second* drift and the loss
  cluster is where smoke actually runs. Realigning both is the parity the issue
  title implies and avoids "fixed standalone, cluster still drifts."
  Risk: the loss cluster is the smoke-gating env; a botched cluster realign
  blocks all smoke. Mitigation: land standalone first, validate, then cluster
  as a separate reviewed increment; keep `IMAGE_VM` env-overridable so a
  rollback to `images:debian/13` is a one-liner.
- **C2: standalone only (minimum to close #1943).** The issue body is
  explicitly scoped to the standalone VM. Cluster realign could be a follow-up
  issue. Lower blast radius, but leaves known drift.
- **Recommendation:** C1 as two sequential increments (standalone PR validated,
  then cluster), OR C2 + a filed follow-up if the reviewer prefers minimal
  blast radius on the smoke-gating env. **This is the main decision for the
  user at /engineer time.**

### Path-SB — secureboot profile shape
- **SB1 (RECOMMENDED): explicit `security.secureboot: "true"` in the default
  VM profile + documented `make test-vm`** (Secure-Boot is the production
  posture; default-on matches prod and adds no perf cost). EFI varstore
  persistence is automatic for incus VMs.
- **SB2: separate `xpf-vm-secureboot` profile + `XPF_SECUREBOOT=1` toggle**,
  default profile stays Secure-Boot-off for the perf VM. Keeps boot-path
  experiments isolated. More moving parts.
- **Recommendation:** SB1 — production runs Secure-Boot, the test VM should
  too; one profile, prod-faithful.

## 8. Test / validation plan (manual, in-lab; no CI change)

1. **Kernel probe (GATE):** `incus launch images:ubuntu/26.04/cloud probe --vm`
   → `uname -r` >= 6.18? Records the K-path decision (K1 vs K2).
2. **Package probe:** dry `apt-get install --simulate` the full REVISED tooling
   list (with `linux-headers-generic`, `linux-modules-extra-generic`,
   `linux-tools-generic`, golang dropped) on the probe VM; confirm every name
   resolves. Adjust §6.3 names per result.
3. **NIC-driver probe (GATE for SR-IOV/passthrough):** confirm
   `/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/{mellanox,intel}`
   exist after installing `linux-modules-extra-generic` (mirror
   `bake.py:227-228`). Without this both test envs fail to bring up dataplane
   NICs.
4. **init_on_alloc verify:** after the grub.d drop-in + reboot, confirm
   `init_on_alloc=0` is in `/proc/cmdline` on the actual V1 image (SMR F1 —
   the linuxcontainers stream may differ from cloud-images.ubuntu.com).
5. **Standalone bring-up:** `make test-destroy && make test-vm && make
   test-deploy`; confirm xpfd loads the AF_XDP shim (verifier-gated) and
   forwards (the verifier floor is the whole reason this matters).
6. **Functional smoke:** existing `make test-connectivity` / standalone
   connectivity passes on the Ubuntu VM.
7. **Secure-Boot + lockdown validation (SMR F3):** boot the SB1 VM, run xpfd,
   confirm the AF_XDP shim loads + forwards with Secure-Boot active. Check
   `dmesg | grep lockdown` / `/sys/kernel/security/lockdown` — confirm no
   out-of-tree kernel module load is refused (the shim is BPF
   `BPF_PROG_TYPE_XDP`, not a signed module, so this should pass; AGY r1 (4)
   independently confirms SB does not block XDP-type BPF). If anything breaks,
   fall back to Path-SB2 (toggle, default-off).
8. **A4 boot-path validation (the real #1930 payoff — requires Path V2):**
   `bake.py` → `incus image import` the qcow2 → launch → confirm
   `xpf-uefi-slots` registered both A/B slots, then exercise A4: arm
   `efibootmgr --bootnext <inactive>` for a candidate kernel → reboot → confirm
   firmware booted the candidate and cleared BootNext → promote-on-success;
   and the rollback path (candidate fails → next reboot returns to known-good
   slot via firmware BootOrder). Done WITHIN ONE VM LIFETIME (destroy wipes the
   varstore — §6.4). HW-watchdog early-hang stays bench/manual.
9. **Cluster (if C1) — must RECREATE, not just deploy (Codex r1 #5):**
   `IMAGE_VM` is consumed only at VM-create time (`cluster-setup.sh:334`);
   `make cluster-deploy` only builds + pushes binaries (`Makefile:256`) and will
   NOT pick up the image change. C1 validation therefore requires a locked
   `cluster-destroy && cluster-create` (or rolling replace one node at a time to
   preserve HA) on the loss userspace cluster, re-applying CoS config, then
   fast smoke + `make test-failover` green. This is the high-risk step — it
   takes the smoke-gating cluster down — which is exactly why C1 is sequenced
   AFTER the standalone PR validates (§7 Path-C).

## 9. Risks & mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `images:ubuntu/26.04` stream ships kernel < 6.18 | High (blocks shim) | §4 GATE probe before deleting dance; Path-K2 fallback |
| **`linux-modules-extra` missing → mlx5/i40e NICs never bind → total test failure** | **High** | §6.3 ADD `linux-modules-extra-generic`; §8 step-3 driver-dir assert mirroring `bake.py:227` (AGY r1 #1, Codex r1 #2) |
| Package name deltas break provisioning (`golang`, `linux-perf`, `host`) | Med | §6.3 renames + drop golang; §8 step-2 simulate the FULL standalone+cluster lists (AGY #5, Codex #3) |
| `init_on_alloc=0` inactive — dropped reboot OR cloudimg override | Med | keep a post-grub reboot (AGY #2); grub.d drop-in form; §8 step-4 verify `/proc/cmdline` on the actual V1 stream (SMR F1) |
| Cluster realign breaks smoke-gating env | High | C1 as separate post-standalone increment; recreate (not deploy) under cluster lock + rolling replace (Codex #5) |
| Secure-Boot enforcement rejects the AF_XDP shim or unsigned modules | Med | shim is BPF `BPF_PROG_TYPE_XDP`, not a signed module — AGY r1 (4) confirms SB allows XDP-type BPF; §8 step-7 confirms under lockdown; SB2 toggle isolates if it breaks |
| A4 channel NOT exercisable on a vanilla SB cloud VM (no A/B substrate) | Med | A4 validation requires Path V2 (baked qcow2 with `xpf-uefi-slots`/`09_xpf`/A/B ESP dirs); §6.4 + §8 step-8 |
| EFI varstore wiped on `test-destroy` → A/B Boot#### entries + MOK lost | Med | A4 runs within ONE VM lifetime; `xpf-uefi-slots` re-registers slots on fresh provision; confirm distro-signed shim needs no MOK (§6.4, AGY #4) |
| Rollback assumed runtime env-override (FALSE once Ubuntu pkg names land) | Med | rollback is `git revert` of the tooling commit, documented in §10 (AGY #3, Codex #6) |
| linuxcontainers `images:` stream lags cloud-images.ubuntu.com | Low | V2 (import baked qcow2) gives exact prod fidelity for boot-path runs |

## 10. Rollback / blast radius

Pure test-env tooling — zero customer/runtime blast radius (no production
artifact, no shipped image, no deploy path changes).

**Rollback is `git revert` of the setup-script + CLAUDE.md diff — NOT a runtime
env-override (r1 fallacy, AGY #3 + SMR).** Once the scripts carry Ubuntu package
names (`linux-headers-generic`, `linux-modules-extra-generic`,
`linux-tools-generic`) and drop the Debian-unstable kernel dance,
`IMAGE_VM=images:debian/13 make test-vm` would FAIL: those package names don't
exist on Debian, and Debian 13's stock kernel is < 6.18 so the AF_XDP shim
verifier floor (`pkg/dataplane/verify_userspace_shim.go`) rejects the dataplane.
The image var stays overridable for *pinning a different Ubuntu release*
(`XPF_BASE_RELEASE`), not for cross-distro fallback. If true dual-distro support
were ever wanted it would require OS-conditional package/kernel branches in the
scripts — explicitly out of scope here (the whole point is to STOP supporting
Debian in test). `git revert` of the tooling commit is the rollback.

## 11. Recommendation summary (for /engineer)

- **V1** (`images:ubuntu/26.04/cloud`) default; **V2** (baked qcow2) documented
  for boot-path validation.
- **K1** (drop Debian dance + floor assert) gated on the §4 probe; **K2** only
  if the probe regresses.
- **C1** (realign both) as two sequential increments — standalone PR first,
  cluster second — OR **C2** + follow-up if the user wants minimal smoke-env
  risk. *User decides at /engineer.*
- **SB1** (default Secure-Boot-on VM profile, prod-faithful).
- Update **CLAUDE.md** test-env section + line 69.
- No production code; `install.sh` already accepts Ubuntu.

**Net:** low-blast-radius tooling realignment. The real footguns, all surfaced
+ mitigated above, are: (a) **`linux-modules-extra` omission** (would silently
break SR-IOV/passthrough NICs — the highest-impact finding); (b) the
linuxcontainers kernel-stream floor (probe-gated); (c) package renames
(`linux-headers/tools-generic`, `bind9-host`, drop `golang`) verified by a
full simulate; (d) keep a reboot so `init_on_alloc=0` actually applies; (e) the
grub.d override quirk; (f) A4 validation needs the **baked image (V2)**, not a
vanilla SB cloud VM; (g) rollback is `git revert`, not a runtime env-override.

---

## 12. Review status

| Round | Reviewer | Verdict |
|-------|----------|---------|
| r1 | Codex (gpt-5.5, xhigh) | PLAN-NEEDS-WORK — 6 findings (A4 overclaim/grub-reboot-vs-bootnext, modules-extra, package audit, grub reboot, cluster recreate-not-deploy, pinning/rollback) |
| r1 | AGY (adversarial-review-mqhsj7h5-33m3ob) | PLAN-NEEDS-WORK — 5 findings (modules-extra, reboot, rollback fallacy, EFI varstore lifecycle, drop golang) |
| r1 | Claude SMR | PLAN-NEEDS-WORK (minor) — 6 findings (grub-stream probe, V1-fidelity wording, SB+lockdown, destroy-path, vestigial toolchain, pin-drift) |

**r2 resolves all of the above.** Convergent themes across all three reviewers:
(1) `linux-modules-extra` is mandatory (AGY+Codex independently); (2) keep a
reboot for the grub change (AGY+Codex); (3) rollback is git-revert not
env-override (AGY+Codex); (4) A4 needs the baked substrate + the mechanism is
`efibootmgr BootNext` not `grub-reboot` (Codex+SMR); (5) drop `golang`
(AGY+SMR). No reviewer recommended PLAN-KILL — all three judged the direction
correct and the issue worth doing.

r2 re-review dispatched after this revision; convergence verdicts recorded in
`reviewer-ids.md` and the issue comment.
