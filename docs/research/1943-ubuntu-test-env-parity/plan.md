# Plan of action — #1943: Realign standalone test env to production parity (Ubuntu 26.04)

- **Issue:** #1943 — Test env drift: standalone test VM is Debian 13 but
  production is Ubuntu 26.04.
- **Revision:** r1 (draft, pre-review)
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
   `bake.py`'s base (version-pinnable the same way bake.py pins:
   `XPF_BASE_RELEASE`, default auto-latest).
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
| `test/incus/setup.sh` | `IMAGE_VM/IMAGE_CT` → Ubuntu 26.04 (pinnable); pkg names; conditional kernel dance removal; secureboot profile knob |
| `test/incus/cluster-setup.sh` | same image + pkg + kernel changes (if cluster realign chosen — see Path-C decision §7) |
| `CLAUDE.md` | "Test Environment (Incus VM)" section + line 69 + any Debian-13 refs |
| `docs/research/1943-ubuntu-test-env-parity/plan.md` | this doc (research branch only) |

No `.go`, `.rs`, `proto`, or shipped-`scripts/dist`/`scripts/image` source is
edited. (`scripts/image/bake.py` is already Ubuntu — it is the *reference*, not
a change target.)

## 6. Detailed change design (recommended path)

### 6.1 Image base + version pinning (setup.sh)
Replace the two hardcoded constants with an env-pinnable selector that mirrors
bake.py's `XPF_BASE_RELEASE` contract:

```sh
XPF_BASE_RELEASE="${XPF_BASE_RELEASE:-26.04}"      # pin; matches bake.py default intent
IMAGE_VM="images:ubuntu/${XPF_BASE_RELEASE}/cloud"
IMAGE_CT="images:ubuntu/${XPF_BASE_RELEASE}/cloud"
```

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
**delete** the Debian-unstable repo + pin + `linux-image-amd64` install + the
dedicated kernel-reboot loop (`setup.sh:287-300`). Replace with a hard
assertion mirroring bake.py:

```sh
kver=$(incus exec "$INSTANCE_NAME" -- uname -r)
# fail loudly if base regressed below the AF_XDP verifier floor
dpkg --compare-versions "${kver%%-*}" ge 6.18 || die "base kernel $kver < 6.18"
```

The `init_on_alloc=0` grub tuning stays, but switches from the Debian
`sed /etc/default/grub` form to the Ubuntu-cloudimg-safe **grub.d drop-in**
form that bake.py already uses (`bake.py:78-87` `GRUB_DROPIN`) — Ubuntu cloud
images override `GRUB_CMDLINE_LINUX_DEFAULT` in
`/etc/default/grub.d/50-cloudimg-settings.cfg`, so a sed on `/etc/default/grub`
is silently lost. This is a real Ubuntu footgun the Debian script does not hit.

### 6.3 Package names (setup.sh:281, cluster-setup.sh:459)
Delta Debian→Ubuntu for the test-tooling install line:
- `linux-image-amd64 linux-headers-amd64` → `linux-headers-generic` (headers
  for the running `-generic` kernel; the image already has the kernel).
- `golang` → confirm name on 26.04 (`golang-go` is the canonical Ubuntu
  metapackage; `golang` is a valid alias in recent Ubuntu — verify in probe).
- Everything else (`build-essential clang llvm libbpf-dev tcpdump iproute2
  iperf3 bpftool frr strongswan strongswan-swanctl kea-dhcp4-server
  kea-dhcp6-server chrony mtr-tiny linux-perf host pciutils curl wget
  ripgrep`) exists on Ubuntu 26.04 with identical names. `linux-perf` →
  confirm (`linux-tools-generic` is the Ubuntu equivalent; `linux-perf` may be
  a transitional package). These two (`golang`, `linux-perf`) are the only
  at-risk names — probe-verify both.

### 6.4 UEFI Secure-Boot profile (new)
Add a secureboot-capable VM profile variant. incus VMs default to OVMF with
`security.secureboot: "true"`. The standalone profile (`setup.sh
create_vm_profile`) should expose this explicitly and add an opt-in env switch:

```sh
# in create_vm_profile YAML config:
config:
  security.secureboot: "true"   # OVMF + shim signature enforcement
```

To make the #1930 A4 chain testable, the profile must:
- Boot OVMF in Secure-Boot mode (default true; make it explicit + documented).
- Persist EFI vars (incus VM root disk includes the OVMF varstore by default —
  confirm A/B ESP slot writes + `grub-reboot` survive a reboot, which is the
  whole point of the #1930 channel).

Add a documented `make test-vm-secureboot` path or `XPF_SECUREBOOT=1 make
test-vm` toggle so boot-path work selects it without disturbing the default
perf-test VM (Secure-Boot adds no perf cost but the explicit profile makes the
intent reviewable). Decision deferred to a Path-SB option in §7.

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
- **Recommendation:** V1 for the default `make test-vm`; offer V2 as the
  documented path for #1930-class boot-path validation (it IS the appliance).

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
   → `uname -r` >= 6.18? Records the K-path decision.
2. **Package probe:** dry `apt-get install --simulate` the full tooling list on
   the probe VM; confirm `golang`/`golang-go` and `linux-perf`/
   `linux-tools-generic` resolve. Adjust §6.3 names per result.
3. **Standalone bring-up:** `make test-destroy && make test-vm && make
   test-deploy`; confirm xpfd loads the AF_XDP shim (verifier-gated) and
   forwards (the verifier floor is the whole reason this matters).
4. **Functional smoke:** existing `make test-connectivity` / standalone
   connectivity passes on the Ubuntu VM.
5. **Secure-Boot validation (the #1930 payoff):** boot the Secure-Boot VM,
   confirm shim→grub→kernel chain boots; if V2/baked-image, exercise the A4
   one-shot promote (`grub-reboot` candidate → reboot → boots candidate →
   promote-on-success) and rollback (candidate fails verify → next reboot
   returns to default). HW-watchdog early-hang stays bench/manual.
6. **Cluster (if C1):** `make cluster-deploy` on the loss userspace cluster +
   fast smoke green before considering cluster realign done.

## 9. Risks & mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| `images:ubuntu/26.04` stream ships kernel < 6.18 | High (blocks shim) | §4 GATE probe before deleting dance; Path-K2 fallback |
| Package name deltas break provisioning (`golang`, `linux-perf`) | Med | §8 step-2 simulate-probe; correct names before merge |
| `init_on_alloc=0` lost via /etc/default/grub sed on Ubuntu cloudimg | Med | switch to grub.d drop-in (bake.py form) — §6.2 |
| Cluster realign breaks smoke-gating env | High | C1 as separate post-standalone increment; env-overridable image for instant rollback |
| Secure-Boot enforcement rejects the AF_XDP shim or unsigned modules | Med | shim is kernel-*verifier*-gated, not module-signed; confirm no out-of-tree module load under SB; if it breaks, SB2 (toggle) isolates it |
| linuxcontainers `images:` stream lags cloud-images.ubuntu.com | Low | V2 (import baked qcow2) gives exact prod fidelity for boot-path runs |
| EFI varstore not persisted → A/B slot / grub-reboot state lost | Med | confirm incus VM varstore persistence in §8 step-5; this is core to #1930 channel |

## 10. Rollback / blast radius

Pure test-env tooling. Rollback is `git revert` of the setup-script + CLAUDE.md
diff, or even simpler at runtime: `IMAGE_VM=images:debian/13 make test-vm`
(image is env-overridable in the proposed design). No production artifact, no
shipped image, no deploy path changes. Zero customer/runtime blast radius.

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

**Net:** low-risk tooling realignment whose only real footguns are (a) the
linuxcontainers kernel-stream floor (probe-gated), (b) two package names, and
(c) the Ubuntu-cloudimg grub.d override quirk — all surfaced above with
mitigations.
