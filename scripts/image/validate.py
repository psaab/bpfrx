#!/usr/bin/env python3
"""xpf appliance image validation (#1879 Path C), in Python.

Boots the baked artifacts under LOCAL incus (instances xpf-image-* —
never the shared loss cluster) and proves the first-boot contract:

  a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0 DHCP,
     sshd listening, in-guest `xpfd verify-dataplane` PASSES against the
     image's own kernel (the bake gate), AND the #1930 LANE-1 A/B kernel
     channel actually came up in the guest (#6494): both slots registered
     with their own signed shim and reachable in BootOrder, and both
     first-boot oneshots ran clean.
  b  valid day-0 drive -> config validated + installed + committed at first
     boot (hostname applied); a reboot does NOT re-apply (stamp).
  c  invalid day-0 drive -> commit-check REJECT logged, nothing installed,
     boot survives, factory bootstrap still reachable; THEN the operator
     swaps in a VALID drive and reboots and the config now applies (the
     fix->reboot->applied retry contract, #4209 H-9 / pairs with H-1).
  d  resized disk (#1925) -> first-boot root auto-grow fills a LARGER root
     disk (partition + ext4), stamps, is idempotent on reboot, and leaves the
     ESP/boot substrate intact; a control boot at the bake size is a clean
     no-op.
  e  cluster node-id drive (#4209 H-9) -> a node-id=1 day-0 drive persists
     /etc/xpf/node-id=1, boots into cluster mode, and (with >=3 NICs) the
     daemon assigns the node-1 vSRX names em0 + ge-7/0/N (FPC 7).
  q  libvirt/plain-QEMU bootability (#4209 H-9) -> the SAME qcow2 the docs
     sell for "libvirt/KVM, plain QEMU" is a valid, non-corrupt qcow2 of at
     least the bake floor (always), and — gated on qemu-system-x86_64 +
     /dev/kvm + OVMF — actually boots under direct QEMU with the day-0 config
     on a cdrom (the cdrom day-0 attach path incus never exercises).

Usage:
  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|d|e|q|all]
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts", "dist"))
import make_config_drive  # noqa: E402
import sign  # noqa: E402  (#1924 signed-distribution helper)

ALIAS = "xpf-image-validate"

# The bake provisions an 8 GiB root disk (see scripts/image/bake.py); a qcow2
# whose virtual size is below this floor is truncated / an incomplete artifact
# that no hypervisor could boot correctly.
BAKE_MIN_BYTES = 8 * 1024 ** 3

# Scenario registry — the single source of truth for the CLI choices AND the
# dispatch map, so a new scenario is wired in one place and is introspectable
# by the hermetic unit test (test_validate_scenarios.py). "q" (QEMU) and "e"
# (node-id) are the #4209 H-9 additions.
SCENARIO_METHODS = {
    "a": "scenario_a", "b": "scenario_b", "c": "scenario_c",
    "d": "scenario_d", "e": "scenario_e", "q": "scenario_qemu",
}
SCENARIO_ORDER = ["a", "b", "c", "d", "e", "q"]

# Preference order: a NON-secboot OVMF_CODE first so shim->grub->kernel boots
# without needing MOK enrollment in the firmware var store (the shipped image
# is Secure-Boot-signed, but plain-QEMU bootability is proven fine with SB off).
_OVMF_CODE_CANDIDATES = (
    "/usr/share/OVMF/OVMF_CODE_4M.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
    "/usr/share/qemu/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
    "/usr/share/OVMF/OVMF_CODE.secboot.fd",
)
_OVMF_VARS_CANDIDATES = (
    "/usr/share/OVMF/OVMF_VARS_4M.fd",
    "/usr/share/OVMF/OVMF_VARS.fd",
    "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    "/usr/share/qemu/OVMF_VARS.fd",
)


def _qemu_img_verdict(imginfo, min_bytes):
    """Pure verdict over `qemu-img info --output=json` output: is this a
    bootable qcow2 of at least `min_bytes` virtual size? Returns (ok, reason).
    Split out so the config-level bootability check is unit-testable without a
    real image (#4209 H-9)."""
    fmt = imginfo.get("format")
    if fmt != "qcow2":
        return False, (f"image format is {fmt!r}, not qcow2 — libvirt/plain-QEMU "
                       "consume the qcow2 export")
    vsize = imginfo.get("virtual-size")
    if not isinstance(vsize, int) or vsize < min_bytes:
        return False, (f"virtual-size {vsize} below the {min_bytes}-byte bake floor "
                       "— truncated / incomplete image")
    return True, f"qcow2, virtual-size {vsize / (1024 ** 3):.1f}GiB"


# ── #1930 LANE-1 A/B slot registration (#6494) ────────────────────────
# The bake STAGES /boot/efi/EFI/{xpf-A,xpf-B} and ENABLES xpf-uefi-slots.service
# + xpf-kernel-promote.service, and hard-asserts the signed shim is there. What
# it cannot assert offline is the half that only happens in-guest: UEFI Boot####
# variables live in the target's firmware NVRAM, which virt-customize cannot
# write, so registration is a first-boot oneshot on the real machine.
#
# That oneshot is deliberately NON-FATAL on every failure path ("degraded, not
# bricked" — a read-only/no-efivars platform must still boot), and nothing
# downstream re-read its outcome. So a regression in the ESP disk/part parse,
# the loader-path match, or the efibootmgr write shipped a fully "validated"
# image whose verify-gated kernel channel was silently unavailable, and the
# operator discovered it only when `xpfd upgrade kernel arm` exited 2 with "A/B
# slots not both registered ... the first-boot registration oneshot must run
# first" (pkg/upgrade/kernel_run.go ErrKernelChannelUnavailable).
#
# A gate for a production appliance image should prove the upgrade substrate it
# ships, not only the files that substrate is made of.
#
# The slots the #1930 channel requires. Both must exist; the channel refuses to
# arm unless BOTH are registered, so one is as unavailable as none.
_AB_SLOTS = ("xpf-A", "xpf-B")

# An efibootmgr entry line is "BootXXXX[*]<space>LABEL<TAB>loader-path". The
# label is followed by a TAB and the path, NOT line-end — anchoring at $ is the
# miss that created duplicate slots live during #1930. Mirrors the shell regex
# in scripts/image/xpf-uefi-slots register_slot() on purpose: the gate must
# agree with the script about what "registered" means, or it certifies a state
# the script would not accept.
_EFIBOOT_ENTRY_RE = re.compile(
    r"^Boot([0-9A-Fa-f]{4})\*?[ \t]+(?P<label>\S+)[ \t]+(?P<rest>.*)$")
_BOOTORDER_RE = re.compile(r"^BootOrder:\s*(?P<order>\S*)\s*$", re.MULTILINE)


def _efibootmgr_slot_verdict(out, slots=_AB_SLOTS):
    """Pure verdict over `efibootmgr` (or `efibootmgr -v`) output: are BOTH
    #1930 A/B slots registered exactly once, each pointing at its own signed
    shim, and both reachable in BootOrder? Returns (ok, reason).

    Split out from the scenario so the acceptance criterion is unit-testable
    without a hypervisor, in the _qemu_img_verdict idiom (#4209 H-9).

    Three separate properties, reported separately, because they have three
    different causes:
      - exactly once  -> a duplicate means the registration guard's label match
                         missed (the #1930 live bug); a duplicate ALSO poisons
                         BootNext, since which Boot#### the slot means is then
                         ambiguous.
      - loader path   -> an entry that merely shares the LABEL but points
                         elsewhere chainloads the wrong loader.
      - in BootOrder  -> a slot the firmware will never reach is registered but
                         unusable, which is not "registered" in any sense the
                         kernel channel can act on.
    """
    ids = {}          # slot -> [Boot#### ids with the RIGHT loader path]
    wrong_path = {}   # slot -> [rendered lines whose path does not match]
    for line in out.splitlines():
        m = _EFIBOOT_ENTRY_RE.match(line.rstrip())
        if not m:
            continue
        label = m.group("label")
        if label not in slots:
            continue
        # efibootmgr prints "...File(\EFI\xpf-A\shimx64.efi)" or the bare
        # "...\EFI\xpf-A\shimx64.efi". Match the slot's shim path with any
        # separator between the components and case-insensitively, exactly as
        # the shell guard does (grep -qiE "EFI.${slot}.shimx64\.efi").
        want = re.compile(r"EFI.%s.shimx64\.efi" % re.escape(label), re.IGNORECASE)
        if want.search(m.group("rest")):
            ids.setdefault(label, []).append(m.group(1))
        else:
            wrong_path.setdefault(label, []).append(line.strip())

    problems = []
    for slot in slots:
        got = ids.get(slot, [])
        if not got:
            bad = wrong_path.get(slot)
            if bad:
                problems.append(
                    f"{slot}: registered but the loader path is NOT "
                    f"\\EFI\\{slot}\\shimx64.efi ({bad!r}) — it would chainload "
                    "the wrong loader")
            else:
                problems.append(
                    f"{slot}: NOT registered — the first-boot xpf-uefi-slots "
                    "oneshot did not create it (LANE-1 kernel channel "
                    "unavailable on this image)")
        elif len(got) > 1:
            problems.append(
                f"{slot}: registered {len(got)} times ({', '.join(got)}) — a "
                "duplicated slot makes BootNext ambiguous")

    mo = _BOOTORDER_RE.search(out)
    if mo is None:
        problems.append("efibootmgr reported no BootOrder line — cannot prove "
                        "either slot is reachable by the firmware")
    else:
        order = [x for x in mo.group("order").split(",") if x]
        for slot in slots:
            got = ids.get(slot, [])
            if got and not any(i.upper() in (o.upper() for o in order) for i in got):
                problems.append(
                    f"{slot}: registered ({got[0]}) but absent from BootOrder "
                    f"({mo.group('order')!r}) — the firmware would never reach it")

    if problems:
        return False, "; ".join(problems)
    return True, ("both A/B slots registered exactly once with the right shim "
                  "loader and present in BootOrder")


def _oneshot_clean_verdict(name, exec_main_status, active_state, result):
    """Pure verdict over `systemctl show` fields for a first-boot oneshot:
    did it RUN and exit 0? Returns (ok, reason).

    A oneshot with RemainAfterExit=yes reports ActiveState=active after a clean
    run. The distinction that matters is "did not run" vs "ran and failed":
    inactive means a Condition skipped it (the unit was never enabled, or
    ConditionPathExists=/boot/efi did not hold — an image with no ESP), which
    is a DIFFERENT bake defect from a non-zero exit, so they are reported
    separately rather than as one 'not clean'.
    """
    if active_state in ("inactive", "") and result in ("", "success"):
        return False, (f"{name} never ran (ActiveState={active_state!r}) — the "
                       "bake did not enable it, or its Condition did not hold "
                       "on this image")
    if result and result != "success":
        return False, f"{name} failed (Result={result!r}, ExecMainStatus={exec_main_status!r})"
    if exec_main_status not in ("0", 0):
        return False, f"{name} exited {exec_main_status!r}, not 0"
    return True, f"{name} ran clean (ExecMainStatus=0)"


def _find_first(candidates):
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def info(m):
    print(f"==> {m}")


def fail(m):
    print(f"FAIL: {m}", file=sys.stderr)
    sys.exit(1)


def incus(*args, check=True, capture=False):
    return subprocess.run(["incus", *args], check=check,
                          capture_output=capture, text=True)


def guest(inst, *cmd, check=True, capture=False):
    return subprocess.run(["incus", "exec", inst, "--", *cmd],
                          check=check, capture_output=capture, text=True)


def guest_sh(inst, script):
    """Run a shell snippet in the guest; return True on exit 0."""
    return subprocess.run(["incus", "exec", inst, "--", "sh", "-c", script],
                          capture_output=True, text=True).returncode == 0


class Harness:
    def __init__(self, qcow2, metadata, net, keep, verify_sig=True):
        self.qcow2, self.metadata, self.net, self.keep = qcow2, metadata, net, keep
        # verify_sig: True = verify if a .minisig is present (default),
        # "force" = require one, False = never (dev escape hatch).
        self.verify_sig = verify_sig
        self.created_net = False
        self.instances = []
        self.work = tempfile.mkdtemp(prefix="xpf-validate-")
        # Per-run ownership token (#4905-D). The alias + every instance name is
        # namespaced with it, and every destructive op refuses to touch an
        # object that lacks THIS run's ownership tag — so a concurrent bake or
        # an unrelated same-named VM/image is never force-deleted. process-
        # unique (uuid4) so two `validate.py` runs on one host never collide.
        self.run_id = uuid.uuid4().hex[:8]
        self.alias = f"{ALIAS}-{self.run_id}"
        self.imported_alias = False   # True once WE imported self.alias

    def iname(self, suffix):
        """Run-namespaced instance name for a scenario slot (#4905-D)."""
        return f"xpf-image-{self.run_id}-{suffix}"

    def _owned_delete(self, name):
        """Force-delete instance `name` ONLY if it carries THIS run's ownership
        tag (user.xpf-owner == run_id). Refuses to delete an instance this run
        did not create — a concurrent bake or an unrelated same-named VM
        (#4905-D). A missing instance is a safe no-op."""
        got = incus("config", "get", name, "user.xpf-owner",
                    check=False, capture=True)
        if got.returncode != 0:
            return  # instance does not exist / not queryable — nothing to delete
        owner = (got.stdout or "").strip()
        if owner != self.run_id:
            info(f"refusing to delete instance {name}: ownership tag {owner!r} "
                 f"!= this run {self.run_id!r} (concurrent bake / unrelated VM) "
                 "— #4905-D")
            return
        incus("delete", "-f", name, check=False, capture=True)

    # ── lifecycle ──
    def ensure_network(self):
        # dns.mode=none is REQUIRED, not cosmetic. incus registers one DNS
        # record per instance per managed network, so a second NIC on the same
        # network is refused at device-add time:
        #   Instance DNS name "<inst>" conflict between "extranic0" and "eth0"
        #   because both are connected to same network
        # Scenario e needs three NICs on one network to prove the node-1
        # positional naming (em0 + ge-7/0/N), and scenario d's control leg
        # needs none of the DNS records. Turning DNS off keeps DHCP — which is
        # all any scenario consumes — and removes the conflict.
        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
            info(f"creating validation network {self.net} (NAT + DHCP, no DNS)")
            incus("network", "create", self.net, "ipv4.address=10.199.99.1/24",
                  "ipv4.nat=true", "ipv6.address=none", "dns.mode=none")
            self.created_net = True
        else:
            # A network left behind by an earlier run (or a concurrent bake)
            # may predate this setting. Idempotent, and harmless to a
            # concurrent run: no scenario resolves an instance by DNS.
            incus("network", "set", self.net, "dns.mode=none", check=False,
                  capture=True)

    def verify_signatures(self):
        """Verify the EXACT qcow2 + metadata files against the signed
        per-version manifest sitting next to them (#1924 §5.2). Per-file:
        each artifact's hash is checked against the signed manifest entry for
        its basename. Default ON when a .minisig is present; --no-verify-sig
        opts out for a local dev bake that skipped signing."""
        if not self.verify_sig:
            return
        sigdir = os.path.dirname(os.path.abspath(self.qcow2))
        import glob
        manifests = sorted(glob.glob(os.path.join(sigdir, "*.SHA256SUMS")))
        sigs = [m for m in manifests if os.path.isfile(m + ".minisig")]
        if not sigs:
            if self.verify_sig == "force":
                fail("--verify-sig forced but no signed *.SHA256SUMS.minisig "
                     f"found next to {self.qcow2}")
            info("no signed manifest next to the artifacts — skipping "
                 "signature verification (dev bake; use --verify-sig to force)")
            return
        # Bind BOTH consumed files to the SAME signed manifest (AGY-A3): a
        # mismatched pair (qcow2 from v2's manifest, metadata from v1's) must
        # NOT pass. Find the single manifest that authenticates both; if none
        # does, fail.
        chosen = None
        last_err = None
        for manifest in sigs:
            sig = manifest + ".minisig"
            try:
                sign.verify_image_artifact(self.qcow2, manifest, sig)
                sign.verify_image_artifact(self.metadata, manifest, sig)
                chosen = manifest
                break
            except sign.SignError as e:
                last_err = e
        if not chosen:
            fail("image signature verification FAILED — no single signed "
                 f"manifest authenticates both {os.path.basename(self.qcow2)} and "
                 f"{os.path.basename(self.metadata)}: {last_err}")
        info(f"signature OK: {os.path.basename(self.qcow2)} + "
             f"{os.path.basename(self.metadata)} (manifest {os.path.basename(chosen)})")

    def import_image(self):
        self.verify_signatures()
        # self.alias is run-namespaced, so a concurrent bake using the default
        # `xpf-image-validate` alias is NOT clobbered (#4905-D). The pre-delete
        # only targets our own unique alias (idempotent within a run).
        incus("image", "delete", self.alias, check=False, capture=True)
        info(f"importing image into local incus as {self.alias}")
        incus("image", "import", self.metadata, self.qcow2, "--alias", self.alias)
        self.imported_alias = True   # cleanup may now delete THIS alias (#4905-D)

    def launch(self, name, iso=None, root_size=None, extra_nics=0):
        # Ownership-gated pre-delete (#4905-D): only reclaim a same-named
        # instance if it is one WE created (it won't normally exist — the name
        # is run-namespaced).
        self._owned_delete(name)
        # Tag the instance with this run's ownership token so drop()/cleanup()
        # can prove it is ours before force-deleting (#4905-D).
        incus("init", self.alias, name, "--vm", "--network", self.net,
              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB",
              "-c", f"user.xpf-owner={self.run_id}", capture=True)
        # Register for teardown IMMEDIATELY after init, not after the device
        # adds below. The instance exists and carries this run's ownership tag
        # from the moment init returns; registering later meant any failure
        # between here and the end of launch() (a refused device add, a bad
        # ISO path) left a VM behind that cleanup could not see, because
        # cleanup only walks self.instances.
        self.instances.append(name)
        if root_size:
            # Override the instance's root disk to a size LARGER than the
            # image (#1925 Scenario D). `device override root` materializes an
            # instance-local copy of the profile's root device so size= sticks
            # before the VM ever boots — the operator-resized-disk case.
            incus("config", "device", "override", name, "root",
                  f"size={root_size}", capture=True)
        # Additional NICs beyond the default fxp0 slot, so the daemon's
        # positional namer has em0 (idx 1) + ge-*/0/* (idx >= 2) to assign —
        # required to prove the cluster node-id naming (#4209 H-9 scenario e).
        for i in range(extra_nics):
            incus("config", "device", "add", name, f"extranic{i}", "nic",
                  f"network={self.net}", capture=True)
        if iso:
            incus("config", "device", "add", name, "day0", "disk",
                  f"source={os.path.realpath(iso)}", capture=True)
        incus("start", name)
        self.wait_agent(name)

    def drop(self, name):
        if not self.keep:
            self._owned_delete(name)   # ownership-gated (#4905-D)
            if name in self.instances:
                self.instances.remove(name)

    def cleanup(self):
        if self.keep:
            print(f"keeping instances {self.instances}, alias {self.alias}, "
                  f"network {self.net}")
            # Retain the per-run scratch dir under --keep too (codex-182
            # A10-b03-C01). Scenarios B/C/E/Q write config files and day-0
            # ISOs under self.work and attach those HOST paths to the
            # instances. Deleting self.work while keeping the VMs leaves each
            # retained instance referencing a source that can no longer be
            # reopened on a later restart/inspection/reproduction — the exact
            # forensic environment --keep was asked to preserve. Print the
            # path so the operator can find the retained media.
            print(f"keeping work dir {self.work} (day-0 media / config drives)")
            return
        for i in self.instances:
            self._owned_delete(i)   # ownership-gated (#4905-D)
        # Only delete the alias if WE imported it this run, and only the
        # run-namespaced name — never a bystander's `xpf-image-validate`
        # (#4905-D).
        if self.imported_alias:
            incus("image", "delete", self.alias, check=False, capture=True)
        # created_net already gates the network delete to one WE created.
        if self.created_net:
            incus("network", "delete", self.net, check=False, capture=True)
        subprocess.run(["rm", "-rf", self.work], check=False)

    # ── waiters ──
    def _wait(self, name, pred, tries, secs, what):
        for _ in range(tries):
            if pred():
                return
            time.sleep(secs)
        fail(f"{name}: {what}")

    def wait_agent(self, name):
        self._wait(name, lambda: guest(name, "true", check=False, capture=True).returncode == 0,
                   80, 3, "incus agent not ready after 240s")

    def wait_xpfd(self, name):
        self._wait(name, lambda: guest(name, "systemctl", "is-active", "--quiet", "xpfd",
                                       check=False, capture=True).returncode == 0,
                   40, 3, "xpfd not active after 120s")

    def wait_fxp0_dhcp(self, name):
        self._wait(name, lambda: guest_sh(name, 'ip -4 addr show fxp0 2>/dev/null | grep -q "inet "'),
                   30, 3, "fxp0 has no IPv4 DHCP address after 90s")

    # ── scenarios ──
    def scenario_a(self):
        info("── Scenario A: first boot, NO config drive ──")
        a = self.iname("a")   # run-namespaced instance name (#4905-D)
        self.launch(a)
        self.wait_xpfd(a)
        kver = guest(a, "uname", "-r", capture=True).stdout.strip()
        info(f"guest kernel: {kver}")
        rel = kver.split("-")[0]
        if not _kver_ge(rel, (6, 18)):
            fail(f"guest kernel {kver} < 6.18")
        if not guest_sh(a, 'uname -r | grep -q -- -generic'):
            fail("running kernel is not the -generic flavor")
        if not guest_sh(a, 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox"'):
            fail("linux-modules-extra (mlx5/i40e driver set) missing")
        if not guest_sh(a, '[ "$(ls /lib/modules | wc -l)" -eq 1 ]'):
            fail("more than one kernel in /lib/modules — stale cloudimg kernel not purged")
        if not guest_sh(a, 'grep -qw init_on_alloc=0 /proc/cmdline'):
            fail("init_on_alloc=0 missing from the booted kernel cmdline")
        info("in-guest verify-dataplane (the bake gate, image kernel)...")
        if guest(a, "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
                 check=False).returncode != 0:
            fail("in-guest verify-dataplane REJECTED — image must not ship")
        # #7114: the appliance marker is what re-enables the factory
        # fxp0-DHCP bootstrap on this artifact. The bake purges cloud-init and
        # netplan, so on a no-config-drive boot xpfd's #1922 lifeline finds no
        # default route; without the marker it declines to touch any NIC and
        # the port below stays DOWN and unrenamed. Assert the marker FIRST so a
        # bake that stopped writing it fails with its own cause instead of as
        # the downstream "fxp0 has no address" timeout.
        if not guest_sh(a, 'test -f /etc/xpf/appliance'):
            fail("/etc/xpf/appliance missing — the bake did not write the #7114 "
                 "appliance-image marker; xpfd will hold the factory boot in the "
                 "console-only bootstrap state (no fxp0, no DHCP)")
        self.wait_fxp0_dhcp(a)
        # #4172: frr-pythontools (/usr/lib/frr/frr-reload.py) MUST be present
        # or every FRR reload silently degrades to the additive `vtysh -f`
        # fallback and stale-config removal never converges (a deleted route
        # keeps forwarding). It is NOT pulled in transitively by `frr`, so
        # assert presence here — package-name drift fails with a clear cause
        # rather than as the downstream "deleted route still active" symptom.
        if not guest_sh(a, 'test -x /usr/lib/frr/frr-reload.py'):
            fail("frr-reload.py missing (/usr/lib/frr/frr-reload.py) — "
                 "frr-pythontools not installed (#4172 FRR reload permanently "
                 "degraded; stale-config removal never converges)")
        if not guest_sh(a, 'ss -tln | grep -q ":22 "'):
            fail("sshd not listening")
        if not guest_sh(a,
                        '/usr/sbin/sshd -T | grep -qxE "permitrootlogin (prohibit-password|without-password|no)"'):
            fail("sshd effective config does not refuse root password auth")
        if not guest_sh(a, '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'):
            fail("sshd effective config does not pin PermitEmptyPasswords no")
        self.assert_ab_kernel_channel(a)
        if guest(a, "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
            fail("unexpected /etc/xpf/xpf.conf")
        if guest(a, "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
            fail("unexpected day-0 stamp")
        if not guest_sh(a,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
            fail("day-0 loader did not log the no-medium fallback")
        info("Scenario A PASS")
        self.drop(a)

    def _show_unit(self, inst, unit, prop):
        """One `systemctl show -p <prop> --value <unit>` field from the guest."""
        return guest(inst, "systemctl", "show", "-p", prop, "--value", unit,
                     check=False, capture=True).stdout.strip()

    def assert_ab_kernel_channel(self, inst):
        """Assert the #1930 LANE-1 A/B kernel-channel substrate actually came
        up IN THE GUEST (#6494) — not merely that the bake staged its files.

        Three things, in the order their failures would be diagnosed:
          1. the registration oneshot ran clean (it is non-fatal by design, so
             its own exit is the only place a failure is recorded at all);
          2. both slots are registered exactly once, with the right shim loader,
             and reachable in BootOrder — the state `xpfd upgrade kernel arm`
             refuses to proceed without;
          3. the promotion gate ran clean on this ordinary boot.

        On (3), note what is NOT asserted: the "promotion gate: clean" line.
        That line is only emitted once the gate has exec'd xpfd to run the
        promote verb. On a factory boot with nothing armed the script exits 0
        much earlier, logging "no armed kernel candidate recorded", so requiring
        the former here would fail every good image. What IS asserted is that
        the unit ran and exited 0, plus the ordinary-boot line, which together
        prove the gate EXECUTED rather than being skipped by a Condition — the
        thing an operator is relying on when they arm a candidate later.
        """
        info("#1930 LANE-1: A/B slot registration + promotion gate...")

        # Both oneshots are WantedBy=multi-user.target and are NOT ordered
        # Before=xpfd (deliberately — a hanging efibootmgr must never block the
        # #1922 mgmt lifeline), so xpfd being active does not imply they have
        # finished. Wait for each to settle rather than racing it.
        for unit in ("xpf-uefi-slots.service", "xpf-kernel-promote.service"):
            self._wait(inst,
                       lambda u=unit: self._show_unit(inst, u, "ActiveState")
                       not in ("activating", "reloading"),
                       40, 3, f"{unit} still activating after 120s")

        ok, reason = _oneshot_clean_verdict(
            "xpf-uefi-slots.service",
            self._show_unit(inst, "xpf-uefi-slots.service", "ExecMainStatus"),
            self._show_unit(inst, "xpf-uefi-slots.service", "ActiveState"),
            self._show_unit(inst, "xpf-uefi-slots.service", "Result"))
        if not ok:
            jrn = guest(inst, "journalctl", "-u", "xpf-uefi-slots", "-b",
                        "--no-pager", check=False, capture=True).stdout
            fail(f"#1930 A/B slot registration: {reason}\n{jrn[-800:]}")

        got = guest(inst, "efibootmgr", check=False, capture=True)
        if got.returncode != 0:
            fail("efibootmgr failed in the guest "
                 f"(rc={got.returncode}: {(got.stderr or '').strip()!r}) — the "
                 "#1930 A/B kernel channel needs it to register the slots, so "
                 "an image where it is absent or cannot read NVRAM ships with "
                 "LANE-1 permanently unavailable")
        ok, reason = _efibootmgr_slot_verdict(got.stdout)
        if not ok:
            fail("#1930 A/B slot registration FAILED in-guest: " + reason +
                 "\n--- efibootmgr ---\n" + got.stdout)
        info(f"  slots OK: {reason}")

        ok, reason = _oneshot_clean_verdict(
            "xpf-kernel-promote.service",
            self._show_unit(inst, "xpf-kernel-promote.service", "ExecMainStatus"),
            self._show_unit(inst, "xpf-kernel-promote.service", "ActiveState"),
            self._show_unit(inst, "xpf-kernel-promote.service", "Result"))
        if not ok:
            jrn = guest(inst, "journalctl", "-u", "xpf-kernel-promote", "-b",
                        "--no-pager", check=False, capture=True).stdout
            fail(f"#1930 promotion gate: {reason}\n{jrn[-800:]}")
        if not guest_sh(inst,
                        'journalctl -u xpf-kernel-promote -b --no-pager '
                        '| grep -q "no armed kernel candidate recorded"'):
            fail("#1930 promotion gate did not log the ordinary-boot path "
                 "(\"no armed kernel candidate recorded\") — it exited 0 without "
                 "reaching its decision, so an armed candidate would go "
                 "unverified on a later boot")
        info("  promotion gate ran clean on this ordinary boot")

    def scenario_b(self):
        info("── Scenario B: first boot WITH valid day-0 config drive ──")
        b = self.iname("b")   # run-namespaced instance name (#4905-D)
        conf = os.path.join(self.work, "day0-valid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-b;\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-valid.iso"),
                                                   validate=False)
        self.launch(b, iso)
        self.wait_xpfd(b)
        if guest(b, "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode != 0:
            fail("day-0 stamp missing")
        if guest(b, "test", "-s", "/etc/xpf/xpf.conf", check=False).returncode != 0:
            fail("/etc/xpf/xpf.conf missing")
        if not guest_sh(b,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("day-0 loader did not log the install")
        self._wait(b,
                   lambda: guest_sh(b,
                                    'echo "show configuration" | /usr/local/sbin/cli 2>/dev/null '
                                    '| grep -q "host-name xpf-day0-b"'),
                   20, 3, "committed config does not show host-name xpf-day0-b")
        if not guest_sh(b, '[ "$(hostname)" = xpf-day0-b ]'):
            fail("hostname not applied")
        info(f"rebooting {b} — second boot must NOT re-apply...")
        incus("restart", b)
        self.wait_agent(b)
        self.wait_xpfd(b)
        if not guest_sh(b,
                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("second boot re-applied the day-0 config")
        if not guest_sh(b,
                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
            fail("second boot: day-0 loader neither condition-skipped nor stamp-skipped")
        info("Scenario B PASS")
        self.drop(b)

    def scenario_c(self):
        info("── Scenario C: first boot WITH INVALID day-0 config drive ──")
        c = self.iname("c")   # run-namespaced instance name (#4905-D)
        conf = os.path.join(self.work, "day0-invalid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-invalid.iso"),
                                                   validate=False)
        self.launch(c, iso)
        self.wait_xpfd(c)
        if not guest_sh(c,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
            fail("day-0 loader did not log the commit-check REJECT")
        if guest(c, "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
            fail("invalid config was installed")
        if guest(c, "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
            fail("stamp written on REJECT")
        self.wait_fxp0_dhcp(c)
        if not guest_sh(c, '[ "$(hostname)" != xpf-day0-c ]'):
            fail("invalid config changed the hostname")
        info("Scenario C reject leg PASS (fallback reachable, boot survived)")

        # ── Retry leg (#4209 H-9, pairs with H-1): the REJECT wrote no stamp
        # and left no committed active.json, so the box is still factory-
        # default. Swap the bad drive for a VALID one and reboot — the day-0
        # loader must re-probe and apply it. A regression that guarded on the
        # bare .configdb directory (H-1) would have declared "already
        # configured" here and never retried. ──
        info("C retry: swapping in a VALID drive and rebooting...")
        good = os.path.join(self.work, "day0-c-fixed.conf")
        with open(good, "w") as f:
            f.write("system {\n    host-name xpf-day0-c-fixed;\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        good_iso = make_config_drive.build_config_drive(
            good, os.path.join(self.work, "day0-c-fixed.iso"), validate=False)
        # Replace the day0 medium in place, then reboot.
        incus("config", "device", "remove", c, "day0", capture=True)
        incus("config", "device", "add", c, "day0", "disk",
              f"source={os.path.realpath(good_iso)}", capture=True)
        incus("restart", c)
        self.wait_agent(c)
        self.wait_xpfd(c)
        if guest(c, "test", "-e", "/etc/xpf/.day0-config-applied",
                 check=False).returncode != 0:
            fail("retry: day-0 stamp missing after fix+reboot — the retry "
                 "contract is broken (a rejected first boot could never be fixed)")
        if not guest_sh(c,
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q '
                        '"day-0 config installed"'):
            fail("retry: day-0 loader did not install the fixed config on reboot")
        self._wait(c,
                   lambda: guest_sh(c, '[ "$(hostname)" = xpf-day0-c-fixed ]'),
                   20, 3, "retry: fixed hostname xpf-day0-c-fixed not applied")
        info("Scenario C PASS (reject survived, fix+reboot applied — retry contract)")
        self.drop(c)

    def _root_fs_gib(self, name):
        """Total size of the root filesystem in GiB (float), via df."""
        out = guest(name, "sh", "-c",
                    "df -B1 --output=size / | tail -n1", capture=True).stdout.strip()
        return int(out) / (1024.0 ** 3)

    def _root_part_gib(self, name):
        """Total size of the partition backing / in GiB (float), via lsblk
        on the resolved root source device — proves the PARTITION grew, not
        just the fs."""
        src = guest(name, "sh", "-c", "findmnt -no SOURCE /",
                    capture=True).stdout.strip()
        out = guest(name, "sh", "-c",
                    f"lsblk -bno SIZE {src} | head -n1", capture=True).stdout.strip()
        return int(out) / (1024.0 ** 3)

    def scenario_d(self):
        info("── Scenario D: first-boot root auto-grow on a resized disk (#1925) ──")
        d = self.iname("d")     # run-namespaced instance names (#4905-D)
        d2 = self.iname("d2")

        # ── Grow case: provision a root disk LARGER than the 8 GiB bake. ──
        info("D1 grow: launching with a 20GiB root disk (bake is 8GiB)...")
        self.launch(d, root_size="20GiB")
        self.wait_xpfd(d)
        # growpart + resize2fs MUST survive the cloud-init purge + autoremove
        # (#1925); a missing tool makes the grow a permanent no-op. Assert
        # presence first so package-name drift fails here with a clear cause
        # rather than as the downstream "partition still 8GiB" symptom.
        if not guest_sh(d, 'command -v growpart >/dev/null'):
            fail("growpart missing in the image — cloud-guest-utils not installed "
                 "(#1925 grow would no-op; the cloud-init purge orphaned it)")
        if not guest_sh(d, 'command -v resize2fs >/dev/null'):
            fail("resize2fs missing in the image — e2fsprogs not installed (#1925)")
        if not guest_sh(d, 'systemctl is-active --quiet xpf-grow-root'):
            fail("xpf-grow-root.service is not active after first boot")
        if guest(d, "test", "-e", "/etc/xpf/.root-grown",
                 check=False).returncode != 0:
            fail("root-grow stamp /etc/xpf/.root-grown missing after grow")
        part = self._root_part_gib(d)
        fs = self._root_fs_gib(d)
        info(f"D1 grow: root partition {part:.1f}GiB, filesystem {fs:.1f}GiB")
        # The 20GiB disk minus the small ESP/BIOS/BOOT partitions leaves the
        # root partition well above the 8GiB bake floor; assert it grew past a
        # conservative midpoint so a no-grow regression (still ~8GiB) fails.
        if part < 15.0:
            fail(f"root partition only {part:.1f}GiB on a 20GiB disk — did not grow")
        if fs < 15.0:
            fail(f"root filesystem only {fs:.1f}GiB on a 20GiB disk — resize2fs did not run")
        # The grow must not have disturbed the dataplane gate.
        if guest(d, "nice", "-n", "19", "/usr/local/sbin/xpfd",
                 "verify-dataplane", check=False).returncode != 0:
            fail("verify-dataplane REJECTED after root grow")
        # Boot/ESP partitions intact: exactly the root partition grew, the
        # partition count is unchanged, and the ESP is still mounted.
        if not guest_sh(d, 'mountpoint -q /boot/efi'):
            fail("ESP (/boot/efi) not mounted after grow — boot substrate disturbed")

        # ── Idempotency: reboot must NOT re-grow / re-stamp. ──
        info("D1 idempotency: rebooting — second boot must skip the grow...")
        incus("restart", d)
        self.wait_agent(d)
        self.wait_xpfd(d)
        if not guest_sh(d,
                        'systemctl show -p ConditionResult xpf-grow-root | grep -q '
                        '"ConditionResult=no"'):
            fail("second boot did not condition-skip xpf-grow-root (stamp ineffective)")
        part2 = self._root_part_gib(d)
        if abs(part2 - part) > 0.1:
            fail(f"root partition changed across reboot ({part:.1f} -> {part2:.1f}GiB)")
        info("D1 PASS (grew once, idempotent on reboot, boot substrate intact)")
        self.drop(d)

        # ── Control (no-op) case: bake-size disk must boot clean, no grow. ──
        info("D2 control: launching at the exact bake size (no resize)...")
        self.launch(d2)
        self.wait_xpfd(d2)
        # The grow ran (one-shot fired) but was a no-op: growpart NOCHANGE +
        # resize2fs no-op. The stamp is written either way (clean exit), and
        # the box boots clean with the dataplane gate green.
        if guest(d2, "test", "-e", "/etc/xpf/.root-grown",
                 check=False).returncode != 0:
            fail("root-grow stamp missing on the control (no-op) boot")
        if not guest_sh(d2,
                        'journalctl -u xpf-grow-root -b --no-pager | '
                        'grep -qiE "NOCHANGE|done"'):
            fail("control boot: xpf-grow-root did not log a no-op grow")
        if guest(d2, "nice", "-n", "19", "/usr/local/sbin/xpfd",
                 "verify-dataplane", check=False).returncode != 0:
            fail("verify-dataplane REJECTED on the control boot")
        info("D2 PASS (clean boot, grow was a no-op at bake size)")
        self.drop(d2)
        info("Scenario D PASS")

    def scenario_e(self):
        info("── Scenario E: cluster node-id day-0 drive (#4209 H-9) ──")
        e = self.iname("e")   # run-namespaced instance name (#4905-D)
        conf = os.path.join(self.work, "day0-node1.conf")
        with open(conf, "w") as f:
            # The `chassis cluster` stanza is REQUIRED, not decoration.
            # /etc/xpf/node-id does NOT select cluster naming: the daemon reads
            # clusterMode from the committed config
            # (namingParamsFromConfig -> cfg.Chassis.Cluster != nil), and
            # hasNodeIDFile() feeds only computeBootClass (bootstrap vs
            # normal). A node-id box with a cluster-less config runs STANDALONE
            # naming by design (#4179). Without this stanza the daemon
            # correctly produces fxp0 + ge-0-0-X and the em0 assertion below
            # can never pass (#7129).
            #
            # authentication-key is mandatory for a cluster stanza to survive
            # the real commit-check gate — the control channel fails OPEN
            # without a PSK. It is a throwaway literal: this VM never peers
            # with anything, and the scenario asserts naming only.
            f.write("system {\n    host-name xpf-node1;\n}\n"
                    "chassis {\n    cluster {\n        node 1;\n"
                    "        peer-address 10.99.12.1;\n"
                    "        authentication-key "
                    "\"xpf-image-validate-scenario-e-not-a-real-key\";\n"
                    "    }\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        # node_id=1 writes a `node-id` file (contents "1") alongside xpf.conf on
        # the drive; the loader persists it to /etc/xpf/node-id and the daemon
        # reads it BEFORE positional naming (fpc=7 for node 1).
        iso = make_config_drive.build_config_drive(
            conf, os.path.join(self.work, "day0-node1.iso"), node_id=1,
            validate=False)
        # Two extra NICs so the namer has em0 (idx 1) and ge-7-0-0 (idx 2).
        self.launch(e, iso, extra_nics=2)
        self.wait_xpfd(e)
        if guest(e, "test", "-e", "/etc/xpf/.day0-config-applied",
                 check=False).returncode != 0:
            fail("node-id drive: day-0 stamp missing")
        # node-id persisted verbatim.
        nid = guest(e, "sh", "-c",
                    "cat /etc/xpf/node-id 2>/dev/null",
                    capture=True).stdout.strip()
        if nid != "1":
            fail(f"/etc/xpf/node-id is '{nid}', expected '1' — node-id not "
                 "persisted from the day-0 drive")
        # Cluster-mode naming: node 1 uses FPC 7. em0 is assigned only in
        # cluster mode (position 2); ge-7/0/0 proves the node-1 FPC branch.
        if not guest_sh(e, 'ip link show em0 >/dev/null 2>&1'):
            fail("em0 not present — daemon did not enter cluster naming mode "
                 "for a node-id-present image")
        # KERNEL link name, not the Junos display name: the namer assigns
        # ge-{FPC}-0-{idx-2}, so `ip link show ge-7/0/0` could never match
        # whatever the daemon did (#7129). `show interfaces terse` is where
        # the slashes live.
        if not guest_sh(e, 'ip link show ge-7-0-0 >/dev/null 2>&1'):
            fail("ge-7-0-0 not present — node-1 FPC-7 positional naming did not "
                 "run (a node-0 image would name it ge-0-0-0)")
        info("Scenario E PASS (node-id=1 persisted, cluster em0 + ge-7-0-N naming)")
        self.drop(e)

    def scenario_qemu(self):
        info("── Scenario Q: libvirt/plain-QEMU bootability (#4209 H-9) ──")
        # ── Config-level probe (always runs when qemu-img is present): the
        # qcow2 the docs sell for libvirt/KVM + plain QEMU must be a valid,
        # non-corrupt qcow2 of at least the bake floor. Catches a truncated /
        # wrong-format / corrupt export that incus import might still accept
        # but a raw qcow2 consumer (libvirt) would refuse. ──
        if not shutil.which("qemu-img"):
            info("SKIP: qemu-img not installed (qemu-utils) — cannot probe the "
                 "qcow2's libvirt bootability")
            return
        raw = subprocess.run(["qemu-img", "info", "--output=json", self.qcow2],
                             capture_output=True, text=True)
        if raw.returncode != 0:
            fail(f"qemu-img info failed on {self.qcow2}: {raw.stderr.strip()}")
        ok, reason = _qemu_img_verdict(json.loads(raw.stdout), BAKE_MIN_BYTES)
        if not ok:
            fail(f"qcow2 is not libvirt-bootable: {reason}")
        info(f"qcow2 structural probe OK: {reason}")
        chk = subprocess.run(["qemu-img", "check", "-q", self.qcow2],
                             capture_output=True, text=True)
        # qemu-img check exits 0 clean, 2/3 on leaked/corrupt clusters.
        if chk.returncode not in (0,):
            fail("qemu-img check reported qcow2 corruption:\n"
                 f"{chk.stdout}{chk.stderr}")
        info("qcow2 consistency check OK (no corruption)")

        # ── Boot leg (gated): actually boot the SAME qcow2 under direct QEMU
        # with a valid day-0 config on a cdrom, and confirm via the serial
        # console that the appliance booted its userland and the day-0 loader
        # applied the config off the cdrom — the plain-QEMU + cdrom-day-0 path
        # incus never exercises. Needs qemu-system + KVM + OVMF; SKIP (probe
        # stands) when any is absent, mirroring the root-required skips. ──
        qsys = shutil.which("qemu-system-x86_64")
        ovmf = _find_first(_OVMF_CODE_CANDIDATES)
        ovmf_vars = _find_first(_OVMF_VARS_CANDIDATES)
        if not qsys or not os.path.exists("/dev/kvm") or not ovmf or not ovmf_vars:
            info("SKIP boot leg: need qemu-system-x86_64 + /dev/kvm + OVMF "
                 f"(qemu={bool(qsys)} kvm={os.path.exists('/dev/kvm')} "
                 f"ovmf_code={bool(ovmf)} ovmf_vars={bool(ovmf_vars)}) — "
                 "the structural probe above stands")
            return
        conf = os.path.join(self.work, "day0-qemu.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-qemu;\n}\n")
        iso = make_config_drive.build_config_drive(
            conf, os.path.join(self.work, "day0-qemu.iso"), validate=False)
        vars_copy = os.path.join(self.work, "OVMF_VARS.fd")
        shutil.copyfile(ovmf_vars, vars_copy)
        serial = os.path.join(self.work, "qemu-serial.log")
        argv = [qsys, "-machine", "q35,accel=kvm", "-cpu", "host",
                "-m", "2048", "-smp", "2", "-nographic",
                "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf}",
                "-drive", f"if=pflash,format=raw,file={vars_copy}",
                # snapshot=on: never mutate the artifact under test.
                "-drive", f"file={self.qcow2},if=virtio,format=qcow2,snapshot=on",
                "-drive", f"file={os.path.realpath(iso)},media=cdrom",
                "-serial", f"file:{serial}", "-nic", "none"]
        info("booting the qcow2 under direct QEMU (serial-captured, snapshot)...")
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.time() + 360
            txt = ""
            while time.time() < deadline:
                if proc.poll() is not None:
                    _, err = proc.communicate()
                    fail(f"QEMU exited early (rc={proc.returncode}): "
                         f"{(err or b'').decode(errors='replace')[-400:]}")
                if os.path.isfile(serial):
                    txt = open(serial, errors="replace").read()
                    if "day-0 config installed" in txt:
                        info("QEMU boot: day-0 config installed off the cdrom")
                        break
                    if "REJECTED by commit-check" in txt:
                        fail("QEMU boot: day-0 loader REJECTED a valid config")
                time.sleep(3)
            else:
                fail("QEMU boot: no 'day-0 config installed' on the serial "
                     f"console within 360s (serial tail:\n{txt[-600:]})")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        info("Scenario Q PASS (qcow2 valid + boots under plain QEMU with cdrom day-0)")


def _kver_ge(ver, floor):
    try:
        parts = tuple(int(x) for x in ver.split(".")[:2])
    except ValueError:
        return False
    return parts >= floor


def maybe_reexec_incus_admin():
    if subprocess.run(["incus", "list"], capture_output=True).returncode == 0:
        return
    import grp
    try:
        in_grp = "incus-admin" in [g.gr_name for g in grp.getgrall()
                                   if os.getlogin() in g.gr_mem]
    except Exception:
        in_grp = False
    if in_grp:
        # Quote every token — a qcow2/metadata path with spaces or shell
        # metacharacters must not break (or inject into) the `sg -c` shell.
        cmd = " ".join(shlex.quote(a) for a in [sys.executable] + sys.argv)
        os.execvp("sg", ["sg", "incus-admin", "-c", cmd])


def main():
    maybe_reexec_incus_admin()
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--qcow2", required=True)
    p.add_argument("--metadata", required=True)
    p.add_argument("--keep", action="store_true")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--verify-sig", dest="verify_sig", action="store_const",
                   const="force", help="require a signed manifest (#1924)")
    g.add_argument("--no-verify-sig", dest="verify_sig", action="store_const",
                   const=False, help="skip image signature verification (dev)")
    p.set_defaults(verify_sig=True)  # default: verify if a .minisig is present
    p.add_argument("scenario", nargs="?", default="all",
                   choices=SCENARIO_ORDER + ["all"])
    a = p.parse_args()
    if not os.path.isfile(a.qcow2):
        fail(f"--qcow2 not found: {a.qcow2}")
    if not os.path.isfile(a.metadata):
        fail(f"--metadata not found: {a.metadata}")
    net = os.environ.get("XPF_VALIDATE_NETWORK", "xpf-image-net")
    h = Harness(a.qcow2, a.metadata, net, a.keep, a.verify_sig)
    try:
        h.ensure_network()
        h.import_image()
        keys = SCENARIO_ORDER if a.scenario == "all" else [a.scenario]
        for k in keys:
            getattr(h, SCENARIO_METHODS[k])()
        info("Validation complete.")
        return 0
    finally:
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
