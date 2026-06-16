#!/usr/bin/env python3
"""xpf appliance image validation (#1879 Path C), in Python.

Boots the baked artifacts under LOCAL incus (instances xpf-image-* —
never the shared loss cluster) and proves the first-boot contract:

  a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0 DHCP,
     sshd listening, AND in-guest `xpfd verify-dataplane` PASSES against
     the image's own kernel (the bake gate).
  b  valid day-0 drive -> config validated + installed + committed at first
     boot (hostname applied); a reboot does NOT re-apply (stamp).
  c  invalid day-0 drive -> commit-check REJECT logged, nothing installed,
     boot survives, factory bootstrap still reachable.

Usage:
  validate.py --qcow2 <img> --metadata <tar.gz> [a|b|c|all]
"""

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts", "dist"))
import make_config_drive  # noqa: E402
import sign  # noqa: E402  (#1924 signed-distribution helper)

ALIAS = "xpf-image-validate"


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

    # ── lifecycle ──
    def ensure_network(self):
        if incus("network", "show", self.net, check=False, capture=True).returncode != 0:
            info(f"creating validation network {self.net} (NAT + DHCP)")
            incus("network", "create", self.net, "ipv4.address=10.199.99.1/24",
                  "ipv4.nat=true", "ipv6.address=none")
            self.created_net = True

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
        incus("image", "delete", ALIAS, check=False, capture=True)
        info(f"importing image into local incus as {ALIAS}")
        incus("image", "import", self.metadata, self.qcow2, "--alias", ALIAS)

    def launch(self, name, iso=None):
        incus("delete", "-f", name, check=False, capture=True)
        incus("init", ALIAS, name, "--vm", "--network", self.net,
              "-c", "limits.cpu=2", "-c", "limits.memory=2GiB", capture=True)
        if iso:
            incus("config", "device", "add", name, "day0", "disk",
                  f"source={os.path.realpath(iso)}", capture=True)
        self.instances.append(name)
        incus("start", name)
        self.wait_agent(name)

    def drop(self, name):
        if not self.keep:
            incus("delete", "-f", name, check=False, capture=True)
            if name in self.instances:
                self.instances.remove(name)

    def cleanup(self):
        if self.keep:
            print(f"keeping instances {self.instances}, alias {ALIAS}, network {self.net}")
        else:
            for i in self.instances:
                incus("delete", "-f", i, check=False, capture=True)
            incus("image", "delete", ALIAS, check=False, capture=True)
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
        self.launch("xpf-image-a")
        self.wait_xpfd("xpf-image-a")
        kver = guest("xpf-image-a", "uname", "-r", capture=True).stdout.strip()
        info(f"guest kernel: {kver}")
        rel = kver.split("-")[0]
        if not _kver_ge(rel, (6, 18)):
            fail(f"guest kernel {kver} < 6.18")
        if not guest_sh("xpf-image-a", 'uname -r | grep -q -- -generic'):
            fail("running kernel is not the -generic flavor")
        if not guest_sh("xpf-image-a", 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox"'):
            fail("linux-modules-extra (mlx5/i40e driver set) missing")
        if not guest_sh("xpf-image-a", '[ "$(ls /lib/modules | wc -l)" -eq 1 ]'):
            fail("more than one kernel in /lib/modules — stale cloudimg kernel not purged")
        if not guest_sh("xpf-image-a", 'grep -qw init_on_alloc=0 /proc/cmdline'):
            fail("init_on_alloc=0 missing from the booted kernel cmdline")
        info("in-guest verify-dataplane (the bake gate, image kernel)...")
        if guest("xpf-image-a", "nice", "-n", "19", "/usr/local/sbin/xpfd", "verify-dataplane",
                 check=False).returncode != 0:
            fail("in-guest verify-dataplane REJECTED — image must not ship")
        self.wait_fxp0_dhcp("xpf-image-a")
        if not guest_sh("xpf-image-a", 'ss -tln | grep -q ":22 "'):
            fail("sshd not listening")
        if not guest_sh("xpf-image-a",
                        '/usr/sbin/sshd -T | grep -qxE "permitrootlogin (prohibit-password|without-password|no)"'):
            fail("sshd effective config does not refuse root password auth")
        if not guest_sh("xpf-image-a", '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'):
            fail("sshd effective config does not pin PermitEmptyPasswords no")
        if guest("xpf-image-a", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
            fail("unexpected /etc/xpf/xpf.conf")
        if guest("xpf-image-a", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
            fail("unexpected day-0 stamp")
        if not guest_sh("xpf-image-a",
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"'):
            fail("day-0 loader did not log the no-medium fallback")
        info("Scenario A PASS")
        self.drop("xpf-image-a")

    def scenario_b(self):
        info("── Scenario B: first boot WITH valid day-0 config drive ──")
        conf = os.path.join(self.work, "day0-valid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-b;\n}\n"
                    "interfaces {\n    fxp0 {\n        unit 0 {\n"
                    "            family inet {\n                dhcp;\n"
                    "            }\n        }\n    }\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-valid.iso"),
                                                   validate=False)
        self.launch("xpf-image-b", iso)
        self.wait_xpfd("xpf-image-b")
        if guest("xpf-image-b", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode != 0:
            fail("day-0 stamp missing")
        if guest("xpf-image-b", "test", "-s", "/etc/xpf/xpf.conf", check=False).returncode != 0:
            fail("/etc/xpf/xpf.conf missing")
        if not guest_sh("xpf-image-b",
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("day-0 loader did not log the install")
        self._wait("xpf-image-b",
                   lambda: guest_sh("xpf-image-b",
                                    'echo "show configuration" | /usr/local/sbin/cli 2>/dev/null '
                                    '| grep -q "host-name xpf-day0-b"'),
                   20, 3, "committed config does not show host-name xpf-day0-b")
        if not guest_sh("xpf-image-b", '[ "$(hostname)" = xpf-day0-b ]'):
            fail("hostname not applied")
        info("rebooting xpf-image-b — second boot must NOT re-apply...")
        incus("restart", "xpf-image-b")
        self.wait_agent("xpf-image-b")
        self.wait_xpfd("xpf-image-b")
        if not guest_sh("xpf-image-b",
                        '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"'):
            fail("second boot re-applied the day-0 config")
        if not guest_sh("xpf-image-b",
                        'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" '
                        '|| journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"'):
            fail("second boot: day-0 loader neither condition-skipped nor stamp-skipped")
        info("Scenario B PASS")
        self.drop("xpf-image-b")

    def scenario_c(self):
        info("── Scenario C: first boot WITH INVALID day-0 config drive ──")
        conf = os.path.join(self.work, "day0-invalid.conf")
        with open(conf, "w") as f:
            f.write("system {\n    host-name xpf-day0-c;\n    dataplane-type ebpf;\n}\n")
        iso = make_config_drive.build_config_drive(conf, os.path.join(self.work, "day0-invalid.iso"),
                                                   validate=False)
        self.launch("xpf-image-c", iso)
        self.wait_xpfd("xpf-image-c")
        if not guest_sh("xpf-image-c",
                        'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"'):
            fail("day-0 loader did not log the commit-check REJECT")
        if guest("xpf-image-c", "test", "-e", "/etc/xpf/xpf.conf", check=False).returncode == 0:
            fail("invalid config was installed")
        if guest("xpf-image-c", "test", "-e", "/etc/xpf/.day0-config-applied", check=False).returncode == 0:
            fail("stamp written on REJECT")
        self.wait_fxp0_dhcp("xpf-image-c")
        if not guest_sh("xpf-image-c", '[ "$(hostname)" != xpf-day0-c ]'):
            fail("invalid config changed the hostname")
        info("Scenario C PASS (fallback reachable, boot survived)")
        self.drop("xpf-image-c")


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
    p.add_argument("scenario", nargs="?", default="all", choices=["a", "b", "c", "all"])
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
        scenarios = {"a": [h.scenario_a], "b": [h.scenario_b], "c": [h.scenario_c],
                     "all": [h.scenario_a, h.scenario_b, h.scenario_c]}[a.scenario]
        for s in scenarios:
            s()
        info("Validation complete.")
        return 0
    finally:
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
