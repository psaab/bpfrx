#!/usr/bin/env python3
"""Unit tests for the libvirt per-VM disk overlay (fable-165 H-20).

The libvirt deploy path must NOT attach the shared golden qcow2 to a VM
as a writable disk. qcow2 is not a cluster filesystem, so an HA pair
booting two live domains off one file corrupts it, and even a single
`virt-install --import` would mutate the golden master in place (day-0
stamp, host keys, configstore DB baked in). Each domain must instead get
its OWN copy-on-write overlay
(`qemu-img create -f qcow2 -b <golden> -F qcow2 <overlay>`), leaving the
golden an immutable read-only backing store.

These tests drive deploy_libvirt() with a recording runner and assert:
  - an HA pair (fw0, fw1) gets TWO DISTINCT per-VM disk paths;
  - neither VM's writable --disk is the golden image;
  - each VM's overlay is created with the golden as the read-only -b
    backing store;
  - the overlay handed to virt-install is exactly the one qemu-img just
    created;
  - the standalone case also gets its own overlay, never the golden.

On revert (attach `path=.../{image}.qcow2` directly to both domains) the
distinctness and non-golden assertions go RED: both VMs get the same
path and it IS the golden.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy", Path(__file__).with_name("xpf-deploy.py")
)
xpf_deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(xpf_deploy)


class RecordingRunner:
    """Runner that records every argv instead of executing it.

    dry=True so libvirt_disk() skips the host-state golden-exists check
    (there is no real image in a unit test); the recording still captures
    the qemu-img/virt-install argv the code would run.
    """

    def __init__(self):
        self.dry = True
        self.calls = []

    def run(self, argv):
        self.calls.append(list(argv))
        return ""


def _appliance(name, node_id=None):
    ap = {
        "name": name,
        "mode": "cluster" if node_id is not None else "standalone",
        "node_id": node_id,
        "image": "xpf-appliance",
        "cpu": 2,
        "memory": "4G",
        # no "config" -> build_config_drive returns None (no ISO build).
        "interfaces": [
            {"_name": "fxp0", "backing": "bridge", "source": "br-mgmt"},
        ],
    }
    return ap


def _find_call(calls, prog):
    for c in calls:
        if c and c[0] == prog:
            return c
    return None


def _boot_disk_path(virt_install_argv):
    """Return the writable boot --disk path (the one that is not a cdrom)."""
    disks = [virt_install_argv[i + 1]
             for i, a in enumerate(virt_install_argv) if a == "--disk"]
    boot = [d for d in disks if "device=cdrom" not in d]
    assert len(boot) == 1, f"expected exactly one boot disk, got {boot}"
    val = boot[0]
    assert val.startswith("path="), f"unexpected --disk form: {val}"
    return val[len("path="):]


def _qemu_backing_and_overlay(qemu_argv):
    """Return (backing, overlay) from a `qemu-img create ... -b B ... OVERLAY`."""
    backing = qemu_argv[qemu_argv.index("-b") + 1]
    overlay = qemu_argv[-1]  # target is the final positional arg
    return backing, overlay


GOLDEN = f"{xpf_deploy.LIBVIRT_IMAGES}/xpf-appliance.qcow2"


class LibvirtPerVmDiskTests(unittest.TestCase):
    def _deploy(self, ap):
        r = RecordingRunner()
        xpf_deploy.deploy_libvirt(ap, r, start=False)
        virt = _find_call(r.calls, "virt-install")
        qemu = _find_call(r.calls, "qemu-img")
        self.assertIsNotNone(virt, "virt-install was not invoked")
        self.assertIsNotNone(qemu, "qemu-img create was not invoked")
        return virt, qemu

    def test_ha_pair_gets_two_distinct_non_golden_disks(self):
        virt0, qemu0 = self._deploy(_appliance("ha-fw0", node_id=0))
        virt1, qemu1 = self._deploy(_appliance("ha-fw1", node_id=1))

        disk0 = _boot_disk_path(virt0)
        disk1 = _boot_disk_path(virt1)

        # (a) each VM gets a DISTINCT writable disk — the corruption fix.
        self.assertNotEqual(
            disk0, disk1,
            "HA pair must not share one writable qcow2 (image corruption)")

        # (b) neither writable disk is the golden image.
        self.assertNotEqual(disk0, GOLDEN)
        self.assertNotEqual(disk1, GOLDEN)

        # (c) each overlay is backed READ-ONLY by the golden image.
        back0, ov0 = _qemu_backing_and_overlay(qemu0)
        back1, ov1 = _qemu_backing_and_overlay(qemu1)
        self.assertEqual(back0, GOLDEN)
        self.assertEqual(back1, GOLDEN)

        # (d) virt-install attaches exactly the overlay qemu-img created.
        self.assertEqual(disk0, ov0)
        self.assertEqual(disk1, ov1)
        self.assertNotEqual(ov0, ov1)

        # (e) qemu-img creates qcow2 overlays with the qcow2 backing fmt.
        for q in (qemu0, qemu1):
            self.assertEqual(q[:3], ["qemu-img", "create", "-f"])
            self.assertIn("-F", q)
            self.assertEqual(q[q.index("-F") + 1], "qcow2")

    def test_golden_is_never_attached_writable(self):
        # Across BOTH nodes, no virt-install writable --disk is the golden.
        for name, nid in (("ha-fw0", 0), ("ha-fw1", 1)):
            virt, _ = self._deploy(_appliance(name, node_id=nid))
            self.assertNotEqual(_boot_disk_path(virt), GOLDEN)

    def test_standalone_gets_own_overlay(self):
        virt, qemu = self._deploy(_appliance("fw-solo"))
        disk = _boot_disk_path(virt)
        back, overlay = _qemu_backing_and_overlay(qemu)
        self.assertNotEqual(disk, GOLDEN)
        self.assertEqual(back, GOLDEN)
        self.assertEqual(disk, overlay)

    def test_name_equal_image_is_rejected(self):
        # If the VM name equals the golden basename the overlay path would
        # collide with the golden and overwrite it — must hard-fail.
        ap = _appliance("xpf-appliance")  # name == image
        r = RecordingRunner()
        with self.assertRaises(SystemExit):
            xpf_deploy.deploy_libvirt(ap, r, start=False)


if __name__ == "__main__":
    unittest.main()
