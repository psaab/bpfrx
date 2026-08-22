#!/usr/bin/env python3
"""Hermetic tests for the #6500 image-inventory format.

`scripts/dist/image_inventory.py` is the ONE definition of a format with two
readers: bake.py WRITES it (in-guest, POSIX sh, then reads it back out with
virt-cat) and publish.py READS it to gate a release. A divergence between
those is always a bug, which is why the format is single-sourced rather than
duplicated — and why the writer is tested by RUNNING it, not by inspecting its
text. A writer whose quoting is wrong produces a valid-looking empty file:
bake.py's neighbouring apt-mark fragment aborted every bake twice during #1926
for exactly that, once from an unexpanded `${Package}` and once from
`dpkg-query -W` returning never-installed names.

The parser's job is to REFUSE a hollow record rather than return one. A
present-but-empty inventory satisfies a presence check and answers no
question — strictly worse than an absent one, because it argues against
anyone re-examining it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import image_inventory as inv  # noqa: E402

KVER = "7.0.0-15-generic"


def _record(kernel=KVER, npkgs=inv.MIN_PACKAGES, header=True, packages_line=True):
    lines = []
    if header:
        lines.append(inv.HEADER)
    if kernel is not None:
        lines.append(f"{inv.KERNEL_KEY}: {kernel}")
    if packages_line:
        lines.append(inv.PACKAGES_KEY)
    lines += [f"pkg{i}=1.0-{i}" for i in range(npkgs)]
    return "\n".join(lines) + "\n"


class ParseTests(unittest.TestCase):
    def test_a_well_formed_record_round_trips(self):
        kern, pkgs = inv.parse(_record())
        self.assertEqual(kern, KVER)
        self.assertEqual(len(pkgs), inv.MIN_PACKAGES)
        self.assertIn("pkg0=1.0-0", pkgs)

    def test_empty_text_is_refused(self):
        with self.assertRaises(inv.InventoryError):
            inv.parse("")
        with self.assertRaises(inv.InventoryError):
            inv.parse("   \n\n")

    def test_no_kernel_line_is_refused(self):
        with self.assertRaises(inv.InventoryError) as c:
            inv.parse(_record(kernel=None))
        self.assertIn(inv.KERNEL_KEY, str(c.exception))

    def test_blank_kernel_value_is_refused(self):
        with self.assertRaises(inv.InventoryError):
            inv.parse(_record(kernel=""))

    def test_a_hollow_package_list_is_refused(self):
        # The record exists, names a kernel, and answers nothing about
        # packages. It must NOT parse as an inventory.
        with self.assertRaises(inv.InventoryError) as c:
            inv.parse(_record(npkgs=3))
        self.assertIn("collapsed", str(c.exception))

    def test_exactly_the_floor_passes(self):
        _, pkgs = inv.parse(_record(npkgs=inv.MIN_PACKAGES))
        self.assertEqual(len(pkgs), inv.MIN_PACKAGES)

    def test_one_below_the_floor_is_refused(self):
        with self.assertRaises(inv.InventoryError):
            inv.parse(_record(npkgs=inv.MIN_PACKAGES - 1))

    def test_malformed_package_lines_do_not_count(self):
        # A line with an empty name or empty version is not a package record;
        # counting it would let a corrupt file clear the floor.
        text = (f"{inv.HEADER}\n{inv.KERNEL_KEY}: {KVER}\n{inv.PACKAGES_KEY}\n"
                + "=1.0\n" * 200)
        with self.assertRaises(inv.InventoryError):
            inv.parse(text)

    def test_comments_and_blank_lines_are_ignored(self):
        text = _record().replace(inv.PACKAGES_KEY,
                                 f"# a comment\n\n{inv.PACKAGES_KEY}")
        kern, pkgs = inv.parse(text)
        self.assertEqual(kern, KVER)
        self.assertEqual(len(pkgs), inv.MIN_PACKAGES)

    def test_guest_kernel_helper_agrees_with_parse(self):
        self.assertEqual(inv.guest_kernel(_record()), inv.parse(_record())[0])

    def test_sidecar_name(self):
        self.assertEqual(inv.sidecar_name("1.2.3"), "xpf-1.2.3.pkgs")


@unittest.skipUnless(shutil.which("dpkg-query"),
                     "dpkg-query not available (non-Debian host)")
class WriteCommandTests(unittest.TestCase):
    """RUN the in-guest writer and parse what it produced.

    virt-customize hands `--run-command` to the guest's `sh -c` — exactly one
    shell layer — so running the same string through a local `sh -c` has the
    same quoting semantics. Only the two absolute paths are re-rooted; the
    dpkg-query format string, the installed-only filter, and the non-vacuity
    check are the shipped bytes.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-inv-write."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "etc" / "xpf").mkdir(parents=True)
        (self.tmp / "lib" / "modules" / KVER).mkdir(parents=True)

    def _run(self):
        cmd = (inv.WRITE_CMD
               .replace("/etc/xpf", f"{self.tmp}/etc/xpf")
               .replace("ls /lib/modules", f"ls {self.tmp}/lib/modules"))
        return subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)

    def test_the_writer_produces_a_record_the_parser_accepts(self):
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        body = (self.tmp / "etc" / "xpf" / "image-inventory").read_text()
        kern, pkgs = inv.parse(body)
        self.assertEqual(kern, KVER)
        # A real dpkg database has far more than the floor; this is the
        # assertion the quoting bug would break (a bad format string yields a
        # file of blank lines, which parses to zero packages).
        self.assertGreater(len(pkgs), inv.MIN_PACKAGES)
        self.assertTrue(all("=" in p for p in pkgs))

    def test_every_recorded_package_is_actually_installed(self):
        # The ${db:Status-Status} filter: dpkg-query -W matches every package
        # dpkg knows OF, including purged and never-installed names.
        self._run()
        body = (self.tmp / "etc" / "xpf" / "image-inventory").read_text()
        _, pkgs = inv.parse(body)
        installed = subprocess.run(
            ["dpkg-query", "-W", "-f=${db:Status-Status} ${Package}\n"],
            capture_output=True, text=True).stdout
        real = {ln.split()[1] for ln in installed.splitlines()
                if ln.startswith("installed ")}
        recorded = {p.split("=", 1)[0] for p in pkgs}
        self.assertEqual(recorded - real, set(),
                         "the writer recorded packages that are not installed "
                         "— the ${db:Status-Status} filter is not applied")

    def test_no_kernel_in_lib_modules_fails_the_bake(self):
        shutil.rmtree(self.tmp / "lib" / "modules" / KVER)
        res = self._run()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("no kernel in /lib/modules", res.stderr)


if __name__ == "__main__":
    unittest.main()
