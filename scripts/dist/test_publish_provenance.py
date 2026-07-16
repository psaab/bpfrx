#!/usr/bin/env python3
"""Unit tests for #4904 A — publish REFUSES a --skip-validate (unvalidated)
image.

A `--skip-validate` bake still produces a fully signed manifest/signature set
that is byte-shape-indistinguishable from a validated release, so the
fail-closed publish gate would ship a dev/emergency image that never booted or
verified the dataplane. bake.py now binds a signed `validated: true|false`
field into the xpf-<ver>.manifest provenance sidecar (covered by the signed
xpf-<ver>.SHA256SUMS); publish.gate_provenance REQUIRES validated: true.

These tests build a real minisign-signed image set with a throwaway key (SKIP
if minisign is absent) and drive publish.gate_provenance directly. On revert
(drop the gate / accept validated:false) the negative cases go RED.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("publish", _DIST / "publish.py")
publish = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(publish)

# sign.py sits beside publish.py; publish already puts _DIST on sys.path.
import sign  # noqa: E402

_HAVE_MINISIGN = shutil.which("minisign") is not None
VER = "0.0.0-provtest"


@unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
class GateProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-provtest-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.pub = os.path.join(self.dir, "img.pub")
        self.sec = os.path.join(self.dir, "img.sec")
        subprocess.run(["minisign", "-G", "-W", "-p", self.pub, "-s", self.sec],
                       check=True, capture_output=True)
        # Fake image artifacts.
        self.qcow = os.path.join(self.dir, f"xpf-{VER}.qcow2")
        self.meta = os.path.join(self.dir, f"xpf-{VER}.incus-metadata.tar.gz")
        Path(self.qcow).write_bytes(b"\x00fake-qcow2\x00")
        Path(self.meta).write_bytes(b"\x00fake-meta\x00")
        self.sidecar = os.path.join(self.dir, f"xpf-{VER}.manifest")
        self.sums = os.path.join(self.dir, f"xpf-{VER}.SHA256SUMS")

    def _sign_set(self, validated, base_pinned=True):
        """(Re)write the provenance sidecar with the given validated /
        base_image_pinned flags and sign a manifest covering qcow + meta +
        sidecar (mirrors a real bake).

        `base_pinned=None` omits the base_image_pinned line entirely, modelling
        an old/tampered sidecar that never asserts pinning (#5815 fail-closed
        missing-key case)."""
        text = f"version: {VER}\n"
        if base_pinned is not None:
            text += f"base_image_pinned: {'true' if base_pinned else 'false'}\n"
        text += f"validated: {'true' if validated else 'false'}\n"
        Path(self.sidecar).write_text(text)
        sign.write_manifest(self.sums, [self.qcow, self.meta, self.sidecar])
        sign.sign_manifest(self.sums, self.sec, comment="provtest")

    def test_validated_true_passes(self):
        # Regression guard: a fully-pinned validated bake still publishes
        # (validated:true AND base_image_pinned:true → no regression).
        self._sign_set(validated=True, base_pinned=True)
        # Should not raise.
        publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)

    def test_base_unpinned_refused(self):
        # #5815: a signed sidecar that is otherwise valid (validated:true) but
        # says base_image_pinned:false (an XPF_ALLOW_UNPINNED_BASE=1 dev bake)
        # must NOT publish. RED on revert: drop the base_image_pinned check ->
        # no SystemExit here.
        self._sign_set(validated=True, base_pinned=False)
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_base_pinned_missing_refused(self):
        # #5815 fail-closed: a signed sidecar that never asserts base_image_pinned
        # (old/tampered manifest) is NOT publishable — a sidecar that does not
        # assert pinning must not default-allow.
        self._sign_set(validated=True, base_pinned=None)
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_validated_false_refused(self):
        self._sign_set(validated=False)
        # RED on revert: gate_provenance gone -> no SystemExit here.
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_missing_sidecar_refused(self):
        self._sign_set(validated=True)
        os.remove(self.sidecar)
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)
        self.assertNotEqual(ctx.exception.code, 0)

    def test_unsigned_tampered_sidecar_refused(self):
        # Sidecar hash-covered by the signed manifest, then swapped on disk to
        # say validated:true — verify_listed_artifact_bytes must reject the
        # hash mismatch (TOCTOU-safe), so a post-sign flip cannot slip through.
        self._sign_set(validated=False)
        Path(self.sidecar).write_text(
            f"version: {VER}\nbase_image_pinned: true\nvalidated: true\n")
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_provenance(self.dir, {VER: self.sums}, self.pub)
        self.assertNotEqual(ctx.exception.code, 0)


class ParseManifestFieldsTests(unittest.TestCase):
    def test_parse(self):
        fields = publish._parse_manifest_fields(
            "version: 1.2.3\n# comment\nvalidated: true\n"
            "base_image_pinned: false\nblank\n\n")
        self.assertEqual(fields["validated"], "true")
        self.assertEqual(fields["base_image_pinned"], "false")
        self.assertEqual(fields["version"], "1.2.3")
        self.assertNotIn("# comment", fields)


if __name__ == "__main__":
    unittest.main()
