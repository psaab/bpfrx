#!/usr/bin/env python3
"""The `--no-import` install digest must be the SIGNED one, not a re-hash (#9170).

`cmd_fetch --no-import` / `--qcow2-only` verifies the downloaded qcow2 against
the signed manifest and then hands the operator a one-liner to run LATER:

    echo '<sha>  <out>/xpf-<ver>.qcow2' | sha256sum -c - && sudo install ...

That `<sha>` used to be produced by `sign.sha256_file(qcow2_pub)` — a SECOND
read of the same public path, taken AFTER the signature check had already
finished. So the printed digest bound "the bytes in --out at print time", not
"the bytes that passed the signature", and the value that should have been
printed had already been computed and thrown away inside
`sign.verify_image_artifact`.

Why that is a real window and not a formality: `--out` is the operator's own
directory and `_verified_private_artifacts`' docstring says of it, in the same
file, "The public --out dir may be writable by another local process". Between
the verify read and the digest read sit a full `verify_manifest_map` ->
`verify_and_read` -> `verify_signature` -> `subprocess.run(minisign)`, two
mkdtemp/rmtree cycles and the watermark `os.replace`. A local process that wins
that window gets its bytes installed AND gets the operator's own
`sha256sum -c` to bless them — the last integrity check before `sudo install`
puts an image on a firewall.

WHY THIS FILE EXISTS SEPARATELY FROM test_xpf_deploy_golden_guard_8597.py.
That file's K08 cell asserted `assertIn("expected_sha", window)` with the
message "the digest must be computed from the verified file". The message named
exactly the property the code lacked; the predicate was a substring the
defective code satisfied, because `expected_sha` was present and merely derived
from the wrong bytes. It was green over the defect for its whole life. A
source-text assertion cannot see where a value came from, so the guard for this
property has to DRIVE the path and read what it printed.

Hermetic: a throwaway minisign keypair, a `file://` base URL, a private
XDG_STATE_HOME, `incus` stubbed out. No network, no incus, no root.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "dist"))

_SPEC = importlib.util.spec_from_file_location(
    "xpf_deploy_9170", _HERE / "xpf-deploy.py")
deploy = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(deploy)

import sign  # noqa: E402

VER = "1.2.3-4-gaaaaaaa"

# The bytes a local dir-writer swaps in AFTER the signature check has passed.
EVIL = b"MALICIOUS-UNAUTHENTICATED-QCOW2-BYTES" * 16

_PRINTED = re.compile(r"echo '([0-9a-f]{64})  (\S+)' \| sha256sum -c -")


@unittest.skipUnless(shutil.which("minisign") and shutil.which("curl"),
                     "minisign and curl are required")
class NoImportDigestIsTheSignedOne9170(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-9170."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        self.pub = self.tmp / "img.pub"
        self.sec = self.tmp / "img.sec"
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)

        self.host = self.tmp / "host"
        self.host.mkdir()
        self.base = self.host.as_uri()
        self.out = self.tmp / "out"
        self.state = self.tmp / "state"

        self._env = {}
        for k, v in (("XPF_IMAGE_PUBKEY", str(self.pub)),
                     ("XDG_STATE_HOME", str(self.state))):
            self._env[k] = os.environ.get(k)
            os.environ[k] = v
        self.addCleanup(self._restore_env)

        self.names = {
            "qcow2": f"xpf-{VER}.qcow2",
            "metadata": f"xpf-{VER}.incus-metadata.tar.gz",
        }
        self.authentic = {n: n.encode() * 64 for n in self.names.values()}
        for n, b in self.authentic.items():
            (self.host / n).write_bytes(b)
        man = self.host / f"xpf-{VER}.SHA256SUMS"
        man.write_text("".join(
            f"{sign.sha256_file(str(self.host / n))}  {n}\n"
            for n in self.names.values()))
        sign.sign_manifest(str(man), str(self.sec), comment="9170 test")

        self.signed_qcow2_sha = hashlib.sha256(
            self.authentic[self.names["qcow2"]]).hexdigest()

        self.incus_calls = []
        self._real_run = deploy.subprocess.run
        deploy.subprocess.run = self._fake_run
        self.addCleanup(self._restore_run)

    # ── harness ──

    def _restore_env(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _restore_run(self):
        deploy.subprocess.run = self._real_run

    def _fake_run(self, cmd, *a, **kw):
        """Let curl through (it is the file:// transport); stub incus."""
        if cmd and cmd[0] == "incus":
            self.incus_calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return self._real_run(cmd, *a, **kw)

    def _args(self, **over):
        ns = argparse.Namespace(
            version=VER, image_url=self.base, out=str(self.out),
            alias=None, channel="stable", allow_rollback=False,
            qcow2_only=False, install_libvirt=False, no_import=False,
            dry_run=False)
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _pub_qcow2(self):
        return self.out / self.names["qcow2"]

    def _swap_public_qcow2_after_its_verify(self):
        """Model the local dir-writer: overwrite the PUBLIC qcow2 the instant
        its signature check returns. Returns the `fired` list so a cell can
        prove the window was actually entered (an unfired hook makes the cell
        vacuous, not passing)."""
        real = sign.verify_image_artifact
        fired = []

        def hooked(path, *a, **kw):
            out = real(path, *a, **kw)
            if os.path.basename(path) == self.names["qcow2"] and not fired:
                fired.append(True)
                self._pub_qcow2().write_bytes(EVIL)
            return out

        sign.verify_image_artifact = hooked
        self.addCleanup(setattr, sign, "verify_image_artifact", real)
        return fired

    def _run_fetch(self, **over):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = deploy.cmd_fetch(self._args(**over))
        return rc, buf.getvalue()

    def _printed(self, text):
        m = _PRINTED.search(text)
        self.assertIsNotNone(
            m, "the --no-import hint no longer prints a "
               "`echo '<sha>  <path>' | sha256sum -c -` line; re-derive this "
               f"cell against what it does print:\n{text}")
        return m.group(1), m.group(2)

    # ── the defect ──

    def test_a_post_verify_swap_does_not_change_the_printed_digest(self):
        """THE DEFECT ROW. The public qcow2 is replaced the moment its
        signature check returns. The digest handed to the operator must still
        be the SIGNED one, so their `sha256sum -c` refuses the swapped bytes.

        Before the fix the printed value is `sha256(EVIL)`: the swap is blessed
        by the operator's own verification command."""
        fired = self._swap_public_qcow2_after_its_verify()
        rc, text = self._run_fetch(no_import=True)
        self.assertEqual(rc, 0)

        self.assertTrue(fired, "the post-verify swap never fired — this cell "
                               "would be vacuous, not passing")
        self.assertEqual(self._pub_qcow2().read_bytes(), EVIL,
                         "the swap did not land on the public path, so nothing "
                         "was actually tested")

        sha, path = self._printed(text)
        self.assertEqual(os.path.realpath(path),
                         os.path.realpath(self._pub_qcow2()),
                         "the printed digest must be bound to the path the "
                         "printed `sudo install` reads")
        self.assertNotEqual(
            sha, hashlib.sha256(EVIL).hexdigest(),
            "#9170: the printed digest is a re-hash of the PUBLIC file taken "
            "after signature verification finished, so a local process that "
            "swapped --out gets its bytes installed AND gets the operator's "
            "own `sha256sum -c` to bless them")
        self.assertEqual(
            sha, self.signed_qcow2_sha,
            "the printed digest must be the value from the SIGNED manifest — "
            "the one the verification established — not any later read of a "
            "path that stays writable after this command exits")

    def test_the_swapped_file_fails_the_printed_check(self):
        """The consequence, end-to-end: run the operator's own command. It must
        REFUSE the swapped file. This is the property the digest exists for,
        and it is not implied by the string comparison above — a fix that
        printed a correct-looking but unrelated digest would pass that one and
        fail this."""
        self._swap_public_qcow2_after_its_verify()
        _, text = self._run_fetch(no_import=True)
        sha, path = self._printed(text)

        r = subprocess.run(["sha256sum", "-c", "-"],
                           input=f"{sha}  {path}\n", text=True,
                           capture_output=True)
        self.assertNotEqual(
            r.returncode, 0,
            "#9170: the operator's `sha256sum -c` ACCEPTED unauthenticated "
            "bytes, because the digest it was given was computed from those "
            "same bytes")

    # ── controls that must still be ACCEPTED ──

    def test_an_untampered_fetch_prints_a_line_that_actually_verifies(self):
        """LOAD-BEARING CONTROL. With no tampering the printed one-liner must
        SUCCEED. `sha256sum -c` is run for real, so a fix that printed a
        constant, a placeholder, or the wrong artifact's digest reds here —
        "refuse everything" does not satisfy this file."""
        rc, text = self._run_fetch(no_import=True)
        self.assertEqual(rc, 0)
        sha, path = self._printed(text)
        self.assertEqual(sha, self.signed_qcow2_sha)

        r = subprocess.run(["sha256sum", "-c", "-"],
                           input=f"{sha}  {path}\n", text=True,
                           capture_output=True)
        self.assertEqual(r.returncode, 0,
                         "an untampered fetch must print a digest the operator "
                         f"can verify; got {r.stdout}{r.stderr}")

    def test_qcow2_only_takes_the_same_path(self):
        """--qcow2-only shares the branch with --no-import, so it must get the
        same digest. It fetches ONLY the qcow2, so it also proves the digest
        does not depend on the metadata artifact being present."""
        rc, text = self._run_fetch(qcow2_only=True)
        self.assertEqual(rc, 0)
        sha, _ = self._printed(text)
        self.assertEqual(sha, self.signed_qcow2_sha)

    def test_the_incus_import_path_is_unaffected(self):
        """POSITIVE CONTROL, sibling path 1. The importing path must still
        import."""
        rc, _ = self._run_fetch()
        self.assertEqual(rc, 0)
        imports = [c for c in self.incus_calls if c[1:3] == ["image", "import"]]
        self.assertEqual(len(imports), 1,
                         "the incus import path stopped publishing")

    def test_the_install_libvirt_path_still_stages_privately(self):
        """POSITIVE CONTROL, sibling path 2. `--install-libvirt` must still
        hand `_install_libvirt_golden` a PRIVATE staged copy (#5817) carrying
        the authentic bytes — not the public path, and not a broken one."""
        seen = []
        real = deploy._install_libvirt_golden
        deploy._install_libvirt_golden = lambda src, name: seen.append(
            (src, Path(src).read_bytes()))
        self.addCleanup(setattr, deploy, "_install_libvirt_golden", real)

        rc, _ = self._run_fetch(install_libvirt=True)
        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1, "the libvirt golden install never ran")
        src, data = seen[0]
        self.assertEqual(data, self.authentic[self.names["qcow2"]])
        self.assertNotEqual(
            os.path.dirname(os.path.realpath(src)),
            os.path.realpath(self.out),
            "#5817: the golden must be installed from the private staging "
            "copy, not from the re-openable public --out path")

    # ── the digest is the manifest's, not any file's ──

    def test_the_digest_survives_deleting_the_public_file(self):
        """The sharpest form of the property: with the public qcow2 REMOVED
        after verification there is no file left to hash, so a re-hash cannot
        produce a digest at all. The printed value must still be the signed
        one, because it came from the manifest."""
        real = sign.verify_image_artifact
        fired = []

        def hooked(path, *a, **kw):
            out = real(path, *a, **kw)
            if os.path.basename(path) == self.names["qcow2"] and not fired:
                fired.append(True)
                os.unlink(self._pub_qcow2())
            return out

        sign.verify_image_artifact = hooked
        self.addCleanup(setattr, sign, "verify_image_artifact", real)

        rc, text = self._run_fetch(no_import=True)
        self.assertTrue(fired, "the unlink hook never fired")
        self.assertEqual(rc, 0,
                         "#9170: the digest is re-derived from the public path, "
                         "so removing that path aborts a fetch whose signature "
                         "check had already succeeded")
        sha, _ = self._printed(text)
        self.assertEqual(sha, self.signed_qcow2_sha)


class VerifyImageArtifactReturnsTheSignedDigest9170(unittest.TestCase):
    """The wiring the fix depends on, pinned at its own layer.

    `verify_image_artifact` returned a bare `True`, discarding the signed
    digest it had just established inside the very call the deploy path makes.
    Returning it is what lets the caller print a value it did not have to
    re-read a file to get."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-9170-sign."))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.pub = self.tmp / "k.pub"
        self.sec = self.tmp / "k.sec"
        if not shutil.which("minisign"):
            self.skipTest("minisign is required")
        subprocess.run(["minisign", "-G", "-W", "-p", str(self.pub),
                        "-s", str(self.sec)], check=True, capture_output=True)
        self.art = self.tmp / "artifact.bin"
        self.art.write_bytes(b"authentic-bytes" * 32)
        self.man = self.tmp / "SHA256SUMS"
        self.man.write_text(
            f"{sign.sha256_file(str(self.art))}  artifact.bin\n")
        sign.sign_manifest(str(self.man), str(self.sec), comment="9170")
        self.sig = str(self.man) + ".minisig"

    def test_it_returns_the_signed_digest(self):
        got = sign.verify_image_artifact(
            str(self.art), str(self.man), self.sig, str(self.pub))
        self.assertEqual(
            got, hashlib.sha256(self.art.read_bytes()).hexdigest(),
            "#9170: verify_image_artifact must hand back the digest that "
            "authorised the artifact, so callers never re-hash to learn it")

    def test_a_mismatch_still_raises(self):
        """The refusal must survive the return-value change: a function that
        returns a digest unconditionally would satisfy the cell above."""
        self.art.write_bytes(b"tampered")
        with self.assertRaises(sign.SignError):
            sign.verify_image_artifact(
                str(self.art), str(self.man), self.sig, str(self.pub))


if __name__ == "__main__":
    unittest.main(verbosity=2)
