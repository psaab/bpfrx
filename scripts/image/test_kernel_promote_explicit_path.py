#!/usr/bin/env python3
"""Self-test: the #1930 kernel promotion gate resolves xpfd by EXPLICIT path.

#6541. `scripts/image/xpf-kernel-promote` is the OUTER hop of the A/B kernel
promote/rollback gate: systemd runs it as root on every boot, and on a candidate
boot the exit status of the `xpfd upgrade kernel promote` it invokes decides
promote-vs-rollback. A bare, $PATH-resolved `xpfd` lets any PATH entry ordered
ahead of the real location author that decision — or, with no attacker at all,
lets a stale xpfd from some other directory verify the wrong build against the
candidate kernel.

This asserts the script never PATH-resolves the artifact, and exercises the
resolution end to end against a fake filesystem root.

FAIL-ON-REVERT: restore `command -v xpfd` / bare `xpfd upgrade kernel promote`
and both test classes below fail.
"""

import os
import re
import shutil

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "xpf-kernel-promote"

# The two explicit candidates the script must consult, in order. Both are
# version-multiplexed (versions/current is the #1917 runtime pointer; the sbin
# path is normally a symlink onto it).
VERSIONED = "/var/lib/xpf/versions/current/xpfd"
SBIN = "/usr/local/sbin/xpfd"


def script_text() -> str:
    return SCRIPT.read_text()


class TestNoPathResolution(unittest.TestCase):
    """Static assertions on the script source."""

    def test_script_exists(self):
        # The tracked mode is 0644; debian/rules (install -m 0755) and
        # bake.py (chmod 0755) set the exec bit at install time, so the mode
        # here is deliberately not asserted.
        self.assertTrue(SCRIPT.is_file(), f"{SCRIPT} missing")
        self.assertTrue(
            script_text().startswith("#!/bin/sh"),
            "xpf-kernel-promote must stay a POSIX sh script (early boot)",
        )

    def test_no_command_v_probe_for_xpfd(self):
        # `command -v xpfd` is a $PATH lookup. The presence check must stat the
        # explicit candidates instead.
        self.assertIsNone(
            re.search(r"command\s+-v\s+xpfd", script_text()),
            "xpf-kernel-promote probes for xpfd via `command -v` ($PATH); "
            "it must test the explicit candidate paths instead (#6541)",
        )

    def test_no_bare_xpfd_invocation(self):
        # Any line that starts a command with a bare `xpfd` word (not a
        # quoted variable, not an absolute path) is the bug.
        for lineno, line in enumerate(script_text().splitlines(), start=1):
            code = line.split("#", 1)[0]
            self.assertIsNone(
                re.search(r"(?:^|[;&|]|\bthen\b|\bdo\b)\s*xpfd\s", code),
                f"{SCRIPT.name}:{lineno} invokes a BARE, $PATH-resolved xpfd "
                f"(#6541): {line.strip()!r}",
            )

    def test_consults_both_explicit_candidates(self):
        text = script_text()
        for want in (VERSIONED, SBIN):
            self.assertIn(
                want,
                text,
                f"xpf-kernel-promote does not consult the explicit path {want} "
                "(#6541)",
            )
        # Versioned runtime first: it is the authoritative #1917 pointer, and
        # the sbin path is only a fallback for a non-versioned (raw-deploy)
        # install. Assert the order on the CANDIDATE LIST itself, not on the
        # file as a whole — the prose above it names the paths too.
        candidates = None
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            if VERSIONED in code and SBIN in code:
                candidates = code
                break
        self.assertIsNotNone(
            candidates,
            "no single line enumerates both explicit candidates; the "
            "resolution order is not assertable (#6541)",
        )
        self.assertLess(
            candidates.index(VERSIONED),
            candidates.index(SBIN),
            f"{VERSIONED} must be consulted before {SBIN} (#6541)",
        )


class TestResolutionBehaviour(unittest.TestCase):
    """Run the script against a fake root, with a hostile xpfd on $PATH."""

    def setUp(self):
        if not shutil.which("sh"):
            self.skipTest("no /bin/sh")
        self.tmp = Path(tempfile.mkdtemp(prefix="xpf-promote-6541-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

        # A hostile/stale xpfd EARLY on $PATH. Any PATH-resolving
        # implementation finds this one. It records that it ran and exits 0
        # (a false "clean promote").
        self.path_dir = self.tmp / "hostile-path"
        self.path_dir.mkdir()
        self.marker = self.tmp / "hostile-ran"
        self._write_stub(self.path_dir / "xpfd", exit_code=0, marker=self.marker)

        # A rewritten copy of the script whose candidate paths are re-rooted
        # into the temp tree, so the test never touches the real filesystem.
        self.fake_root = self.tmp / "root"
        self.script_copy = self.tmp / "xpf-kernel-promote"
        text = script_text()
        text = text.replace(VERSIONED, str(self.fake_root) + VERSIONED)
        text = text.replace(SBIN, str(self.fake_root) + SBIN)
        self.script_copy.write_text(text)
        self.script_copy.chmod(0o755)

    def _write_stub(self, path: Path, exit_code: int, marker: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/bin/sh\n"
            f'echo "$0 $*" >> "{marker}"\n'
            f"exit {exit_code}\n"
        )
        path.chmod(0o755)

    def _run(self):
        env = dict(os.environ)
        env["PATH"] = str(self.path_dir) + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            ["/bin/sh", str(self.script_copy)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _install(self, rel: str, exit_code: int) -> Path:
        marker = self.tmp / (rel.replace("/", "_") + ".ran")
        self._write_stub(Path(str(self.fake_root) + rel), exit_code, marker)
        return marker

    def test_prefers_versioned_runtime_over_sbin_and_path(self):
        versioned_ran = self._install(VERSIONED, 0)
        sbin_ran = self._install(SBIN, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            versioned_ran.exists(),
            f"the versioned-runtime xpfd was not the one executed: {res.stderr}",
        )
        self.assertFalse(sbin_ran.exists(), "the sbin fallback ran instead")
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_falls_back_to_sbin_when_no_versioned_runtime(self):
        sbin_ran = self._install(SBIN, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(sbin_ran.exists(), f"the sbin xpfd did not run: {res.stderr}")
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_directory_candidate_is_not_treated_as_the_binary(self):
        # `test -x` alone is TRUE for a searchable DIRECTORY. The inner hop's
        # validateGateBin rejects a non-regular target, so the outer hop must
        # too — otherwise the two hops' admission tests are not actually
        # symmetric. A directory at the primary candidate must be skipped and
        # the sbin fallback used, NOT exec'd and not resolved via $PATH.
        Path(str(self.fake_root) + VERSIONED).mkdir(parents=True)
        sbin_ran = self._install(SBIN, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            sbin_ran.exists(),
            f"a DIRECTORY at {VERSIONED} was accepted as the gate binary "
            f"instead of falling through to {SBIN}: {res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_skips_rather_than_falling_back_to_path(self):
        # NEITHER explicit candidate exists, but a perfectly good xpfd is
        # sitting on $PATH. The gate must SKIP (exit 0, the pre-existing
        # not-installed behaviour), never reach for $PATH.
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(
            self.marker.exists(),
            "with no explicit candidate the gate fell back to $PATH (#6541)",
        )
        self.assertIn("skipping promotion gate", res.stderr)

    def test_revert_exit_3_still_reboots(self):
        # OVER-REACH GUARD: the explicit-path change must not disturb the
        # revert contract. An xpfd exiting 3 (REVERT) must still drive the
        # reboot branch. `systemctl` is stubbed on PATH — it is a system
        # binary and is legitimately PATH-resolved.
        self._install(VERSIONED, 3)
        systemctl_ran = self.tmp / "systemctl.ran"
        self._write_stub(self.path_dir / "systemctl", 0, systemctl_ran)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("REVERT", res.stderr)
        self.assertTrue(
            systemctl_ran.exists(),
            f"exit 3 did not trigger the recovery reboot: {res.stderr}",
        )
        self.assertIn("reboot", systemctl_ran.read_text())

    def test_infra_error_does_not_reboot(self):
        # OVER-REACH GUARD: a non-0/non-3 rc stays a non-rebooting infra error.
        self._install(VERSIONED, 1)
        systemctl_ran = self.tmp / "systemctl.ran"
        self._write_stub(self.path_dir / "systemctl", 0, systemctl_ran)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("infra error", res.stderr)
        self.assertFalse(systemctl_ran.exists(), "an infra error triggered a reboot")


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)
