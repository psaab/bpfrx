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

# The two explicit candidates the script must consult, IN THIS ORDER.
#
# SBIN first is load-bearing, not cosmetic. flip step 6b repoints
# <SbinDir>/<bin> -> <VersionsDir>/current/<bin> on every cut
# (pkg/upgrade/flip.go), so the sbin entry tracks the live version even when the
# operator relocated the runtime with `--versions-dir`. Relocating does NOT
# remove an older /var/lib/xpf/versions/current, so consulting the hardcoded
# default root first would select a STALE build on a relocated install --
# strictly worse than the bare `xpfd` this replaced, which at least resolved to
# the live sbin entry through systemd's default PATH.
SBIN = "/usr/local/sbin/xpfd"
VERSIONED = "/var/lib/xpf/versions/current/xpfd"
CANDIDATES_IN_ORDER = [SBIN, VERSIONED]


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

    def test_discovers_configured_path_from_systemd(self):
        # The compiled defaults cannot cover a box that relocated BOTH
        # --versions-dir and --sbin-dir; the gate must ASK rather than add a
        # third guess. systemd's ExecStart for xpfd.service is what the cut
        # writes (flip step 6c) and is a concrete absolute path.
        text = script_text()
        self.assertIn(
            "ExecStart",
            text,
            "the gate never consults systemd's ExecStart for xpfd.service, so a "
            "box with both runtime roots relocated has no resolvable candidate "
            "(#6541 fold r3)",
        )
        self.assertIn("xpfd.service", text)
        # Discovery must be consulted BEFORE the compiled defaults, or a stale
        # leftover at a default path wins over the live binary.
        self.assertLess(
            text.index("unit_exec_start"),
            text.index('try_candidate /usr/local/sbin/xpfd'),
            "systemd discovery must be tried before the compiled defaults",
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
        # SBIN first, VERSIONED second. Assert the order on the CANDIDATE LIST
        # itself, not on the file as a whole — the prose above it names the
        # paths too.
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
        positions = [candidates.index(c) for c in CANDIDATES_IN_ORDER]
        self.assertEqual(
            positions,
            sorted(positions),
            "candidate order is wrong. It must be "
            f"{CANDIDATES_IN_ORDER!r}: the sbin entry is repointed by every cut "
            "and so tracks the live version even under `--versions-dir` "
            "relocation, while the hardcoded default root is NOT removed on "
            "relocation and would select a STALE build (#6541 fold r2)",
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

        # systemctl stub. `show` answers from env vars the test sets, so unit
        # discovery is exercised hermetically; anything else (reboot) is
        # recorded. systemctl is legitimately $PATH-resolved -- it is a
        # distribution binary, unlike xpfd.
        self.systemctl_ran = self.tmp / "systemctl.ran"
        (self.path_dir / "systemctl").write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "show" ]; then\n'
            '  case "$*" in\n'
            '    *ExecStart*) printf \'%s\\n\' "${STUB_EXECSTART-}" ;;\n'
            '    *LoadState*) printf \'%s\\n\' "${STUB_LOADSTATE-not-found}" ;;\n'
            "  esac\n"
            "  exit 0\n"
            "fi\n"
            f'echo "$0 $*" >> "{self.systemctl_ran}"\n'
            "exit 0\n"
        )
        (self.path_dir / "systemctl").chmod(0o755)
        # Default: systemd knows nothing, so the compiled-default chain runs.
        self.stub_execstart = ""
        self.stub_loadstate = "not-found"

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
        env["STUB_EXECSTART"] = self.stub_execstart
        env["STUB_LOADSTATE"] = self.stub_loadstate
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

    def test_prefers_sbin_entry_over_default_versions_root(self):
        # RELOCATED-INSTALL regression guard. Both candidates exist, as they do
        # on a box that was cut with `--versions-dir` while an older default
        # runtime was left behind: the sbin entry points at the LIVE build, the
        # default root holds the STALE one. The sbin entry must win.
        versioned_ran = self._install(VERSIONED, 0)
        sbin_ran = self._install(SBIN, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            sbin_ran.exists(),
            f"the managed sbin entry was not the one executed: {res.stderr}",
        )
        self.assertFalse(
            versioned_ran.exists(),
            f"the gate ran {VERSIONED} instead of {SBIN}. On a `--versions-dir` "
            "relocated install that path holds a STALE build and the candidate "
            "kernel would be verified against the wrong dataplane "
            "(#6541 fold r2)",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_falls_back_to_versioned_runtime_when_no_sbin_entry(self):
        versioned_ran = self._install(VERSIONED, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            versioned_ran.exists(),
            f"the versioned-runtime xpfd did not run: {res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_dangling_sbin_symlink_falls_through_to_versioned_runtime(self):
        # #2176 leaves a sbin symlink pointing into a removed versions dir. It
        # must not shadow the versioned-runtime fallback — that is the whole
        # reason the second candidate still exists. `-f` is what rejects it.
        versioned_ran = self._install(VERSIONED, 0)
        sbin_path = Path(str(self.fake_root) + SBIN)
        sbin_path.parent.mkdir(parents=True, exist_ok=True)
        sbin_path.symlink_to(str(self.fake_root) + "/removed/versions/v1/xpfd")

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            versioned_ran.exists(),
            f"a DANGLING {SBIN} symlink shadowed the {VERSIONED} fallback "
            f"instead of falling through: {res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_directory_candidate_is_not_treated_as_the_binary(self):
        # `test -x` alone is TRUE for a searchable DIRECTORY. The inner hop's
        # validateGateBin rejects a non-regular target, so the outer hop must
        # too — otherwise the two hops' admission tests are not actually
        # symmetric.
        #
        # The directory MUST be placed at the candidate that is examined FIRST,
        # or the test is vacuous. An earlier revision put it at VERSIONED while
        # also installing a valid SBIN; since SBIN is checked first the
        # directory was never examined and reverting `[ -f ]` left the test
        # green. Place it at SBIN and require the fall-through to VERSIONED.
        sbin_dir_path = Path(str(self.fake_root) + SBIN)
        sbin_dir_path.mkdir(parents=True)
        versioned_ran = self._install(VERSIONED, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            versioned_ran.exists(),
            f"a DIRECTORY at {SBIN} — the FIRST compiled-default candidate — "
            f"was accepted as the gate binary instead of falling through to "
            f"{VERSIONED}: {res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_discovers_relocated_roots_via_systemd_execstart(self):
        # MAJOR (fold r3). `--versions-dir` AND `--sbin-dir` are both real
        # operator options, and the cut maintains whatever was configured. On a
        # box that relocated BOTH — e.g. --versions-dir=/opt/xpf/versions with
        # --sbin-dir=/usr/sbin — NEITHER compiled default exists, yet the live
        # binary is perfectly intact. Systemd knows where it is, because that is
        # the ExecStart the cut templated (flip step 6c).
        relocated = self.tmp / "opt-xpf" / "versions" / "v7" / "xpfd"
        relocated_ran = self.tmp / "relocated.ran"
        self._write_stub(relocated, 0, relocated_ran)

        self.stub_execstart = f"{{ path={relocated} ; argv[]={relocated} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            relocated_ran.exists(),
            "the gate did not run the relocated xpfd that systemd's ExecStart "
            f"names. With both roots relocated no compiled default exists, so "
            f"an ExecStart-blind gate skips an ARMED promotion: {res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_systemd_execstart_outranks_stale_compiled_defaults(self):
        # The other half of the MAJOR: with both roots relocated, leftover
        # artifacts at the compiled defaults are STALE. Executing one can reject
        # a healthy candidate and trigger a needless revert/reboot, or validate
        # the wrong embedded dataplane build. Discovery must win over both.
        relocated = self.tmp / "opt-xpf" / "versions" / "v7" / "xpfd"
        relocated_ran = self.tmp / "relocated.ran"
        self._write_stub(relocated, 0, relocated_ran)

        stale_sbin = self._install(SBIN, 0)
        stale_versioned = self._install(VERSIONED, 0)

        self.stub_execstart = f"{{ path={relocated} ; argv[]={relocated} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(relocated_ran.exists(), f"the live binary did not run: {res.stderr}")
        self.assertFalse(
            stale_sbin.exists(),
            f"ran the STALE leftover at {SBIN} instead of the live binary "
            "systemd's ExecStart names",
        )
        self.assertFalse(
            stale_versioned.exists(),
            f"ran the STALE leftover at {VERSIONED} instead of the live binary",
        )

    def test_unusable_execstart_falls_through_to_compiled_defaults(self):
        # Over-reach guard: discovery must not become a single point of failure.
        # A unit whose ExecStart names a path that no longer exists (mid-cut,
        # GC'd version dir) must fall through, not strand the gate.
        self.stub_execstart = f"{{ path={self.tmp}/gone/xpfd ; argv[]={self.tmp}/gone/xpfd }}"
        self.stub_loadstate = "loaded"
        sbin_ran = self._install(SBIN, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            sbin_ran.exists(),
            f"an unusable ExecStart stranded the gate instead of falling "
            f"through to {SBIN}: {res.stderr}",
        )

    def test_refuses_loudly_when_installed_but_unlocatable(self):
        # FAIL LOUD, not quiet. xpfd.service is installed but nothing resolves:
        # an armed candidate would otherwise sail past unverified with nothing
        # in the journal to say so. The refusal must be explicit AND must stay
        # exit 0 — a non-zero exit trips OnFailure= and reboots the box.
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(
            res.returncode,
            0,
            "the refusal must exit 0 (the non-rebooting infra-error path); a "
            f"non-zero exit trips OnFailure= and reboots: {res.stderr}",
        )
        self.assertIn("ERROR", res.stderr, f"the refusal was not loud: {res.stderr}")
        self.assertIn("REFUSING to promote", res.stderr)
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )
        self.assertFalse(
            self.systemctl_ran.exists(),
            f"the refusal rebooted the box: {self.systemctl_ran.read_text()}"
            if self.systemctl_ran.exists()
            else "",
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
        systemctl_ran = self.systemctl_ran

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
        systemctl_ran = self.systemctl_ran

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("infra error", res.stderr)
        self.assertFalse(systemctl_ran.exists(), "an infra error triggered a reboot")


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)
