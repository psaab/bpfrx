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

# The two compiled-default candidates. They are consulted as an UNAMBIGUOUS
# SET, not as a ranked list, because no fixed rank is right for both partial
# relocations (#6601 r4 MAJOR-2): `--sbin-dir` and `--versions-dir` move
# INDEPENDENTLY, and each partial move inverts which default is the live one.
#
#   --versions-dir only : flip step 6b repoints <SbinDir>/<bin> ->
#                         <VersionsDir>/current/<bin> on every cut, so the sbin
#                         entry is LIVE; the default versions root is a stale
#                         leftover that relocation does not remove.
#   --sbin-dir only     : flip maintains the CONFIGURED sbin dir, so the default
#                         versions root is LIVE and the leftover
#                         /usr/local/sbin/xpfd is the STALE one.
#
# A default is therefore usable only when the two name the SAME file (the
# ordinary layout, where the sbin entry is a symlink to the versioned runtime),
# or when only one of them is usable at all.
SBIN = "/usr/local/sbin/xpfd"
VERSIONED = "/var/lib/xpf/versions/current/xpfd"


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
        # Both discovery sources must be consulted BEFORE the compiled
        # defaults, or a stale leftover at a default path wins over the live
        # binary. Index the CALL SITES (unique literals), not the definitions.
        defaults_call = text.index("\ntry_compiled_defaults\n")
        for call in (
            'try_candidate "$(unit_main_pid_exe)"',
            'try_candidate "$(unit_exec_start)"',
        ):
            self.assertIn(call, text, f"the gate never calls {call} (#6601 r4)")
            self.assertLess(
                text.index(call),
                defaults_call,
                "systemd/kernel discovery must be tried before the compiled "
                "defaults",
            )

    def test_execstart_is_parsed_at_systemds_real_field_delimiter(self):
        # MAJOR (#6601 r4). `systemctl show -p ExecStart --value` renders
        #   { path=/x ; argv[]=/x ... ; ignore_errors=no ; ... }
        # and the property printer substitutes the stored path RAW ("path=%s"),
        # with no escaping. systemd PERMITS an executable path containing a
        # space or a ';', so a parser that stops at the first one does not fail
        # to resolve -- it resolves to a SHORTER, DIFFERENT path, suppresses
        # every remaining candidate, and lets that binary's exit 0 authorize the
        # promotion. Cut at the real field delimiter instead.
        text = script_text()
        self.assertIn(
            " ; argv[]=",
            text,
            "the ExecStart parse does not cut at systemd's real field "
            "delimiter, so a path containing a space or a ';' truncates into a "
            "different executable (#6601 r4 MAJOR-1)",
        )
        self.assertNotIn(
            "[^ ;]",
            text,
            "a `[^ ;]` character class still terminates the ExecStart path at "
            "the first space or semicolon -- both are legal in a systemd "
            "executable path (#6601 r4 MAJOR-1)",
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
        # The two defaults must be compared for SAME-FILE identity, not ranked.
        # `-ef` (same device+inode) is what makes the ordinary layout -- where
        # flip 6b left <SbinDir>/xpfd as a symlink to <VersionsDir>/current/xpfd
        # -- resolve, while two genuinely different files refuse loudly.
        compare = None
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            if VERSIONED in code and SBIN in code and "-ef" in code:
                compare = code
                break
        self.assertIsNotNone(
            compare,
            "no line compares the two compiled defaults with `-ef`. Without a "
            "same-file test the gate must RANK them, and no fixed rank is "
            "right for both `--sbin-dir`-only and `--versions-dir`-only "
            "relocation (#6601 r4 MAJOR-2)",
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
            # STUB_SHOW_FAIL models a systemctl that cannot answer at all
            # (missing, erroring, or a query it does not understand).
            '  [ -n "${STUB_SHOW_FAIL-}" ] && exit 1\n'
            '  case "$*" in\n'
            '    *MainPID*) printf \'%s\\n\' "${STUB_MAINPID-0}" ;;\n'
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
        self.stub_mainpid = "0"
        self.stub_show_fail = ""
        self._stub_seq = 0

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
        env["STUB_MAINPID"] = self.stub_mainpid
        env["STUB_SHOW_FAIL"] = self.stub_show_fail
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

    def _install_abs(self, abs_path: Path, exit_code: int = 0) -> Path:
        """Install a recording stub at an ABSOLUTE path outside the fake root."""
        self._stub_seq += 1
        marker = self.tmp / f"stub{self._stub_seq}.ran"
        self._write_stub(abs_path, exit_code, marker)
        return marker

    def test_disagreeing_compiled_defaults_refuse_instead_of_guessing(self):
        # MAJOR (#6601 r4). `--sbin-dir` and `--versions-dir` relocate
        # INDEPENDENTLY, so NO fixed rank over the two compiled defaults is
        # right for both partial relocations:
        #
        #   --versions-dir only : sbin entry LIVE, default versions root stale
        #   --sbin-dir only     : default versions root LIVE, sbin entry STALE
        #
        # Two usable defaults that are DIFFERENT files therefore mean one of
        # them is stale with nothing on the box to say which. The previous
        # revision ranked sbin first unconditionally and so executed the STALE
        # leftover on every `--sbin-dir`-only box whose systemd could not
        # answer -- verifying the candidate kernel against the wrong dataplane,
        # or rejecting a healthy candidate into a needless revert/reboot. Refuse
        # LOUDLY instead of flipping a coin.
        sbin_ran = self._install(SBIN, 0)
        versioned_ran = self._install(VERSIONED, 0)
        self.stub_show_fail = "1"  # systemd cannot answer

        res = self._run()
        self.assertEqual(
            res.returncode,
            0,
            "the refusal must stay on the non-rebooting infra-error path: "
            f"{res.stderr}",
        )
        self.assertFalse(
            sbin_ran.exists(),
            f"the gate executed {SBIN} while {VERSIONED} named a DIFFERENT file "
            "and systemd could not say which one is live. On a `--sbin-dir`-only "
            "relocated box that leftover is the STALE build (#6601 r4 MAJOR-2): "
            f"{res.stderr}",
        )
        self.assertFalse(
            versioned_ran.exists(),
            f"the gate executed {VERSIONED} while {SBIN} named a DIFFERENT file; "
            "one of the two is stale and nothing says which (#6601 r4 MAJOR-2): "
            f"{res.stderr}",
        )
        self.assertIn("ERROR", res.stderr, f"the refusal was not loud: {res.stderr}")
        self.assertIn("REFUSING to promote", res.stderr)
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_agreeing_compiled_defaults_still_resolve(self):
        # ANTI-OVER-REACH for the test above. On an ORDINARY default-rooted box
        # flip step 6b leaves <SbinDir>/xpfd as a symlink to
        # <VersionsDir>/current/xpfd, so both defaults are usable and they are
        # ONE file. There is nothing ambiguous about that -- refusing here would
        # strand the promotion gate on a perfectly healthy box, which is its own
        # outage.
        versioned_ran = self._install(VERSIONED, 0)
        sbin_path = Path(str(self.fake_root) + SBIN)
        sbin_path.parent.mkdir(parents=True, exist_ok=True)
        sbin_path.symlink_to(str(self.fake_root) + VERSIONED)
        self.stub_show_fail = "1"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            versioned_ran.exists(),
            "the gate refused on an ORDINARY default layout where the sbin "
            "entry is merely a symlink to the versioned runtime -- the two "
            f"defaults are the same file: {res.stderr}",
        )
        self.assertNotIn("REFUSING", res.stderr)
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

    def test_execstart_path_containing_a_space_is_not_truncated(self):
        # MAJOR (#6601 r4). systemd PERMITS an executable path containing a
        # space, and `systemctl show -p ExecStart` substitutes the stored path
        # RAW into `path=%s` -- there is no escaping. A parse that stops at the
        # first space therefore does not merely fail to resolve: it resolves to
        # a SHORTER, DIFFERENT path. Here `<tmp>/relocated` is itself a valid
        # executable, so the truncated read is ACCEPTED, every remaining
        # candidate is suppressed, and that binary's exit 0 authorizes the
        # promotion -- the candidate kernel gets verified against a build nobody
        # chose.
        live = self.tmp / "relocated live" / "xpfd"
        live_ran = self._install_abs(live)
        truncated = self.tmp / "relocated"
        truncated_ran = self._install_abs(truncated)

        self.stub_execstart = (
            f"{{ path={live} ; argv[]={live} ; ignore_errors=no ; "
            "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; "
            "status=0/0 }"
        )
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(
            truncated_ran.exists(),
            f"the gate TRUNCATED systemd's ExecStart at the first space and "
            f"executed {truncated} -- a DIFFERENT binary from the "
            f"{live} systemd actually launches (#6601 r4 MAJOR-1): {res.stderr}",
        )
        self.assertTrue(
            live_ran.exists(),
            f"the gate did not run the xpfd systemd's ExecStart names: "
            f"{res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

    def test_execstart_path_containing_a_semicolon_is_not_truncated(self):
        # The other half of MAJOR-1: `;` is legal in a path too, and the
        # property printer does not escape it either.
        live = self.tmp / "reloc;ated" / "xpfd"
        live_ran = self._install_abs(live)
        truncated = self.tmp / "reloc"
        truncated_ran = self._install_abs(truncated)

        self.stub_execstart = f"{{ path={live} ; argv[]={live} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(
            truncated_ran.exists(),
            f"the gate TRUNCATED systemd's ExecStart at the first ';' and "
            f"executed {truncated} instead of {live} (#6601 r4 MAJOR-1): "
            f"{res.stderr}",
        )
        self.assertTrue(
            live_ran.exists(),
            f"the gate did not run the xpfd systemd's ExecStart names: "
            f"{res.stderr}",
        )

    def test_multiple_execstart_entries_are_not_reduced_to_the_first(self):
        # MAJOR-1, second shape. systemd renders one ExecStart entry per LINE
        # (verified against man-db.service). The shipped Type=simple unit cannot
        # validly carry more than one, but an operator-overridden Type=oneshot
        # can -- and its FIRST entry need not be xpfd at all. Taking it
        # unconditionally hands the promote-vs-rollback decision to an arbitrary
        # command. Ambiguous input must yield NOTHING so the compiled defaults
        # still get their turn.
        foreign = self.tmp / "prep" / "install"
        foreign_ran = self._install_abs(foreign)
        entry = self.tmp / "opt" / "xpfd"
        self._install_abs(entry)
        sbin_ran = self._install(SBIN, 0)

        self.stub_execstart = (
            f"{{ path={foreign} ; argv[]={foreign} -d ; ignore_errors=no }}\n"
            f"{{ path={entry} ; argv[]={entry} ; ignore_errors=no }}"
        )
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(
            foreign_ran.exists(),
            f"the gate executed {foreign}, the FIRST of several ExecStart "
            "entries, which need not be xpfd (#6601 r4 MAJOR-1): "
            f"{res.stderr}",
        )
        self.assertTrue(
            sbin_ran.exists(),
            "an ambiguous multi-entry ExecStart must yield nothing and let the "
            f"compiled defaults resolve: {res.stderr}",
        )

    def test_discovers_the_running_binary_via_main_pid_proc_exe(self):
        # #6601 r4: the structured, un-parsed discovery source. MainPID is an
        # integer property and /proc/<pid>/exe is a kernel symlink, so this hop
        # reads the path of the binary the live daemon is ACTUALLY executing
        # without parsing systemd's lossy textual render at all. It must outrank
        # stale leftovers at both compiled defaults.
        sleep_bin = shutil.which("sleep")
        if not sleep_bin:
            self.skipTest("no sleep(1) to model a running daemon")
        target = self.tmp / "opt-live" / "xpfd"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sleep_bin, target)
        if not os.access(target, os.X_OK):
            self.skipTest("could not stage an executable copy")
        proc = subprocess.Popen(
            [str(target), "60"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)

        self.stub_mainpid = str(proc.pid)
        self.stub_loadstate = "loaded"
        stale_sbin = self._install(SBIN, 0)
        stale_versioned = self._install(VERSIONED, 0)

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            f"using {target} (",
            res.stderr,
            "the gate did not resolve xpfd through xpfd.service's MainPID and "
            f"/proc/<pid>/exe: {res.stderr}",
        )
        self.assertIn("MainPID", res.stderr)
        self.assertFalse(
            stale_sbin.exists(),
            f"ran the leftover at {SBIN} instead of the binary the live daemon "
            f"is executing: {res.stderr}",
        )
        self.assertFalse(
            stale_versioned.exists(),
            f"ran the leftover at {VERSIONED} instead of the binary the live "
            f"daemon is executing: {res.stderr}",
        )

    def test_unqueryable_systemd_refuses_loudly_rather_than_skipping(self):
        # #6601 r4 audit note. The quiet "xpf is not on this box" skip is only
        # honest when systemd ANSWERED not-found. A systemctl that is missing or
        # erroring proves NOTHING about whether xpf is installed -- laundering
        # that into the benign skip lets an ARMED candidate sail past the gate
        # behind a reassuring log line.
        self.stub_show_fail = "1"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            "ERROR",
            res.stderr,
            "an unqueryable systemd was treated as proof that xpf is absent "
            f"(#6601 r4): {res.stderr}",
        )
        self.assertIn("REFUSING to promote", res.stderr)
        self.assertNotIn("skipping promotion gate", res.stderr)
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
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
