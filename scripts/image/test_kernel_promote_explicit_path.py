#!/usr/bin/env python3
"""Self-test: the #1930 kernel promotion gate resolves xpfd by EXPLICIT path.

#6541. `scripts/image/xpf-kernel-promote` is the OUTER hop of the A/B kernel
promote/rollback gate: systemd runs it as root on every boot, and on a candidate
boot the exit status of the `xpfd upgrade kernel promote` it invokes decides
promote-vs-rollback. A bare, $PATH-resolved `xpfd` lets any PATH entry ordered
ahead of the real location author that decision — or, with no attacker at all,
lets a stale xpfd from some other directory verify the wrong build against the
candidate kernel.

The gate's authority order is (#6601 r5):

    1. /proc/<MainPID>/exe for xpfd.service, bound back to the unit
    2. a strictly-parsed ExecStart for xpfd.service
    3. a LOUD refusal

with **no inference fallback**. That third step is the point of this file. Three
earlier revisions guessed from the filesystem when systemd could not answer, and
each one closed a single ambiguous case and left another, because a runtime left
behind by `--versions-dir`/`--sbin-dir` relocation is indistinguishable from a
live one — Codex reproduced a both-roots-relocated box whose two leftover
defaults are the SAME INODE, so even a same-file test called them unambiguous
and the gate executed the stale build. The class of bug is closed by removing
the guess, not by patching one more case.

FAIL-ON-REVERT: restore `command -v xpfd` / bare `xpfd upgrade kernel promote`,
or reintroduce a compiled-default fallback, and this file fails.
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

# The two paths a compiled-default fallback used to consult. They are named
# here ONLY so the tests can plant leftovers at them and prove the gate never
# reaches for either: `--sbin-dir` and `--versions-dir` relocate INDEPENDENTLY
# and neither relocation removes what it left behind, so every shape a
# defaults fallback could recognise —
#
#   both usable, DIFFERENT files : one is stale, nothing says which
#   both usable, SAME inode      : the healthy default layout AND a
#                                  both-roots-relocated box's leftovers
#                                  (#6601 r4 Codex MAJOR-1)
#   exactly one usable           : the surviving half of a partial relocation
#
# — has a relocation shape that makes it the stale build.
SBIN = "/usr/local/sbin/xpfd"
# The arm record: written by `xpfd upgrade kernel arm`, read by the gate. Its
# path is asserted against Go by TestPromoteScriptArmRecordPathMatchesGo.
ARM_RECORD = "/var/lib/xpf/kernel-promote-binary"
VERSIONED = "/var/lib/xpf/versions/current/xpfd"


def script_text() -> str:
    return SCRIPT.read_text()


def shell_function_body(text: str, name: str) -> str:
    """Return the body of `name() { ... }` from a POSIX sh source.

    Used to scope source assertions to one function, so an unrelated query
    elsewhere in the script cannot mask a deletion inside it.
    """
    start = text.index(f"{name}() {{")
    depth, i = 0, start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated shell function {name}")


def code_lines():
    """The script's lines with comments stripped."""
    for lineno, line in enumerate(script_text().splitlines(), start=1):
        yield lineno, line.split("#", 1)[0]


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
        # The gate must ASK systemd rather than guess. `--versions-dir` and
        # `--sbin-dir` are both real operator options and the cut maintains
        # whatever was configured, so a box that relocated BOTH has a perfectly
        # intact xpfd at a path no hardcoded list contains.
        text = script_text()
        self.assertIn(
            "ExecStart",
            text,
            "the gate never consults systemd's ExecStart for xpfd.service, so a "
            "box with both runtime roots relocated has no resolvable candidate "
            "(#6541 fold r3)",
        )
        self.assertIn("xpfd.service", text)
        for call in (
            'try_candidate "$(unit_main_pid_exe)"',
            'try_candidate "$(unit_exec_start)"',
        ):
            self.assertIn(call, text, f"the gate never calls {call} (#6601 r4)")
        # Order matters: the kernel's answer for the LIVE process outranks the
        # declared one.
        self.assertLess(
            text.index('try_candidate "$(unit_main_pid_exe)"'),
            text.index('try_candidate "$(unit_exec_start)"'),
        )

    def test_no_compiled_default_inference_fallback(self):
        # #6601 r5, the class-closing invariant. NO code path may select a
        # binary from an inference that a leftover file can satisfy. The
        # filesystem cannot answer "which of these is the live xpfd" once a
        # root has been relocated — leftovers are indistinguishable from a
        # healthy layout, in EVERY shape (different files, same inode, only one
        # survivor) — so the gate must have no filesystem-derived candidate at
        # all, not a cleverer test over one.
        offenders = []
        for lineno, code in code_lines():
            for lit in (SBIN, VERSIONED):
                if lit in code:
                    offenders.append(f"{SCRIPT.name}:{lineno}: {code.strip()}")
            if re.search(r"(?:^|\s)-ef(?:\s|$)", code):
                offenders.append(
                    f"{SCRIPT.name}:{lineno}: same-inode test: {code.strip()}"
                )
        self.assertEqual(
            offenders,
            [],
            "the gate reintroduced a compiled-default fallback. A leftover at a "
            "default path is byte-for-byte indistinguishable from a live one, "
            "and `-ef` cannot tell a healthy default layout from a "
            "both-roots-relocated box whose leftover symlink still points at "
            "its leftover runtime (#6601 r4 MAJOR-1). Refuse instead:\n  "
            + "\n  ".join(offenders),
        )

    def test_main_pid_candidate_is_bound_to_the_unit(self):
        # #6601 r4 MAJOR-2. A pid is a number, and a number is not an identity.
        # If xpfd.service exits and the kernel recycles its pid onto an
        # unrelated process, /proc/<pid>/exe names THAT binary — and a basename
        # check only requires the impostor to be called `xpfd`. The pid must be
        # bound back to the unit.
        text = script_text()
        self.assertIn(
            "ControlGroup",
            text,
            "the MainPID hop never checks that the pid belongs to "
            "xpfd.service's own control group, so a recycled pid running an "
            "unrelated binary named `xpfd` can author the promotion decision "
            "(#6601 r4 MAJOR-2)",
        )
        self.assertIn("/cgroup", text)
        # Count within the DISCOVERY FUNCTION, not the whole file. The refusal
        # path also queries MainPID (to print it as a fact), and a whole-file
        # count would silently absorb the re-read being deleted: 1 discovery +
        # 1 diagnostic still totals 2. Scoping keeps the revert-detection exact
        # (#6601 r5).
        body = shell_function_body(text, "unit_main_pid_exe")
        self.assertEqual(
            len(re.findall(r"--property=MainPID", body)),
            2,
            "MainPID must be read AGAIN after the readlink, inside "
            "unit_main_pid_exe, and required to be the same pid, so a recycle "
            "DURING the sequence is caught rather than raced past "
            "(#6601 r4 MAJOR-2)",
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
        for lineno, code in code_lines():
            self.assertIsNone(
                re.search(r"(?:^|[;&|]|\bthen\b|\bdo\b)\s*xpfd\s", code),
                f"{SCRIPT.name}:{lineno} invokes a BARE, $PATH-resolved xpfd "
                f"(#6541): {code.strip()!r}",
            )


class _GateBase(unittest.TestCase):
    """Shared harness: runs the gate against a fake root, hostile xpfd on $PATH.

    Holds setUp and the helpers only -- no test methods, so unittest does not
    collect it. Subclassed by every behavioural class below so the systemctl
    stub, the re-rooting and the $PATH trap are defined ONCE.
    """

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
        #
        # MainPID reads are COUNTED so a test can model a pid that changes
        # mid-sequence (the recycle race): with STUB_MAINPID2 set, the second
        # and later reads answer differently from the first.
        self.systemctl_ran = self.tmp / "systemctl.ran"
        self.mainpid_seq = self.tmp / "mainpid.seq"
        (self.path_dir / "systemctl").write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "show" ]; then\n'
            # STUB_SHOW_FAIL models a systemctl that cannot answer at all
            # (missing, erroring, or a query it does not understand).
            '  [ -n "${STUB_SHOW_FAIL-}" ] && exit 1\n'
            '  case "$*" in\n'
            "    *MainPID*)\n"
            f'      n=$(cat "{self.mainpid_seq}" 2>/dev/null || echo 0)\n'
            "      n=$((n + 1))\n"
            f'      echo "$n" > "{self.mainpid_seq}"\n'
            '      if [ "$n" -ge 2 ] && [ -n "${STUB_MAINPID2-}" ]; then\n'
            "        printf '%s\\n' \"$STUB_MAINPID2\"\n"
            "      else\n"
            "        printf '%s\\n' \"${STUB_MAINPID-0}\"\n"
            "      fi\n"
            "      ;;\n"
            '    *ControlGroup*) printf \'%s\\n\' "${STUB_CONTROLGROUP-}" ;;\n'
            '    *ExecStart*) printf \'%s\\n\' "${STUB_EXECSTART-}" ;;\n'
            '    *LoadState*) printf \'%s\\n\' "${STUB_LOADSTATE-not-found}" ;;\n'
            "  esac\n"
            "  exit 0\n"
            "fi\n"
            f'echo "$0 $*" >> "{self.systemctl_ran}"\n'
            "exit 0\n"
        )
        (self.path_dir / "systemctl").chmod(0o755)
        # Default: systemd knows nothing, so nothing resolves.
        self.stub_execstart = ""
        self.stub_loadstate = "not-found"
        # Which shell runs the gate. Overridden by the busybox leg (NIT-1); the
        # script is POSIX sh and must behave identically under both.
        self.shell_argv = ["/bin/sh"]
        # The arm record. None => _run() derives it from a well-formed
        # stub_execstart, so a test that models a HEALTHY box expresses
        # "record agrees with the unit" without restating the path. Set it
        # explicitly to model a disagreement, a stale record, or no arming.
        self.armed = None
        self.arm_explicitly_absent = False
        self.stub_mainpid = "0"
        self.stub_mainpid2 = ""
        self.stub_controlgroup = ""
        self.stub_show_fail = ""
        self._stub_seq = 0

        # A rewritten copy of the script whose HISTORICAL compiled-default
        # paths are re-rooted into the temp tree. The current gate names
        # neither, so this is a no-op for it -- it exists so that a revision
        # which reintroduces a defaults fallback is caught HERE, resolving
        # into the fake root, instead of touching the real filesystem.
        self.fake_root = self.tmp / "root"
        self.script_copy = self.tmp / "xpf-kernel-promote"
        text = script_text()
        text = text.replace(VERSIONED, str(self.fake_root) + VERSIONED)
        text = text.replace(SBIN, str(self.fake_root) + SBIN)
        text = text.replace(ARM_RECORD, str(self.fake_root) + ARM_RECORD)
        self.script_copy.write_text(text)
        self.script_copy.chmod(0o755)

    # ---------------------------------------------------------------- helpers

    def _write_stub(self, path: Path, exit_code: int, marker: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/bin/sh\n"
            f'echo "$0 $*" >> "{marker}"\n'
            f"exit {exit_code}\n"
        )
        path.chmod(0o755)

    def _derive_armed(self):
        """The binary a well-formed ExecStart names, parsed the way the gate does.

        This MUST use the gate's own delimiter rule (` ; argv[]=`), not a
        naive cut at the first space. Parsing it more loosely here arms a
        TRUNCATED path, the gate resolves the correct longer one, and the
        cross-check fires -- which is the harness disagreeing with itself, not
        a finding. (That is exactly what happened when this helper cut at the
        first space: the #6601 r4 space-in-path fixtures started refusing.)
        """
        raw = self.stub_execstart
        cand = ""
        if "\n" in raw.strip():
            return ""   # multi-line render: ambiguous, exactly as the gate treats it
        if "path=" in raw:
            rest = raw.split("path=", 1)[1]
            if rest.count(" ; argv[]=") == 1:
                cand = rest.split(" ; argv[]=", 1)[0]
        elif raw.strip().startswith("/"):
            stripped = raw.strip()
            if not re.search(r"[\s;]", stripped):
                cand = stripped
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
        return ""

    def _run(self):
        if not self.arm_explicitly_absent:
            armed = self.armed if self.armed is not None else self._derive_armed()
            if armed:
                self._arm(armed)
        env = dict(os.environ)
        env["PATH"] = str(self.path_dir) + os.pathsep + env.get("PATH", "")
        env["STUB_EXECSTART"] = self.stub_execstart
        env["STUB_LOADSTATE"] = self.stub_loadstate
        env["STUB_MAINPID"] = self.stub_mainpid
        env["STUB_MAINPID2"] = self.stub_mainpid2
        env["STUB_CONTROLGROUP"] = self.stub_controlgroup
        env["STUB_SHOW_FAIL"] = self.stub_show_fail
        return subprocess.run(
            self.shell_argv + [str(self.script_copy)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _arm(self, binary) -> Path:
        """Write the arm record the way `xpfd upgrade kernel arm` does."""
        rec = Path(str(self.fake_root) + ARM_RECORD)
        rec.parent.mkdir(parents=True, exist_ok=True)
        rec.write_text(f"{binary}\n")
        return rec

    def _install(self, rel: str, exit_code: int) -> Path:
        """Install a recording stub at a re-rooted historical default path."""
        marker = self.tmp / (rel.replace("/", "_") + ".ran")
        self._write_stub(Path(str(self.fake_root) + rel), exit_code, marker)
        return marker

    def _install_abs(self, abs_path: Path, exit_code: int = 0) -> Path:
        """Install a recording stub at an ABSOLUTE path outside the fake root."""
        self._stub_seq += 1
        marker = self.tmp / f"stub{self._stub_seq}.ran"
        self._write_stub(abs_path, exit_code, marker)
        return marker

    def _sbin_symlink_to_versioned(self):
        """The `flip` 6b layout: <SbinDir>/xpfd -> <VersionsDir>/current/xpfd.

        This is what a HEALTHY default-rooted box looks like — and, verbatim,
        what a box that relocated BOTH roots leaves behind (relocation removes
        neither), which is why a same-inode test cannot tell them apart.
        """
        sbin_path = Path(str(self.fake_root) + SBIN)
        sbin_path.parent.mkdir(parents=True, exist_ok=True)
        sbin_path.symlink_to(str(self.fake_root) + VERSIONED)

    def _assert_refused(self, res, why: str):
        self.assertEqual(
            res.returncode,
            0,
            "the refusal must stay on the non-rebooting infra-error path; a "
            f"non-zero exit trips OnFailure= and reboots: {res.stderr}",
        )
        # DID NOT ADOPT AN INFERRED BINARY. Under the r7 arm-record design there
        # are two correct non-promotion outcomes, and which one applies depends
        # on whether a candidate was armed at all:
        #
        #   * a candidate IS armed and something contradicts or invalidates the
        #     record -> loud ERROR + REFUSING;
        #   * nothing is armed -> "nothing to promote", which is not a failure
        #     to diagnose but a definitive statement (the record is written by
        #     arming and removed with the journal).
        #
        # Both mean the gate did not let an inferred binary authorize a
        # promotion, which is what every caller of this helper is testing. The
        # per-test assertNotIn("using <impostor>") above pins that the specific
        # bad candidate was not adopted.
        refused = "REFUSING to promote" in res.stderr
        nothing_armed = "nothing to promote" in res.stderr
        self.assertTrue(
            refused or nothing_armed,
            f"the gate neither refused nor reported nothing-armed ({why}); it "
            f"may have adopted an inferred binary: {res.stderr}",
        )
        if refused:
            self.assertIn("ERROR", res.stderr, f"the refusal was not loud ({why}): {res.stderr}")
        self.assertNotIn(
            "promotion gate: clean",
            res.stderr,
            f"the gate reported a CLEAN promotion ({why}) — an inferred binary "
            f"authorized it: {res.stderr}",
        )
        self.assertFalse(
            self.systemctl_ran.exists(),
            f"the refusal rebooted the box ({why})",
        )
        self.assertFalse(
            self.marker.exists(),
            f"the gate executed the xpfd it found on $PATH ({why}) (#6541)",
        )

    def _spawn_fake_daemon(self, subdir: str, basename: str = "xpfd", unlink: bool = False):
        """Run a real process from a real file; return (proc, path, cgroup)."""
        sleep_bin = shutil.which("sleep")
        if not sleep_bin:
            self.skipTest("no sleep(1) to model a running daemon")
        target = self.tmp / subdir / basename
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
        if unlink:
            # Models a binary REPLACED on disk while the daemon runs: the
            # kernel then renders /proc/<pid>/exe as "<path> (deleted)".
            target.unlink()
        try:
            first = Path(f"/proc/{proc.pid}/cgroup").read_text().splitlines()[0]
        except (OSError, IndexError):
            self.skipTest("no readable /proc/<pid>/cgroup on this kernel")
        # "<hierarchy-id>:<controllers>:<path>" — cgroup v2 renders "0::<path>".
        # The path field is exactly what systemd reports as the unit's
        # ControlGroup for a unit whose main process is this one (verified
        # firsthand against cron/dbus/incus on a live systemd host).
        fields = first.split(":", 2)
        if len(fields) != 3 or not fields[2].startswith("/"):
            self.skipTest(f"unrecognised /proc/<pid>/cgroup rendering: {first!r}")
        return proc, target, fields[2]


class TestResolutionBehaviour(_GateBase):
    """Resolution behaviour of the gate itself."""

    # ------------------------------------------------- no inference fallback

    def test_relocated_roots_with_same_inode_leftovers_are_never_executed(self):
        # #6601 r4 Codex MAJOR-1, reproduced exactly. Both roots relocated, so
        # the LIVE xpfd is at neither default — and relocation removed neither
        # leftover, so the old sbin symlink still points at the old versioned
        # runtime. The two leftovers are therefore ONE INODE, which is
        # bit-identical to what a HEALTHY default-rooted box looks like: `-ef`
        # calls it unambiguous and hands the promotion decision to a STALE
        # build (Codex: live_ran False / stale_ran True).
        #
        # Neither systemd source can rescue it here: the daemon is not running
        # (MainPID 0) and the ExecStart cannot be parsed, because the live
        # path legally contains the literal " ; argv[]=" that is systemd's own
        # field delimiter — so no textual parse can find the field boundary.
        # `<tmp>/opt/relocated`, where cutting at the FIRST delimiter lands, is
        # itself a real executable, so a parse that gives up on the count rule
        # does not fail to resolve: it resolves to a THIRD binary.
        #
        # There is nothing left that is an ANSWER, so the gate must REFUSE.
        live_dir = self.tmp / "opt" / "relocated ; argv[]=x"
        live = live_dir / "xpfd"
        live_ran = self._install_abs(live)
        truncated = self.tmp / "opt" / "relocated"
        truncated_ran = self._install_abs(truncated)

        stale_ran = self._install(VERSIONED, 0)
        self._sbin_symlink_to_versioned()

        self.stub_mainpid = "0"
        self.stub_execstart = f"{{ path={live} ; argv[]={live} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            stale_ran.exists(),
            "the gate executed the STALE leftover left behind by relocating "
            "BOTH roots. Its sbin symlink still points at its versioned "
            "runtime, so the pair is a single inode and looks exactly like a "
            "healthy default layout -- no filesystem test can tell them apart, "
            f"which is why there must be no filesystem fallback at all: {res.stderr}",
        )
        self.assertFalse(
            live_ran.exists(),
            "the gate parsed an ExecStart whose path contains systemd's own "
            f"field delimiter: {res.stderr}",
        )
        self.assertFalse(
            truncated_ran.exists(),
            "the gate cut the ExecStart at the FIRST field delimiter and "
            f"executed {truncated} -- a shorter, different, and real binary "
            f"(#6601 r4 MAJOR-1): {res.stderr}",
        )
        self._assert_refused(res, "both roots relocated, same-inode leftovers")

    def test_disagreeing_leftover_defaults_are_never_executed(self):
        # The `--sbin-dir`-only / `--versions-dir`-only shapes: two usable
        # defaults that are DIFFERENT files. One is stale and nothing on the
        # box says which, so no ranking is right for both.
        sbin_ran = self._install(SBIN, 0)
        versioned_ran = self._install(VERSIONED, 0)
        self.stub_show_fail = "1"  # systemd cannot answer

        res = self._run()
        self.assertFalse(sbin_ran.exists(), f"the gate executed {SBIN}: {res.stderr}")
        self.assertFalse(
            versioned_ran.exists(), f"the gate executed {VERSIONED}: {res.stderr}"
        )
        self._assert_refused(res, "two different usable defaults")

    def test_a_single_surviving_default_is_never_executed(self):
        # The remaining shape a defaults fallback would accept: exactly one
        # default is usable, so "the only usable default" looks decisive. It is
        # not — it is precisely the surviving half of a partial relocation, and
        # relocation leaves the STALE half behind just as readily as the live
        # one.
        versioned_ran = self._install(VERSIONED, 0)
        self.stub_show_fail = "1"

        res = self._run()
        self.assertFalse(
            versioned_ran.exists(),
            "the gate executed the ONLY usable compiled default. That is the "
            "surviving leftover of a `--versions-dir`-only relocation just as "
            f"often as it is a live install (#6601 r5): {res.stderr}",
        )
        self._assert_refused(res, "exactly one usable default")

    # ---------------------------------------------- anti-over-reach: it works

    def test_healthy_default_rooted_box_resolves_via_execstart(self):
        # ANTI-OVER-REACH. Removing the guess must not strand the gate on an
        # ordinary box. A default-rooted install has not relocated anything, so
        # systemd answers: the shipped base unit carries
        # ExecStart=/usr/local/sbin/xpfd before the first cut, and `flip` 6c
        # templates ExecStart=<VersionsDir>/<ver>/xpfd after every cut. The
        # binary it names is reached DIRECTLY, through the sbin->versioned
        # symlink `flip` 6b leaves.
        versioned_ran = self._install(VERSIONED, 0)
        self._sbin_symlink_to_versioned()
        sbin = str(self.fake_root) + SBIN
        self.stub_execstart = f"{{ path={sbin} ; argv[]={sbin} ; ignore_errors=no }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            versioned_ran.exists(),
            "the gate refused on an ORDINARY, healthy default-rooted box whose "
            "systemd names the binary outright -- removing the compiled-default "
            f"guess must not cost availability: {res.stderr}",
        )
        self.assertNotIn("REFUSING", res.stderr)
        self.assertIn("ExecStart", res.stderr)
        self.assertFalse(self.marker.exists(), "the gate used $PATH (#6541)")

    def test_healthy_default_rooted_box_resolves_via_main_pid(self):
        # The other half of anti-over-reach, and the ordinary case on a box
        # where the gate runs while xpfd is UP (the unit is After=xpfd.service).
        # Verified firsthand on a live systemd host as root: `systemctl show
        # -p MainPID --value` + `readlink /proc/<pid>/exe` yields the real
        # binary, and `-p ControlGroup --value` is exactly the path field of
        # that pid's /proc/<pid>/cgroup line.
        proc, target, cgroup = self._spawn_fake_daemon("opt-live")
        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = cgroup
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
        self.assertFalse(stale_sbin.exists(), f"ran a leftover: {res.stderr}")
        self.assertFalse(stale_versioned.exists(), f"ran a leftover: {res.stderr}")

    def test_discovers_relocated_roots_via_systemd_execstart(self):
        # MAJOR (fold r3). With `--versions-dir=/opt/xpf/versions
        # --sbin-dir=/usr/sbin`, NEITHER compiled default exists yet the live
        # binary is perfectly intact. Systemd knows where it is, because that
        # is the ExecStart the cut templated (flip step 6c).
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
            f"names, so an ARMED promotion is skipped: {res.stderr}",
        )
        self.assertFalse(self.marker.exists(), "the gate used $PATH (#6541)")

    def test_systemd_execstart_outranks_leftover_defaults(self):
        # Discovery must win over leftovers even when leftovers exist and are
        # perfectly usable.
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
        self.assertFalse(stale_sbin.exists(), f"ran the STALE leftover at {SBIN}")
        self.assertFalse(stale_versioned.exists(), f"ran the STALE leftover at {VERSIONED}")

    # ------------------------------------------------- MainPID -> unit binding

    def test_main_pid_outside_the_unit_cgroup_is_rejected(self):
        # #6601 r4 MAJOR-2. The recycle race, made concrete: MainPID names a
        # live process running a binary CALLED `xpfd`, but that process is not
        # in xpfd.service's control group — it is an unrelated program that
        # inherited the pid after the daemon exited. The basename guard alone
        # accepts it and hands it the promote-vs-rollback decision.
        proc, target, real_cgroup = self._spawn_fake_daemon("impostor")
        unit_cgroup = "/system.slice/xpfd.service"
        if real_cgroup == unit_cgroup or real_cgroup.startswith(unit_cgroup + "/"):
            self.skipTest("test process really is inside /system.slice/xpfd.service")
        impostor_ran = self.tmp / "impostor-would-have-run"

        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = unit_cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "the gate accepted a process that is NOT a member of "
            "xpfd.service's control group as the promotion authority. A "
            "recycled pid running any binary named `xpfd` then decides "
            f"promote-vs-rollback (#6601 r4 MAJOR-2): {res.stderr}",
        )
        self.assertFalse(impostor_ran.exists())
        self._assert_refused(res, "MainPID outside the unit cgroup")

    def test_main_pid_that_changes_mid_sequence_is_rejected(self):
        # The narrower half of the same race: the association held when it was
        # first read, but systemd's MainPID moved on while the gate was
        # resolving. Re-read and require the SAME pid.
        proc, target, cgroup = self._spawn_fake_daemon("racing")
        self.stub_mainpid = str(proc.pid)
        self.stub_mainpid2 = str(proc.pid + 1)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "the gate believed a MainPID that had already changed by the time "
            "it finished resolving, so /proc/<pid>/exe may name a recycled "
            f"process's binary (#6601 r4 MAJOR-2): {res.stderr}",
        )
        self._assert_refused(res, "MainPID changed mid-sequence")

    def test_main_pid_naming_a_non_xpfd_binary_is_rejected(self):
        # The basename guard. Every layout this gate supports names the
        # artifact `xpfd` (the manifest basename), so a MainPID whose
        # /proc/<pid>/exe names something else is not a layout the gate
        # understands — it is an override, a wrapper, or a mis-association, and
        # a wrong answer here authorizes the promotion.
        proc, target, cgroup = self._spawn_fake_daemon("wrapper", basename="xpfd-wrapper")
        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "the gate accepted a MainPID whose executable is not named `xpfd` "
            f"as the promotion authority: {res.stderr}",
        )
        self._assert_refused(res, "MainPID names a non-xpfd binary")

    def test_main_pid_whose_binary_was_replaced_on_disk_is_rejected(self):
        # A binary replaced (or removed) under a running daemon reads back as
        # "<path> (deleted)". That string is not a path — it cannot be
        # re-executed, and the file it once named is gone — so the MainPID hop
        # must yield nothing. Asserted as an OUTCOME: three independent things
        # reject it (the "(deleted)" case, the basename guard, and the
        # regular-file admission test), so no single one of them is claimed to
        # be the sole rejector (#6601 r4 MINOR).
        proc, target, cgroup = self._spawn_fake_daemon("replaced", unlink=True)
        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = cgroup
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            str(target),
            res.stderr,
            "the gate adopted a MainPID whose executable was replaced on disk; "
            f'its /proc/<pid>/exe reads "<path> (deleted)": {res.stderr}',
        )
        self._assert_refused(res, "MainPID binary deleted on disk")

    def test_prefix_sibling_cgroup_does_not_satisfy_membership(self):
        # The membership test matches the PATH FIELD of a /proc/<pid>/cgroup
        # line, not a substring of the line. A substring test would let a
        # same-prefix sibling stand in for the unit — `/system.slice/xpfd.serv`
        # for `/system.slice/xpfd.service`, or the unit's cgroup for a
        # DIFFERENT unit whose name merely extends it — which is the whole
        # association silently going away again.
        proc, target, real_cgroup = self._spawn_fake_daemon("prefixy")
        if len(real_cgroup) < 2:
            self.skipTest(f"cgroup path too short to truncate: {real_cgroup!r}")
        # A strict prefix of the real path: contained in the line, but not the
        # path field and not a parent directory of it.
        self.stub_controlgroup = real_cgroup[:-1]
        self.stub_mainpid = str(proc.pid)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            f"using {target} (",
            res.stderr,
            "a cgroup path that merely OCCURS in the process's "
            "/proc/<pid>/cgroup line was accepted as unit membership "
            f"(#6601 r4 MAJOR-2): {res.stderr}",
        )
        self._assert_refused(res, "prefix-sibling cgroup")

    def test_delegated_subgroup_still_satisfies_membership(self):
        # OVER-REACH GUARD on the same matcher. systemd may place a unit's
        # processes in a subgroup of the unit's own cgroup (delegation), so a
        # process UNDER the reported ControlGroup is still a member. Requiring
        # an exact equality would reject a legitimately delegated unit and
        # strand the gate.
        proc, target, real_cgroup = self._spawn_fake_daemon("delegated")
        parent = real_cgroup.rsplit("/", 1)[0]
        if not parent.startswith("/") or parent == real_cgroup:
            self.skipTest(f"cgroup path has no parent to delegate from: {real_cgroup!r}")
        self.stub_controlgroup = parent
        self.stub_mainpid = str(proc.pid)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(
            f"using {target} (",
            res.stderr,
            "a process in a DELEGATED SUBGROUP of the unit's control group was "
            f"not recognised as a member: {res.stderr}",
        )

    def test_unreported_control_group_falls_through_to_execstart(self):
        # OVER-REACH GUARD on the binding: a systemd that cannot report
        # ControlGroup (or a /proc the gate cannot correlate) must not strand
        # the gate — the MainPID source simply yields nothing and ExecStart
        # gets its turn. Availability is preserved by the NEXT authority, never
        # by a guess.
        proc, _target, _cgroup = self._spawn_fake_daemon("live-unbindable")
        declared = self.tmp / "declared" / "xpfd"
        declared_ran = self._install_abs(declared)

        self.stub_mainpid = str(proc.pid)
        self.stub_controlgroup = ""  # systemd did not answer
        self.stub_execstart = f"{{ path={declared} ; argv[]={declared} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            declared_ran.exists(),
            "an unbindable MainPID stranded the gate instead of falling "
            f"through to the declared ExecStart: {res.stderr}",
        )

    # ---------------------------------------------------- ExecStart strictness

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
            f"the gate did not run the xpfd systemd's ExecStart names: {res.stderr}",
        )
        self.assertFalse(self.marker.exists(), "the gate used $PATH (#6541)")

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
            f"the gate did not run the xpfd systemd's ExecStart names: {res.stderr}",
        )

    def test_multiple_execstart_entries_are_not_reduced_to_the_first(self):
        # MAJOR-1, second shape. systemd renders one ExecStart entry per LINE
        # (verified against man-db.service). The shipped Type=simple unit cannot
        # validly carry more than one, but an operator-overridden Type=oneshot
        # can -- and its FIRST entry need not be xpfd at all. Taking it
        # unconditionally hands the promote-vs-rollback decision to an arbitrary
        # command.
        #
        # NOTE (#6601 r4 MINOR): on a REAL multi-entry render each entry brings
        # its own " ; argv[]=", so the delimiter-COUNT rule already rejects this
        # value; the newline guard is defence in depth here, not the sole
        # rejector. The test below covers what only the newline guard rejects.
        foreign = self.tmp / "prep" / "install"
        foreign_ran = self._install_abs(foreign)
        entry = self.tmp / "opt" / "xpfd"
        entry_ran = self._install_abs(entry)

        self.stub_execstart = (
            f"{{ path={foreign} ; argv[]={foreign} -d ; ignore_errors=no }}\n"
            f"{{ path={entry} ; argv[]={entry} ; ignore_errors=no }}"
        )
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            foreign_ran.exists(),
            f"the gate executed {foreign}, the FIRST of several ExecStart "
            f"entries, which need not be xpfd (#6601 r4 MAJOR-1): {res.stderr}",
        )
        self.assertFalse(entry_ran.exists(), "the gate picked an entry out of an ambiguous list")
        self._assert_refused(res, "multi-entry ExecStart")

    def test_multiline_execstart_with_one_delimiter_is_rejected(self):
        # The case the newline guard alone rejects, so that guard carries its
        # own weight (#6601 r4 MINOR: the delimiter-count rule subsumes it for
        # ordinary multi-entry renders). One delimiter, several lines: the
        # count rule passes and, without the newline guard, the parse silently
        # adopts the first entry -- a REAL, usable binary here, so the mutation
        # is not merely a failed resolve but a wrong execution.
        first = self.tmp / "first" / "xpfd"
        first_ran = self._install_abs(first)
        second = self.tmp / "second" / "xpfd"
        second_ran = self._install_abs(second)

        self.stub_execstart = f"{{ path={first} ; argv[]={first} }}\n{{ path={second} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            first_ran.exists(),
            "the gate adopted the first of a MULTI-LINE ExecStart render that "
            f"carries only one field delimiter: {res.stderr}",
        )
        self.assertFalse(second_ran.exists())
        self._assert_refused(res, "multi-line ExecStart with one delimiter")

    def test_bare_execstart_with_a_tab_is_rejected(self):
        # #6601 r4 audit note. The bare (unstructured) rendering is accepted
        # only when the WHOLE value is one absolute path. Rejecting just spaces
        # and semicolons does not make that true: a tab separates a path from
        # its arguments equally well, and the value here names a real,
        # executable file, so tolerating it is a wrong execution rather than a
        # failed resolve.
        tabbed = self.tmp / "tabbed" / "xpfd\t--flag"
        tabbed_ran = self._install_abs(tabbed)

        self.stub_execstart = str(tabbed)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(
            tabbed_ran.exists(),
            "the gate accepted a bare ExecStart rendering containing a TAB. "
            "`path<TAB>--flag` is indistinguishable from a path plus an "
            f"argument, so it is not a whole path (#6601 r4): {res.stderr}",
        )
        self._assert_refused(res, "bare ExecStart containing a tab")

    def test_bare_absolute_execstart_is_accepted(self):
        # OVER-REACH GUARD on the whitespace tightening: an ordinary bare
        # rendering (a single absolute path, no arguments) must still resolve.
        plain = self.tmp / "plain" / "xpfd"
        plain_ran = self._install_abs(plain)

        self.stub_execstart = str(plain)
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(
            plain_ran.exists(),
            f"a plain absolute bare ExecStart did not resolve: {res.stderr}",
        )

    # --------------------------------------------------- admission + refusals

    def test_directory_candidate_is_not_treated_as_the_binary(self):
        # `test -x` alone is TRUE for a searchable DIRECTORY. The inner hop's
        # validateGateBin rejects a non-regular target, so the outer hop must
        # too — otherwise the two hops' admission tests are not actually
        # symmetric, and the gate execs a directory (rc=126) which then reads
        # as an infra error rather than the refusal it is.
        candidate = self.tmp / "isadir" / "xpfd"
        candidate.mkdir(parents=True)

        self.stub_execstart = f"{{ path={candidate} ; argv[]={candidate} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertNotIn(
            "infra error",
            res.stderr,
            f"a DIRECTORY named by ExecStart was exec'd as the gate binary "
            f"instead of being rejected by the `-f` regular-file test: {res.stderr}",
        )
        self._assert_refused(res, "ExecStart names a directory")

    def test_dangling_symlink_candidate_is_rejected(self):
        # #2176 leaves a symlink pointing into a removed versions dir.
        dangling = self.tmp / "dangle" / "xpfd"
        dangling.parent.mkdir(parents=True, exist_ok=True)
        dangling.symlink_to(self.tmp / "removed" / "versions" / "v1" / "xpfd")

        self.stub_execstart = f"{{ path={dangling} ; argv[]={dangling} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "ExecStart names a dangling symlink")

    def test_unqueryable_systemd_refuses_loudly_rather_than_skipping(self):
        # #6601 r4 audit note. The quiet "xpf is not on this box" skip is only
        # honest when systemd ANSWERED not-found. A systemctl that is missing or
        # erroring proves NOTHING about whether xpf is installed -- laundering
        # that into the benign skip lets an ARMED candidate sail past the gate
        # behind a reassuring log line.
        self.stub_show_fail = "1"

        res = self._run()
        self.assertNotIn(
            "skipping promotion gate",
            res.stderr,
            "an unqueryable systemd was treated as proof that xpf is absent "
            f"(#6601 r4): {res.stderr}",
        )
        self._assert_refused(res, "systemctl cannot be consulted")

    def test_unusable_execstart_refuses_rather_than_guessing(self):
        # A unit whose ExecStart names a path that no longer exists (mid-cut, a
        # GC'd version dir). Earlier revisions fell through to the compiled
        # defaults here -- which is exactly the wrong instinct: an ExecStart
        # pointing into a relocated//GC'd root is the STRONGEST signal that a
        # leftover at a default path is stale.
        stale_sbin = self._install(SBIN, 0)
        stale_versioned = self._install(VERSIONED, 0)
        self.stub_execstart = f"{{ path={self.tmp}/gone/xpfd ; argv[]={self.tmp}/gone/xpfd }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertFalse(stale_sbin.exists(), f"ran a leftover: {res.stderr}")
        self.assertFalse(stale_versioned.exists(), f"ran a leftover: {res.stderr}")
        self._assert_refused(res, "ExecStart names a path that is gone")

    def test_refuses_loudly_when_installed_but_unlocatable(self):
        # FAIL LOUD, not quiet. xpfd.service is installed but nothing resolves:
        # an armed candidate would otherwise sail past unverified with nothing
        # in the journal to say so. The refusal must be explicit AND must stay
        # exit 0 — a non-zero exit trips OnFailure= and reboots the box.
        self.stub_loadstate = "loaded"

        res = self._run()
        self._assert_refused(res, "installed but unlocatable")

    def test_skips_rather_than_falling_back_to_path(self):
        # systemd ANSWERED not-found: the one honest "xpf is not on this box"
        # case. Skip quietly — and never reach for the perfectly good xpfd
        # sitting on $PATH.
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(
            self.marker.exists(),
            "with no explicit candidate the gate fell back to $PATH (#6541)",
        )
        # MINOR-1 (#6601 r5): this must NOT read like a benign skip. The deb
        # that installs this script also installs xpfd.service, so a not-found
        # means the unit was removed or renamed -- and on such a box an armed
        # candidate goes unverified. The line has to say the gate did not run
        # and name what it looked for.
        self.assertIn("WARNING", res.stderr)
        self.assertIn("did NOT run", res.stderr)
        self.assertIn("xpfd.service", res.stderr)
        self.assertNotIn(
            "skipping promotion gate",
            res.stderr,
            "the not-found branch still reads like a routine skip; on a box cut "
            "with `--unit <name>` that line hides an UNVERIFIED armed candidate "
            "(#6601 r5 MINOR-1)",
        )

    # ------------------------------------------------------ contract preserved

    def test_revert_exit_3_still_reboots(self):
        # OVER-REACH GUARD: the explicit-path change must not disturb the
        # revert contract. An xpfd exiting 3 (REVERT) must still drive the
        # reboot branch. `systemctl` is stubbed on PATH — it is a system
        # binary and is legitimately PATH-resolved.
        live = self.tmp / "live" / "xpfd"
        self._install_abs(live, exit_code=3)
        self.stub_execstart = f"{{ path={live} ; argv[]={live} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("REVERT", res.stderr)
        self.assertTrue(
            self.systemctl_ran.exists(),
            f"exit 3 did not trigger the recovery reboot: {res.stderr}",
        )
        self.assertIn("reboot", self.systemctl_ran.read_text())

    def test_infra_error_does_not_reboot(self):
        # OVER-REACH GUARD: a non-0/non-3 rc stays a non-rebooting infra error.
        live = self.tmp / "live" / "xpfd"
        self._install_abs(live, exit_code=1)
        self.stub_execstart = f"{{ path={live} ; argv[]={live} }}"
        self.stub_loadstate = "loaded"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("infra error", res.stderr)
        self.assertFalse(self.systemctl_ran.exists(), "an infra error triggered a reboot")


class TestRenamedUnitIsNotLaundered(_GateBase):
    """#6601 r5 MINOR-1 — `--unit <name>` boxes must not get a benign skip.

    `xpfd upgrade cut --unit myxpf` is a SUPPORTED standalone selector
    (cmd/xpfd/upgrade.go). On such a host flip maintains myxpf.service, and the
    deb-installed xpfd.service may have been removed. The gate queries
    xpfd.service specifically -- deliberately, since inferring which unit is the
    xpf one would resolve a leftover from a renamed unit as readily as the live
    one -- so it finds not-found and cannot resolve a binary.

    That state must NOT be reported as a routine skip: an armed candidate would
    boot, run UNVERIFIED, never be promoted, and the only journal line would read
    like everything was fine. Two defences, both asserted here:

      * `xpfd upgrade kernel arm` REFUSES this layout up front
        (CheckKernelPromotionUnit, pkg/upgrade -- Go-side tests).
      * the boot-time gate says loudly that it did not run, and names what it
        looked for.
    """

    def test_renamed_unit_does_not_read_as_a_benign_skip(self):
        # The whole scenario: the default unit is GONE (renamed to myxpf), and a
        # perfectly good xpfd is on $PATH for a PATH-resolving gate to find.
        self.stub_loadstate = "not-found"
        self.stub_mainpid = "0"
        self.stub_execstart = ""

        res = self._run()
        self.assertEqual(
            res.returncode,
            0,
            "must stay exit 0 -- a non-zero exit trips OnFailure= and reboots "
            f"the box: {res.stderr}",
        )
        self.assertFalse(
            self.marker.exists(),
            "the gate executed the xpfd it found on $PATH (#6541)",
        )

        # The load-bearing assertion. A line that reads like a routine skip is
        # exactly what launders an unverified candidate.
        self.assertNotIn(
            "skipping promotion gate",
            res.stderr,
            "a renamed-unit box still gets a reassuring 'skipping' line while an "
            "armed candidate goes UNVERIFIED (#6601 r5 MINOR-1)",
        )
        for want in ("WARNING", "did NOT run", "xpfd.service", "UNVERIFIED"):
            self.assertIn(
                want,
                res.stderr,
                f"the not-found line does not say {want!r}; an operator cannot "
                f"tell the gate silently did not run: {res.stderr}",
            )
        # It must name what it looked for, so the operator can act.
        self.assertIn("LoadState=[not-found]", res.stderr)
        self.assertIn("--unit", res.stderr)


class TestRefusalCarriesFacts(_GateBase):
    """#6601 r5 MINOR-2 — the refusal is the only signal, so it must carry data.

    exit 0 keeps the unit `active`, so `systemctl status xpf-kernel-promote`
    reads SUCCESS. The journal line is all an operator gets, and policy prose
    without the facts systemd returned is not actionable. Its advice must also
    branch on which of the two named causes fired: telling someone to fix
    ExecStart when systemctl could not be consulted points at the wrong system.
    """

    def test_refusal_echoes_what_systemd_returned(self):
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = "{ path=/nonexistent/xpfd ; argv[]=/nonexistent/xpfd ; ignore_errors=no }"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("ERROR", res.stderr)
        self.assertIn("REFUSING to promote", res.stderr)

        for want in (
            "LoadState=[loaded]",
            "MainPID=[0]",
            "/nonexistent/xpfd",
        ):
            self.assertIn(
                want,
                res.stderr,
                f"the refusal omits {want!r}. With exit 0 keeping the unit "
                "active, this line is the ONLY operator signal and it must "
                "carry what systemd actually returned (#6601 r5 MINOR-2)",
            )

    def test_advice_branches_on_the_cause_installed(self):
        # xpf IS installed; the actionable advice is to fix the unit.
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = "garbage-not-a-path"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("IS known to systemd", res.stderr)
        self.assertIn("Fix xpfd.service", res.stderr)
        self.assertNotIn("systemd-availability problem", res.stderr)

    def test_advice_branches_on_the_cause_systemctl_unreachable(self):
        # systemctl could not be consulted. Telling the operator to fix
        # ExecStart here is actively WRONG -- there is no evidence about the
        # unit at all.
        self.stub_show_fail = "1"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("ERROR", res.stderr)
        self.assertIn("could not be consulted", res.stderr)
        self.assertIn("systemd-availability problem", res.stderr)
        self.assertNotIn(
            "Fix xpfd.service so its ExecStart",
            res.stderr,
            "the refusal tells the operator to fix ExecStart even though "
            "systemctl could not be consulted at all -- that points at the "
            "wrong system (#6601 r5 MINOR-2)",
        )


class TestBusyboxParity(_GateBase):
    """NIT-1 (#6601 r5) — the portability claim was asserted but never bound.

    The `[[:space:]]` note claims dash and busybox both honour the class, and
    the suite only ever ran /bin/sh. Re-run the state matrix under busybox sh so
    the claim is tested rather than trusted. SKIPs when busybox is absent.
    """

    def setUp(self):
        busybox = shutil.which("busybox")
        if not busybox:
            self.skipTest("busybox not installed")
        super().setUp()
        self.shell_argv = [busybox, "sh"]

    def test_parses_and_resolves_under_busybox(self):
        live = self.tmp / "opt" / "versions" / "v9" / "xpfd"
        ran = self._install_abs(live)
        self.stub_loadstate = "loaded"
        self.stub_mainpid = "0"
        self.stub_execstart = f"{{ path={live} ; argv[]={live} ; ignore_errors=no }}"

        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(ran.exists(), f"busybox sh did not resolve+run: {res.stderr}")

    def test_whitespace_rejection_holds_under_busybox(self):
        # The bare-rendering branch must reject a TAB as well as a space. This
        # is the specific claim the comment makes about [[:space:]].
        for ws, label in ((" ", "space"), ("\t", "tab")):
            with self.subTest(label):
                self.stub_loadstate = "loaded"
                self.stub_mainpid = "0"
                self.stub_execstart = f"/opt/xpfd{ws}--flag"
                res = self._run()
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertIn(
                    "REFUSING to promote",
                    res.stderr,
                    f"busybox sh accepted a bare ExecStart containing a {label}; "
                    "the [[:space:]] portability claim is false there",
                )

    def test_renamed_unit_warning_holds_under_busybox(self):
        self.stub_loadstate = "not-found"
        self.stub_mainpid = "0"
        self.stub_execstart = ""
        res = self._run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("WARNING", res.stderr)
        self.assertNotIn("skipping promotion gate", res.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)
