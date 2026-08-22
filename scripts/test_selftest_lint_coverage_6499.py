#!/usr/bin/env python3
"""Guard: `run-selftests.sh`'s shell-lint list covers every shipped
`scripts/image/xpf-*` shell script (#6499).

`scripts/run-selftests.sh:12` says the runner "DISCOVERS and runs every
hermetic self-test", but its shell-syntax lint (`SH_SCRIPTS`, :90-100) is a
HAND ENUMERATION. A hand enumeration drifts silently: a script gets added to
the image surface, nobody remembers the list, and a shipped production
script — one the bake installs and enables — never gets so much as a parse
check. `xpf-kernel-promote` was exactly that for a while: installed and enabled
by `bake.py:501-507`, with an exit-3 path that REBOOTS the appliance, and
absent from the list. (It is in the list now, so this guard is what keeps the
next one from repeating it rather than a fix for that instance.)

Two directions, because the list can rot both ways:

  * a shipped script MISSING from the list — the #6499 defect: no lint at all;
  * a listed path that no longer EXISTS — `run-selftests.sh:103` does
    `[ -f "$s" ] || continue`, so a renamed or deleted script makes its lint
    leg silently vanish. That is the same drift wearing the other face, and it
    is invisible in the summary line (the PASS count just quietly drops).

SCOPE — SHELL scripts only. The runner picks its interpreter from each
script's shebang (`*bash*` -> bash, everything else -> sh), so a hypothetical
`scripts/image/xpf-*` written in Python does not belong in a shell-lint list
and is deliberately not required here. The membership test is therefore
"shebang names a shell", not "the filename matches".

This is NOT #7296. That issue is about the runner's *execution* discovery:
`:139` globs Python self-tests over four directories while `:146-160`
hand-enumerates the SHELL self-tests, so a hermetic `.sh` self-test can exist
and never RUN. Different list, different failure mode (an unrun test vs an
unlinted script), different fix. This guard touches only `SH_SCRIPTS`.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "run-selftests.sh"
IMAGE_DIR = ROOT / "scripts" / "image"


def _sh_scripts():
    """The paths listed in run-selftests.sh's SH_SCRIPTS block."""
    text = RUNNER.read_text(encoding="utf-8")
    m = re.search(r'^SH_SCRIPTS="\n(.*?)\n"$', text, re.MULTILINE | re.DOTALL)
    assert m, "could not locate the SH_SCRIPTS block in run-selftests.sh"
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]


def _shipped_image_shell_scripts():
    """Every `scripts/image/xpf-*` regular file whose shebang names a shell."""
    out = []
    for p in sorted(IMAGE_DIR.glob("xpf-*")):
        if not p.is_file():
            continue
        try:
            with p.open("rb") as fh:
                first = fh.readline().decode("utf-8", "replace")
        except OSError:
            continue
        if not first.startswith("#!"):
            continue
        if not re.search(r"\b(ba|da|k|z)?sh\b", first):
            continue
        out.append(p.relative_to(ROOT).as_posix())
    return out


class LintListCoverageTests(unittest.TestCase):
    def test_the_sh_scripts_block_is_parseable(self):
        # A guard that cannot find the list would pass vacuously over an empty
        # set — the worst outcome, since it argues against re-examining it.
        listed = _sh_scripts()
        self.assertGreater(len(listed), 5,
                           "SH_SCRIPTS parsed to almost nothing — the guard is "
                           "reading the wrong thing and would pass vacuously")

    def test_the_shipped_script_scan_is_not_empty(self):
        found = _shipped_image_shell_scripts()
        self.assertGreaterEqual(
            len(found), 4,
            "scripts/image/xpf-* scan found almost nothing — the guard would "
            f"pass vacuously over an empty set (got {found})")

    def test_every_shipped_image_shell_script_is_linted(self):
        listed = set(_sh_scripts())
        missing = [p for p in _shipped_image_shell_scripts() if p not in listed]
        self.assertEqual(
            missing, [],
            "these shipped scripts/image/xpf-* shell scripts are NOT in "
            "run-selftests.sh's SH_SCRIPTS lint list, so `make selftest` never "
            f"parse-checks them: {missing}. Add them to the list at "
            "scripts/run-selftests.sh:90.")

    def test_every_listed_script_still_exists(self):
        # run-selftests.sh:103 skips a missing path silently, so a rename
        # deletes a lint leg without a single word in the output.
        gone = [p for p in _sh_scripts() if not (ROOT / p).is_file()]
        self.assertEqual(
            gone, [],
            "these paths are in SH_SCRIPTS but do not exist, so their lint "
            f"legs silently vanish (run-selftests.sh:103 `|| continue`): {gone}")


if __name__ == "__main__":
    unittest.main()
