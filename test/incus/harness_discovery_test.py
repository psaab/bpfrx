"""#8136: every test/incus/*_test.py must actually contribute tests.

THE DEFECT THIS EXISTS FOR. 20 of 21 files here were run by no target: the
Makefile passed a LITERAL filename as the discovery pattern, so exactly one
file ran. Widening the pattern is half a fix — the other half is that two
distinct mechanisms make a file contribute ZERO tests while everything reports
success:

  1. A hyphenated filename is not a valid module identifier, so `unittest
     discover` cannot import it and skips it. Six files were invisible this way,
     including the 260-line step3 file the issue notes had failed to catch
     #7424 row 1.
  2. A pytest-style module has module-level `def test_*` functions and no
     TestCase, so unittest imports it and collects nothing from it.

Neither shows up as a failure. The suite reports OK and a smaller number, and
nobody compares that number to anything — which is why this went unnoticed long
enough for the orphaned files to accumulate real drift.

So the guard is not "does discovery run" but "does every file on disk
contribute". A count of files versus a count of loaded modules is the cheap
version of exactly that, and it is what stops the next hyphenated or
pytest-style file from being invisible the day it lands.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PATTERN = "*_test.py"


class HarnessDiscoveryTest(unittest.TestCase):
    def test_every_test_file_contributes_at_least_one_test(self) -> None:
        on_disk = sorted(p.name for p in HERE.glob(PATTERN))
        self.assertTrue(on_disk, f"no {PATTERN} files found in {HERE}")

        loader = unittest.TestLoader()
        suite = loader.discover(str(HERE), pattern=PATTERN)

        # Map every collected test back to the file that defined it. A module
        # that failed to import shows up as unittest.loader._FailedTest, which
        # is a REAL test that fails — so it is counted here as contributing,
        # and the suite reds on its own. The silent cases are the ones that
        # contribute nothing at all.
        contributing: set[str] = set()

        def walk(s):
            for item in s:
                if isinstance(item, unittest.TestSuite):
                    walk(item)
                    continue
                mod = type(item).__module__
                if mod:
                    contributing.add(mod.split(".")[-1])
                # A FunctionTestCase carries no useful __module__, so fall back
                # to the module the underlying callable came from.
                fn = getattr(item, "_testFunc", None)
                if fn is not None and getattr(fn, "__module__", None):
                    contributing.add(fn.__module__.split(".")[-1])

        walk(suite)

        silent = [f for f in on_disk if Path(f).stem not in contributing]
        self.assertEqual(
            silent,
            [],
            "these files contribute NO tests to `unittest discover` and fail "
            "silently — the suite still reports OK:\n  "
            + "\n  ".join(silent)
            + "\n\nCauses seen in #8136: a hyphenated filename is not an importable "
            "module name (rename it to underscores); a pytest-style module has no "
            "TestCase (see unittest_shim.collect_module_tests).",
        )

    def test_no_hyphenated_test_filenames(self) -> None:
        """The specific cause, named, so the failure says what to do.

        The check above would catch a hyphenated file too, but reports it as
        "contributes nothing", which sends the reader looking for a missing
        TestCase. Naming the cause separately turns a symptom into an
        instruction.
        """
        hyphenated = sorted(p.name for p in HERE.glob(PATTERN) if "-" in p.name)
        self.assertEqual(
            hyphenated,
            [],
            "these filenames contain hyphens, so they are not valid Python module "
            "identifiers and `unittest discover` skips them without error:\n  "
            + "\n  ".join(hyphenated)
            + "\nRename the hyphens to underscores.",
        )


class CollectionAgreementTest(unittest.TestCase):
    """#8278: a pytest-style file must collect the same tests both ways.

    `test_every_test_file_contributes_at_least_one_test` above is a LOWER
    BOUND, and a lower bound cannot see a file that collects MOST of its
    tests. step3 defined three `_7424` cases below its `__main__` block:
    `unittest discover` ran all 14, `python3 <file>` ran 11, and both
    reported success. step1 ran 17 and 0 the same way. The bound was
    satisfied in every case.

    So this asserts the AGREEMENT between the two ways of running the
    file rather than pinning either count -- pinning one would encode
    which of them we trust, and the defect is precisely that they can
    disagree while both look healthy.
    """

    HERE = Path(__file__).parent

    @staticmethod
    def _ran(out: str) -> int:
        for line in out.splitlines():
            if line.startswith("Ran "):
                return int(line.split()[1])
        return 0

    def test_direct_execution_collects_what_discovery_collects(self) -> None:
        # Match the ASSIGNMENT, not a mention. A marker matching any file
        # that DISCUSSES the collector matches this file's own docstring,
        # and the check then runs itself as a subprocess, forever -- the
        # shape the #7296 census comment warns about, a source-scanning
        # gate satisfied by its own documentation. Excluded by
        # construction rather than by a name allowlist that can rot.
        marker = "load_tests = collect_module_tests("
        subjects = sorted(
            q for q in self.HERE.glob("*_test.py")
            if q.name != Path(__file__).name and marker in q.read_text()
        )
        # Positive control: if the glob or the marker string stops
        # matching, this test would pass over an empty set and report a
        # clean sweep of nothing.
        self.assertGreater(
            len(subjects), 0,
            "no pytest-style test module found -- the collect_module_tests "
            "marker moved and this check is now vacuous",
        )
        for path in subjects:
            with self.subTest(module=path.name):
                direct = subprocess.run(
                    [sys.executable, str(path)],
                    capture_output=True, text=True, cwd=self.HERE, timeout=120,
                )
                disc = subprocess.run(
                    [sys.executable, "-m", "unittest", "discover",
                     "-s", str(self.HERE), "-p", path.name],
                    capture_output=True, text=True, cwd=self.HERE, timeout=120,
                )
                n_direct = self._ran(direct.stdout + direct.stderr)
                n_disc = self._ran(disc.stdout + disc.stderr)
                self.assertEqual(
                    n_direct, n_disc,
                    f"{path.name} collects {n_direct} tests when run directly "
                    f"and {n_disc} under discovery. unittest.main() collects at "
                    f"call time and never returns, so anything defined below "
                    f"the __main__ block -- a load_tests collector, or a test "
                    f"appended later -- is invisible to it.",
                )
                self.assertGreater(n_disc, 0, f"{path.name} collects nothing")
