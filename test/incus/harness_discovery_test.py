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
