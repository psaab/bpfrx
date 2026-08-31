"""#8136: run pytest-style test modules under stdlib `unittest discover`.

Two of the `test/incus/*_test.py` files were written pytest-style — module-level
`def test_*` functions, `pytest.raises`, `pytest.approx`. They were invisible to
the harness for a different reason (hyphenated filenames are not importable
module names), and once renamed they still could not run, because pytest is not
installed in this environment and `import pytest` fails the loader.

Porting them meant a choice. Re-indenting ~840 lines into `TestCase` methods is
a large diff over tests nobody has run in months, and a large mechanical diff is
where a silently-inverted assertion hides. This shim is the smaller change: it
supplies the three pytest features those files actually use and lets `unittest`
collect the module-level functions as they are.

It is deliberately NOT a general pytest emulation. It covers exactly what those
two files use: `raises`, `approx`, a `load_tests` collector, and the two
BUILT-IN fixtures they request by parameter name — `tmp_path` and a
`monkeypatch` with `setattr` only. Anything else should be written as a
`TestCase` rather than grow this file, because a half-emulation is the thing
that silently changes what a test asserts.

Note on how the fixture set was determined: grepping for `@pytest.fixture` finds
DEFINITIONS and reports zero here, because built-in fixtures are requested by
PARAMETER NAME and define nothing. The set below came from reading the actual
signatures, which is the only place that information exists.
"""

from __future__ import annotations

import functools
import inspect
import math
import re
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def raises(expected, match=None):
    """`pytest.raises`: assert the block raises `expected`, optionally matching.

    `match` is a regex SEARCHED against str(exception), which is pytest's
    semantics — not a full match. Getting that wrong would silently weaken every
    call site that uses it.
    """
    try:
        yield
    except expected as exc:  # noqa: B902 - mirroring pytest's contract
        if match is not None and re.search(match, str(exc)) is None:
            raise AssertionError(
                f"raised {type(exc).__name__}({exc!r}) which does not match {match!r}"
            ) from exc
        return
    raise AssertionError(f"did not raise {getattr(expected, '__name__', expected)}")


class approx:  # noqa: N801 - matches the pytest spelling the tests already use
    """`pytest.approx` for floats, with pytest's default relative tolerance."""

    def __init__(self, expected, rel=1e-6, abs=1e-12):  # noqa: A002
        self.expected = expected
        self.rel = rel
        self.abs = abs

    def __eq__(self, other):
        return math.isclose(other, self.expected, rel_tol=self.rel, abs_tol=self.abs)

    def __repr__(self):
        return f"approx({self.expected!r}, rel={self.rel!r})"


class _MonkeyPatch:
    """`monkeypatch` limited to `setattr`, with undo on teardown.

    pytest's fixture does far more (setenv, delitem, syspath_insert). Only
    setattr is used here, and implementing the rest untested would be a
    half-emulation that looks complete.
    """

    def __init__(self):
        self._undo = []

    def setattr(self, target, name, value):  # noqa: A003 - pytest's spelling
        self._undo.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def undo(self):
        while self._undo:
            target, name, old = self._undo.pop()
            setattr(target, name, old)


def _invoke_with_fixtures(fn):
    """Call `fn`, supplying the built-in fixtures it requests by name."""
    params = list(inspect.signature(fn).parameters)
    unknown = [p for p in params if p not in ("tmp_path", "monkeypatch")]
    if unknown:
        # Fail loudly rather than silently passing a test that asked for
        # something this shim does not provide.
        raise AssertionError(
            f"{fn.__name__} requests unsupported fixture(s) {unknown}; "
            "unittest_shim provides only tmp_path and monkeypatch"
        )
    mp = _MonkeyPatch() if "monkeypatch" in params else None
    try:
        if "tmp_path" in params:
            with tempfile.TemporaryDirectory() as td:
                kwargs = {"tmp_path": Path(td)}
                if mp is not None:
                    kwargs["monkeypatch"] = mp
                fn(**kwargs)
        else:
            fn(**({"monkeypatch": mp} if mp is not None else {}))
    finally:
        if mp is not None:
            mp.undo()


def collect_module_tests(namespace):
    """Return a `load_tests` implementation collecting module-level `test_*`.

    `unittest discover` finds classes, not bare functions, so a pytest-style
    module loads with zero tests and reports nothing. That is the same
    fails-to-a-healthy-value shape as the hyphenated filenames this change also
    fixes, so it is closed the same way rather than left to a convention.
    """

    def load_tests(loader, tests, pattern):  # noqa: ARG001 - unittest protocol
        suite = unittest.TestSuite()
        for name, obj in sorted(namespace.items()):
            if name.startswith("test_") and callable(obj):
                # functools.wraps carries __module__ and __name__ onto the
                # wrapper. Without it the wrapper reports unittest_shim as its
                # origin, and any tooling that attributes a collected test back
                # to its source file — harness_discovery_test's
                # contributes-at-least-one check among them — sees this module
                # instead of the test's own, so a pytest-style file reads as
                # contributing NOTHING even while its tests run and pass.
                @functools.wraps(obj)
                def _run(f=obj):
                    _invoke_with_fixtures(f)

                suite.addTest(unittest.FunctionTestCase(_run, description=name))
        return suite

    return load_tests
