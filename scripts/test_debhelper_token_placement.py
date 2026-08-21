#!/usr/bin/env python3
"""Guard the `#DEBHELPER#` token placement in debian/ maintainer scripts.

debhelper substitutes EVERY occurrence of the literal `#DEBHELPER#` in a
maintainer script with a generated shell snippet. The token therefore has
to sit alone on its own line, at the point where that snippet belongs. A
token that appears mid-line — including inside a prose comment — is still
substituted, so the generated block is spliced into the middle of the
script and whatever followed the token on that line is left behind as a
top-level command.

That is exactly what happened in debian/xpf.postinst (#1964, 723427b1e):

    # Seed the versioned runtime layout BEFORE #DEBHELPER# starts

became the dh_installsystemd block followed by a bare line ` starts`, so
the built package's postinst died on a fresh install with

    /var/lib/dpkg/info/xpf.postinst: 148: starts: not found
    dpkg: error processing package xpf (--configure):
     ... postinst maintainer script subprocess failed with exit status 127

which aborted `apt-get install ./xpf_*.deb` and, with it, every appliance
bake. Found by running a real bake for #1926.

RED on revert: put `#DEBHELPER#` back inside the comment on
debian/xpf.postinst:48 and test_token_is_alone_on_its_line fails.
"""

from __future__ import annotations

import unittest
from pathlib import Path

_TOKEN = "#DEBHELPER#"
_DEBIAN = Path(__file__).resolve().parents[1] / "debian"
# Maintainer scripts debhelper post-processes. `.debhelper` files are
# debhelper's own generated fragments, not sources — skip them.
_SUFFIXES = (".postinst", ".preinst", ".postrm", ".prerm", ".config")


def _maintainer_scripts() -> list[Path]:
    return sorted(
        p for p in _DEBIAN.iterdir()
        if p.is_file()
        and p.suffix in _SUFFIXES
        and not p.name.endswith(".debhelper")
    )


class DebhelperTokenPlacementTests(unittest.TestCase):
    def test_scripts_found(self):
        """Fail loudly rather than pass vacuously if the layout moves."""
        scripts = _maintainer_scripts()
        self.assertTrue(scripts, f"no maintainer scripts found under {_DEBIAN}")
        names = {p.name for p in scripts}
        self.assertIn("xpf.postinst", names,
                      f"xpf.postinst missing from {sorted(names)}")

    def test_token_is_alone_on_its_line(self):
        """Every `#DEBHELPER#` must be the entire (stripped) line.

        Anything else — a prose mention, a trailing word, a leading
        comment marker — gets substituted in place and corrupts the script.
        """
        for path in _maintainer_scripts():
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if _TOKEN not in line:
                    continue
                self.assertEqual(
                    line.strip(), _TOKEN,
                    f"{path.name}:{lineno} has {_TOKEN} embedded in a line; "
                    f"debhelper substitutes it in place and leaves the rest "
                    f"of the line as executable shell. Line: {line!r}")

    def test_token_present_where_required(self):
        """postinst/postrm/preinst must still carry exactly one token.

        Guards the inverse mistake: deleting the token to satisfy the
        placement rule would silently drop the generated systemd handling.
        """
        for name in ("xpf.postinst", "xpf.preinst", "xpf.postrm"):
            path = _DEBIAN / name
            if not path.is_file():
                continue
            n = path.read_text().count(_TOKEN)
            self.assertEqual(n, 1, f"{name} has {n} {_TOKEN} tokens, want 1")


if __name__ == "__main__":
    unittest.main()
