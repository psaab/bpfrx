#!/usr/bin/env python3
"""Guard: the install surface describes the base-image pin contract the code
actually enforces (#6501).

`docs/install-images.md` promised mirror-latest Ubuntu discovery long after
#1943 pinned the base and #4904-B added the SHA256 trust anchor. An operator
following it expected the newest upstream release with no pin enforcement and
was surprised by the bake aborting on a `PINNED_BASE_SHA256` mismatch or on an
unpinned release.

A claim fix owes TWO proofs, and this file asserts both.

LANDED — the false claims are gone. Matching is WRAP-INSENSITIVE: comment and
markdown markers are stripped and all whitespace is collapsed before the
search, because a claim that wraps across two lines is invisible to a
line-oriented `grep -F`. That blind spot is not hypothetical here: the fourth
site this issue's fix had to correct — `Makefile:287-288`, "LATEST Ubuntu
server cloudimg base / discovered at bake time" — is split across two comment
lines and is not named in the issue at all. A line-based sweep would have
shipped it.

The banned fragments are complete ASSERTING clauses, not bare keywords,
because a claim-guard keyed to keywords is defeated by NEGATION rather than by
paraphrase: the corrected text and `bake.py` both say "not auto-latest" and
"opts back into mirror-latest discovery", which a keyword ban would red on
while the actual false claim walked past.

TRUE — the replacement text matches the code. The doc must name the real
constants, must carry the SAME pinned release value `bake.py` compiles in, and
must not name a bake override `bake.py` does not read. A base bump that
updates the code and forgets the doc reds here, which is the failure mode that
produced this issue in the first place.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "install-images.md"
MAKEFILE = ROOT / "Makefile"
BAKE = ROOT / "scripts" / "image" / "bake.py"

# The install-surface files that describe bake behaviour to an operator.
SURFACE = (DOC, MAKEFILE)

# Complete asserting clauses that were FALSE. Each is normalized the same way
# the surface is, so a re-wrap cannot smuggle one back in.
BANNED = (
    "the latest ubuntu release (operator policy: always the newest",
    "discover the latest ubuntu release from the upstream listing",
    "the base tracks the newest upstream release",
    "latest ubuntu server cloudimg base discovered at bake time",
    "discovered at bake time), a >= 6.18 kernel",
)

# Every environment variable the doc is allowed to present as a bake override
# must be one bake.py actually reads.
DOC_ENV_RE = re.compile(r"XPF_[A-Z0-9_]+")


def pin_policy_section(normalized=False):
    """The base-image pin-policy section of the doc, or "" if its heading is
    gone. Returning "" rather than raising keeps a lost anchor a readable test
    FAILURE instead of a collection error that reports no tests at all."""
    raw = DOC.read_text(encoding="utf-8")
    try:
        start = raw.index("### Base-image pin policy")
        end = raw.index("Full first-boot matrix", start)
    except ValueError:
        return ""
    section = raw[start:end]
    return normalize(section) if normalized else section


def normalize(text):
    """Strip comment/markdown markers and collapse all whitespace, so a claim
    that wraps across lines reads as one string."""
    stripped = [re.sub(r"^\s*(#+|//+|\*|>|\||-|\d+\.)\s?", " ", ln)
                for ln in text.splitlines()]
    return re.sub(r"\s+", " ", " ".join(stripped)).lower()


class MatcherVacuityTests(unittest.TestCase):
    """A guard whose matcher cannot see the thing it bans passes vacuously —
    and a vacuous green argues against anyone re-examining the property."""

    def test_the_normalizer_finds_a_claim_that_wraps_across_lines(self):
        wrapped = ("# offline-built bootable root disk (LATEST Ubuntu server\n"
                   "# cloudimg base discovered at bake time — XPF_BASE_RELEASE\n")
        self.assertIn("latest ubuntu server cloudimg base discovered at bake time",
                      normalize(wrapped))

    def test_a_line_oriented_search_would_MISS_that_same_claim(self):
        # The reason this file normalizes at all, asserted rather than assumed.
        wrapped = ("# offline-built bootable root disk (LATEST Ubuntu server\n"
                   "# cloudimg base discovered at bake time\n")
        self.assertFalse(any(
            "latest ubuntu server cloudimg base discovered at bake time" in ln.lower()
            for ln in wrapped.splitlines()))

    def test_the_normalizer_strips_markdown_and_comment_markers(self):
        self.assertIn("a b", normalize("# a\n> b"))
        self.assertIn("c d", normalize("- c\n  d"))

    def test_the_pin_policy_section_is_non_trivial(self):
        # Every scoped assertion below would pass over an empty slice.
        self.assertGreater(
            len(TrueTests.SECTION), 800,
            "the pin-policy section is missing or nearly empty — its heading "
            "moved, or the section was gutted. Every scoped assertion below "
            "would pass over an empty slice.")

    def test_the_surface_files_are_non_trivial(self):
        # If a path stopped resolving, every ban below would pass over an empty
        # string.
        for p in SURFACE:
            self.assertTrue(p.is_file(), f"{p} missing")
            self.assertGreater(len(normalize(p.read_text(encoding="utf-8"))), 500,
                               f"{p} normalized to almost nothing")


class LandedTests(unittest.TestCase):
    def test_no_auto_latest_claim_survives_on_the_install_surface(self):
        for p in SURFACE:
            n = normalize(p.read_text(encoding="utf-8"))
            for claim in BANNED:
                self.assertNotIn(
                    claim, n,
                    f"{p.relative_to(ROOT)} still asserts the retired "
                    f"auto-latest contract: {claim!r}. The base is a REVIEWED "
                    "PIN (PINNED_BASE_RELEASE / PINNED_BASE_SHA256, #1943 / "
                    "#4904-B); autodiscovery is opt-in and an unpinned base is "
                    "refused.")


class TrueTests(unittest.TestCase):
    """The replacement text has to be right, not merely different."""

    DOCN = normalize(DOC.read_text(encoding="utf-8"))
    BAKESRC = BAKE.read_text(encoding="utf-8")

    # The pin-policy section, isolated. Content assertions are scoped HERE, not
    # to the whole document: a doc-wide `assertIn("not publishable", ...)` is
    # satisfied by pipeline step 8's unrelated sentence about --skip-validate
    # artifacts, so deleting the pin section's own statement left it green.
    # Caught by mutating exactly that sentence and watching the test pass.
    # Resolved DEFENSIVELY: a renamed heading must produce a clear FAILURE
    # from the non-trivial guard below, not a collection-time crash that
    # reports zero tests.
    SECTION = pin_policy_section(normalized=True)

    def _bake_const(self, name):
        m = re.search(rf'^{name} = "([^"]+)"', self.BAKESRC, re.MULTILINE)
        self.assertIsNotNone(m, f"{name} not found in bake.py")
        return m.group(1)

    def test_the_doc_names_the_real_constants(self):
        for c in ("pinned_base_release", "pinned_base_sha256"):
            self.assertIn(c, self.DOCN,
                          f"the doc does not name {c.upper()}, the constant the "
                          "bake actually enforces")

    def test_the_doc_carries_the_SAME_pinned_release_as_the_code(self):
        # A base bump that edits bake.py and forgets the doc reds here — the
        # exact drift that produced #6501.
        rel = self._bake_const("PINNED_BASE_RELEASE")
        self.assertIn(rel, self.DOCN,
                      f"bake.py pins Ubuntu {rel} but the doc does not say so")

    def test_the_doc_states_the_reviewed_bump_policy(self):
        self.assertTrue(
            "reviewed commit" in self.SECTION or "reviewed pin" in self.SECTION,
            "the pin-policy section does not say a base bump is a reviewed "
            "commit")

    def test_the_doc_states_the_unpinned_bake_is_refused_and_unpublishable(self):
        self.assertIn("not publishable", self.SECTION)
        self.assertIn("refuse", self.SECTION)

    def test_the_doc_presents_autodiscovery_as_OPT_IN(self):
        self.assertIn("xpf_ubuntu_autodiscover", self.SECTION)
        self.assertIn("opt back into mirror-latest discovery", self.SECTION)

    def test_every_bake_override_the_doc_names_is_one_bake_py_reads(self):
        # The doc must not invent a knob. Restricted to the pin-policy section
        # so unrelated XPF_* names elsewhere in the doc are out of scope.
        named = {v for v in DOC_ENV_RE.findall(pin_policy_section())}
        self.assertTrue(named, "no XPF_* override documented — vacuous")
        for var in sorted(named):
            self.assertIn(
                f'"{var}"', self.BAKESRC,
                f"the doc presents {var} as a bake override but bake.py never "
                "reads it")

    def test_the_doc_cites_the_same_gpg_fingerprint_as_the_code(self):
        m = re.search(r"([0-9A-F]{40})", self.BAKESRC)
        self.assertIsNotNone(m)
        self.assertIn(m.group(1).lower(), self.DOCN,
                      "the doc cites a different Canonical signing key than "
                      "bake.py's provenance comment")


if __name__ == "__main__":
    unittest.main()
