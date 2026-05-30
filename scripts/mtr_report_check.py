#!/usr/bin/env python3
"""Classify an ``mtr --report`` capture for the userspace HA smoke.

Extracted from the inline heredoc that used to live in
``scripts/userspace-ha-validation.sh`` so the classification logic can be
unit-tested directly (see ``scripts/test_mtr_report_check.py``).

Contract (preserved from the old shell wrapper):

* stdout carries a single human-readable summary/warning line.
* exit 0  -> the smoke leg passes; the line is informational.
* exit 1  -> hard failure; the caller ``die``s with the line.

The IPv6 leg passes ``allow_unresolved_destination=1`` because the public
IPv6 traceroute target is outside our control and may not answer the
final hop. For IPv6 the mtr report is observability-only: forwarding
correctness is gated by the controlled ping / TTL / iperf3 legs in the
validator, not by this external trace. The IPv4 leg
(``allow_unresolved_destination=0``) still hard-gates on the final hop,
because ``1.1.1.1`` is a reliable responder.
"""

from __future__ import annotations

import re
import sys

HOP_LINE_RE = re.compile(r"\s*\d+\.\|--")
# The loss percentage is the only field on an mtr --report hop line that
# ends in '%'. Anchor on it directly so a host field that contains spaces
# (e.g. "(waiting for reply)") does not break parsing the way a
# host-anchored "\S+" regex would.
LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%")

WAITING = "(waiting for reply)"


def hop_loss_pct(line: str) -> float | None:
    """Return the hop's loss percentage as a float, or None if absent."""
    m = LOSS_RE.search(line)
    return float(m.group(1)) if m else None


def hop_unresolved(line: str) -> bool:
    """True if the hop produced no usable reply (no name / waiting)."""
    return "???" in line or WAITING in line


def classify_mtr_report(
    label: str, report: str, allow_unresolved_destination: bool
) -> tuple[bool, str]:
    """Classify an mtr --report capture.

    Returns ``(ok, message)``. ``ok=False`` is a hard failure.
    """
    hop_lines = [line for line in report.splitlines() if HOP_LINE_RE.match(line)]
    if not hop_lines:
        # A missing report is a local mtr failure (binary missing, bad
        # target syntax, capture lost). For the observability-only IPv6
        # leg this is a warning; for the gated IPv4 leg it is fatal.
        if allow_unresolved_destination:
            return True, f"{label} mtr: warning produced no hop lines"
        return False, f"{label} mtr produced no hop lines"

    first = hop_lines[0]
    last = hop_lines[-1]
    if hop_unresolved(first):
        return False, f"{label} mtr first hop unresolved: {first}"

    last_loss = hop_loss_pct(last)
    # A dead final hop is one that is explicitly unresolved, reports >=100%
    # loss, or whose loss column could not be parsed at all. The last case
    # fails closed: we never silently pass an unparseable final row.
    last_dead = (
        hop_unresolved(last)
        or last_loss is None
        or last_loss >= 100.0
    )

    if last_dead:
        if allow_unresolved_destination:
            # IPv6 public trace: observability-only. Controlled ping / TTL
            # / iperf3 legs gate forwarding correctness, not this trace.
            return True, f"{label} mtr: warning destination unresolved: {last}"
        return False, f"{label} mtr destination unresolved: {last}"

    return True, f"{label} mtr: ok"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write(
            "usage: mtr_report_check.py <label> <report> "
            "<allow_unresolved_destination:0|1>\n"
        )
        return 2
    label, report, allow = argv
    ok, message = classify_mtr_report(label, report, allow == "1")
    # Match the old heredoc: the summary/warning line goes to stdout so the
    # shell wrapper can tee it; failures exit non-zero and the wrapper dies.
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
