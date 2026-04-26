"""Parser for `iperf3 -i 1 --forceflush -P N` text-mode `[SUM]` lines.

Per-second rows look like:
    [SUM]   3.00-4.00   sec  118 MBytes  990 Mbits/sec   ...

Final summary lines look like:
    [SUM]   0.00-60.00  sec  6.96 GBytes  996 Mbits/sec   ...      receiver
    [SUM]   0.00-60.00  sec  6.96 GBytes  996 Mbits/sec   ...      sender

Per-stream lines start with `[N]` where N is a digit; they must NOT
match. Anchored regex on `[SUM]` only.
"""

import re
from typing import Optional, Tuple

# Match `[SUM]   <start>-<end>   sec  <transferred> <unit>  <rate> <rate-unit>/sec`.
# Capture (rate_value, rate_unit_prefix).
_SUM_RE = re.compile(
    r"^\[SUM\]\s+\d+(?:\.\d+)?-\d+(?:\.\d+)?\s+sec\s+\S+\s+\S+\s+(\S+)\s+([KMGT]?)bits/sec",
    re.IGNORECASE,
)

_UNIT_MULTIPLIER = {
    "": 1,
    "K": 1_000,
    "M": 1_000_000,
    "G": 1_000_000_000,
    "T": 1_000_000_000_000,
}


def parse_sum_line(line: str) -> Optional[Tuple[float, int]]:
    """Return (rate_value, rate_bps) or None if not a [SUM] line."""
    m = _SUM_RE.match(line)
    if not m:
        return None
    try:
        rate_value = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2).upper()
    multiplier = _UNIT_MULTIPLIER.get(unit)
    if multiplier is None:
        return None
    return (rate_value, int(rate_value * multiplier))


def parse_sum_bps(line: str) -> Optional[int]:
    """Return rate in bits/sec, or None."""
    parsed = parse_sum_line(line)
    return None if parsed is None else parsed[1]
