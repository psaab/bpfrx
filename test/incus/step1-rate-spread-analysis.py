#!/usr/bin/env python3
"""
step1-rate-spread-analysis.py — derive Verdict B Threshold Y from the
8-matrix per-flow rate captures.

Reads `docs/pr/line-rate-investigation/evidence-8matrix/p<port>-<dir>.json`
files (iperf3 -J output, 16 streams each), extracts per-flow
sender.bits_per_second, and computes the within-cell spread statistics
the Step 1 plan needs to set Y quantitatively.

We treat the 4 forward shaped cells (`p5201-fwd`, `p5202-fwd`,
`p5203-fwd`, `p5204-fwd`) as the empirical "healthy-ish" reference for
in-cell flow-rate spread under a working CoS pipeline. Y is set to
`mean + 2*stddev` of the observed within-cell `max/min` ratios across
those cells (per the round-2 review's "mean + 2 stddev of observed
spread" rule).

Reverse cells are excluded because §2 of the Step 1 plan already
documents that reverse traffic is unshaped — those rates are not bound
by a per-flow byte-rate-fair shaper, so their spread is not the right
empirical reference.

Slow-start tails: per the plan's existing B-indirect rule, flows whose
rate is < 0.5x median are dropped before computing min — they're
slow-start stragglers, not steady-state shaper output.

Usage:
    python3 step1-rate-spread-analysis.py
    python3 step1-rate-spread-analysis.py --evidence-dir docs/pr/...
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import List, Tuple


def load_per_flow_rates(path: Path) -> List[float]:
    with path.open() as f:
        data = json.load(f)
    streams = data.get("end", {}).get("streams", [])
    rates: List[float] = []
    for s in streams:
        sender = s.get("sender") or {}
        bps = sender.get("bits_per_second")
        if bps and bps > 0:
            rates.append(float(bps))
    return rates


def trimmed_min(rates: List[float], floor_ratio: float = 0.5) -> float:
    """Drop slow-start tails (< floor_ratio * median) before taking min."""
    if not rates:
        return 0.0
    med = statistics.median(rates)
    kept = [r for r in rates if r >= floor_ratio * med]
    return min(kept) if kept else min(rates)


def cell_spread(rates: List[float]) -> Tuple[float, float, float, int]:
    """Return (max/min ratio, max bps, trimmed_min bps, n_streams)."""
    if not rates:
        return (math.nan, math.nan, math.nan, 0)
    mx = max(rates)
    mn = trimmed_min(rates)
    ratio = mx / mn if mn > 0 else math.inf
    return (ratio, mx, mn, len(rates))


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "docs"
        / "pr"
        / "line-rate-investigation"
        / "evidence-8matrix",
    )
    p.add_argument(
        "--cells",
        nargs="*",
        default=["p5201-fwd", "p5202-fwd", "p5203-fwd", "p5204-fwd"],
        help="Cell basenames to analyze (default: 4 forward shaped cells).",
    )
    p.add_argument("--floor-ratio", type=float, default=0.5)
    args = p.parse_args(argv)

    if not args.evidence_dir.is_dir():
        print(f"error: {args.evidence_dir} is not a directory", file=sys.stderr)
        return 2

    print(f"# Evidence dir: {args.evidence_dir}")
    print(f"# Cells: {args.cells}")
    print(f"# Slow-start floor: < {args.floor_ratio}x median dropped before min()")
    print()

    print(f"{'cell':<12}  {'n':>3}  {'max_gbps':>10}  "
          f"{'min_gbps':>10}  {'ratio':>7}")
    ratios: List[float] = []
    for name in args.cells:
        path = args.evidence_dir / f"{name}.json"
        if not path.is_file():
            print(f"# WARN: missing {path}", file=sys.stderr)
            continue
        rates = load_per_flow_rates(path)
        ratio, mx, mn, n = cell_spread(rates)
        print(f"{name:<12}  {n:>3}  {mx/1e9:>10.4f}  {mn/1e9:>10.4f}  {ratio:>7.4f}")
        ratios.append(ratio)

    if len(ratios) < 2:
        print("# error: need >= 2 cells to compute mean + stddev", file=sys.stderr)
        return 2

    mean = statistics.mean(ratios)
    stdev = statistics.stdev(ratios)
    y_2sigma = mean + 2.0 * stdev
    print()
    print("# Verdict B — Threshold Y derivation (max/min ratio per cell)")
    print(f"  mean across {len(ratios)} cells:  {mean:0.4f}")
    print(f"  stddev:                          {stdev:0.4f}")
    print(f"  Y = mean + 2*stddev:             {y_2sigma:0.4f}")
    print(f"  Y rounded for plan:              {math.ceil(y_2sigma * 100) / 100:0.2f}")
    print()
    print("# Citation: docs/pr/line-rate-investigation/evidence-8matrix/")
    print(f"#   {', '.join(name + '.json' for name in args.cells)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
