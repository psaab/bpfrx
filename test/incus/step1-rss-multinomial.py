#!/usr/bin/env python3
"""
step1-rss-multinomial.py — Monte Carlo for the Step 1 Verdict A boundary.

Models 16 iperf3 flows distributed across 4 RSS workers under fair RSS
(Multinomial(n=16, p=(1/4,1/4,1/4,1/4))). Reports the empirical
probability of the per-bin tail events used by the Verdict A predicate
in docs/pr/line-rate-investigation/step1-plan.md §4.2.

Deterministic seed (--seed, default 42) so the FP numbers cited in the
plan are reproducible. 10^6 trials by default — enough that the third
decimal of each probability is stable across reseeds.

Usage:
    python3 step1-rss-multinomial.py
    python3 step1-rss-multinomial.py --trials 10000000 --seed 7
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from typing import Dict, List, Tuple


def simulate(trials: int, n_flows: int, n_workers: int, seed: int) -> List[Tuple[int, int]]:
    """Return list of (max_count, min_count) per trial under fair RSS."""
    rng = random.Random(seed)
    out: List[Tuple[int, int]] = []
    for _ in range(trials):
        counts = [0] * n_workers
        for _f in range(n_flows):
            counts[rng.randrange(n_workers)] += 1
        out.append((max(counts), min(counts)))
    return out


def tail_probabilities(samples: List[Tuple[int, int]], n_flows: int) -> Dict[str, float]:
    """Compute the FP tails the plan references plus union events."""
    total = len(samples)
    max_counter: Counter[int] = Counter()
    min_counter: Counter[int] = Counter()
    union_8_or_0 = 0
    union_9_or_0 = 0
    union_7_or_1 = 0
    for mx, mn in samples:
        max_counter[mx] += 1
        min_counter[mn] += 1
        if mx >= 8 or mn <= 0:
            union_8_or_0 += 1
        if mx >= 9 or mn <= 0:
            union_9_or_0 += 1
        if mx >= 7 or mn <= 1:
            union_7_or_1 += 1

    def ge(counter: Counter[int], threshold: int) -> float:
        return sum(c for k, c in counter.items() if k >= threshold) / total

    def le(counter: Counter[int], threshold: int) -> float:
        return sum(c for k, c in counter.items() if k <= threshold) / total

    return {
        "P(max>=7)": ge(max_counter, 7),
        "P(max>=8)": ge(max_counter, 8),
        "P(max>=9)": ge(max_counter, 9),
        "P(min<=0)": le(min_counter, 0),
        "P(min<=1)": le(min_counter, 1),
        "FP_union_max8_or_min0": union_8_or_0 / total,
        "FP_union_max9_or_min0": union_9_or_0 / total,
        "FP_union_max7_or_min1": union_7_or_1 / total,
    }


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trials", type=int, default=1_000_000)
    p.add_argument("--flows", type=int, default=16)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)

    samples = simulate(args.trials, args.flows, args.workers, args.seed)
    probs = tail_probabilities(samples, args.flows)

    print(f"# Monte Carlo: {args.trials} trials, "
          f"{args.flows} flows over {args.workers} workers, seed={args.seed}")
    width = max(len(k) for k in probs)
    for k, v in probs.items():
        print(f"{k:<{width}}  {v:0.4f}")

    # Emit the plan-relevant verdict on the boundary choice.
    chosen_fp = probs["FP_union_max8_or_min0"]
    looser_fp = probs["FP_union_max7_or_min1"]
    tighter_fp = probs["FP_union_max9_or_min0"]
    print()
    print("# Boundary candidates (Verdict A union FP rate)")
    print(f"  max>=7 OR min<=1  -> FP={looser_fp:0.4f}  (Codex round-1 'looser' suggestion)")
    print(f"  max>=8 OR min<=0  -> FP={chosen_fp:0.4f}  (round-1 plan revision)")
    print(f"  max>=9 OR min<=0  -> FP={tighter_fp:0.4f}  (current plan — Codex round-2 recommendation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
