#!/usr/bin/env python3
"""
step1-rss-multinomial.py — Monte Carlo for the Step 1 Verdict A boundary.

Two modes, both driven by the same 16-flow / 4-worker model:

1. Null (fair-RSS) mode (default): Multinomial(n=16, p=(1/4,1/4,1/4,1/4)).
   Reports the false-positive tail probabilities used by the Verdict A
   predicate in docs/pr/line-rate-investigation/step1-plan.md §4.2.

2. Power (skewed-RSS) mode (--skewed-worker0): simulates the
   "one worker gets 56% of flows, other three share the rest"
   failure mode the Verdict A predicate must catch. Reports the
   fire rate (true-positive power) under that alternative. Used to
   close round-3 finding #3: the null-case Monte Carlo alone does
   not prove Verdict A has power against the exact failure mode the
   plan cites as justification for keeping threshold max>=9.

Deterministic seed (--seed, default 42) so the numbers cited in the
plan are reproducible. 10^6 trials by default — enough that the third
decimal of each probability is stable across reseeds.

Usage:
    python3 step1-rss-multinomial.py
    python3 step1-rss-multinomial.py --skewed-worker0 0.56
    python3 step1-rss-multinomial.py --trials 10000000 --seed 7
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from typing import Dict, List, Sequence, Tuple


def simulate(
    trials: int,
    n_flows: int,
    n_workers: int,
    seed: int,
    probs: Sequence[float] | None = None,
) -> List[Tuple[int, int]]:
    """Return list of (max_count, min_count) per trial.

    If ``probs`` is None, workers are drawn uniformly (fair RSS).
    Otherwise ``probs`` is a sequence of length ``n_workers`` that
    sums to ~1.0 — passed in to drive the skewed-worker0 power case.
    """
    rng = random.Random(seed)
    if probs is not None:
        if len(probs) != n_workers:
            raise ValueError(
                f"probs length {len(probs)} != n_workers {n_workers}"
            )
        total = sum(probs)
        if not (0.999 <= total <= 1.001):
            raise ValueError(f"probs must sum to ~1.0, got {total}")
        cum = []
        acc = 0.0
        for p in probs:
            acc += p
            cum.append(acc)
    else:
        cum = None

    out: List[Tuple[int, int]] = []
    for _ in range(trials):
        counts = [0] * n_workers
        for _f in range(n_flows):
            if cum is None:
                w = rng.randrange(n_workers)
            else:
                u = rng.random()
                w = 0
                while w < n_workers - 1 and u > cum[w]:
                    w += 1
            counts[w] += 1
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
    p.add_argument(
        "--skewed-worker0",
        type=float,
        default=None,
        metavar="P",
        help=(
            "Power-case probability for worker 0 (e.g. 0.56). "
            "Remaining probability mass is split evenly across the "
            "other n_workers-1 workers. When set, the script reports "
            "Verdict A fire rate (true-positive power) under the "
            "alternative hypothesis, NOT the FP rate under the null."
        ),
    )
    args = p.parse_args(argv)

    if args.skewed_worker0 is not None:
        p0 = args.skewed_worker0
        if not (0.0 < p0 < 1.0):
            print(
                f"error: --skewed-worker0 must be in (0,1), got {p0}",
                file=sys.stderr,
            )
            return 2
        remainder = (1.0 - p0) / (args.workers - 1)
        probs = [p0] + [remainder] * (args.workers - 1)
        samples = simulate(
            args.trials, args.flows, args.workers, args.seed, probs=probs
        )
        power = tail_probabilities(samples, args.flows)
        print(
            f"# Monte Carlo (skewed): {args.trials} trials, "
            f"{args.flows} flows, p=({p0:0.4f}, "
            f"{remainder:0.4f}*{args.workers - 1}), seed={args.seed}"
        )
        width = max(len(k) for k in power)
        for k, v in power.items():
            print(f"{k:<{width}}  {v:0.4f}")
        print()
        print(
            "# Verdict A TRUE-POSITIVE power under the skewed alternative"
        )
        fire_rate = power["FP_union_max9_or_min0"]
        print(
            f"  max>=9 OR min<=0  -> per-cell fire_rate={fire_rate:0.4f}"
        )
        print(
            f"  max>=8 OR min<=0  -> per-cell fire_rate={power['FP_union_max8_or_min0']:0.4f}"
        )
        print(
            f"  max>=7 OR min<=1  -> per-cell fire_rate={power['FP_union_max7_or_min1']:0.4f}"
        )

        # Multi-cell aggregation (round-3 finding #4 FP-discount policy):
        # Verdict A is trusted only when >= 2 of 12 cells fire A.
        # Given per-cell power p, probability that >= 2 of N cells fire
        # is 1 - (1-p)^N - N*p*(1-p)^(N-1).
        def ge2(p: float, n: int) -> float:
            q = 1.0 - p
            return 1.0 - q ** n - n * p * q ** (n - 1)

        print()
        print(
            "# Multi-cell aggregation: P(>= 2 of N cells fire Verdict A)"
        )
        print(
            "# Used when the skew is systematic across cells (the case the"
        )
        print(
            "# plan cares about — one worker is structurally overloaded)."
        )
        for n in (4, 8, 12):
            print(
                f"  N={n:>2}  max>=9 -> {ge2(fire_rate, n):0.4f}  "
                f"max>=8 -> {ge2(power['FP_union_max8_or_min0'], n):0.4f}"
            )
        return 0

    samples = simulate(args.trials, args.flows, args.workers, args.seed)
    probs_out = tail_probabilities(samples, args.flows)

    print(f"# Monte Carlo: {args.trials} trials, "
          f"{args.flows} flows over {args.workers} workers, seed={args.seed}")
    width = max(len(k) for k in probs_out)
    for k, v in probs_out.items():
        print(f"{k:<{width}}  {v:0.4f}")

    # Emit the plan-relevant verdict on the boundary choice.
    chosen_fp = probs_out["FP_union_max8_or_min0"]
    looser_fp = probs_out["FP_union_max7_or_min1"]
    tighter_fp = probs_out["FP_union_max9_or_min0"]
    print()
    print("# Boundary candidates (Verdict A union FP rate)")
    print(f"  max>=7 OR min<=1  -> FP={looser_fp:0.4f}  (Codex round-1 'looser' suggestion)")
    print(f"  max>=8 OR min<=0  -> FP={chosen_fp:0.4f}  (round-1 plan revision)")
    print(f"  max>=9 OR min<=0  -> FP={tighter_fp:0.4f}  (current plan — Codex round-2 recommendation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
