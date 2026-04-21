#!/usr/bin/env python3
"""#816 Step 1 histogram block-permutation classifier.

Implements the #812 plan §11.3 Fisher-Pitman two-sample permutation test
on per-block histogram shape statistics (D1, D2 channels).  D3 is ejected
from the formal classifier this round (plan §4.2); bucket 14-15 mass is
reported as exploratory telemetry only.

Reads:
    evidence/{with-cos,no-cos}/<slug>/flow_steer_cold.json
    evidence/{with-cos,no-cos}/<slug>/flow_steer_samples.jsonl
    evidence/baseline/<pool>/run{1..5}/flow_steer_cold.json
    evidence/baseline/<pool>/run{1..5}/flow_steer_samples.jsonl

Writes:
    evidence/.../hist-blocks.jsonl
    evidence/.../perm-test-results.json
    summary-table.csv

Usage:
    python3 step1-histogram-classify.py --evidence-root <path>
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

import numpy as np
import scipy
import scipy.stats

SEED = 42
N_RESAMPLES = 10_000
ALPHA = 0.05
I11_FLOOR = 1000
I12_LOW = 0.05
I12_HIGH = 20.0

POOL_BY_CELL = {
    "with-cos/p5201-fwd": "fwd-with-cos",
    "with-cos/p5201-rev": "rev-with-cos",
    "with-cos/p5202-fwd": "fwd-with-cos",
    "with-cos/p5202-rev": "rev-with-cos",
    "with-cos/p5203-fwd": "fwd-with-cos",
    "with-cos/p5203-rev": "rev-with-cos",
    "with-cos/p5204-fwd": "fwd-with-cos",
    "with-cos/p5204-rev": "rev-with-cos",
    "no-cos/p5201-fwd": "fwd-no-cos",
    "no-cos/p5202-fwd": "fwd-no-cos",
    "no-cos/p5203-fwd": "fwd-no-cos",
    "no-cos/p5204-fwd": "fwd-no-cos",
}


def sum_per_binding_hist(snap: dict) -> tuple[np.ndarray, int, int, int]:
    """Aggregate per-binding histograms into a cell-level 16-bucket array.

    Returns (hist_array, count_total, sum_ns_total, tx_packets_total).
    Enforces I13 per-snapshot wire-format invariant: for each binding,
    `sum(tx_submit_latency_hist) == tx_submit_latency_count`.  Raises
    on violation; H-STOP-1 per plan §11.  Also guards the §9
    `count == 0 despite substantial tx_packets` branch — callers that
    see a nonzero tx_packets aggregate and a zero count should abort.
    """
    status = snap.get("status", snap)
    per_binding = status.get("per_binding") or status.get("bindings") or []
    hist = np.zeros(16, dtype=np.int64)
    count = 0
    sum_ns = 0
    tx_packets = 0
    for b in per_binding:
        bh = b.get("tx_submit_latency_hist") or [0] * 16
        if len(bh) != 16:
            raise ValueError(
                f"histogram length {len(bh)}, expected 16 — wire format regression"
            )
        bh_arr = np.asarray(bh, dtype=np.int64)
        b_count = int(b.get("tx_submit_latency_count", 0))
        # I13 per-snapshot per-binding wire-format check (plan §6, §11 H-STOP-1).
        if bh_arr.sum() != b_count:
            raise ValueError(
                f"I13 violation: per-binding sum(hist)={bh_arr.sum()} "
                f"!= count={b_count}"
            )
        hist += bh_arr
        count += b_count
        sum_ns += int(b.get("tx_submit_latency_sum_ns", 0))
        tx_packets += int(b.get("tx_packets", 0))
    # Cell-level I13 cross-check.
    if hist.sum() != count:
        raise ValueError(
            f"I13 violation: cell-level sum(hist)={hist.sum()} != count={count}"
        )
    return hist, count, sum_ns, tx_packets


def load_snapshots(cell_dir: Path) -> list[dict]:
    cold_path = cell_dir / "flow_steer_cold.json"
    samples_path = cell_dir / "flow_steer_samples.jsonl"
    with cold_path.open() as f:
        cold = json.load(f)
    snaps = [cold]
    with samples_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            snaps.append(json.loads(line))
    if len(snaps) != 13:
        raise ValueError(
            f"{cell_dir}: expected 13 snapshots (1 cold + 12 during), got {len(snaps)}"
        )
    return snaps


def compute_blocks(snaps: list[dict]) -> list[dict]:
    """Return 12 non-overlapping 5-s blocks from 13 snapshots (b ∈ 0..=11).

    I13 is enforced inside `sum_per_binding_hist` on each raw snapshot
    BEFORE any delta is taken, so a compensating corruption across
    snapshots cannot sneak past a delta-only check.  Here we only
    compute arithmetic deltas on already-validated aggregates.
    """
    aggregated = [sum_per_binding_hist(s) for s in snaps]
    # §9 "count == 0 despite substantial tx_packets" H-STOP branch.
    for i, (_h, c, _s, txp) in enumerate(aggregated):
        if c == 0 and txp > 10_000:
            raise ValueError(
                f"snapshot {i}: tx_submit_latency_count=0 but tx_packets={txp} "
                "— #813 wire regression (plan §9)"
            )
    blocks = []
    for b in range(12):
        h0, c0, _, txp0 = aggregated[b]
        h1, c1, _, txp1 = aggregated[b + 1]
        count_delta = c1 - c0
        buckets_delta = h1 - h0
        tx_packets_delta = txp1 - txp0
        if count_delta > 0:
            shape = buckets_delta.astype(np.float64) / count_delta
        else:
            shape = np.zeros(16, dtype=np.float64)
        blocks.append(
            {
                "b": b,
                "count_delta": int(count_delta),
                "buckets": [int(x) for x in buckets_delta],
                "shape": [float(x) for x in shape],
                "tx_packets_delta": int(tx_packets_delta),
            }
        )
    return blocks


def compute_T_D1(blocks: list[dict]) -> np.ndarray:
    """T_D1,b = mass_b(buckets 3..=6) / count_b — 4-64 µs mass fraction."""
    return np.array(
        [sum(b["shape"][3 : 6 + 1]) for b in blocks], dtype=np.float64
    )


def compute_T_D2(blocks: list[dict]) -> np.ndarray:
    """T_D2,b = (mass_b(0..=2)/count_b) × (mass_b(6..=9)/count_b)."""
    return np.array(
        [sum(b["shape"][0 : 2 + 1]) * sum(b["shape"][6 : 9 + 1]) for b in blocks],
        dtype=np.float64,
    )


def permutation_pvalue(cell_T: np.ndarray, base_T: np.ndarray) -> tuple[float, float]:
    """Fisher-Pitman one-sided (greater) permutation test on mean-diff."""
    res = scipy.stats.permutation_test(
        data=(cell_T, base_T),
        statistic=lambda x, y, axis=0: x.mean(axis=axis) - y.mean(axis=axis),
        permutation_type="independent",
        n_resamples=N_RESAMPLES,
        alternative="greater",
        random_state=np.random.default_rng(SEED),
    )
    return float(res.pvalue), float(res.statistic)


def classify_cell(
    cell_slug: str,
    cell_blocks: list[dict],
    baseline_blocks: list[dict],
) -> dict:
    counts = [b["count_delta"] for b in cell_blocks]
    base_counts = [b["count_delta"] for b in baseline_blocks]
    invariants = {}
    invariants["I11"] = "PASS" if min(counts) >= I11_FLOOR else "FAIL"
    median_cell = float(np.median(counts))
    median_base = float(np.median(base_counts)) if base_counts else 0.0
    ratio = median_cell / median_base if median_base > 0 else 0.0
    invariants["I12"] = "PASS" if I12_LOW <= ratio <= I12_HIGH else "FAIL"
    invariants["I13"] = "PASS"  # enforced at compute_blocks

    suspect = "PASS" not in invariants.values() or "FAIL" in invariants.values()
    # Correct: suspect = any invariant FAIL
    suspect = any(v == "FAIL" for v in invariants.values())

    cell_T_D1 = compute_T_D1(cell_blocks)
    cell_T_D2 = compute_T_D2(cell_blocks)
    base_T_D1 = compute_T_D1(baseline_blocks)
    base_T_D2 = compute_T_D2(baseline_blocks)

    if suspect:
        p_D1, stat_D1 = math.nan, math.nan
        p_D2, stat_D2 = math.nan, math.nan
    else:
        p_D1, stat_D1 = permutation_pvalue(cell_T_D1, base_T_D1)
        p_D2, stat_D2 = permutation_pvalue(cell_T_D2, base_T_D2)

    # Exploratory aggregates use count-weighted sums across blocks
    # (i.e. they are shape fractions of the cell-level summed histogram),
    # not unweighted means of per-block shape fractions.  This matches
    # plan §4.7.2 / §4.7.3 which define the out-of-family and D3-LEAD
    # inputs on the summed cell histogram.  Low-count blocks would
    # otherwise sway the aggregate toward their noisy shape.
    summed_buckets = np.sum(
        np.asarray([b["buckets"] for b in cell_blocks], dtype=np.int64),
        axis=0,
    )
    summed_count = int(sum(b["count_delta"] for b in cell_blocks))
    if summed_count > 0:
        summed_shape = summed_buckets.astype(np.float64) / summed_count
    else:
        summed_shape = np.zeros(16, dtype=np.float64)
    exploratory = {
        "bucket_14_15_mass_fraction": float(
            summed_shape[14] + summed_shape[15]
        ),
        "out_of_family_bucket_10_13_max": float(
            max(summed_shape[k] for k in (10, 11, 12, 13))
        ),
        "bucket_mode_index": int(np.argmax(summed_shape)),
        "per_binding_cell_dominated": False,  # placeholder; §4.7.2 narrative
    }

    return {
        "cell": cell_slug,
        "pool": POOL_BY_CELL.get(cell_slug, "unknown"),
        "python_version": sys.version.split()[0],
        "scipy_version": scipy.__version__,
        "numpy_version": np.__version__,
        "seed": SEED,
        "n_resamples": N_RESAMPLES,
        "B_cell": len(cell_blocks),
        "B_base": len(baseline_blocks),
        "mde_sigma_80pct": 0.79,
        "suspect": suspect,
        "suspect_reason": (
            next((k for k, v in invariants.items() if v == "FAIL"), None)
            if suspect
            else None
        ),
        "invariants": invariants,
        "channels": {
            "D1": {
                "p": p_D1,
                "fire": (not suspect) and (p_D1 <= ALPHA),
                "stat_obs": stat_D1,
            },
            "D2": {
                "p": p_D2,
                "fire": (not suspect) and (p_D2 <= ALPHA),
                "stat_obs": stat_D2,
            },
        },
        "exploratory": exploratory,
    }


def gather_baseline(evidence_root: Path, pool: str) -> list[dict]:
    """Baseline pool: concatenate 12 blocks × 5 runs = 60 blocks per pool."""
    pool_dir = evidence_root / "baseline" / pool
    if not pool_dir.is_dir():
        return []
    all_blocks = []
    for run_dir in sorted(pool_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        try:
            snaps = load_snapshots(run_dir)
            all_blocks.extend(compute_blocks(snaps))
        except Exception as e:
            print(f"WARN: baseline {run_dir} skipped: {e}", file=sys.stderr)
    return all_blocks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-root", required=True, type=Path)
    ap.add_argument("--output-summary", type=Path, default=None)
    args = ap.parse_args()

    baselines: dict[str, list[dict]] = {}
    for pool in ("fwd-no-cos", "fwd-with-cos", "rev-with-cos"):
        blocks = gather_baseline(args.evidence_root, pool)
        baselines[pool] = blocks
        # H-STOP-5 (plan §11): require ≥ 3 of 5 baseline runs (≥ 36 blocks)
        # per pool.  Emit the per-pool serialized blocks for reproducibility
        # per plan §13 (evidence layout).
        if len(blocks) < 36:
            print(
                f"ERROR: pool {pool} has only {len(blocks)} baseline blocks "
                "(< 36 required per H-STOP-5); aborting classification",
                file=sys.stderr,
            )
            return 5
        pool_out = args.evidence_root / "baseline" / pool / "baseline-blocks.jsonl"
        pool_out.parent.mkdir(parents=True, exist_ok=True)
        with pool_out.open("w") as f:
            for blk in blocks:
                f.write(json.dumps(blk) + "\n")

    summary_rows = []
    for rel_dir, pool in POOL_BY_CELL.items():
        cell_dir = args.evidence_root / rel_dir
        if not cell_dir.is_dir():
            print(f"WARN: cell dir missing {cell_dir}", file=sys.stderr)
            continue
        try:
            snaps = load_snapshots(cell_dir)
            blocks = compute_blocks(snaps)
        except Exception as e:
            print(f"ERROR: cell {rel_dir} failed: {e}", file=sys.stderr)
            continue

        with (cell_dir / "hist-blocks.jsonl").open("w") as f:
            for b in blocks:
                f.write(json.dumps(b) + "\n")

        result = classify_cell(rel_dir, blocks, baselines.get(pool, []))
        with (cell_dir / "perm-test-results.json").open("w") as f:
            json.dump(result, f, indent=2, default=str)

        summary_rows.append(
            {
                "cell": rel_dir,
                "pool": pool,
                "suspect": result["suspect"],
                "suspect_reason": result.get("suspect_reason") or "",
                "i11_pass": result["invariants"].get("I11") == "PASS",
                "i12_pass": result["invariants"].get("I12") == "PASS",
                "i13_pass": result["invariants"].get("I13") == "PASS",
                "verdict_abcd": "",  # populated from existing step1-classify.sh verdict.txt
                "p_D1": result["channels"]["D1"]["p"],
                "D1_fire": result["channels"]["D1"]["fire"],
                "p_D2": result["channels"]["D2"]["p"],
                "D2_fire": result["channels"]["D2"]["fire"],
                "b14_15": result["exploratory"]["bucket_14_15_mass_fraction"],
                "oof_10_13_max": result["exploratory"]["out_of_family_bucket_10_13_max"],
                "mode_bucket": result["exploratory"]["bucket_mode_index"],
            }
        )

    if summary_rows:
        summary_path = args.output_summary or (
            args.evidence_root / "summary-table.csv"
        )
        with summary_path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
            w.writeheader()
            w.writerows(summary_rows)
        print(f"wrote {summary_path}")

    # Investigation-level aggregation: k_v across valid cells.
    valid = [r for r in summary_rows if not r["suspect"]]
    k_D1 = sum(1 for r in valid if r["D1_fire"])
    k_D2 = sum(1 for r in valid if r["D2_fire"])
    print(f"k_D1 = {k_D1} of {len(valid)}  (gate: k_v >= 2)")
    print(f"k_D2 = {k_D2} of {len(valid)}  (gate: k_v >= 2)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
