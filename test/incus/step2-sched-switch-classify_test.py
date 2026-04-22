#!/usr/bin/env python3
"""Unit tests for step2-sched-switch-classify.py (#821 V7 gate).

Covers:
 - IN verdict on synthetic correlated input with duty >= 1%
 - OUT verdict on anti-correlated input OR low duty
 - INCONCLUSIVE verdict on borderline input
 - meta.json schema (required keys, types)
 - WARN aggregation from off-cpu JSONL

Run:
    python3 test/incus/step2-sched-switch-classify_test.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_CLASSIFY_PATH = _HERE / "step2-sched-switch-classify.py"


def _load_classifier():
    spec = importlib.util.spec_from_file_location(
        "step2_sched_switch_classify", str(_CLASSIFY_PATH)
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = _load_classifier()


def _write_jsonl(objs: list[dict]) -> Path:
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    buf = ("\n".join(json.dumps(o) for o in objs) + "\n").encode()
    os.write(fd, buf)
    os.close(fd)
    return Path(path)


def _hist_blocks_with_shape3to6(values: list[float]) -> list[dict]:
    """Synthesize 12 hist-block dicts with shape[3..6] summing to `values[b]`.

    We place the full per-block value in shape[3] and zero elsewhere for
    simplicity.  T_D1,b will equal values[b] exactly.
    """
    assert len(values) == 12
    out = []
    for b, v in enumerate(values):
        shape = [0.0] * 16
        shape[3] = v
        out.append(
            {
                "b": b,
                "count_delta": 10000,
                "buckets": [0] * 16,
                "shape": shape,
                "tx_packets_delta": 1000,
            }
        )
    return out


def _off_cpu_blocks(
    off_times: list[int],
    stat: list[str] | None = None,
    vol_of: float = 0.5,
) -> list[dict]:
    """Synthesize 12 off-cpu reducer dicts.

    `stat[b]` is "PASS" or "WARN"; defaults to all PASS.  The off time
    is placed entirely in bucket 3 (so the reducer invariant holds).
    """
    assert len(off_times) == 12
    if stat is None:
        stat = ["PASS"] * 12
    out = []
    for b, t in enumerate(off_times):
        buckets = [0] * 16
        buckets[3] = t
        vol = int(t * vol_of)
        invol = t - vol
        out.append(
            {
                "b": b,
                "buckets": buckets,
                "off_cpu_time_3to6": t,
                "voluntary_3to6": vol,
                "involuntary_3to6": invol,
                "stat_runtime_check": stat[b],
            }
        )
    return out


def _run_classifier(
    hist_blocks: list[dict], off_blocks: list[dict], cell: str = "test/cell"
) -> tuple[int, dict]:
    h_path = _write_jsonl(hist_blocks)
    o_path = _write_jsonl(off_blocks)
    out_dir = Path(tempfile.mkdtemp())
    out_md = out_dir / "correlation-report.md"
    try:
        rc = C.main(
            [
                "--hist-blocks", str(h_path),
                "--off-cpu", str(o_path),
                "--cell", cell,
                "--out", str(out_md),
            ]
        )
        meta_path = out_dir / "correlation-report.meta.json"
        meta = json.loads(meta_path.read_text())
    finally:
        h_path.unlink()
        o_path.unlink()
    return rc, meta


class TestClassifyVerdicts(unittest.TestCase):
    def test_verdict_IN_correlated_and_high_duty(self):
        """High rho + high duty-cycle -> IN."""
        # Correlated ramps: shape[3] grows as off-cpu time grows.
        # off times chosen so sum = 3 s = 5 % duty on 60 s nominal.
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        # sum = 250M * (1+2+..+12) = 250M * 78 = 19.5 G = 32.5 % duty
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]  # strictly increasing
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "IN", f"meta={meta}")
        self.assertGreaterEqual(meta["rho"], 0.8)
        self.assertGreaterEqual(meta["duty_cycle_pct"], 1.0)

    def test_verdict_OUT_low_duty_regardless_of_rho(self):
        """duty < 1% -> OUT even with perfect rho."""
        off_times = [1_000_000 for _ in range(12)]  # 12 ms total = 0.02 %
        shape_vals = [float(b + 1) for b in range(12)]  # correlated
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "OUT", f"meta={meta}")
        self.assertLess(meta["duty_cycle_pct"], 1.0)

    def test_verdict_OUT_low_rho(self):
        """rho <= 0.3 -> OUT (even with high duty)."""
        # Anti-correlated: hist increasing, off decreasing.
        off_times = [int((12 - b) * 500_000_000) for b in range(12)]
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(meta["verdict"], "OUT", f"meta={meta}")
        self.assertLessEqual(meta["rho"], 0.3)

    def test_verdict_INCONCLUSIVE_midrange_rho(self):
        """0.3 < rho < 0.8 and duty >= 1% -> INCONCLUSIVE.

        We construct an input whose Spearman rho lands in the middle.
        Easiest approach: partial correlation via a permutation pattern.
        """
        # Shapes: 1..12 (rank: 1..12).
        # Off-cpu ranks: (6,1,2,3,4,5,7,8,9,10,11,12) - one swap from
        # perfect -> Spearman rho ~ 1 - 6d^2/(n(n^2-1)).
        # d_i = rank(x_i) - rank(y_i).  With pattern [6,1,2,3,4,5,7,...]:
        # ranks of y: [6,1,2,3,4,5,7,8,9,10,11,12] (already ranks).
        # d = (1-6,2-1,3-2,4-3,5-4,6-5,7-7,...) = (-5,1,1,1,1,1,0,0,0,0,0,0)
        # sum d^2 = 25+1+1+1+1+1 = 30.  n=12, n(n^2-1)=1716.
        # rho = 1 - 6*30/1716 = 1 - 0.1049 = 0.8951 -> still IN.
        #
        # Heavier swap: [12,11,1,2,3,4,5,6,7,8,9,10] (two swaps at head)
        # -> still high rho; not what we want.  Use random-ish pattern.
        # d pattern to hit rho ~ 0.5:
        # Want 1 - 6*sum(d^2)/1716 = 0.5 -> sum(d^2) = 143.
        # Use pattern: [4,2,6,1,3,5,7,12,9,11,8,10].  Compute sum(d^2).
        off_pattern = [4, 2, 6, 1, 3, 5, 7, 12, 9, 11, 8, 10]
        # Verify by calculation:
        d = [off_pattern[i] - (i + 1) for i in range(12)]
        sum_d2 = sum(x * x for x in d)
        expected_rho = 1.0 - 6 * sum_d2 / (12 * (12 * 12 - 1))
        # If it's not mid-range, the test harness is stale; tweak pattern.
        # We'll assert the computed verdict matches our expectation.
        off_times = [p * 500_000_000 for p in off_pattern]
        shape_vals = [float(b + 1) for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        # duty check: sum = 500M * 78 = 39 G = 65 % -> plenty
        self.assertGreaterEqual(meta["duty_cycle_pct"], 1.0)
        # Classify rho bucket.
        rho = meta["rho"]
        if rho >= 0.8:
            self.assertEqual(meta["verdict"], "IN")
        elif rho <= 0.3:
            self.assertEqual(meta["verdict"], "OUT")
        else:
            self.assertEqual(meta["verdict"], "INCONCLUSIVE")
        # For this hand-tuned pattern, confirm we got INCONCLUSIVE.
        self.assertGreater(rho, 0.3)
        self.assertLess(rho, 0.8)
        self.assertEqual(meta["verdict"], "INCONCLUSIVE")


class TestClassifyMetaSchema(unittest.TestCase):
    def test_meta_json_schema(self):
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        off = _off_cpu_blocks(off_times)
        rc, meta = _run_classifier(hist, off, cell="slug/under/test")
        self.assertEqual(rc, 0)
        required = [
            "cell",
            "verdict",
            "reason",
            "rho",
            "pvalue",
            "duty_cycle_pct",
            "T_D1",
            "off_cpu_time_3to6",
            "voluntary_total_ns",
            "involuntary_total_ns",
            "warn_blocks",
            "n_blocks",
            "rho_in",
            "rho_out",
            "duty_in_pct",
            "duty_out_pct",
            "nominal_window_ns",
        ]
        for k in required:
            self.assertIn(k, meta, f"missing key: {k}")
        self.assertEqual(meta["cell"], "slug/under/test")
        self.assertEqual(meta["n_blocks"], 12)
        self.assertEqual(len(meta["T_D1"]), 12)
        self.assertEqual(len(meta["off_cpu_time_3to6"]), 12)
        self.assertIn(meta["verdict"], ("IN", "OUT", "INCONCLUSIVE"))


class TestClassifyWarnAggregation(unittest.TestCase):
    def test_warn_block_aggregation(self):
        off_times = [int((b + 1) * 250_000_000) for b in range(12)]
        shape_vals = [float(b + 1) * 0.01 for b in range(12)]
        hist = _hist_blocks_with_shape3to6(shape_vals)
        stat = ["PASS"] * 12
        stat[0] = "WARN"
        stat[5] = "WARN"
        stat[11] = "WARN"
        off = _off_cpu_blocks(off_times, stat=stat)
        rc, meta = _run_classifier(hist, off)
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(meta["warn_blocks"]), [0, 5, 11])


class TestVerdictHelper(unittest.TestCase):
    def test_verdict_from_degenerate_rho(self):
        v, _ = C.verdict_from(None, 50.0)
        self.assertEqual(v, "INCONCLUSIVE")

    def test_verdict_from_rules_boundary(self):
        # rho=0.8, duty=1.0 -> IN (>= in both)
        v, _ = C.verdict_from(0.8, 1.0)
        self.assertEqual(v, "IN")
        # rho=0.3, duty=50 -> OUT
        v, _ = C.verdict_from(0.3, 50.0)
        self.assertEqual(v, "OUT")
        # rho=0.5, duty=5.0 -> INCONCLUSIVE
        v, _ = C.verdict_from(0.5, 5.0)
        self.assertEqual(v, "INCONCLUSIVE")
        # rho=0.9, duty=0.5 -> OUT (low duty)
        v, _ = C.verdict_from(0.9, 0.5)
        self.assertEqual(v, "OUT")


if __name__ == "__main__":
    unittest.main()
