#!/usr/bin/env python3
"""Unit tests for step2-sched-switch-reduce.py (#821 V1-V3 gates).

Covers:
 - bucket_index_for_ns boundary pins (V1)
 - load_boundaries_ns derivation from cold + samples, including _error skip
 - reducer synthetic three-switches-two-durations (V2, §3.4 case 3)
 - out-of-order perf timestamp skip
 - empty events still emit 12 blocks
 - invariant sum(buckets[3:7]) == off_cpu_time_3to6 (V3)
 - drift warning when PERF_START_NS = STEP1_START_NS + 2 s

Run from the repo root:
    python3 -m unittest test.incus.step2-sched-switch-reduce_test
Or directly:
    python3 test/incus/step2-sched-switch-reduce_test.py
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


# --- load the reducer as a module ("-" in filename blocks normal import) -----

_HERE = Path(__file__).resolve().parent
_REDUCER_PATH = _HERE / "step2-sched-switch-reduce.py"


def _load_reducer():
    spec = importlib.util.spec_from_file_location(
        "step2_sched_switch_reduce", str(_REDUCER_PATH)
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_reducer()


# --- V1: bucket_index_for_ns pins --------------------------------------------


class TestBucketIndex(unittest.TestCase):
    def test_bucket_index_for_ns_boundary_pins(self):
        """Port of umem.rs::bucket_index_for_ns must match these pins."""
        cases = [
            (0, 0),
            (1, 0),
            (1023, 0),
            (1024, 1),
            (2047, 1),
            (2048, 2),
            (4095, 2),
            (4096, 3),
            (8192, 4),
            (16384, 5),
            (32768, 6),
            (65536, 7),
            (2**24 - 1, 14),
            (2**24, 15),
            (2**64 - 1, 15),
        ]
        for ns, want in cases:
            with self.subTest(ns=ns):
                got = R.bucket_index_for_ns(ns)
                self.assertEqual(
                    got, want, f"ns={ns}: got b{got}, want b{want}"
                )


# --- STEP1_START_NS derivation -----------------------------------------------


def _write_inline(content: str, suffix: str) -> Path:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, content.encode())
    os.close(fd)
    return Path(path)


class TestBoundariesDerivation(unittest.TestCase):
    def test_step1_start_ns_from_samples(self):
        """cold _sample_ts=1713571200 -> boundaries[0] = 1713571200_000_000_000.

        _error first-line in samples must be skipped; reducer uses the next
        12 valid warm samples.
        """
        cold = {"_sample_ts": "1713571200", "status": {"per_binding": []}}
        cold_path = _write_inline(json.dumps(cold), ".json")
        # 13 warm lines: first has _error, so we need 12 valid after it.
        warm_lines = []
        warm_lines.append(
            json.dumps({"_sample_ts": "1713571205", "_error": "timeout"})
        )
        for i in range(12):
            warm_lines.append(
                json.dumps(
                    {"_sample_ts": str(1713571205 + (i + 1) * 5), "status": {}}
                )
            )
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")

        try:
            boundaries, warnings = R.load_boundaries_ns(cold_path, samples_path)
            self.assertEqual(len(boundaries), 13)
            self.assertEqual(boundaries[0], 1713571200 * 1_000_000_000)
            # The first warm line was skipped (error), so warm[0] should
            # be the second warm line = 1713571210.
            self.assertEqual(boundaries[1], 1713571210 * 1_000_000_000)
            # At least one warning about the _error skip.
            self.assertTrue(any("_error" in w for w in warnings))
        finally:
            cold_path.unlink()
            samples_path.unlink()

    def test_missing_cold_sample_ts_raises(self):
        cold = {"status": {"per_binding": []}}  # no _sample_ts
        cold_path = _write_inline(json.dumps(cold), ".json")
        samples_path = _write_inline("", ".jsonl")
        try:
            with self.assertRaises(ValueError):
                R.load_boundaries_ns(cold_path, samples_path)
        finally:
            cold_path.unlink()
            samples_path.unlink()

    def test_interval_halt_on_giant_gap(self):
        cold = {"_sample_ts": "1000000000"}
        # Next warm is 60 s later -> HALT (>30 s).
        warm_lines = [json.dumps({"_sample_ts": "1000000060"})]
        # Pad to 12 valid warm, 5 s each thereafter.
        for i in range(11):
            warm_lines.append(
                json.dumps({"_sample_ts": str(1000000060 + (i + 1) * 5)})
            )
        cold_path = _write_inline(json.dumps(cold), ".json")
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")
        try:
            with self.assertRaises(ValueError):
                R.load_boundaries_ns(cold_path, samples_path)
        finally:
            cold_path.unlink()
            samples_path.unlink()


# --- V2: synthetic reducer test ----------------------------------------------


def _make_boundaries(start_s: int = 1_000_000_000) -> list[int]:
    """Evenly-spaced 5-s boundaries: 13 entries, start..start+60 s."""
    return [(start_s + i * 5) * 1_000_000_000 for i in range(13)]


class TestReducerSynthetic(unittest.TestCase):
    def test_reducer_synthetic_three_switches_two_durations(self):
        """§3.4 test case 3.

        Two (switch, wake) pairs at t=1.000008 s (prev_state=S, 8 us,
        voluntary) and t=2.500032 s (prev_state=R, 32 us, involuntary)
        relative to STEP1_START.  Both land in block b=0.

        Expected per block 0:
          buckets[3] = 8000       (8 us = bucket 3: [4096, 8192))
          buckets[5] = 32000      (32 us = bucket 5: [16384, 32768))
          off_cpu_time_3to6 = 40000
          voluntary_3to6 = 8000
          involuntary_3to6 = 32000
        """
        boundaries = _make_boundaries()
        step1_start_ns = boundaries[0]
        tid = 9999
        worker_tids = {tid}
        perf_start_ns = step1_start_ns  # zero drift

        # Perf times are monotonic from some origin; we choose the first
        # event at perf_ts = 0 ns and translate via PERF_START_NS anchor.
        # t_wall = PERF_START_NS + (perf_ts - first_perf_ts); since
        # first_perf_ts == perf_ts of the first event, wall = PERF_START_NS
        # at that moment.  So:
        #   event at wall = step1_start + 1.000008 s  ->  perf_ts = 1.000008 s
        # We'll use perf_ts in nanoseconds directly.
        events = [
            # First switch: tid goes off-CPU at wall=step1_start + 1.000008 s
            (
                "sched:sched_switch",
                tid,
                1_000_008_000,  # 1.000008 s in ns, used as perf_ts
                {"prev_pid": tid, "prev_state": "S"},
            ),
            # Wake at wall=step1_start + 1.000016 s  (8 us later)
            (
                "sched:sched_wakeup",
                tid,
                1_000_016_000,
                {"pid": tid},
            ),
            # Second switch at 2.500032 s with prev_state=R (involuntary)
            (
                "sched:sched_switch",
                tid,
                2_500_032_000,
                {"prev_pid": tid, "prev_state": "R"},
            ),
            # Wake 32 us later
            (
                "sched:sched_wakeup",
                tid,
                2_500_064_000,
                {"pid": tid},
            ),
            # A stat_runtime event in block 0 so stat_runtime_check=PASS
            (
                "sched:sched_stat_runtime",
                tid,
                3_000_000_000,
                {"runtime_ns": 123456},
            ),
        ]

        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=perf_start_ns,
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertEqual(warnings, [], f"unexpected warnings: {warnings}")
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 12)
        blocks = [json.loads(l) for l in lines]
        # Block 0 assertions.
        b0 = blocks[0]
        self.assertEqual(b0["b"], 0)
        self.assertEqual(b0["buckets"][3], 8000)
        self.assertEqual(b0["buckets"][5], 32000)
        # All other buckets zero.
        for i, v in enumerate(b0["buckets"]):
            if i not in (3, 5):
                self.assertEqual(v, 0, f"block 0 bucket {i} = {v}, want 0")
        self.assertEqual(b0["off_cpu_time_3to6"], 40000)
        self.assertEqual(b0["voluntary_3to6"], 8000)
        self.assertEqual(b0["involuntary_3to6"], 32000)
        self.assertEqual(b0["stat_runtime_check"], "PASS")
        # Blocks 1..11: all zero, stat_runtime_check=WARN.
        for i in range(1, 12):
            bi = blocks[i]
            self.assertEqual(sum(bi["buckets"]), 0)
            self.assertEqual(bi["off_cpu_time_3to6"], 0)
            self.assertEqual(bi["stat_runtime_check"], "WARN")


class TestReducerOutOfOrder(unittest.TestCase):
    def test_reducer_out_of_order_skip(self):
        """Out-of-order perf timestamp -> WARN + skip (monotonicity)."""
        boundaries = _make_boundaries()
        tid = 42
        worker_tids = {tid}
        events = [
            # First event at perf_ts = 1.0 s
            ("sched:sched_switch", tid, 1_000_000_000,
             {"prev_pid": tid, "prev_state": "S"}),
            # Second event at perf_ts = 0.5 s (rewinds) -> skipped
            ("sched:sched_wakeup", tid, 500_000_000, {"pid": tid}),
        ]
        buf = io.StringIO()
        warn = io.StringIO()
        warnings = R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        self.assertTrue(any("out-of-order" in w for w in warnings))
        # 12 blocks still emitted, all zero (since wake was skipped).
        blocks = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        self.assertEqual(len(blocks), 12)
        self.assertEqual(sum(sum(b["buckets"]) for b in blocks), 0)


class TestReducerEmpty(unittest.TestCase):
    def test_reducer_emits_12_blocks(self):
        """Empty events still emit 12 zero-histogram lines."""
        boundaries = _make_boundaries()
        buf = io.StringIO()
        warn = io.StringIO()
        R.reduce_events(
            events=iter([]),
            boundaries_ns=boundaries,
            worker_tids={1, 2, 3, 4},
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        lines = buf.getvalue().strip().split("\n")
        self.assertEqual(len(lines), 12)
        for i, l in enumerate(lines):
            obj = json.loads(l)
            self.assertEqual(obj["b"], i)
            self.assertEqual(len(obj["buckets"]), 16)
            self.assertEqual(sum(obj["buckets"]), 0)
            self.assertEqual(obj["off_cpu_time_3to6"], 0)
            self.assertEqual(obj["voluntary_3to6"], 0)
            self.assertEqual(obj["involuntary_3to6"], 0)
            self.assertEqual(obj["stat_runtime_check"], "WARN")


class TestReducerInvariant(unittest.TestCase):
    def test_reducer_invariant_sum_buckets_3to6(self):
        """V3: sum(buckets[3:7]) == off_cpu_time_3to6 on every block.

        Exercise with several off-CPU events landing in and out of the
        D1 window.
        """
        boundaries = _make_boundaries()
        tid = 7
        worker_tids = {tid}
        events = []
        # Events at t = b*5 + 1 s (in block b).  Alternate durations:
        # 512 ns -> bucket 0 (out-of-D1)
        # 4096 ns -> bucket 3 (in D1)
        # 16384 ns -> bucket 5 (in D1)
        # 262144 ns -> bucket 9 (out-of-D1)
        durations = [512, 4096, 16384, 262144]
        for b in range(12):
            off_ts = (b * 5 + 1) * 1_000_000_000
            d = durations[b % len(durations)]
            events.append(
                ("sched:sched_switch", tid, off_ts,
                 {"prev_pid": tid, "prev_state": "S"})
            )
            events.append(
                ("sched:sched_wakeup", tid, off_ts + d, {"pid": tid})
            )

        buf = io.StringIO()
        warn = io.StringIO()
        R.reduce_events(
            events=events,
            boundaries_ns=boundaries,
            worker_tids=worker_tids,
            perf_start_ns=boundaries[0],
            out_stream=buf,
            warn_stream=warn,
        )
        blocks = [json.loads(l) for l in buf.getvalue().strip().split("\n")]
        for blk in blocks:
            self.assertEqual(
                sum(blk["buckets"][3:7]),
                blk["off_cpu_time_3to6"],
                f"block {blk['b']}: invariant violated",
            )


class TestReducerDrift(unittest.TestCase):
    def test_reducer_drift_warning(self):
        """PERF_START_NS = STEP1_START_NS + 2 s -> WARN (no hard fail).

        We exercise this via main() with temp files so we can catch the
        stderr WARN string.
        """
        cold = {"_sample_ts": "1000000000"}
        cold_path = _write_inline(json.dumps(cold), ".json")
        warm_lines = []
        for i in range(12):
            warm_lines.append(
                json.dumps({"_sample_ts": str(1000000000 + (i + 1) * 5)})
            )
        samples_path = _write_inline("\n".join(warm_lines) + "\n", ".jsonl")
        # Empty perf-script (valid input: no events = 12 zero blocks).
        perf_path = _write_inline("", ".txt")
        step1_start_ns = 1_000_000_000 * 1_000_000_000
        perf_start_ns = step1_start_ns + 2_000_000_000  # +2 s

        # Capture stderr.  Also silence stdout (main() emits 12 JSONL lines).
        real_stderr = sys.stderr
        real_stdout = sys.stdout
        cap = io.StringIO()
        try:
            sys.stderr = cap
            sys.stdout = io.StringIO()
            rc = R.main(
                [
                    "--perf-script", str(perf_path),
                    "--step1-cold", str(cold_path),
                    "--step1-samples", str(samples_path),
                    "--worker-tids", "1",
                    "--perf-start-ns", str(perf_start_ns),
                ]
            )
        finally:
            sys.stderr = real_stderr
            sys.stdout = real_stdout
            cold_path.unlink()
            samples_path.unlink()
            perf_path.unlink()
        self.assertEqual(rc, 0)
        self.assertIn("WARN:", cap.getvalue())
        self.assertIn("drift_ns", cap.getvalue())


# --- Parser sanity: perf-script line format ---------------------------------


class TestPerfScriptParse(unittest.TestCase):
    def test_parse_perf_script_basic(self):
        """Parser handles typical perf-script line shapes."""
        # Textbook sched_switch line (perf 6.x, no call-graph):
        txt = (
            "xpf-userspace-w 12345 [003] 1234.567890123: "
            "sched:sched_switch: prev_comm=xpf-userspace-w prev_pid=12345 "
            "prev_prio=120 prev_state=R+ ==> next_comm=swapper/0 next_pid=0 "
            "next_prio=120\n"
            "xpf-userspace-w 12345 [003] 1234.567900000: "
            "sched:sched_wakeup: comm=xpf-userspace-w pid=12345 "
            "prio=120 target_cpu=003\n"
            "xpf-userspace-w 12345 [003] 1234.567999999: "
            "sched:sched_stat_runtime: comm=xpf-userspace-w pid=12345 "
            "runtime=9876 [ns] vruntime=12345 [ns]\n"
        )
        path = _write_inline(txt, ".txt")
        try:
            events = list(R.parse_perf_script(path))
        finally:
            path.unlink()
        self.assertEqual(len(events), 3)
        ev0 = events[0]
        self.assertEqual(ev0[0], "sched:sched_switch")
        self.assertEqual(ev0[1], 12345)
        self.assertEqual(ev0[2], 1234_567_890_123)
        self.assertEqual(ev0[3]["prev_pid"], 12345)
        self.assertEqual(ev0[3]["prev_state"], "R+")

        ev1 = events[1]
        self.assertEqual(ev1[0], "sched:sched_wakeup")
        self.assertEqual(ev1[3]["pid"], 12345)

        ev2 = events[2]
        self.assertEqual(ev2[0], "sched:sched_stat_runtime")
        self.assertEqual(ev2[3]["runtime_ns"], 9876)


if __name__ == "__main__":
    unittest.main()
