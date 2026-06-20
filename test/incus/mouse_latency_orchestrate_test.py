import json
import math
import os
import pathlib
import tempfile
import unittest

import mouse_latency_orchestrate as orch

_ROOT = pathlib.Path(__file__).resolve().parent
_COS_SET = (_ROOT / "cos-iperf-config.set").read_text()

# A minimal synthetic fixture used to exercise the parser/guard in
# isolation from the real fixture's port grid. Two exact classes plus a
# non-exact best-effort class bounded by the interface shaping-rate.
_SYNTH_SET = """\
set class-of-service forwarding-classes queue 0 best-effort
set class-of-service forwarding-classes queue 2 cls-1g
set class-of-service forwarding-classes queue 5 cls-9g
set class-of-service schedulers sched-be priority low
set class-of-service schedulers sched-1g transmit-rate 1.0g
set class-of-service schedulers sched-1g transmit-rate exact
set class-of-service schedulers sched-9g transmit-rate 9.0g
set class-of-service schedulers sched-9g transmit-rate exact
set class-of-service scheduler-maps m forwarding-class best-effort scheduler sched-be
set class-of-service scheduler-maps m forwarding-class cls-1g scheduler sched-1g
set class-of-service scheduler-maps m forwarding-class cls-9g scheduler sched-9g
set class-of-service interfaces reth0 unit 80 shaping-rate 25g
set firewall family inet filter f term 0 from destination-port 5200
set firewall family inet filter f term 0 then forwarding-class best-effort
set firewall family inet filter f term 2 from destination-port 5202
set firewall family inet filter f term 2 then forwarding-class cls-1g
set firewall family inet filter f term 5 from destination-port 5205
set firewall family inet filter f term 5 then forwarding-class cls-9g
"""

# Fixture rows use 120 KBytes and 180 KBytes in iperf3 output.
_EXPECTED_MIN_CWND_KBYTES = 120
_EXPECTED_MAX_CWND_KBYTES = 180


def _write(tmpdir: str, name: str, content: str) -> str:
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


class CheckCwndSettleTests(unittest.TestCase):
    def _make_args(self, txt_path: str, shaper: int):
        class A: pass
        a = A()
        a.iperf3_txt = txt_path
        a.shaper_bps = shaper
        a.window_rows = 3
        return a

    def test_settled(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   1.00-2.00   sec  118 MBytes  990 Mbits/sec
[SUM]   2.00-3.00   sec  118 MBytes  995 Mbits/sec
[SUM]   3.00-4.00   sec  118 MBytes  988 Mbits/sec
""")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 0)

    def test_not_settled_too_low(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   1.00-2.00   sec  118 MBytes  500 Mbits/sec
[SUM]   2.00-3.00   sec  118 MBytes  600 Mbits/sec
[SUM]   3.00-4.00   sec  118 MBytes  650 Mbits/sec
""")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 1)

    def test_not_settled_unstable(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   1.00-2.00   sec  118 MBytes  900 Mbits/sec
[SUM]   2.00-3.00   sec  118 MBytes  990 Mbits/sec
[SUM]   3.00-4.00   sec  118 MBytes  700 Mbits/sec
""")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 1)

    def test_no_sum_rows_yet(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", "Connecting to host 172.16.80.200, port 5201\n")
            self.assertEqual(orch.cmd_check_cwnd_settle(self._make_args(txt, 1_000_000_000)), 1)


class CwndSettleDiagnosticsTests(unittest.TestCase):
    def test_diagnostics_reports_aggregate_and_per_flow_window(self):
        text = """\
[  5]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec    1    100 KBytes
[  7]   0.00-1.00   sec  20.0 MBytes  160.0 Mbits/sec   0    200 KBytes
[SUM]   0.00-1.00   sec  30.0 MBytes  240.0 Mbits/sec
[  5]   1.00-2.00   sec  11.0 MBytes  88.0 Mbits/sec    2    110 KBytes
[  7]   1.00-2.00   sec  19.0 MBytes  152.0 Mbits/sec   0    190 KBytes
[SUM]   1.00-2.00   sec  30.0 MBytes  240.0 Mbits/sec
[  5]   2.00-3.00   sec  10.5 MBytes  84.0 Mbits/sec    3    120 KBytes
[  7]   2.00-3.00   sec  19.5 MBytes  156.0 Mbits/sec   0    180 KBytes
[SUM]   2.00-3.00   sec  30.0 MBytes  240.0 Mbits/sec
"""
        d = orch.build_cwnd_settle_diagnostics(
            text,
            300_000_000,
            elapsed_sec=20,
            sample_index=0,
        )
        self.assertTrue(d["settled"], d["reasons"])
        self.assertEqual(d["elapsed_sec"], 20)
        self.assertEqual(d["aggregate"]["window_bps"], [240_000_000] * 3)
        self.assertEqual(d["per_flow"]["flow_count"], 2)
        self.assertEqual(d["per_flow"]["retransmits_total"], 6)
        self.assertEqual(d["per_flow"]["mean_bps"]["min"], 84_000_000)
        self.assertEqual(d["per_flow"]["mean_bps"]["max"], 156_000_000)
        self.assertEqual(
            d["per_flow"]["cwnd_bytes"]["min"],
            _EXPECTED_MIN_CWND_KBYTES * 1024,
        )
        self.assertEqual(
            d["per_flow"]["cwnd_bytes"]["max"],
            _EXPECTED_MAX_CWND_KBYTES * 1024,
        )
        self.assertEqual(d["per_flow"]["slowest_streams"][0]["stream_id"], 5)

    def test_settle_diagnostics_writes_json_and_returns_status(self):
        with tempfile.TemporaryDirectory() as t:
            txt = _write(t, "iperf3.txt", """\
[SUM]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec
[SUM]   1.00-2.00   sec  30.0 MBytes  240.0 Mbits/sec
[SUM]   2.00-3.00   sec  10.0 MBytes  80.0 Mbits/sec
""")
            out_path = os.path.join(t, "cwnd-settle.json")

            class MockSettleDiagnosticsArgs: pass
            args = MockSettleDiagnosticsArgs()
            args.iperf3_txt = txt
            args.shaper_bps = 300_000_000
            args.window_rows = 3
            args.elapsed_sec = 20
            args.sample_index = 1
            args.out = out_path

            self.assertEqual(orch.cmd_settle_diagnostics(args), 1)
            with open(out_path) as f:
                payload = json.load(f)
            self.assertFalse(payload["settled"])
            self.assertEqual(payload["elapsed_sec"], 20)
            self.assertEqual(payload["sample_index"], 1)

    def test_diagnostics_explains_failed_thresholds(self):
        text = """\
[SUM]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec
[SUM]   1.00-2.00   sec  30.0 MBytes  240.0 Mbits/sec
[SUM]   2.00-3.00   sec  10.0 MBytes  80.0 Mbits/sec
"""
        d = orch.build_cwnd_settle_diagnostics(text, 300_000_000)
        self.assertFalse(d["settled"])
        self.assertTrue(any("aggregate-window-spread" in r for r in d["reasons"]))
        self.assertTrue(any("aggregate-too-low" in r for r in d["reasons"]))

    def test_diagnostics_requires_enough_sum_rows(self):
        d = orch.build_cwnd_settle_diagnostics(
            "[SUM]   0.00-1.00   sec  10.0 MBytes  80.0 Mbits/sec\n",
            300_000_000,
        )
        self.assertFalse(d["settled"])
        self.assertIn("insufficient-sum-rows", d["reasons"][0])


class CheckCollapseTests(unittest.TestCase):
    def _make_args(self, txt_path: str, shaper: int, n_rows: int = 0, skip_front: int = 0):
        class A: pass
        a = A()
        a.iperf3_txt = txt_path
        a.shaper_bps = shaper
        a.n_rows = n_rows
        a.skip_front = skip_front
        return a

    def test_settle_window_drops_ignored_with_skip_front(self):
        # R5 HIGH: the window must anchor on probe-start (skip_front=20)
        # not "last DURATION rows" (which would lose probe-start
        # collapse and include post-probe slack).
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(20):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
            for i in range(20, 80):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            for i in range(80, 90):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            # skip_front=20, n_rows=60 (probe window only) → no collapse
            self.assertEqual(
                orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000, 60, 20)), 1
            )
            # skip_front=0 (full log) → collapse from warmup
            self.assertEqual(
                orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000, 0, 0)), 0
            )

    def test_collapse_at_probe_start_caught_with_skip_front(self):
        # Settle is steady, but a 3-row dip happens RIGHT at probe start.
        # The R5 fix must not lose this.
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(20):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            for i in range(20, 23):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
            for i in range(23, 80):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            for i in range(80, 90):
                lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            self.assertEqual(
                orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000, 60, 20)), 0
            )

    def test_steady_no_collapse(self):
        with tempfile.TemporaryDirectory() as t:
            lines = [f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec" for i in range(60)]
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            # Collapse detection returns 0 IF collapsed; 1 IF not.
            self.assertEqual(orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000)), 1)

    def test_3_consecutive_drops_collapse(self):
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(60):
                if 30 <= i <= 32:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
                else:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            self.assertEqual(orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000)), 0)

    def test_2_drops_no_collapse(self):
        with tempfile.TemporaryDirectory() as t:
            lines = []
            for i in range(60):
                if 30 <= i <= 31:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  20 MBytes  100 Mbits/sec")
                else:
                    lines.append(f"[SUM]   {i}.00-{i+1}.00   sec  118 MBytes  990 Mbits/sec")
            txt = _write(t, "iperf3.txt", "\n".join(lines) + "\n")
            self.assertEqual(orch.cmd_check_collapse(self._make_args(txt, 1_000_000_000)), 1)


class RGStateFlappedTests(unittest.TestCase):
    def _make_args(self, path: str):
        class A: pass
        a = A()
        a.poll_file = path
        return a

    def test_stable(self):
        with tempfile.TemporaryDirectory() as t:
            content = "\n".join([
                "1000\trg=1\tnode=0\tstate=primary",
                "1000\trg=1\tnode=1\tstate=secondary",
                "2000\trg=1\tnode=0\tstate=primary",
                "2000\trg=1\tnode=1\tstate=secondary",
                "3000\trg=1\tnode=0\tstate=primary",
                "3000\trg=1\tnode=1\tstate=secondary",
            ]) + "\n"
            poll = _write(t, "rg.txt", content)
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 1)

    def test_flap_detected(self):
        with tempfile.TemporaryDirectory() as t:
            content = "\n".join([
                "1000\trg=1\tnode=0\tstate=primary",
                "1000\trg=1\tnode=1\tstate=secondary",
                "2000\trg=1\tnode=0\tstate=secondary",
                "2000\trg=1\tnode=1\tstate=primary",
            ]) + "\n"
            poll = _write(t, "rg.txt", content)
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 0)

    def test_failover_failback_returns_to_initial(self):
        # 3 samples: initial → flapped → back to initial. ANY drift
        # invalidates, even if the end matches the start.
        with tempfile.TemporaryDirectory() as t:
            content = "\n".join([
                "1000\trg=1\tnode=0\tstate=primary",
                "1000\trg=1\tnode=1\tstate=secondary",
                "2000\trg=1\tnode=0\tstate=secondary",
                "2000\trg=1\tnode=1\tstate=primary",
                "3000\trg=1\tnode=0\tstate=primary",
                "3000\trg=1\tnode=1\tstate=secondary",
            ]) + "\n"
            poll = _write(t, "rg.txt", content)
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 0)

    def test_empty_poll_file_returns_2(self):
        # R1 HIGH 5: empty poll file is "no data", not "stable" — caller
        # must invalidate, not pass.
        with tempfile.TemporaryDirectory() as t:
            poll = _write(t, "rg.txt", "")
            self.assertEqual(orch.cmd_rg_state_flapped(self._make_args(poll)), 2)


class CoSFixtureParseTests(unittest.TestCase):
    def test_parses_exact_class_cap_from_scheduler_rate(self):
        caps = orch.parse_cos_class_caps(_SYNTH_SET)
        self.assertEqual(caps[5202]["forwarding_class"], "cls-1g")
        self.assertEqual(caps[5202]["scheduler"], "sched-1g")
        self.assertTrue(caps[5202]["exact"])
        self.assertEqual(caps[5202]["cap_bps"], 1_000_000_000)
        self.assertEqual(caps[5205]["cap_bps"], 9_000_000_000)

    def test_non_exact_class_capped_at_interface_shaping_rate(self):
        caps = orch.parse_cos_class_caps(_SYNTH_SET)
        self.assertFalse(caps[5200]["exact"])
        # best-effort has no transmit-rate; ceiling is the 25g shaper.
        self.assertEqual(caps[5200]["cap_bps"], 25_000_000_000)

    def test_classified_but_unscheduled_class_raises(self):
        # A port classified into a forwarding-class that has no
        # scheduler-map entry must NOT silently fall through to the
        # interface-shaper cap (which would mask fixture drift/misparse).
        broken = (
            "set class-of-service forwarding-classes queue 2 cls-1g\n"
            "set class-of-service interfaces reth0 unit 80 shaping-rate 25g\n"
            "set firewall family inet filter f term 2 from destination-port 5202\n"
            "set firewall family inet filter f term 2 then forwarding-class cls-1g\n"
        )
        with self.assertRaises(orch.CoSFixtureError):
            orch.parse_cos_class_caps(broken)

    def test_real_fixture_grid_matches_canonical_rates(self):
        # Drift guard: the table parsed from the live fixture must agree
        # with the canonical port -> exact-class-rate map. If the fixture
        # port grid changes, this test fails loudly rather than letting
        # the guard silently compare against a stale cap.
        caps = orch.parse_cos_class_caps(_COS_SET)
        expected = {
            5201: (100_000_000, True),
            5202: (1_000_000_000, True),
            5203: (3_000_000_000, True),
            5204: (6_000_000_000, True),
            5205: (9_000_000_000, True),
            5206: (12_000_000_000, True),
            5207: (15_000_000_000, True),
            5208: (18_000_000_000, True),
            5209: (21_000_000_000, True),
            5210: (24_000_000_000, True),
        }
        for port, (rate, exact) in expected.items():
            with self.subTest(port=port):
                self.assertIn(port, caps)
                self.assertEqual(caps[port]["exact"], exact)
                self.assertEqual(caps[port]["cap_bps"], rate)
        # Echo ports 620x mirror the same classes as 520x.
        self.assertEqual(caps[6202]["cap_bps"], 1_000_000_000)
        # Non-exact classes (best-effort 5200, uncapped 5211) ride the
        # 25g interface shaper, not a per-class transmit-rate.
        self.assertFalse(caps[5200]["exact"])
        self.assertFalse(caps[5211]["exact"])
        self.assertEqual(caps[5200]["cap_bps"], 25_000_000_000)
        self.assertEqual(caps[5211]["cap_bps"], 25_000_000_000)


class SettleThresholdSatisfiableTests(unittest.TestCase):
    def test_reported_1365_misconfig_is_unsatisfiable(self):
        # The exact #1365 footgun: port 5202 (1 Gbps exact class) paired
        # with SHAPER_BPS=10G. Floor = 0.7 * 10G = 7G > 1G cap.
        r = orch.check_settle_threshold_satisfiable(
            5202, 10_000_000_000, set_text=_COS_SET,
        )
        self.assertFalse(r["satisfiable"])
        self.assertEqual(r["forwarding_class"], "iperf-1g")
        self.assertEqual(r["cap_bps"], 1_000_000_000)
        self.assertEqual(r["floor_bps"], 7_000_000_000)

    def test_matched_1g_pairing_is_satisfiable(self):
        # Same port, matched bps. Floor = 0.7 * 1G = 700M <= 1G cap.
        r = orch.check_settle_threshold_satisfiable(
            5202, 1_000_000_000, set_text=_COS_SET,
        )
        self.assertTrue(r["satisfiable"])
        self.assertEqual(r["floor_bps"], 700_000_000)

    def test_high_rate_class_with_matched_bps_is_satisfiable(self):
        # Port 5205 = 9 Gbps exact class, matched SHAPER_BPS=9G.
        # Floor = 6.3G <= 9G cap.
        r = orch.check_settle_threshold_satisfiable(
            5205, 9_000_000_000, set_text=_COS_SET,
        )
        self.assertTrue(r["satisfiable"])

    @staticmethod
    def _largest_satisfiable_shaper(cap_bps: int, min_utilization: float) -> int:
        # The largest SHAPER_BPS whose ceil(min_utilization * SHAPER_BPS)
        # is still <= cap_bps — i.e. the TRUE settle-floor boundary under
        # the guard's ceil semantics. Derived with the same float
        # arithmetic the guard uses (math.ceil) so the boundary is exact
        # on this platform rather than a hand-picked constant.
        lo, hi = cap_bps, cap_bps * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if math.ceil(min_utilization * mid) <= cap_bps:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def test_boundary_floor_equals_cap_is_satisfiable(self):
        # True boundary: the largest SHAPER_BPS whose ceil-floor lands
        # EXACTLY on the 1G cap. floor == cap must PASS (<=, not <).
        cap = 1_000_000_000
        shaper = self._largest_satisfiable_shaper(cap, 0.7)
        r = orch.check_settle_threshold_satisfiable(
            5202, shaper, set_text=_COS_SET,
        )
        self.assertEqual(r["cap_bps"], cap)
        self.assertEqual(r["floor_bps"], cap)  # exactly on the boundary
        self.assertTrue(r["satisfiable"])

    def test_one_bps_over_boundary_is_unsatisfiable(self):
        # One bps of SHAPER_BPS above the true boundary must flip the
        # verdict to unsatisfiable, proving the guard is not a no-op
        # rubber stamp and that the boundary is sharp to a single bps.
        cap = 1_000_000_000
        shaper_ok = self._largest_satisfiable_shaper(cap, 0.7)
        r_ok = orch.check_settle_threshold_satisfiable(
            5202, shaper_ok, set_text=_COS_SET,
        )
        self.assertEqual(r_ok["floor_bps"], cap)
        self.assertTrue(r_ok["satisfiable"])
        # Exactly +1 bps of shaper pushes the ceil-floor to cap + 1.
        r_bad = orch.check_settle_threshold_satisfiable(
            5202, shaper_ok + 1, set_text=_COS_SET,
        )
        self.assertEqual(r_bad["floor_bps"], cap + 1)
        self.assertGreater(r_bad["floor_bps"], r_bad["cap_bps"])
        self.assertFalse(r_bad["satisfiable"])

    def test_unknown_port_raises(self):
        with self.assertRaises(orch.CoSFixtureError):
            orch.check_settle_threshold_satisfiable(
                9999, 1_000_000_000, set_text=_COS_SET,
            )


class CheckEnvConsistencyCmdTests(unittest.TestCase):
    def _args(self, port, shaper, set_file=None):
        class A: pass
        a = A()
        a.elephant_port = port
        a.shaper_bps = shaper
        a.set_file = set_file
        return a

    def test_cmd_returns_0_for_satisfiable(self):
        with tempfile.TemporaryDirectory() as t:
            sf = _write(t, "cos.set", _COS_SET)
            self.assertEqual(
                orch.cmd_check_env_consistency(self._args(5202, 1_000_000_000, sf)),
                0,
            )

    def test_cmd_returns_1_for_unsatisfiable(self):
        with tempfile.TemporaryDirectory() as t:
            sf = _write(t, "cos.set", _COS_SET)
            self.assertEqual(
                orch.cmd_check_env_consistency(self._args(5202, 10_000_000_000, sf)),
                1,
            )

    def test_cmd_returns_2_for_unknown_port(self):
        with tempfile.TemporaryDirectory() as t:
            sf = _write(t, "cos.set", _COS_SET)
            self.assertEqual(
                orch.cmd_check_env_consistency(self._args(9999, 1_000_000_000, sf)),
                2,
            )

    def test_cmd_default_set_file_uses_real_fixture(self):
        # No --set-file: must resolve the real cos-iperf-config.set and
        # agree with the default harness pairing (5202 / 1G).
        self.assertEqual(
            orch.cmd_check_env_consistency(self._args(5202, 1_000_000_000)),
            0,
        )


if __name__ == "__main__":
    unittest.main()
