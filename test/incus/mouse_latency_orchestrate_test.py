import os
import tempfile
import unittest

import mouse_latency_orchestrate as orch


def _write(tmpdir: str, name: str, content: str) -> str:
    path = os.path.join(tmpdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


class CheckCwndSettleTests(unittest.TestCase):
    def _make_args(self, txt_path: str, shaper: int, floor_fraction: float = 0.5):
        class A: pass
        a = A()
        a.iperf3_txt = txt_path
        a.shaper_bps = shaper
        a.floor_fraction = floor_fraction
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


class CheckCollapseTests(unittest.TestCase):
    def _make_args(self, txt_path: str, shaper: int, n_rows: int = 0, skip_front: int = 0, threshold_fraction: float = 0.3):
        class A: pass
        a = A()
        a.iperf3_txt = txt_path
        a.shaper_bps = shaper
        a.n_rows = n_rows
        a.skip_front = skip_front
        a.threshold_fraction = threshold_fraction
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


if __name__ == "__main__":
    unittest.main()
