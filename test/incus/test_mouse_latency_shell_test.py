import pathlib
import re
import unittest


SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency.sh").read_text()
MATRIX_SCRIPT = pathlib.Path(__file__).with_name("test-mouse-latency-matrix.sh").read_text()


class MouseLatencyShellTests(unittest.TestCase):
    def test_surplus_fixture_env_is_validated_and_passed_to_apply(self):
        self.assertIn('MOUSE_COS_SURPLUS_SHARING="${MOUSE_COS_SURPLUS_SHARING:-0}"', SCRIPT)
        self.assertIn('MOUSE_COS_SURPLUS_SHARING=1', SCRIPT)
        self.assertIn("MOUSE_COS_SURPLUS_SHARING='$MOUSE_COS_SURPLUS_SHARING' must be boolean", SCRIPT)

        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ "\$MOUSE_COS_SURPLUS_SHARING" -eq 1 \]\]; then\s+'
                r'APPLY_COS_FLAGS\+=\(--surplus-sharing\)\s+fi',
                re.MULTILINE,
            ),
        )

    def test_surplus_fixture_choice_is_written_to_manifest(self):
        self.assertIn(
            'MOUSE_CLASS="$MOUSE_CLASS" MOUSE_COS_SURPLUS_SHARING="$MOUSE_COS_SURPLUS_SHARING"',
            SCRIPT,
        )
        self.assertIn('"cos_surplus_sharing": os.environ["MOUSE_COS_SURPLUS_SHARING"] == "1"', SCRIPT)

    def test_matrix_documents_surplus_fixture_knob(self):
        self.assertIn("Set MOUSE_COS_SURPLUS_SHARING=1", MATRIX_SCRIPT)
        self.assertIn("per-rep manifest records the selected fixture bit", MATRIX_SCRIPT)

    def test_settle_budget_and_diagnostics_are_recorded(self):
        self.assertIn('SETTLE_BUDGET="${MOUSE_LATENCY_SETTLE_BUDGET:-20}"', SCRIPT)
        self.assertIn("MOUSE_LATENCY_SETTLE_BUDGET='$SETTLE_BUDGET' must be a positive integer second count", SCRIPT)
        self.assertIn('settle-diagnostics "${OUT_DIR}/iperf3-settle.txt" "$SHAPER_BPS"', SCRIPT)
        self.assertIn('"settle_budget_s": int(os.environ["SETTLE_BUDGET"])', SCRIPT)
        self.assertIn('"cwnd_settle_elapsed_s": int(os.environ["CWND_SETTLE_ELAPSED"])', SCRIPT)
        self.assertIn('CWND_SETTLE_OK="unknown"', SCRIPT)
        self.assertIn('CWND_SETTLE_OK="false"', SCRIPT)
        self.assertIn('settle_ok = None', SCRIPT)
        self.assertIn('"cwnd_settle_ok": settle_ok', SCRIPT)
        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ \$pull_rc -ne 0 \|\| ! -s "\$\{OUT_DIR\}/iperf3-settle\.txt" \]\]; then\s+'
                r'invalidate "iperf3-settle-pull-failed"',
                re.MULTILINE,
            ),
        )
        self.assertIn('"status": "INVALID"', SCRIPT)
        self.assertIn('write_invalid_manifest "$reason"', SCRIPT)

    def test_env_consistency_guard_runs_before_rep(self):
        # #1365: the harness must reject an ELEPHANT_PORT/SHAPER_BPS
        # pairing whose cwnd-settle floor exceeds the class cap, before
        # spending a whole matrix cell on an impossible pairing.
        self.assertIn(
            'check-env-consistency \\\n    "$ELEPHANT_PORT" "$SHAPER_BPS"',
            SCRIPT,
        )
        self.assertIn("unsatisfiable cwnd-settle pairing", SCRIPT)
        # Must fire before the rep does any cluster work (mkdir OUT_DIR is
        # the first post-validation step).
        guard_idx = SCRIPT.index("check-env-consistency")
        mkdir_idx = SCRIPT.index('mkdir -p "$OUT_DIR"')
        self.assertLess(guard_idx, mkdir_idx)

    def test_runtime_cos_and_settle_cpu_artifacts_are_cleared_and_captured(self):
        for artifact in (
            '"/cwnd-settle.json \\',
            '"/mpstat-settle.txt \\',
            '"/cos-interface-pre.txt \\',
            '"/cos-interface-settle.txt \\',
            '"/cos-interface-post.txt \\',
        ):
            self.assertIn(artifact, SCRIPT)
        self.assertIn("show class-of-service interface", SCRIPT)
        self.assertIn("mpstat 1 ${SETTLE_BUDGET} > /tmp/mpstat-settle-${REP_TAG}.txt", SCRIPT)


class ElephantLifecycleWiringTests(unittest.TestCase):
    """#7159: the rep script must USE the elephant lifecycle library.

    mouse-elephant-selftest.sh proves the library's start/stop pair
    reaps the leaf process. It cannot see whether test-mouse-latency.sh
    calls it -- and the whole defect was a call site, not a helper: the
    EXIT trap killed the local incus-exec client and believed the
    remote iperf3 had stopped. These bind the wiring.
    """

    def test_rep_script_sources_the_lifecycle_library(self):
        self.assertIn('. "${SCRIPT_DIR}/mouse-elephant-lib.sh"', SCRIPT)

    def test_elephant_is_launched_through_the_library(self):
        # The raw `iperf3 -c ...` launch string is what leaked: it left
        # nothing on the remote side that a kill could address.
        self.assertNotIn('"iperf3 -c ${TARGET_V4}', SCRIPT)
        self.assertIn('mouse_elephant_start_cmd "$REP_TAG" "$TARGET_V4" "$ELEPHANT_PORT"', SCRIPT)

    def test_cleanup_stops_the_elephant_on_the_source_container(self):
        # Killing IPERF_PID alone is the pre-#7159 behaviour: it closes
        # the local client and leaves the remote process running.
        self.assertRegex(
            SCRIPT,
            re.compile(
                r'if \[\[ -n "\$\{IPERF_PID:-\}" && "\$\{IPERF_DONE:-0\}" -ne 1 \]\]; then\s+'
                r'incus_exec "\$SOURCE" sh -c "\$\(mouse_elephant_kill_cmd "\$REP_TAG"\)"',
                re.MULTILINE,
            ),
        )
        # ... and a rep that ran to completion must not re-kill a pid
        # the source may since have reused.
        wait_idx = SCRIPT.index('wait "$IPERF_PID"')
        done_idx = SCRIPT.index("IPERF_DONE=1")
        self.assertLess(wait_idx, done_idx)

    def test_stale_elephant_guard_runs_before_any_cos_mutation(self):
        self.assertIn('mouse_elephant_stale_check_cmd', SCRIPT)
        self.assertIn('invalidate "stale-elephant-client"', SCRIPT)
        guard_idx = SCRIPT.index("mouse_elephant_stale_check_cmd")
        cos_idx = SCRIPT.index('"${SCRIPT_DIR}/apply-cos-config.sh"')
        self.assertLess(guard_idx, cos_idx)

    def test_pidfile_is_swept_with_the_other_stale_rep_artifacts(self):
        self.assertIn("/tmp/iperf3-${REP_TAG}.pid", SCRIPT)


if __name__ == "__main__":
    unittest.main()
