#!/usr/bin/env python3
"""Dry-run tests for the userspace HA validation smoke matrix."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = PROJECT_ROOT / "scripts" / "userspace-ha-validation.sh"


class UserspaceHASmokeMatrixTests(unittest.TestCase):
    def run_validator(
        self,
        *args: str,
        check: bool = True,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "loss-userspace-cluster.env"
            env_file.write_text(
                textwrap.dedent(
                    """\
                    INCUS_REMOTE=loss
                    VM0=xpf-userspace-fw0
                    VM1=xpf-userspace-fw1
                    LAN_HOST=cluster-userspace-host
                    """
                ),
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update(
                {
                    "RUNS": "1",
                    "DURATION": "1",
                    "PARALLEL": "1",
                    "MIN_GBPS_V4": "1.0",
                    "MIN_GBPS_V6": "1.0",
                }
            )
            if extra_env:
                env.update(extra_env)
            result = subprocess.run(
                [str(VALIDATOR), "--env", str(env_file), "--dry-run-matrix", *args],
                cwd=PROJECT_ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        if check and result.returncode != 0:
            self.fail(
                "validator exited "
                f"{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def test_full_matrix_lists_all_cos_direction_cells(self) -> None:
        result = self.run_validator("--smoke-matrix")
        plan = [line for line in result.stdout.splitlines() if line.startswith("matrix plan: ")]
        self.assertEqual(
            plan,
            [
                "matrix plan: cos-off-ipv4-push cos=off family=ipv4 direction=push "
                "target=172.16.80.200 min_gbps=1.0",
                "matrix plan: cos-off-ipv4-reverse cos=off family=ipv4 direction=reverse "
                "target=172.16.80.200 min_gbps=1.0",
                "matrix plan: cos-off-ipv6-push cos=off family=ipv6 direction=push "
                "target=2001:559:8585:80::200 min_gbps=1.0",
                "matrix plan: cos-off-ipv6-reverse cos=off family=ipv6 direction=reverse "
                "target=2001:559:8585:80::200 min_gbps=1.0",
                "matrix plan: cos-on-ipv4-push cos=on family=ipv4 direction=push "
                "target=172.16.80.200 min_gbps=1.0",
                "matrix plan: cos-on-ipv4-reverse cos=on family=ipv4 direction=reverse "
                "target=172.16.80.200 min_gbps=1.0",
                "matrix plan: cos-on-ipv6-push cos=on family=ipv6 direction=push "
                "target=2001:559:8585:80::200 min_gbps=1.0",
                "matrix plan: cos-on-ipv6-reverse cos=on family=ipv6 direction=reverse "
                "target=2001:559:8585:80::200 min_gbps=1.0",
            ],
        )
        self.assertIn("smoke matrix complete: 8/8 cells passed", result.stdout)

    def test_default_fast_mode_is_not_reported_as_full_matrix(self) -> None:
        result = self.run_validator()
        plan = [line for line in result.stdout.splitlines() if line.startswith("matrix plan: ")]
        self.assertEqual(
            plan,
            [
                "matrix plan: fast-current-cos-ipv4-push cos=current-cos family=ipv4 "
                "direction=push target=172.16.80.200 min_gbps=1.0",
                "matrix plan: fast-current-cos-ipv6-push cos=current-cos family=ipv6 "
                "direction=push target=2001:559:8585:80::200 min_gbps=1.0",
            ],
        )
        self.assertIn(
            "smoke matrix: fast mode runs current-CoS IPv4/IPv6 push only",
            result.stdout,
        )
        self.assertIn("smoke fast complete: 2/2 cells passed", result.stdout)
        self.assertNotIn("smoke matrix complete:", result.stdout)

    def test_dry_run_cell_failure_exits_without_complete_summary(self) -> None:
        result = self.run_validator(
            "--smoke-matrix",
            "--dry-run-fail-cell",
            "cos-on-ipv6-reverse",
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dry-run injected failure for cos-on-ipv6-reverse", result.stderr)
        self.assertNotIn("smoke matrix complete:", result.stdout)
        self.assertIn("smoke cell pass: cos-on-ipv6-push", result.stdout)
        self.assertNotIn("smoke cell pass: cos-on-ipv6-reverse", result.stdout)


if __name__ == "__main__":
    unittest.main()
