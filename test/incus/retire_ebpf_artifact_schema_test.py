#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("retire_ebpf_artifact_schema.py")
SPEC = importlib.util.spec_from_file_location("retire_ebpf_artifact_schema", MODULE_PATH)
assert SPEC is not None
schema = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["retire_ebpf_artifact_schema"] = schema
SPEC.loader.exec_module(schema)


COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def write_text(root: Path, rel: str, text: str = "artifact\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(root: Path, rel: str, value: object | None = None) -> None:
    if value is None:
        value = {"ok": True}
    write_text(root, rel, json.dumps(value) + "\n")


def command(gate: str) -> dict[str, object]:
    return {"gate": gate, "command": f"run {gate}", "exit_status": 0}


def make_manifest(commit: str = COMMIT) -> dict[str, object]:
    return {
        "schema_version": 1,
        "issues": [1373, 1477],
        "candidate_commit": commit,
        "cluster": {
            "name": "loss",
            "env_file": "test/incus/loss-userspace-cluster.env",
            "config_files": ["docs/ha-cluster-userspace.conf"],
        },
        "binaries": [
            {
                "host": "xpf-userspace-fw0",
                "path": "/usr/local/sbin/xpfd",
                "sha256": "1" * 64,
            },
            {
                "host": "xpf-userspace-fw0",
                "path": "/usr/local/bin/xpf-userspace-dp",
                "sha256": "2" * 64,
            },
        ],
        "commands": [command(gate) for gate in sorted(schema.REQUIRED_COMMAND_GATES)],
    }


def make_summary(commit: str = COMMIT) -> str:
    lines = ["# #1477 Source-Removal Validation Summary", "", commit, ""]
    for heading in schema.SUMMARY_HEADINGS:
        lines.extend([f"## {heading}", "Recorded in fixture.", ""])
    return "\n".join(lines)


def make_syn_cookie_summary() -> str:
    lines = ["# SYN-Cookie Proof", ""]
    for heading in schema.SYN_COOKIE_HEADINGS:
        lines.extend([f"## {heading}", "Recorded in fixture.", ""])
    return "\n".join(lines)


def build_complete_artifact(root: Path, commit: str = COMMIT) -> None:
    write_json(root, "manifest.json", make_manifest(commit))
    write_text(root, "summary.md", make_summary(commit))

    write_text(root, "metadata/git-rev-parse-head.txt", commit + "\n")
    write_text(root, "metadata/git-status-short.txt", "")
    write_text(root, "metadata/cluster-env.txt")
    write_text(root, "metadata/ha-cluster-userspace.conf")
    write_text(root, "metadata/binary-sha256sums.txt")
    write_text(root, "metadata/cluster-userspace-host-ipv6-route.txt")

    for label in schema.COS_OFF_CASES:
        write_json(root, f"cos-off/{label}.json")
        write_text(root, f"cos-off/{label}.stderr", "")
        write_json(root, f"cos-off/{label}.metrics.json", {"completed": True})

    for probe in schema.SCREEN_PROBES:
        write_text(root, f"screen-flood/{probe}-before.txt")
        write_text(root, f"screen-flood/{probe}-after.txt")
        write_text(root, f"screen-flood/{probe}-configure.stdout")
        write_text(root, f"screen-flood/{probe}-configure.stderr", "")
    write_text(root, "screen-flood/restore.stdout")
    write_text(root, "screen-flood/restore.stderr", "")

    write_text(root, "syn-cookie/summary.md", make_syn_cookie_summary())
    for rel in (
        "syn-cookie/applied-config.txt",
        "syn-cookie/challenge-hping3.stdout",
        "syn-cookie/challenge-hping3.stderr",
        "syn-cookie/challenge-tcpdump.txt",
        "syn-cookie/challenge-counters-before.txt",
        "syn-cookie/challenge-counters-after.txt",
        "syn-cookie/valid-ack-rst-tcpdump.txt",
        "syn-cookie/valid-ack-rst-counters-before.txt",
        "syn-cookie/valid-ack-rst-counters-after.txt",
        "syn-cookie/random-ack-drop-tcpdump.txt",
        "syn-cookie/random-ack-drop-counters-before.txt",
        "syn-cookie/random-ack-drop-counters-after.txt",
        "syn-cookie/retransmitted-syn-admission-tcpdump.txt",
        "syn-cookie/retransmitted-syn-admission-counters-before.txt",
        "syn-cookie/retransmitted-syn-admission-counters-after.txt",
        "syn-cookie/reply-budget-counters.txt",
        "syn-cookie/failover-before-cluster-status.txt",
        "syn-cookie/failover-after-cluster-status.txt",
        "syn-cookie/failover-cookie-ack-tcpdump.txt",
        "syn-cookie/failover-counters-node1.txt",
        "syn-cookie/cleanup.stdout",
        "syn-cookie/cleanup.stderr",
        "syn-cookie/final-cluster-status.txt",
    ):
        write_text(root, rel, "" if rel.endswith(".stderr") else "artifact\n")

    for sweep in schema.COS_SWEEP_DIRS:
        write_text(root, f"{sweep}/summary.tsv")
        write_text(root, f"{sweep}/summary.md")
        write_json(root, f"{sweep}/dataplane/status-before.json")
        write_json(root, f"{sweep}/dataplane/status-after.json")
        write_json(root, f"{sweep}/dataplane/counter-delta.json")
        write_text(root, f"{sweep}/dataplane/journal-since.txt")
        write_text(root, f"{sweep}/dataplane-summary.tsv")
        write_text(root, f"{sweep}/equal-flow-summary.tsv")
        for class_name in schema.COS_CLASSES:
            base = f"{sweep}/{class_name}"
            write_text(root, f"{base}/wrapper.stdout")
            write_text(root, f"{base}/wrapper.stderr", "")
            write_json(root, f"{base}/samples/summary.json")
            write_json(root, f"{base}/equal-flow/summary.json")
            write_json(root, f"{base}/dataplane/status-before.json")
            write_json(root, f"{base}/dataplane/status-after.json")

    write_text(root, "echo-6200-6211/summary.tsv")
    write_text(root, "echo-6200-6211/latency-summary.tsv")
    for port in schema.ECHO_PORTS:
        write_text(root, f"echo-6200-6211/{port}.stdout")
        write_text(root, f"echo-6200-6211/{port}.stderr", "")

    write_text(root, "userspace-phase-cycle.log")
    write_text(root, "userspace-ha-failover.log")
    write_text(root, "ha-test-failover.log")
    write_text(root, "ha-test-ha-crash.log")
    write_text(root, "ha-test-restart-connectivity.log")
    write_text(root, "userspace-ha-failover/iperf3.log")
    write_json(root, "userspace-ha-failover/iperf3.metrics.json")
    write_text(root, "userspace-ha-failover/before-source-status.txt")
    write_text(root, "userspace-ha-failover/before-target-status.txt")
    write_text(root, "userspace-ha-failover/cycle1-failover-fw1-dp-stats.txt")
    write_text(root, "userspace-ha-failover/cycle1-failback-fw0-dp-stats.txt")
    write_text(root, "userspace-ha-failover/cycle1-failover-fw1-dp-interfaces.txt")
    write_text(root, "userspace-ha-failover/cycle1-failback-fw0-dp-interfaces.txt")

    for rel in (
        "fallback-exclusion/fw0-ip-link.txt",
        "fallback-exclusion/fw1-ip-link.txt",
        "fallback-exclusion/fw0-dp-stats.txt",
        "fallback-exclusion/fw1-dp-stats.txt",
        "fallback-exclusion/fw0-userspace-dp.json",
        "fallback-exclusion/fw1-userspace-dp.json",
        "fallback-exclusion/legacy-map-counter-audit.txt",
    ):
        if rel.endswith(".json"):
            write_json(root, rel)
        else:
            write_text(root, rel)


class RetireEbpfArtifactSchemaTests(unittest.TestCase):
    def with_fixture(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / f"evidence-1477-source-removal-20260522-{COMMIT[:12]}"
        build_complete_artifact(root)
        return tmp, root

    def test_complete_candidate_schema_passes(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            summary = schema.validate_artifact_root(root, candidate_commit=COMMIT)
            self.assertEqual(summary["verdict"], "STRUCTURE_OK")
            self.assertEqual(summary["candidate_commit"], COMMIT)

    def test_rejects_missing_reverse_ipv6_cos_off_artifact(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "cos-off/v6-reverse.metrics.json").unlink()
            with self.assertRaisesRegex(
                schema.ValidationFailure, "cos-off/v6-reverse.metrics.json"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_omitted_echo_port(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "echo-6200-6211/6211.stdout").unlink()
            with self.assertRaisesRegex(schema.ValidationFailure, "6211.stdout"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_missing_echo_latency_summary(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "echo-6200-6211/latency-summary.tsv").unlink()
            with self.assertRaisesRegex(schema.ValidationFailure, "latency-summary.tsv"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_missing_udp_screen_probe(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "screen-flood/udp-after.txt").unlink()
            with self.assertRaisesRegex(schema.ValidationFailure, "udp-after.txt"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_missing_ha_failback_leg(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            for path in (root / "userspace-ha-failover").glob(
                "cycle*-failback-*-dp-stats.txt"
            ):
                path.unlink()
            with self.assertRaisesRegex(
                schema.ValidationFailure, "HA failback dataplane stats"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_stale_commit_mismatch(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            with self.assertRaisesRegex(schema.ValidationFailure, "candidate commit mismatch"):
                schema.validate_artifact_root(root, candidate_commit=OTHER_COMMIT)

    def test_rejects_short_manifest_commit(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest("a" * 12)
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(
                schema.ValidationFailure, "full 40-character SHA"
            ):
                schema.validate_artifact_root(root)

    def test_rejects_missing_summary_section(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            text = make_summary().replace("## HA Gates\n", "")
            write_text(root, "summary.md", text)
            with self.assertRaisesRegex(schema.ValidationFailure, "## HA Gates"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

if __name__ == "__main__":
    unittest.main()
