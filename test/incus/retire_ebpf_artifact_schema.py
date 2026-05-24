#!/usr/bin/env python3
"""Validate the #1477 final retirement artifact layout.

This checker is intentionally structural. It proves that the final evidence
bundle is complete, consistently named, and tied to one full source-removal
commit. It does not decide whether the live cluster results are acceptable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_TIME_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[Tt](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<fraction>\.\d+)?(?P<zone>[Zz]|[+-]\d{2}:\d{2})$"
)

COS_OFF_CASES = ("v4-push", "v4-reverse", "v6-push", "v6-reverse")
SCREEN_PROBES = ("land", "syn", "icmp", "udp")
ECHO_PORTS = range(6200, 6212)
COS_CLASSES = (
    "q0-best-effort-root",
    "q1-iperf-100m",
    "q2-iperf-1g",
    "q3-iperf-3g",
    "q4-iperf-6g",
    "q5-iperf-9g",
    "q6-iperf-12g",
    "q7-iperf-15g",
    "q8-iperf-18g",
    "q9-iperf-21g",
    "q10-iperf-24g",
    "q11-iperf-uncapped-root",
)
COS_SWEEP_DIRS = ("cos-on-5200-5211-push", "cos-on-5200-5211-reverse")

REQUIRED_COMMAND_GATES = {
    "cos-off",
    "screen-flood",
    "syn-cookie",
    "cos-on-5200-5211-push",
    "cos-on-5200-5211-reverse",
    "echo-6200-6211",
    "userspace-phase-cycle",
    "userspace-ha-failover",
    "ha-test-failover",
    "ha-test-ha-crash",
    "ha-test-restart-connectivity",
    "fallback-exclusion",
}

MANIFEST_FIELDS = {
    "schema_version",
    "issues",
    "candidate_commit",
    "candidate_branch",
    "artifact_created_at",
    "cluster",
    "binaries",
    "commands",
    "notes",
}

REQUIRED_MANIFEST_FIELDS = {
    "schema_version",
    "issues",
    "candidate_commit",
    "cluster",
    "binaries",
    "commands",
}

CLUSTER_FIELDS = {"name", "env_file", "config_files"}
REQUIRED_CLUSTER_FIELDS = {"name", "env_file", "config_files"}
BINARY_FIELDS = {"host", "path", "sha256", "version"}
REQUIRED_BINARY_FIELDS = {"host", "path", "sha256"}
COMMAND_FIELDS = {
    "gate",
    "command",
    "exit_status",
    "started_at",
    "finished_at",
    "artifacts",
}
REQUIRED_COMMAND_FIELDS = {"gate", "command", "exit_status"}

SUMMARY_HEADINGS = (
    "Candidate",
    "Cluster And Binaries",
    "CoS-Off IPv4/IPv6 Push And Reverse",
    "Screen/Flood Baseline",
    "SYN-Cookie Proof",
    "CoS 5200-5211 Sweeps",
    "TCP Echo 6200-6211",
    "HA Gates",
    "Fallback Exclusion",
    "Command Exit Status",
    "Remaining Exceptions",
)

SYN_COOKIE_HEADINGS = (
    "Temporary Config",
    "SYN-ACK Challenge",
    "Valid ACK RST",
    "Random ACK Drop",
    "Retransmitted SYN Admission",
    "Reply Budget Accounting",
    "HA Failover Acceptance",
    "Cleanup",
)


class ValidationFailure(Exception):
    """Raised when the artifact directory fails structural validation."""


def _display(path: Path) -> str:
    return path.as_posix()


class ArtifactChecker:
    def __init__(self, root: Path, *, candidate_commit: str | None = None) -> None:
        self.root = root
        self.expected_commit = candidate_commit.lower() if candidate_commit else None
        self.errors: list[str] = []
        self.checked = 0
        self.candidate_commit = ""

    def validate(self) -> dict[str, Any]:
        if not self.root.exists():
            raise ValidationFailure(f"artifact root does not exist: {self.root}")
        if not self.root.is_dir():
            raise ValidationFailure(f"artifact root is not a directory: {self.root}")

        manifest = self.validate_manifest()
        self.validate_metadata()
        self.validate_summary("summary.md", SUMMARY_HEADINGS, self.candidate_commit)
        self.validate_cos_off()
        self.validate_screen_flood()
        self.validate_syn_cookie()
        self.validate_cos_sweeps()
        self.validate_echo()
        self.validate_ha()
        self.validate_fallback_exclusion()

        if self.errors:
            raise ValidationFailure("\n".join(self.errors))
        return {
            "verdict": "STRUCTURE_OK",
            "artifact_root": str(self.root),
            "candidate_commit": self.candidate_commit,
            "checked": self.checked,
            "manifest_schema_version": manifest.get("schema_version"),
        }

    def validate_manifest(self) -> dict[str, Any]:
        manifest = self.require_json("manifest.json")
        if not isinstance(manifest, dict):
            self.error("manifest.json must contain a JSON object")
            return {}

        self.validate_known_fields("manifest.json", manifest, MANIFEST_FIELDS)
        self.validate_required_fields(
            "manifest.json", manifest, REQUIRED_MANIFEST_FIELDS
        )

        schema_version = self.json_integer_value(manifest.get("schema_version"))
        if schema_version != 1:
            self.error("manifest.json schema_version must be 1")
        else:
            manifest["schema_version"] = schema_version

        issues = manifest.get("issues")
        if not isinstance(issues, list):
            self.error("manifest.json issues must include 1373 and 1477")
        else:
            issue_numbers = [self.json_integer_value(issue) for issue in issues]
            if any(issue is None for issue in issue_numbers):
                self.error("manifest.json issues must be integer issue numbers")
            elif len(set(issue_numbers)) != len(issue_numbers):
                self.error("manifest.json issues must not contain duplicates")
            elif not {1373, 1477}.issubset(set(issue_numbers)):
                self.error("manifest.json issues must include 1373 and 1477")
            else:
                manifest["issues"] = issue_numbers

        raw_commit = manifest.get("candidate_commit")
        if not isinstance(raw_commit, str) or not FULL_SHA_RE.match(raw_commit):
            self.error("manifest.json candidate_commit must be a full 40-character SHA")
        else:
            self.candidate_commit = raw_commit.lower()
            if self.expected_commit and self.expected_commit != self.candidate_commit:
                self.error(
                    "candidate commit mismatch: "
                    f"expected {self.expected_commit}, manifest has {self.candidate_commit}"
                )
            short = self.candidate_commit[:12]
            if short not in self.root.name:
                self.error(
                    "artifact root name must include the first 12 characters of "
                    f"candidate_commit ({short})"
                )

        if "candidate_branch" in manifest:
            self.validate_non_empty_string(
                "manifest.json candidate_branch", manifest.get("candidate_branch")
            )
        if "artifact_created_at" in manifest:
            self.validate_date_time_string(
                "manifest.json artifact_created_at", manifest.get("artifact_created_at")
            )
        if "notes" in manifest and not isinstance(manifest.get("notes"), str):
            self.error("manifest.json notes must be a string")

        cluster = manifest.get("cluster")
        if not isinstance(cluster, dict):
            self.error("manifest.json cluster must be an object")
        else:
            self.validate_known_fields("manifest.json cluster", cluster, CLUSTER_FIELDS)
            self.validate_required_fields(
                "manifest.json cluster", cluster, REQUIRED_CLUSTER_FIELDS
            )
            self.validate_non_empty_string(
                "manifest.json cluster.name", cluster.get("name")
            )
            if cluster.get("env_file") != "test/incus/loss-userspace-cluster.env":
                self.error(
                    "manifest.json cluster.env_file must be "
                    "test/incus/loss-userspace-cluster.env"
                )
            config_files = cluster.get("config_files")
            if not isinstance(config_files, list):
                self.error("manifest.json cluster.config_files must be a list")
            elif len(config_files) == 0:
                self.error("manifest.json cluster.config_files must not be empty")
            else:
                self.validate_unique_list(
                    "manifest.json cluster.config_files", config_files
                )
                for item in config_files:
                    if not isinstance(item, str) or not item:
                        self.error(
                            "manifest.json cluster.config_files entries must be non-empty strings"
                        )
                        break
                if "docs/ha-cluster-userspace.conf" not in config_files:
                    self.error(
                        "manifest.json cluster.config_files must include "
                        "docs/ha-cluster-userspace.conf"
                    )

        binaries = manifest.get("binaries")
        if not isinstance(binaries, list) or not binaries:
            self.error("manifest.json binaries must be a non-empty list")
        else:
            for idx, binary in enumerate(binaries):
                if not isinstance(binary, dict):
                    self.error(f"manifest.json binaries[{idx}] must be an object")
                    continue
                self.validate_known_fields(
                    f"manifest.json binaries[{idx}]", binary, BINARY_FIELDS
                )
                self.validate_required_fields(
                    f"manifest.json binaries[{idx}]",
                    binary,
                    REQUIRED_BINARY_FIELDS,
                )
                for field in ("host", "path"):
                    self.validate_non_empty_string(
                        f"manifest.json binaries[{idx}].{field}", binary.get(field)
                    )
                digest = binary.get("sha256")
                if not isinstance(digest, str) or not SHA256_RE.match(digest):
                    self.error(
                        f"manifest.json binaries[{idx}].sha256 must be a 64-character hex digest"
                    )
                if "version" in binary and not isinstance(binary.get("version"), str):
                    self.error(f"manifest.json binaries[{idx}].version must be a string")

        commands = manifest.get("commands")
        if not isinstance(commands, list) or not commands:
            self.error("manifest.json commands must be a non-empty list")
        else:
            gates: set[str] = set()
            for idx, command in enumerate(commands):
                if not isinstance(command, dict):
                    self.error(f"manifest.json commands[{idx}] must be an object")
                    continue
                self.validate_known_fields(
                    f"manifest.json commands[{idx}]", command, COMMAND_FIELDS
                )
                self.validate_required_fields(
                    f"manifest.json commands[{idx}]",
                    command,
                    REQUIRED_COMMAND_FIELDS,
                )
                gate = command.get("gate")
                if isinstance(gate, str) and gate:
                    if gate in REQUIRED_COMMAND_GATES:
                        gates.add(gate)
                    else:
                        self.error(f"manifest.json commands[{idx}].gate is unknown: {gate}")
                else:
                    self.error(f"manifest.json commands[{idx}].gate is required")
                if not isinstance(command.get("command"), str) or not command["command"]:
                    self.error(f"manifest.json commands[{idx}].command is required")
                exit_status = self.json_integer_value(command.get("exit_status"))
                if exit_status is None:
                    self.error(
                        f"manifest.json commands[{idx}].exit_status must be recorded as an integer"
                    )
                else:
                    command["exit_status"] = exit_status
                for field in ("started_at", "finished_at"):
                    if field in command:
                        self.validate_date_time_string(
                            f"manifest.json commands[{idx}].{field}",
                            command.get(field),
                        )
                if "artifacts" in command:
                    artifacts = command.get("artifacts")
                    if not isinstance(artifacts, list):
                        self.error(
                            f"manifest.json commands[{idx}].artifacts must be a list"
                        )
                    else:
                        self.validate_unique_list(
                            f"manifest.json commands[{idx}].artifacts", artifacts
                        )
                        for artifact in artifacts:
                            if not isinstance(artifact, str) or not artifact:
                                self.error(
                                    f"manifest.json commands[{idx}].artifacts entries must be non-empty strings"
                                )
                                break
            missing = sorted(REQUIRED_COMMAND_GATES - gates)
            if missing:
                self.error("manifest.json commands missing gates: " + ", ".join(missing))

        return manifest

    def validate_known_fields(
        self, context: str, value: dict[str, Any], allowed: set[str]
    ) -> None:
        unknown = sorted(set(value) - allowed)
        if unknown:
            self.error(f"{context} has unknown fields: {', '.join(unknown)}")

    def validate_required_fields(
        self, context: str, value: dict[str, Any], required: set[str]
    ) -> None:
        missing = sorted(required - set(value))
        if missing:
            self.error(f"{context} missing required fields: {', '.join(missing)}")

    def validate_non_empty_string(self, context: str, value: Any) -> None:
        if not isinstance(value, str) or not value:
            self.error(f"{context} must be a non-empty string")

    def json_integer_value(self, value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, Decimal):
            try:
                integral = value.to_integral_value()
            except InvalidOperation:
                return None
            if value == integral:
                try:
                    return int(value)
                except (InvalidOperation, OverflowError, ValueError):
                    return None
        return None

    def validate_unique_list(self, context: str, value: list[Any]) -> None:
        try:
            unique_count = len(set(value))
        except TypeError:
            self.error(f"{context} entries must be scalar values")
            return
        if unique_count != len(value):
            self.error(f"{context} must not contain duplicates")

    def validate_date_time_string(self, context: str, value: Any) -> None:
        if not isinstance(value, str) or not value:
            self.error(f"{context} must be a date-time string")
            return
        match = DATE_TIME_RE.match(value)
        if not match:
            self.error(f"{context} must be an RFC3339 date-time string")
            return
        second = int(match.group("second"))
        if second > 60:
            self.error(f"{context} must be an RFC3339 date-time string")
            return
        normalized = value
        normalized = normalized[:10] + "T" + normalized[11:]
        if normalized.endswith(("Z", "z")):
            normalized = normalized[:-1] + "+00:00"
        if second == 60:
            start, end = match.span("second")
            normalized = normalized[:start] + "59" + normalized[end:]
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            self.error(f"{context} must be an RFC3339 date-time string")
            return
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            self.error(f"{context} must include a timezone offset")
            return
        if second == 60 and not self.is_practical_leap_second(parsed):
            self.error(f"{context} must be an RFC3339 date-time string")

    def is_practical_leap_second(self, parsed: datetime) -> bool:
        utc = parsed.astimezone(timezone.utc)
        return (
            utc.hour == 23
            and utc.minute == 59
            and utc.second == 59
            and (
                (utc.month == 6 and utc.day == 30)
                or (utc.month == 12 and utc.day == 31)
            )
        )

    def validate_metadata(self) -> None:
        self.require_file("metadata/git-rev-parse-head.txt")
        self.require_file("metadata/git-status-short.txt", non_empty=False)
        self.require_file("metadata/cluster-env.txt")
        self.require_file("metadata/ha-cluster-userspace.conf")
        self.require_file("metadata/binary-sha256sums.txt")
        self.require_file("metadata/cluster-userspace-host-ipv6-route.txt")

        head_path = self.root / "metadata/git-rev-parse-head.txt"
        if self.candidate_commit and head_path.exists():
            head = head_path.read_text(encoding="utf-8", errors="replace").strip()
            if head != self.candidate_commit:
                self.error(
                    "metadata/git-rev-parse-head.txt must match manifest candidate_commit"
                )

    def validate_summary(
        self, rel: str, headings: tuple[str, ...], required_text: str | None = None
    ) -> None:
        path = self.require_file(rel)
        if not path.exists():
            return
        text = path.read_text(encoding="utf-8", errors="replace")
        if required_text and required_text not in text:
            self.error(f"{rel} must contain the full candidate commit {required_text}")
        for heading in headings:
            pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.MULTILINE)
            if not pattern.search(text):
                self.error(f"{rel} missing required section: ## {heading}")

    def validate_cos_off(self) -> None:
        for label in COS_OFF_CASES:
            self.require_json(f"cos-off/{label}.json")
            self.require_file(f"cos-off/{label}.stderr", non_empty=False)
            self.require_json(f"cos-off/{label}.metrics.json")

    def validate_screen_flood(self) -> None:
        for probe in SCREEN_PROBES:
            self.require_file(f"screen-flood/{probe}-before.txt")
            self.require_file(f"screen-flood/{probe}-after.txt")
            self.require_file(f"screen-flood/{probe}-configure.stdout")
            self.require_file(f"screen-flood/{probe}-configure.stderr", non_empty=False)
        self.require_file("screen-flood/restore.stdout")
        self.require_file("screen-flood/restore.stderr", non_empty=False)

    def validate_syn_cookie(self) -> None:
        self.validate_summary("syn-cookie/summary.md", SYN_COOKIE_HEADINGS)
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
            self.require_file(rel, non_empty=not rel.endswith(".stderr"))

    def validate_cos_sweeps(self) -> None:
        for sweep_dir in COS_SWEEP_DIRS:
            self.require_file(f"{sweep_dir}/summary.tsv")
            self.require_file(f"{sweep_dir}/summary.md")
            self.require_json(f"{sweep_dir}/dataplane/status-before.json")
            self.require_json(f"{sweep_dir}/dataplane/status-after.json")
            self.require_json(f"{sweep_dir}/dataplane/counter-delta.json")
            self.require_file(f"{sweep_dir}/dataplane/journal-since.txt")
            self.require_file(f"{sweep_dir}/dataplane-summary.tsv")
            self.require_file(f"{sweep_dir}/equal-flow-summary.tsv")
            for class_name in COS_CLASSES:
                base = f"{sweep_dir}/{class_name}"
                self.require_file(f"{base}/wrapper.stdout")
                self.require_file(f"{base}/wrapper.stderr", non_empty=False)
                self.require_json(f"{base}/samples/summary.json")
                self.require_json(f"{base}/equal-flow/summary.json")
                self.require_json(f"{base}/dataplane/status-before.json")
                self.require_json(f"{base}/dataplane/status-after.json")

    def validate_echo(self) -> None:
        self.require_file("echo-6200-6211/summary.tsv")
        self.require_file("echo-6200-6211/latency-summary.tsv")
        for port in ECHO_PORTS:
            self.require_file(f"echo-6200-6211/{port}.stdout")
            self.require_file(f"echo-6200-6211/{port}.stderr", non_empty=False)

    def validate_ha(self) -> None:
        self.require_file("userspace-phase-cycle.log")
        self.require_file("userspace-ha-failover.log")
        self.require_file("ha-test-failover.log")
        self.require_file("ha-test-ha-crash.log")
        self.require_file("ha-test-restart-connectivity.log")
        self.require_file("userspace-ha-failover/iperf3.log")
        self.require_json("userspace-ha-failover/iperf3.metrics.json")
        self.require_file("userspace-ha-failover/before-source-status.txt")
        self.require_file("userspace-ha-failover/before-target-status.txt")
        self.require_glob(
            "userspace-ha-failover/cycle*-failover-*-dp-stats.txt",
            "HA failover dataplane stats",
        )
        self.require_glob(
            "userspace-ha-failover/cycle*-failback-*-dp-stats.txt",
            "HA failback dataplane stats",
        )
        self.require_glob(
            "userspace-ha-failover/cycle*-failover-*-dp-interfaces.txt",
            "HA failover dataplane interface stats",
        )
        self.require_glob(
            "userspace-ha-failover/cycle*-failback-*-dp-interfaces.txt",
            "HA failback dataplane interface stats",
        )

    def validate_fallback_exclusion(self) -> None:
        json_artifacts = {
            "fallback-exclusion/fw0-userspace-dp.json",
            "fallback-exclusion/fw1-userspace-dp.json",
        }
        for rel in (
            "fallback-exclusion/fw0-ip-link.txt",
            "fallback-exclusion/fw1-ip-link.txt",
            "fallback-exclusion/fw0-dp-stats.txt",
            "fallback-exclusion/fw1-dp-stats.txt",
            "fallback-exclusion/fw0-userspace-dp.json",
            "fallback-exclusion/fw1-userspace-dp.json",
            "fallback-exclusion/legacy-map-counter-audit.txt",
        ):
            if rel in json_artifacts:
                self.require_json(rel)
            else:
                self.require_file(rel)

    def require_file(self, rel: str, *, non_empty: bool = True) -> Path:
        self.checked += 1
        path = self.root / rel
        if not path.exists():
            self.error(f"missing required artifact: {rel}")
            return path
        if not path.is_file():
            self.error(f"required artifact is not a file: {rel}")
            return path
        if non_empty and path.stat().st_size == 0:
            self.error(f"required artifact is empty: {rel}")
        return path

    def require_json(self, rel: str) -> Any:
        path = self.require_file(rel)
        if not path.exists() or not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"), parse_float=Decimal)
        except UnicodeDecodeError as exc:
            self.error(f"invalid UTF-8 JSON artifact {rel}: {exc}")
            return None
        except json.JSONDecodeError as exc:
            self.error(f"invalid JSON artifact {rel}: {exc}")
            return None
        except (InvalidOperation, ValueError) as exc:
            self.error(f"invalid JSON artifact {rel}: {exc}")
            return None

    def require_glob(self, pattern: str, description: str) -> None:
        self.checked += 1
        matches = sorted(self.root.glob(pattern))
        if not matches:
            self.error(f"missing required artifact pattern for {description}: {pattern}")
            return
        if not any(path.is_file() and path.stat().st_size > 0 for path in matches):
            self.error(f"artifact pattern has no non-empty files for {description}: {pattern}")

    def error(self, message: str) -> None:
        self.errors.append(message)


def validate_artifact_root(
    root: Path | str, *, candidate_commit: str | None = None
) -> dict[str, Any]:
    checker = ArtifactChecker(Path(root), candidate_commit=candidate_commit)
    return checker.validate()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the #1477 final userspace-only artifact directory shape."
    )
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument(
        "--candidate-commit",
        help="Full 40-character source-removal commit SHA expected in the artifact set.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable summary.")
    args = parser.parse_args(argv)

    try:
        result = validate_artifact_root(
            args.artifact_root, candidate_commit=args.candidate_commit
        )
    except ValidationFailure as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "STRUCTURE_OK "
            f"candidate_commit={result['candidate_commit']} "
            f"checked={result['checked']} "
            f"artifact_root={_display(Path(result['artifact_root']))}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
