#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"

DURATION=12
PARALLEL=4
REPEATS=3
SETTLE_SECONDS=3
PERF_RUN=1
FAMILY="both"
OUTPUT_DIR="/tmp/userspace-transit-perf-gate"
IPERF_METRICS="${PROJECT_ROOT}/scripts/iperf-json-metrics.py"

usage() {
    cat <<'USAGE'
Usage: userspace-transit-perf-gate.sh [options]

Options:
  --env PATH          Cluster env file
  --duration SEC      iperf3 duration per run (default: 12)
  --parallel N        iperf3 parallel streams (default: 4)
  --repeats N         repeated runs per family (default: 3)
  --settle SEC        seconds to wait between runs (default: 3)
  --perf-run N        which run to capture perf on (default: 1, 0 disables)
  --family NAME       ipv4, ipv6, or both (default: both)
  --output-dir PATH   artifact directory
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env)
            ENV_FILE="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --parallel)
            PARALLEL="$2"
            shift 2
            ;;
        --repeats)
            REPEATS="$2"
            shift 2
            ;;
        --settle)
            SETTLE_SECONDS="$2"
            shift 2
            ;;
        --perf-run)
            PERF_RUN="$2"
            shift 2
            ;;
        --family)
            FAMILY="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "missing env file: ${ENV_FILE}" >&2
    exit 1
fi

case "${FAMILY}" in
    ipv4|ipv6|both) ;;
    *)
        echo "invalid family: ${FAMILY}" >&2
        exit 2
        ;;
esac

# shellcheck disable=SC1090
source "${ENV_FILE}"

FW0="${INCUS_REMOTE}:${VM0}"
FW1="${INCUS_REMOTE}:${VM1}"
HOST="${INCUS_REMOTE}:${LAN_HOST}"
V4_TARGET="172.16.80.200"
V6_TARGET="2001:559:8585:80::200"

mkdir -p "${OUTPUT_DIR}"

cleanup_output() {
    rm -f "${OUTPUT_DIR}"/summary.md \
        "${OUTPUT_DIR}"/fw0.stats.txt \
        "${OUTPUT_DIR}"/fw1.stats.txt \
        "${OUTPUT_DIR}"/ipv4.reachability.txt \
        "${OUTPUT_DIR}"/ipv6.reachability.txt \
        "${OUTPUT_DIR}"/ipv4.run* \
        "${OUTPUT_DIR}"/ipv6.run*
}

run_incus() {
    local vm="$1"
    local cmd="$2"
    local incus_cmd
    printf -v incus_cmd 'incus exec %q -- bash -lc %q' "${vm}" "${cmd}"
    sg incus-admin -c "${incus_cmd}"
}

wait_cli() {
    local vm="$1"
    for _ in $(seq 1 60); do
        if run_incus "${vm}" "cli -c 'show chassis cluster data-plane statistics' >/dev/null 2>&1"; then
            return 0
        fi
        sleep 1
    done
    echo "cli not ready on ${vm}" >&2
    return 1
}

stats_file() {
    local vm="$1"
    local out="$2"
    run_incus "${vm}" "cli -c 'show chassis cluster data-plane statistics'" >"${out}"
}

parse_helper_stats() {
    local stats_txt="$1"
    python3 - "${stats_txt}" <<'PY'
import json
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
patterns = {
    "neighbor_misses": r"Neighbor misses:\s+(\d+)",
    "session_misses": r"Session misses:\s+(\d+)",
    "policy_denied_packets": r"Policy denied packets:\s+(\d+)",
    "tx_errors": r"TX errors:\s+(\d+)",
    "tx_packets": r"TX packets:\s+(\d+)",
    "direct_tx_packets": r"Direct TX packets:\s+(\d+)",
    "copy_tx_packets": r"Copy-path TX packets:\s+(\d+)",
    "in_place_tx_packets": r"In-place TX packets:\s+(\d+)",
}
stats = {}
for key, pattern in patterns.items():
    match = re.search(pattern, text)
    stats[key] = int(match.group(1)) if match else 0
match = re.search(r"Slow path injected:\s+(\d+)\s+pkts\s+/\s+(\d+)\s+bytes", text)
stats["slow_path_injected_packets"] = int(match.group(1)) if match else 0
stats["slow_path_injected_bytes"] = int(match.group(2)) if match else 0
json.dump(stats, sys.stdout, sort_keys=True)
sys.stdout.write("\n")
PY
}

compute_helper_delta() {
    local before_json="$1"
    local after_json="$2"
    python3 - "${before_json}" "${after_json}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    before = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    after = json.load(fh)

delta = {}
for key in sorted(set(before) | set(after)):
    delta[key] = int(after.get(key, 0)) - int(before.get(key, 0))

json.dump(delta, sys.stdout, sort_keys=True)
sys.stdout.write("\n")
PY
}

merge_run_metrics() {
    local metrics_json="$1"
    local helper_delta_json="$2"
    local active_fw="$3"
    local run_idx="$4"
    python3 - "${metrics_json}" "${helper_delta_json}" "${active_fw}" "${run_idx}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    metrics = json.load(fh)
with open(sys.argv[2], "r", encoding="utf-8") as fh:
    helper_delta = json.load(fh)

metrics["active_fw"] = sys.argv[3]
metrics["run_index"] = int(sys.argv[4])
metrics["helper_delta"] = helper_delta

json.dump(metrics, sys.stdout, sort_keys=True)
sys.stdout.write("\n")
PY
}

detect_active_fw() {
    local fw0_stats fw1_stats
    fw0_stats="${OUTPUT_DIR}/fw0.stats.txt"
    fw1_stats="${OUTPUT_DIR}/fw1.stats.txt"
    stats_file "${FW0}" "${fw0_stats}"
    stats_file "${FW1}" "${fw1_stats}"

    if grep -q 'Forwarding armed:[[:space:]]*true' "${fw0_stats}" && grep -Eq 'rg(1|2) active=true' "${fw0_stats}"; then
        echo "${FW0}"
    elif grep -q 'Forwarding armed:[[:space:]]*true' "${fw1_stats}" && grep -Eq 'rg(1|2) active=true' "${fw1_stats}"; then
        echo "${FW1}"
    elif grep -Eq 'rg(1|2) active=true' "${fw0_stats}"; then
        echo "${FW0}"
    else
        echo "${FW1}"
    fi
}

ensure_ipv6_route() {
    run_incus "${HOST}" "sysctl -q net.ipv6.conf.eth0.accept_ra=2; ip -6 route | grep -q '^default ' || (command -v rdisc6 >/dev/null 2>&1 && rdisc6 -1 eth0 >/dev/null 2>&1 || true)"
}

reachability_check() {
    local family="$1"
    local target="$2"
    local out="${OUTPUT_DIR}/${family}.reachability.txt"
    if [[ "${family}" == "ipv4" ]]; then
        run_incus "${HOST}" "ping -c 2 -W 1 ${target}" >"${out}" 2>&1 || true
    else
        run_incus "${HOST}" "ping -6 -c 2 -W 1 ${target}" >"${out}" 2>&1 || true
    fi
}

emit_metrics() {
    local json_path="$1"
    python3 "${IPERF_METRICS}" "${json_path}"
}

run_case() {
    local family="$1"
    local target="$2"
    local run_idx="$3"
    local fw iperf_json iperf_err raw_metrics_json metrics_json perf_data perf_log perf_report
    local before_stats_txt after_stats_txt before_stats_json after_stats_json helper_delta_json

    fw="$(detect_active_fw)"
    sleep "${SETTLE_SECONDS}"

    iperf_json="${OUTPUT_DIR}/${family}.run${run_idx}.json"
    iperf_err="${OUTPUT_DIR}/${family}.run${run_idx}.err"
    raw_metrics_json="${OUTPUT_DIR}/${family}.run${run_idx}.iperf-metrics.json"
    metrics_json="${OUTPUT_DIR}/${family}.run${run_idx}.metrics.json"
    before_stats_txt="${OUTPUT_DIR}/${family}.run${run_idx}.before.stats.txt"
    after_stats_txt="${OUTPUT_DIR}/${family}.run${run_idx}.after.stats.txt"
    before_stats_json="${OUTPUT_DIR}/${family}.run${run_idx}.before.stats.json"
    after_stats_json="${OUTPUT_DIR}/${family}.run${run_idx}.after.stats.json"
    helper_delta_json="${OUTPUT_DIR}/${family}.run${run_idx}.helper-delta.json"
    perf_data="/tmp/${family}-transit-gate-run${run_idx}.data"
    perf_log="${OUTPUT_DIR}/${family}.run${run_idx}.perf.log"
    perf_report="${OUTPUT_DIR}/${family}.run${run_idx}.perf.txt"

    stats_file "${fw}" "${before_stats_txt}"
    parse_helper_stats "${before_stats_txt}" >"${before_stats_json}"

    if [[ "${PERF_RUN}" -gt 0 && "${run_idx}" -eq "${PERF_RUN}" ]]; then
        run_incus "${fw}" "rm -f ${perf_data}"
        sg incus-admin -c "incus exec ${fw} -- sh -lc 'timeout $((DURATION + 4)) perf record -F 997 -a -g -o ${perf_data} -- sleep $((DURATION + 4))'" >"${perf_log}" 2>&1 &
        local perf_pid=$!
        sleep 1
        if [[ "${family}" == "ipv4" ]]; then
            run_incus "${HOST}" "timeout $((DURATION + 8)) iperf3 -J -c ${target} -P ${PARALLEL} -t ${DURATION}" >"${iperf_json}" 2>"${iperf_err}" || true
        else
            run_incus "${HOST}" "timeout $((DURATION + 8)) iperf3 -J -6 -c ${target} -P ${PARALLEL} -t ${DURATION}" >"${iperf_json}" 2>"${iperf_err}" || true
        fi
        wait "${perf_pid}" || true
        run_incus "${fw}" "perf report --stdio --no-children -i ${perf_data} --sort dso,symbol | sed -n '1,160p'" >"${perf_report}" 2>>"${perf_log}" || true
    else
        if [[ "${family}" == "ipv4" ]]; then
            run_incus "${HOST}" "timeout $((DURATION + 8)) iperf3 -J -c ${target} -P ${PARALLEL} -t ${DURATION}" >"${iperf_json}" 2>"${iperf_err}" || true
        else
            run_incus "${HOST}" "timeout $((DURATION + 8)) iperf3 -J -6 -c ${target} -P ${PARALLEL} -t ${DURATION}" >"${iperf_json}" 2>"${iperf_err}" || true
        fi
    fi

    stats_file "${fw}" "${after_stats_txt}"
    parse_helper_stats "${after_stats_txt}" >"${after_stats_json}"
    compute_helper_delta "${before_stats_json}" "${after_stats_json}" >"${helper_delta_json}"
    emit_metrics "${iperf_json}" >"${raw_metrics_json}"
    merge_run_metrics "${raw_metrics_json}" "${helper_delta_json}" "${fw}" "${run_idx}" >"${metrics_json}"
    printf '%s run %s on %s: %s\n' "${family}" "${run_idx}" "${fw}" "$(cat "${metrics_json}")"
}

aggregate_family() {
    local family="$1"
    python3 - "${OUTPUT_DIR}" "${family}" <<'PY'
import json
import pathlib
import statistics
import sys

outdir = pathlib.Path(sys.argv[1])
family = sys.argv[2]
items = []
for path in sorted(outdir.glob(f"{family}.run*.metrics.json")):
    with path.open("r", encoding="utf-8") as fh:
        items.append(json.load(fh))

valid = [item for item in items if item.get("ok")]
helper_keys = [
    "neighbor_misses",
    "session_misses",
    "policy_denied_packets",
    "tx_errors",
    "direct_tx_packets",
    "copy_tx_packets",
    "in_place_tx_packets",
    "slow_path_injected_packets",
    "slow_path_injected_bytes",
]
summary = {
    "family": family,
    "runs": len(items),
    "valid_runs": len(valid),
    "avg_gbps_values": [item.get("avg_gbps", 0.0) for item in valid],
    "tail_ratio_values": [item.get("tail_peak_ratio", 0.0) for item in valid],
    "retransmits": [item.get("retransmits", 0) for item in valid],
    "median_gbps": 0.0,
    "mean_gbps": 0.0,
    "min_gbps": 0.0,
    "max_gbps": 0.0,
    "median_tail_ratio": 0.0,
    "min_tail_ratio": 0.0,
    "median_retransmits": 0,
    "max_retransmits": 0,
    "consistent": False,
    "run_details": [],
    "helper_delta_summary": {},
}

if valid:
    for item in valid:
        helper_delta = item.get("helper_delta") or {}
        summary["run_details"].append(
            {
                "run_index": int(item.get("run_index") or 0),
                "active_fw": item.get("active_fw", ""),
                "avg_gbps": float(item.get("avg_gbps") or 0.0),
                "tail_peak_ratio": float(item.get("tail_peak_ratio") or 0.0),
                "retransmits": int(item.get("retransmits") or 0),
                "helper_delta": {key: int(helper_delta.get(key, 0)) for key in helper_keys},
            }
        )

    vals = summary["avg_gbps_values"]
    tail = summary["tail_ratio_values"]
    retr = summary["retransmits"]
    summary["median_gbps"] = statistics.median(vals)
    summary["mean_gbps"] = statistics.mean(vals)
    summary["min_gbps"] = min(vals)
    summary["max_gbps"] = max(vals)
    summary["median_tail_ratio"] = statistics.median(tail)
    summary["min_tail_ratio"] = min(tail)
    summary["median_retransmits"] = int(statistics.median(retr))
    summary["max_retransmits"] = max(retr)
    if summary["median_gbps"] > 0:
        summary["consistent"] = (summary["min_gbps"] / summary["median_gbps"]) >= 0.90

    for key in helper_keys:
        values = [int((item.get("helper_delta") or {}).get(key, 0)) for item in valid]
        summary["helper_delta_summary"][key] = {
            "median": int(statistics.median(values)),
            "max": max(values),
            "min": min(values),
        }

json.dump(summary, sys.stdout, sort_keys=True)
sys.stdout.write("\n")
PY
}

write_summary() {
    local out="${OUTPUT_DIR}/summary.md"
    local ipv4_summary="" ipv6_summary=""
    [[ "${FAMILY}" == "ipv4" || "${FAMILY}" == "both" ]] && ipv4_summary="$(aggregate_family ipv4)"
    [[ "${FAMILY}" == "ipv6" || "${FAMILY}" == "both" ]] && ipv6_summary="$(aggregate_family ipv6)"

    {
        echo "# Userspace Transit Perf Gate"
        echo
        echo "- Host: \`${HOST}\`"
        echo "- Duration: \`${DURATION}s\`"
        echo "- Parallel streams: \`${PARALLEL}\`"
        echo "- Repeats: \`${REPEATS}\`"
        echo "- Settle between runs: \`${SETTLE_SECONDS}s\`"
        echo "- Perf capture run: \`${PERF_RUN}\`"
        echo
        if [[ -n "${ipv4_summary}" ]]; then
            echo "## IPv4"
            python3 - "${ipv4_summary}" <<'PY'
import json
import sys
s = json.loads(sys.argv[1])
hd = s.get("helper_delta_summary") or {}
print(f"- median/mean/min/max Gbps: `{s['median_gbps']:.3f} / {s['mean_gbps']:.3f} / {s['min_gbps']:.3f} / {s['max_gbps']:.3f}`")
print(f"- median/min tail ratio: `{s['median_tail_ratio']:.3f} / {s['min_tail_ratio']:.3f}`")
print(f"- median/max retransmits: `{s['median_retransmits']} / {s['max_retransmits']}`")
print(f"- consistency gate (min/median >= 0.90): `{'pass' if s['consistent'] else 'fail'}`")
print("- helper delta medians/max:")
print(f"  - session misses: `{hd.get('session_misses', {}).get('median', 0)} / {hd.get('session_misses', {}).get('max', 0)}`")
print(f"  - neighbor misses: `{hd.get('neighbor_misses', {}).get('median', 0)} / {hd.get('neighbor_misses', {}).get('max', 0)}`")
print(f"  - policy denies: `{hd.get('policy_denied_packets', {}).get('median', 0)} / {hd.get('policy_denied_packets', {}).get('max', 0)}`")
print(f"  - copy-path tx: `{hd.get('copy_tx_packets', {}).get('median', 0)} / {hd.get('copy_tx_packets', {}).get('max', 0)}`")
print(f"  - slow-path injected packets: `{hd.get('slow_path_injected_packets', {}).get('median', 0)} / {hd.get('slow_path_injected_packets', {}).get('max', 0)}`")
print("- runs:")
for item in s.get("run_details") or []:
    d = item.get("helper_delta") or {}
    print(
        f"  - run {item['run_index']} on `{item['active_fw']}`: "
        f"`{item['avg_gbps']:.3f} Gbps`, retransmits `{item['retransmits']}`, "
        f"tail `{item['tail_peak_ratio']:.3f}`, "
        f"session/neighbor/policy `{d.get('session_misses', 0)}/{d.get('neighbor_misses', 0)}/{d.get('policy_denied_packets', 0)}`, "
        f"direct/copy/in-place `{d.get('direct_tx_packets', 0)}/{d.get('copy_tx_packets', 0)}/{d.get('in_place_tx_packets', 0)}`, "
        f"slow-path `{d.get('slow_path_injected_packets', 0)}`"
    )
PY
            echo
        fi
        if [[ -n "${ipv6_summary}" ]]; then
            echo "## IPv6"
            python3 - "${ipv6_summary}" <<'PY'
import json
import sys
s = json.loads(sys.argv[1])
hd = s.get("helper_delta_summary") or {}
print(f"- median/mean/min/max Gbps: `{s['median_gbps']:.3f} / {s['mean_gbps']:.3f} / {s['min_gbps']:.3f} / {s['max_gbps']:.3f}`")
print(f"- median/min tail ratio: `{s['median_tail_ratio']:.3f} / {s['min_tail_ratio']:.3f}`")
print(f"- median/max retransmits: `{s['median_retransmits']} / {s['max_retransmits']}`")
print(f"- consistency gate (min/median >= 0.90): `{'pass' if s['consistent'] else 'fail'}`")
print("- helper delta medians/max:")
print(f"  - session misses: `{hd.get('session_misses', {}).get('median', 0)} / {hd.get('session_misses', {}).get('max', 0)}`")
print(f"  - neighbor misses: `{hd.get('neighbor_misses', {}).get('median', 0)} / {hd.get('neighbor_misses', {}).get('max', 0)}`")
print(f"  - policy denies: `{hd.get('policy_denied_packets', {}).get('median', 0)} / {hd.get('policy_denied_packets', {}).get('max', 0)}`")
print(f"  - copy-path tx: `{hd.get('copy_tx_packets', {}).get('median', 0)} / {hd.get('copy_tx_packets', {}).get('max', 0)}`")
print(f"  - slow-path injected packets: `{hd.get('slow_path_injected_packets', {}).get('median', 0)} / {hd.get('slow_path_injected_packets', {}).get('max', 0)}`")
print("- runs:")
for item in s.get("run_details") or []:
    d = item.get("helper_delta") or {}
    print(
        f"  - run {item['run_index']} on `{item['active_fw']}`: "
        f"`{item['avg_gbps']:.3f} Gbps`, retransmits `{item['retransmits']}`, "
        f"tail `{item['tail_peak_ratio']:.3f}`, "
        f"session/neighbor/policy `{d.get('session_misses', 0)}/{d.get('neighbor_misses', 0)}/{d.get('policy_denied_packets', 0)}`, "
        f"direct/copy/in-place `{d.get('direct_tx_packets', 0)}/{d.get('copy_tx_packets', 0)}/{d.get('in_place_tx_packets', 0)}`, "
        f"slow-path `{d.get('slow_path_injected_packets', 0)}`"
    )
PY
            echo
        fi
    } >"${out}"
}

wait_cli "${FW0}"
wait_cli "${FW1}"
ensure_ipv6_route
cleanup_output

if [[ "${FAMILY}" == "ipv4" || "${FAMILY}" == "both" ]]; then
    reachability_check ipv4 "${V4_TARGET}"
fi
if [[ "${FAMILY}" == "ipv6" || "${FAMILY}" == "both" ]]; then
    reachability_check ipv6 "${V6_TARGET}"
fi

if [[ "${FAMILY}" == "ipv4" || "${FAMILY}" == "both" ]]; then
    run_incus "${HOST}" "iperf3 -J -c ${V4_TARGET} -P ${PARALLEL} -t 3 >/dev/null" >/dev/null 2>&1 || true
    for run_idx in $(seq 1 "${REPEATS}"); do
        run_case ipv4 "${V4_TARGET}" "${run_idx}"
    done
fi

if [[ "${FAMILY}" == "ipv6" || "${FAMILY}" == "both" ]]; then
    run_incus "${HOST}" "iperf3 -J -6 -c ${V6_TARGET} -P ${PARALLEL} -t 3 >/dev/null" >/dev/null 2>&1 || true
    for run_idx in $(seq 1 "${REPEATS}"); do
        run_case ipv6 "${V6_TARGET}" "${run_idx}"
    done
fi

write_summary
cat "${OUTPUT_DIR}/summary.md"
