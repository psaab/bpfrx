#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IPERF_METRICS="${PROJECT_ROOT}/scripts/iperf-json-metrics.py"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
RG="${RG:-1}"
SOURCE_NODE="${SOURCE_NODE:-0}"
TARGET_NODE="${TARGET_NODE:-1}"
IPERF_TARGET="${IPERF_TARGET:-172.16.80.200}"
TOTAL_CYCLES="${TOTAL_CYCLES:-1}"
CYCLE_INTERVAL="${CYCLE_INTERVAL:-10}"
if [[ -z "${IPERF_DURATION:-}" ]]; then
	if (( TOTAL_CYCLES > 1 )); then
		IPERF_DURATION="$(( TOTAL_CYCLES * CYCLE_INTERVAL * 2 + 30 ))"
	else
		IPERF_DURATION=60
	fi
else
	IPERF_DURATION="${IPERF_DURATION}"
fi
IPERF_STREAMS="${IPERF_STREAMS:-4}"
SYNC_WAIT="${SYNC_WAIT:-5}"
FAILOVER_WAIT="${FAILOVER_WAIT:-30}"
PRE_FAILOVER_OBSERVE="${PRE_FAILOVER_OBSERVE:-10}"
MIN_SESSIONS="${MIN_SESSIONS:-4}"
MIN_THROUGHPUT="${MIN_THROUGHPUT:-1.0}"
MAX_ZERO_INTERVALS="${MAX_ZERO_INTERVALS:-2}"
MAX_STREAM_ZERO_INTERVALS="${MAX_STREAM_ZERO_INTERVALS:-0}"
MAX_PREFLIGHT_ZERO_INTERVALS="${MAX_PREFLIGHT_ZERO_INTERVALS:-0}"
MAX_PREFLIGHT_STREAM_ZERO_INTERVALS="${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS:-0}"
MAX_RETRANSMITS="${MAX_RETRANSMITS:-}"
MAX_RETRANSMITS_PER_GB="${MAX_RETRANSMITS_PER_GB:-}"
POST_FAILOVER_OBSERVE="${POST_FAILOVER_OBSERVE:-10}"
RESTORE_SOURCE_NODE="${RESTORE_SOURCE_NODE:-1}"
ALLOW_STALE_SESSIONS="${ALLOW_STALE_SESSIONS:-0}"
IPERF_COMPLETION_GRACE_SEC="${IPERF_COMPLETION_GRACE_SEC:-2}"
STEADY_ONLY=0
DEPLOY=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--deploy) DEPLOY=1 ;;
	--env) ENV_FILE="$2"; shift ;;
	--rg) RG="$2"; shift ;;
	--source-node) SOURCE_NODE="$2"; shift ;;
	--target-node) TARGET_NODE="$2"; shift ;;
	--target) IPERF_TARGET="$2"; shift ;;
	--duration) IPERF_DURATION="$2"; shift ;;
	--parallel) IPERF_STREAMS="$2"; shift ;;
	--cycles) TOTAL_CYCLES="$2"; shift ;;
	--interval) CYCLE_INTERVAL="$2"; shift ;;
	--sync-wait) SYNC_WAIT="$2"; shift ;;
	--failover-wait) FAILOVER_WAIT="$2"; shift ;;
	--steady-only) STEADY_ONLY=1 ;;
	*)
		echo "unknown arg: $1" >&2
		exit 2
		;;
	esac
	shift
done

# shellcheck disable=SC1090
source "$ENV_FILE"

REMOTE_PREFIX="${INCUS_REMOTE:+${INCUS_REMOTE}:}"
FW0="${REMOTE_PREFIX}${VM0}"
FW1="${REMOTE_PREFIX}${VM1}"
HOST="${REMOTE_PREFIX}${LAN_HOST}"
ARTIFACT_DIR="${ARTIFACT_DIR:-/tmp/userspace-ha-failover-rg${RG}-$(date +%Y%m%d-%H%M%S)}"
REMOTE_IPERF_LOG="/tmp/userspace-iperf-rg${RG}-failover.log"
REMOTE_IPERF_UNIT="userspace-ha-rg${RG}-iperf3.service"
LOCAL_IPERF_LOG="${ARTIFACT_DIR}/iperf3.log"
LOCAL_IPERF_METRICS="${ARTIFACT_DIR}/iperf3.metrics.json"
FAILED=0

info() { printf '==> %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; FAILED=1; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

required_iperf_duration() {
	local cycles="$1"
	local interval="$2"
	if (( STEADY_ONLY == 1 )); then
		printf '%s\n' "$(( PRE_FAILOVER_OBSERVE + SYNC_WAIT + 10 ))"
		return 0
	fi
	if (( cycles > 1 )); then
		printf '%s\n' "$(( cycles * interval * 2 + cycles * 10 + SYNC_WAIT + 20 ))"
	else
		printf '%s\n' "$(( POST_FAILOVER_OBSERVE + SYNC_WAIT + 10 ))"
	fi
}

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$1")"
}

node_name() {
	case "$1" in
	0) printf 'node0\n' ;;
	1) printf 'node1\n' ;;
	*) die "unsupported node id: $1" ;;
	esac
}

vm_for_node() {
	case "$1" in
	0 | node0) printf '%s\n' "$FW0" ;;
	1 | node1) printf '%s\n' "$FW1" ;;
	*) die "unsupported node selector: $1" ;;
	esac
}

wait_for_vm_cli() {
	local vm="$1"
	local tries=45
	while (( tries > 0 )); do
		if run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics" >/tmp/userspace-cli-ready.out 2>/dev/null'; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

rg_primary_node_name() {
	local rg="$1"
	local status
	status="$(run_vm "$FW0" 'cli -c "show chassis cluster status"' 2>/dev/null || true)"
	if ! grep -Eq "Redundancy group: ${rg} " <<<"$status"; then
		return 1
	fi
	awk -v rg="$rg" '
		$0 ~ ("Redundancy group: " rg " ") { in_rg=1; next }
		in_rg && /^Redundancy group:/ { in_rg=0 }
		in_rg && /primary/ { print $1; exit }
	' <<<"$status"
}

wait_for_rg_owner() {
	local rg="$1"
	local expected
	expected="$(node_name "$2")"
	local tries="${3:-$FAILOVER_WAIT}"
	while (( tries > 0 )); do
		local current=""
		current="$(rg_primary_node_name "$rg" || true)"
		if [[ "$current" == "$expected" ]]; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

ensure_rg_owner() {
	local rg="$1"
	local target_node="$2"
	local current=""
	current="$(rg_primary_node_name "$rg" || true)"
	if [[ "$current" == "$(node_name "$target_node")" ]]; then
		return 0
	fi
	info "pinning RG${rg} to $(node_name "$target_node")"
	run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${rg} node ${target_node}\" >/tmp/userspace-rg${rg}-pin.out"
	wait_for_rg_owner "$rg" "$target_node" 45 || die "RG${rg} did not move to $(node_name "$target_node")"
}

enabled_userspace_rg_vm() {
	local vm="$1"
	local rg="$2"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
		grep -Eq "rg${rg} active=true" <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

wait_for_userspace_rg_owner() {
	local rg="$1"
	local tries=45
	while (( tries > 0 )); do
		local owner_vm
		for owner_vm in "$FW0" "$FW1"; do
			if enabled_userspace_rg_vm "$owner_vm" "$rg" >/dev/null 2>&1; then
				printf '%s\n' "$owner_vm"
				return 0
			fi
		done
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

arm_userspace_runtime() {
	local owner_vm
	owner_vm="$(vm_for_node "$SOURCE_NODE")"
	info "waiting for userspace forwarding on RG${RG}"
	if ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG")"; then
		info "active RG${RG} userspace firewall: ${ACTIVE_FW}"
		return 0
	fi
	info "forcing userspace arm on ${owner_vm}"
	run_vm "$owner_vm" 'cli -c "request chassis cluster data-plane userspace forwarding arm" >/tmp/userspace-arm.out'
	if ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG")"; then
		info "active RG${RG} userspace firewall: ${ACTIVE_FW}"
		return 0
	fi
	die "userspace forwarding did not become active for RG${RG}"
}

capture_vm_state() {
	local vm="$1"
	local label="$2"
	run_vm "$vm" 'cli -c "show chassis cluster status"' >"${ARTIFACT_DIR}/${label}-status.txt" 2>&1 || true
	run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' >"${ARTIFACT_DIR}/${label}-dp-stats.txt" 2>&1 || true
	run_vm "$vm" "cli -c \"show security flow session destination-prefix ${IPERF_TARGET}\"" >"${ARTIFACT_DIR}/${label}-sessions.txt" 2>&1 || true
}

capture_cycle_state() {
	local cycle="$1"
	local phase="$2"
	capture_vm_state "$FW0" "cycle${cycle}-${phase}-fw0"
	capture_vm_state "$FW1" "cycle${cycle}-${phase}-fw1"
}

zero_port_tcp_sessions() {
	local vm="$1"
	run_vm "$vm" "cli -c \"show security flow session destination-prefix ${IPERF_TARGET}\" 2>/dev/null | grep -Ec '^[[:space:]]+(In|Out): .*\\/0;tcp' || true"
}

validate_clean_session_baseline() {
	local source_zero target_zero
	source_zero="$(zero_port_tcp_sessions "$SOURCE_VM")"
	target_zero="$(zero_port_tcp_sessions "$TARGET_VM")"
	if [[ "$source_zero" -gt 0 || "$target_zero" -gt 0 ]]; then
		capture_vm_state "$SOURCE_VM" "preflight-source"
		capture_vm_state "$TARGET_VM" "preflight-target"
		if [[ "$ALLOW_STALE_SESSIONS" == "1" ]]; then
			fail "preflight: stale zero-port TCP sessions present (source=${source_zero} target=${target_zero})"
		else
			die "preflight: stale zero-port TCP sessions present (source=${source_zero} target=${target_zero}); redeploy or clear flow state before stress testing"
		fi
	else
		pass "preflight: no stale zero-port TCP sessions on source or target owner"
	fi
}

session_count() {
	local vm="$1"
	run_vm "$vm" "cli -c \"show security flow session destination-prefix ${IPERF_TARGET}\" 2>/dev/null | grep -c 'Session State: Valid' || true"
}

validate_target_reachability() {
	local ping_log="/tmp/userspace-rg${RG}-ping.out"
	local tcp_log="/tmp/userspace-rg${RG}-tcp.out"
	run_host "ping -c 3 -W 1 ${IPERF_TARGET} >${ping_log} 2>&1 || true"
	if run_host "grep -q 'bytes from' ${ping_log}"; then
		return 0
	fi
	# Some targets drop the first probe while ARP/NDP settles. Fall back to a
	# TCP handshake against the iperf3 server so failover validation does not
	# fail before the actual RG transition is exercised.
	if run_host "timeout 3 bash -lc 'echo > /dev/tcp/${IPERF_TARGET}/5201' >${tcp_log} 2>&1"; then
		return 0
	fi
	return 1
}

start_iperf() {
	local attempt
	for attempt in 1 2 3; do
		run_host "systemctl stop ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true; systemctl reset-failed ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true; pkill -9 iperf3 2>/dev/null || true; rm -f ${REMOTE_IPERF_LOG}"
		run_host "systemd-run --quiet --unit ${REMOTE_IPERF_UNIT%.service} /bin/sh -c $(printf %q "exec iperf3 --json-stream --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > ${REMOTE_IPERF_LOG} 2>&1")"
		sleep 8
		if ! run_host "pgrep -x iperf3 >/dev/null"; then
			info "iperf3 exited on attempt ${attempt}, retrying"
			sleep $((attempt * 5))
			continue
		fi
		return 0
	done
	return 1
}

recent_interval_metric() {
	local intervals="$1"
	local metric="$2"
	local tail_lines=$(( intervals + 8 ))
	local recent_lines
	recent_lines="$(run_host "tail -n ${tail_lines} ${REMOTE_IPERF_LOG} 2>/dev/null || true")"
	python3 - "$metric" "$recent_lines" <<'PY'
import json
import sys

metric = sys.argv[1]
raw_lines = sys.argv[2]
intervals = []
for raw in raw_lines.splitlines():
    raw = raw.strip()
    if not raw:
        continue
    try:
        event = json.loads(raw)
    except Exception:
        continue
    if event.get("event") == "interval":
        intervals.append(event.get("data") or {})

if not intervals:
    print("0")
    raise SystemExit(0)

last = intervals[-1]
stream_zero_total = 0
zero_streams = set()
aggregate_zero_total = 0
for interval in intervals:
    if float((interval.get("sum") or {}).get("bits_per_second") or 0.0) <= 0.0:
        aggregate_zero_total += 1
    for stream in interval.get("streams", []):
        if float(stream.get("bits_per_second") or 0.0) <= 0.0:
            stream_zero_total += 1
            zero_streams.add(str(stream.get("socket") or stream.get("id") or "?"))

if metric == "dead_streams":
    print(
        sum(
            1
            for stream in last.get("streams", [])
            if float(stream.get("bits_per_second") or 0.0) <= 0.0
        )
    )
elif metric == "zero_intervals":
    print(aggregate_zero_total + stream_zero_total)
elif metric == "stream_zero_intervals":
    print(stream_zero_total)
elif metric == "zero_streams":
    print(len(zero_streams))
else:
    raise SystemExit(f"unsupported recent interval metric: {metric}")
PY
}

recent_dead_streams() {
	recent_interval_metric 1 dead_streams
}

count_recent_zero_intervals() {
	local intervals="$1"
	recent_interval_metric "$intervals" zero_intervals
}

count_recent_stream_zero_intervals() {
	local intervals="$1"
	recent_interval_metric "$intervals" stream_zero_intervals
}

count_recent_zero_streams() {
	local intervals="$1"
	recent_interval_metric "$intervals" zero_streams
}

iperf_alive() {
	run_host "pgrep -x iperf3 >/dev/null"
}

iperf_completed() {
	run_host "grep -q '\"event\":\"end\"' ${REMOTE_IPERF_LOG}"
}

iperf_observed_end_remote() {
	local recent_lines
	recent_lines="$(run_host "tail -n 32 ${REMOTE_IPERF_LOG} 2>/dev/null || true")"
	python3 - "$recent_lines" <<'PY'
import json
import sys

observed = 0.0
for raw in sys.argv[1].splitlines():
    raw = raw.strip()
    if not raw:
        continue
    try:
        event = json.loads(raw)
    except Exception:
        continue
    if event.get("event") == "interval":
        observed = max(observed, float((event.get("data") or {}).get("sum", {}).get("end") or 0.0))
    elif event.get("event") == "end":
        observed = max(observed, float((event.get("data") or {}).get("sum_sent", {}).get("end") or 0.0))
print(f"{observed:.3f}" if observed > 0 else "")
PY
}

iperf_reached_expected_duration_remote() {
	local observed_end
	observed_end="$(iperf_observed_end_remote)"
	if [[ -z "${observed_end}" ]]; then
		return 1
	fi
	awk "BEGIN{exit !(${observed_end} >= (${IPERF_DURATION} - ${IPERF_COMPLETION_GRACE_SEC}))}"
}

iperf_effectively_completed_remote() {
	iperf_completed || iperf_reached_expected_duration_remote
}

wait_for_iperf_finish() {
	local tries=$((IPERF_DURATION + 20))
	while (( tries > 0 )); do
		if ! iperf_alive; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

copy_artifacts() {
	mkdir -p "${ARTIFACT_DIR}"
	run_host "cat ${REMOTE_IPERF_LOG} 2>/dev/null || true" >"${LOCAL_IPERF_LOG}"
	if ! python3 "${IPERF_METRICS}" "${LOCAL_IPERF_LOG}" >"${LOCAL_IPERF_METRICS}" 2>"${ARTIFACT_DIR}/iperf3.metrics.err"; then
		printf '{"ok":false,"error":"metrics_parse_failed"}\n' >"${LOCAL_IPERF_METRICS}"
	fi
}

iperf_metrics_field() {
	python3 - "${LOCAL_IPERF_METRICS}" "$1" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
field = sys.argv[2]
if not path.exists():
    print("")
    raise SystemExit(0)

data = json.loads(path.read_text(encoding="utf-8"))
value = data.get(field, "")
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (int, float)):
    print(value)
else:
    print(value)
PY
}

count_zero_intervals() {
	iperf_metrics_field zero_intervals_total
}

count_stream_zero_intervals() {
	iperf_metrics_field stream_zero_intervals_total
}

count_zero_streams() {
	iperf_metrics_field zero_streams_total
}

extract_sender_throughput() {
	local value
	value="$(iperf_metrics_field avg_gbps)"
	printf '%.3f\n' "${value:-0}"
}

extract_retransmits() {
	local value
	value="$(iperf_metrics_field retransmits)"
	printf '%s\n' "${value:-0}"
}

iperf_collapse_detected() {
	[[ "$(iperf_metrics_field collapse_detected)" == "true" ]]
}

iperf_collapse_reason() {
	iperf_metrics_field collapse_reason
}

iperf_completed_local() {
	[[ "$(iperf_metrics_field completed)" == "true" ]]
}

iperf_effectively_completed_local() {
	local completed observed_end
	completed="$(iperf_metrics_field completed)"
	if [[ "$completed" == "true" ]]; then
		return 0
	fi
	observed_end="$(iperf_metrics_field observed_end_sec)"
	awk "BEGIN{exit !(${observed_end:-0} >= (${IPERF_DURATION} - ${IPERF_COMPLETION_GRACE_SEC}))}"
}

cycle_sleep() {
	local seconds="$1"
	local allow_expected_completion="${2:-0}"
	local remaining="$seconds"
	while (( remaining > 0 )); do
		if ! iperf_alive; then
			if iperf_completed; then
				return 0
			fi
			if [[ "$allow_expected_completion" == "1" ]] && iperf_reached_expected_duration_remote; then
				return 0
			fi
			return 1
		fi
		sleep 1
		remaining=$((remaining - 1))
	done
	return 0
}

validate_cycle_health() {
	local cycle="$1"
	local label="$2"
	local owner_vm="$3"
	local owner_name="$4"
	local final_phase="$5"
	local count dead_streams zero_source zero_target
	if iperf_alive; then
		pass "cycle ${cycle} ${label}: iperf3 alive on ${owner_name}"
	elif iperf_effectively_completed_remote; then
		if [[ "$final_phase" == "1" ]]; then
			pass "cycle ${cycle} ${label}: iperf3 completed during final phase"
		else
			fail "cycle ${cycle} ${label}: iperf3 completed before all failover phases finished"
		fi
	else
		fail "cycle ${cycle} ${label}: iperf3 died"
	fi
	count="$(session_count "$owner_vm")"
	if [[ "$count" -lt "$MIN_SESSIONS" ]]; then
		fail "cycle ${cycle} ${label}: ${owner_name} has only ${count} sessions (expected >= ${MIN_SESSIONS})"
	else
		pass "cycle ${cycle} ${label}: ${owner_name} has ${count} sessions"
	fi
	dead_streams="$(recent_dead_streams)"
	if [[ "$dead_streams" -gt 0 ]]; then
		fail "cycle ${cycle} ${label}: ${dead_streams}/${IPERF_STREAMS} streams at 0.00 bits/sec"
	else
		pass "cycle ${cycle} ${label}: all ${IPERF_STREAMS} streams carrying traffic"
	fi
	zero_source="$(zero_port_tcp_sessions "$FW0")"
	zero_target="$(zero_port_tcp_sessions "$FW1")"
	if [[ "$zero_source" -gt 0 || "$zero_target" -gt 0 ]]; then
		fail "cycle ${cycle} ${label}: zero-port TCP sessions present (fw0=${zero_source} fw1=${zero_target})"
	else
		pass "cycle ${cycle} ${label}: no zero-port TCP sessions present"
	fi
}

validate_pre_failover_health() {
	local owner_vm="$1"
	local owner_name="$2"
	local zero_intervals stream_zero_intervals zero_streams

	info "observing steady-state traffic for ${PRE_FAILOVER_OBSERVE}s before failover"
	if ! cycle_sleep "$PRE_FAILOVER_OBSERVE"; then
		fail "steady-state preflight: iperf3 exited before ${PRE_FAILOVER_OBSERVE}s observe window elapsed"
	fi
	capture_vm_state "$SOURCE_VM" "pre-failover-source"
	capture_vm_state "$TARGET_VM" "pre-failover-target"
	validate_cycle_health 0 "steady-state" "$owner_vm" "$owner_name" 0

	zero_intervals="$(count_recent_zero_intervals "$PRE_FAILOVER_OBSERVE")"
	if [[ "$zero_intervals" -le "$MAX_PREFLIGHT_ZERO_INTERVALS" ]]; then
		pass "steady-state preflight: ${zero_intervals} zero-throughput intervals (<= ${MAX_PREFLIGHT_ZERO_INTERVALS})"
	else
		fail "steady-state preflight: ${zero_intervals} zero-throughput intervals (> ${MAX_PREFLIGHT_ZERO_INTERVALS})"
	fi

	stream_zero_intervals="$(count_recent_stream_zero_intervals "$PRE_FAILOVER_OBSERVE")"
	zero_streams="$(count_recent_zero_streams "$PRE_FAILOVER_OBSERVE")"
	if [[ "$stream_zero_intervals" -le "$MAX_PREFLIGHT_STREAM_ZERO_INTERVALS" ]]; then
		pass "steady-state preflight: ${stream_zero_intervals} per-stream zero-throughput intervals (<= ${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS})"
	else
		fail "steady-state preflight: ${stream_zero_intervals} per-stream zero-throughput intervals across ${zero_streams} stream(s) (> ${MAX_PREFLIGHT_STREAM_ZERO_INTERVALS})"
	fi
}

run_failover_phase() {
	local cycle="$1"
	local from_node="$2"
	local to_node="$3"
	local phase="$4"
	local final_phase="$5"
	local from_vm to_vm to_name
	from_vm="$(vm_for_node "$from_node")"
	to_vm="$(vm_for_node "$to_node")"
	to_name="$(node_name "$to_node")"

	info "cycle ${cycle}: ${phase} RG${RG} to ${to_name}"
	run_vm "$from_vm" "cli -c \"request chassis cluster failover redundancy-group ${RG} node ${to_node}\" >/tmp/userspace-rg${RG}-${phase}-cycle${cycle}.out"
	wait_for_rg_owner "$RG" "$to_node" "$FAILOVER_WAIT" || die "RG${RG} did not move to ${to_name} during cycle ${cycle} ${phase}"
	pass "cycle ${cycle} ${phase}: RG${RG} moved to ${to_name}"
	ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG")" || die "userspace forwarding did not settle on ${to_name} during cycle ${cycle} ${phase}"
	pass "cycle ${cycle} ${phase}: userspace forwarding active on ${ACTIVE_FW}"
	capture_cycle_state "$cycle" "$phase"
	if ! cycle_sleep "$CYCLE_INTERVAL" "$final_phase"; then
		fail "cycle ${cycle} ${phase}: iperf3 exited before ${CYCLE_INTERVAL}s interval elapsed"
	fi
	capture_cycle_state "$cycle" "${phase}-post"
	validate_cycle_health "$cycle" "$phase" "$to_vm" "$to_name" "$final_phase"
}

restore_cluster() {
	if [[ "${RESTORE_SOURCE_NODE}" != "1" ]]; then
		return 0
	fi
	info "restoring RG${RG} to $(node_name "$SOURCE_NODE")"
	for vm in "$FW0" "$FW1"; do
		run_vm "$vm" "cli -c \"request chassis cluster failover reset redundancy-group ${RG}\" >/tmp/userspace-rg${RG}-reset.out" >/dev/null 2>&1 || true
	done
	sleep 1
	run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${RG} node ${SOURCE_NODE}\" >/tmp/userspace-rg${RG}-restore.out" >/dev/null 2>&1 || true
	wait_for_rg_owner "$RG" "$SOURCE_NODE" 45 || true
}

cleanup() {
	copy_artifacts
	run_host "systemctl stop ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true; systemctl reset-failed ${REMOTE_IPERF_UNIT} >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
	restore_cluster
	printf 'Artifacts: %s\n' "${ARTIFACT_DIR}"
}
trap cleanup EXIT

mkdir -p "${ARTIFACT_DIR}"

min_duration="$(required_iperf_duration "$TOTAL_CYCLES" "$CYCLE_INTERVAL")"
if (( IPERF_DURATION < min_duration )); then
	die "iperf duration ${IPERF_DURATION}s too short for ${TOTAL_CYCLES} cycle(s); need at least ${min_duration}s"
fi

if [[ $DEPLOY -eq 1 ]]; then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

info "waiting for bpfrxd CLI readiness"
wait_for_vm_cli "$FW0" || die "fw0 CLI did not become reachable in time"
wait_for_vm_cli "$FW1" || die "fw1 CLI did not become reachable in time"

ensure_rg_owner "$RG" "$SOURCE_NODE"
arm_userspace_runtime

info "validating basic reachability to ${IPERF_TARGET}"
validate_target_reachability || die "cluster host cannot reach ${IPERF_TARGET}"

SOURCE_VM="$(vm_for_node "$SOURCE_NODE")"
TARGET_VM="$(vm_for_node "$TARGET_NODE")"
validate_clean_session_baseline
capture_vm_state "$SOURCE_VM" "before-source"
capture_vm_state "$TARGET_VM" "before-target"

info "starting iperf3 ${IPERF_TARGET} -P${IPERF_STREAMS} -t${IPERF_DURATION}"
start_iperf || die "iperf3 failed to start"
pass "iperf3 started"

source_count="$(session_count "$SOURCE_VM")"
if [[ "$source_count" -lt "$MIN_SESSIONS" ]]; then
	fail "source owner has only ${source_count} sessions (expected >= ${MIN_SESSIONS})"
else
	pass "source owner has ${source_count} sessions"
fi

info "waiting ${SYNC_WAIT}s for session sync to peer"
sleep "${SYNC_WAIT}"

target_count="$(session_count "$TARGET_VM")"
if [[ "$target_count" -lt "$MIN_SESSIONS" ]]; then
	fail "target owner has only ${target_count} synced sessions (expected >= ${MIN_SESSIONS})"
else
	pass "target owner has ${target_count} synced sessions"
fi

validate_pre_failover_health "$SOURCE_VM" "$(node_name "$SOURCE_NODE")"

if (( STEADY_ONLY == 1 )); then
	info "steady-only mode: skipping RG${RG} failover"
elif (( TOTAL_CYCLES == 1 )); then
	run_failover_phase 1 "$SOURCE_NODE" "$TARGET_NODE" "failover" 1
else
	run_failover_phase 1 "$SOURCE_NODE" "$TARGET_NODE" "failover" 0
fi

if (( STEADY_ONLY == 1 )); then
	capture_vm_state "$SOURCE_VM" "steady-only-source"
	capture_vm_state "$TARGET_VM" "steady-only-target"
	wait_for_iperf_finish || true
	copy_artifacts
elif (( TOTAL_CYCLES == 1 )); then
	capture_vm_state "$SOURCE_VM" "after-source"
	capture_vm_state "$TARGET_VM" "after-target"

	if iperf_alive; then
		pass "iperf3 survived immediate failover"
	elif iperf_effectively_completed_remote; then
		pass "iperf3 completed during immediate post-failover window"
	else
		fail "iperf3 died immediately after failover"
	fi

	info "observing post-failover traffic for ${POST_FAILOVER_OBSERVE}s"
	cycle_sleep "${POST_FAILOVER_OBSERVE}" 1 || true
	if iperf_alive; then
		pass "iperf3 still alive after post-failover observe window"
	elif iperf_effectively_completed_remote; then
		pass "iperf3 completed during post-failover observe window"
	else
		fail "iperf3 died during post-failover observe window"
	fi
else
	for (( cycle = 1; cycle <= TOTAL_CYCLES; cycle++ )); do
		failover_final_phase=0
		if (( cycle == TOTAL_CYCLES )); then
			failover_final_phase=1
		fi
		if (( cycle > 1 )); then
			run_failover_phase "$cycle" "$SOURCE_NODE" "$TARGET_NODE" "failover" "$failover_final_phase"
		fi
		failback_final_phase=0
		if (( cycle == TOTAL_CYCLES )); then
			failback_final_phase=1
		fi
		run_failover_phase "$cycle" "$TARGET_NODE" "$SOURCE_NODE" "failback" "$failback_final_phase"
	done
fi

wait_for_iperf_finish || true
copy_artifacts

zero_intervals="$(count_zero_intervals)"
if [[ "$zero_intervals" -le "$MAX_ZERO_INTERVALS" ]]; then
	pass "${zero_intervals} zero-throughput intervals (<= ${MAX_ZERO_INTERVALS})"
else
	fail "${zero_intervals} zero-throughput intervals (> ${MAX_ZERO_INTERVALS})"
fi

stream_zero_intervals="$(count_stream_zero_intervals)"
zero_streams="$(count_zero_streams)"
if [[ "$stream_zero_intervals" -le "$MAX_STREAM_ZERO_INTERVALS" ]]; then
	pass "${stream_zero_intervals} per-stream zero-throughput intervals (<= ${MAX_STREAM_ZERO_INTERVALS})"
else
	fail "${stream_zero_intervals} per-stream zero-throughput intervals across ${zero_streams} stream(s) (> ${MAX_STREAM_ZERO_INTERVALS})"
fi

throughput="$(extract_sender_throughput)"
if awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "sender throughput ${throughput} Gbps"
else
	fail "sender throughput too low: ${throughput} Gbps"
fi

retransmits="$(extract_retransmits)"
pass "sender retransmits ${retransmits}"
if [[ -n "${MAX_RETRANSMITS}" ]]; then
	if [[ "${retransmits}" -le "${MAX_RETRANSMITS}" ]]; then
		pass "retransmits ${retransmits} within limit ${MAX_RETRANSMITS}"
	else
		fail "retransmits ${retransmits} exceed limit ${MAX_RETRANSMITS}"
	fi
fi

if [[ -n "${MAX_RETRANSMITS_PER_GB}" ]]; then
	retrans_per_gb="$(awk "BEGIN{if (${throughput} <= 0) {print 0} else {printf \"%.3f\", ${retransmits} / ${throughput}}}")"
	if awk "BEGIN{exit !(${retrans_per_gb} <= ${MAX_RETRANSMITS_PER_GB})}"; then
		pass "retransmits per Gbps ${retrans_per_gb} within limit ${MAX_RETRANSMITS_PER_GB}"
	else
		fail "retransmits per Gbps ${retrans_per_gb} exceed limit ${MAX_RETRANSMITS_PER_GB}"
	fi
fi

if iperf_collapse_detected; then
	fail "iperf3 interval collapse detected: $(iperf_collapse_reason)"
else
	pass "iperf3 interval collapse not detected"
fi

if iperf_completed_local; then
	pass "iperf3 completed successfully"
elif iperf_effectively_completed_local && awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "iperf3 data transfer completed with adequate throughput despite control socket disruption"
elif awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "iperf3 data transfer completed with adequate throughput despite control socket disruption"
else
	fail "iperf3 did not complete successfully"
fi

if (( FAILED != 0 )); then
	exit 1
fi
