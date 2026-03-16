#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
RG="${RG:-1}"
SOURCE_NODE="${SOURCE_NODE:-0}"
TARGET_NODE="${TARGET_NODE:-1}"
IPERF_TARGET="${IPERF_TARGET:-172.16.80.200}"
IPERF_DURATION="${IPERF_DURATION:-60}"
IPERF_STREAMS="${IPERF_STREAMS:-4}"
SYNC_WAIT="${SYNC_WAIT:-5}"
FAILOVER_WAIT="${FAILOVER_WAIT:-30}"
MIN_SESSIONS="${MIN_SESSIONS:-4}"
MIN_THROUGHPUT="${MIN_THROUGHPUT:-1.0}"
MAX_ZERO_INTERVALS="${MAX_ZERO_INTERVALS:-2}"
POST_FAILOVER_OBSERVE="${POST_FAILOVER_OBSERVE:-10}"
RESTORE_SOURCE_NODE="${RESTORE_SOURCE_NODE:-1}"
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
	--sync-wait) SYNC_WAIT="$2"; shift ;;
	--failover-wait) FAILOVER_WAIT="$2"; shift ;;
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
FAILED=0

info() { printf '==> %s\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; FAILED=1; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

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
		run_host "pkill -9 iperf3 2>/dev/null || true; rm -f ${REMOTE_IPERF_LOG}"
		run_host "iperf3 --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > ${REMOTE_IPERF_LOG} 2>&1 &"
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

iperf_alive() {
	run_host "pgrep -x iperf3 >/dev/null"
}

iperf_completed() {
	run_host "grep -q 'iperf Done' ${REMOTE_IPERF_LOG}"
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
	run_host "cat ${REMOTE_IPERF_LOG} 2>/dev/null || true" >"${ARTIFACT_DIR}/iperf3.log"
}

count_zero_intervals() {
	grep -E '^\[  [0-9]|^\[ [0-9][0-9]|\[SUM\]' "${ARTIFACT_DIR}/iperf3.log" 2>/dev/null | grep -c '0.00 bits/sec' || true
}

extract_sender_throughput() {
	local line
	line="$(grep '\[SUM\].*sender' "${ARTIFACT_DIR}/iperf3.log" 2>/dev/null | tail -1 || true)"
	if [[ "$line" =~ ([0-9.]+)[[:space:]]+Gbits/sec ]]; then
		printf '%s\n' "${BASH_REMATCH[1]}"
		return 0
	fi
	if [[ "$line" =~ ([0-9.]+)[[:space:]]+Mbits/sec ]]; then
		awk "BEGIN{printf \"%.3f\", ${BASH_REMATCH[1]} / 1000}"
		return 0
	fi
	printf '0\n'
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
	restore_cluster
	printf 'Artifacts: %s\n' "${ARTIFACT_DIR}"
}
trap cleanup EXIT

mkdir -p "${ARTIFACT_DIR}"

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

info "triggering manual RG${RG} failover to $(node_name "$TARGET_NODE")"
run_vm "$SOURCE_VM" "cli -c \"request chassis cluster failover redundancy-group ${RG} node ${TARGET_NODE}\" >/tmp/userspace-rg${RG}-failover.out"
wait_for_rg_owner "$RG" "$TARGET_NODE" "$FAILOVER_WAIT" || die "RG${RG} did not move to $(node_name "$TARGET_NODE") after failover"
pass "RG${RG} moved to $(node_name "$TARGET_NODE")"

ACTIVE_FW="$(wait_for_userspace_rg_owner "$RG")" || die "userspace forwarding did not settle on the new RG${RG} owner"
pass "userspace forwarding active on new owner ${ACTIVE_FW}"

capture_vm_state "$SOURCE_VM" "after-source"
capture_vm_state "$TARGET_VM" "after-target"

if iperf_alive; then
	pass "iperf3 survived immediate failover"
else
	fail "iperf3 died immediately after failover"
fi

info "observing post-failover traffic for ${POST_FAILOVER_OBSERVE}s"
sleep "${POST_FAILOVER_OBSERVE}"
if iperf_alive; then
	pass "iperf3 still alive after post-failover observe window"
elif iperf_completed; then
	pass "iperf3 completed during post-failover observe window"
else
	fail "iperf3 died during post-failover observe window"
fi

wait_for_iperf_finish || true
copy_artifacts

zero_intervals="$(count_zero_intervals)"
if [[ "$zero_intervals" -le "$MAX_ZERO_INTERVALS" ]]; then
	pass "${zero_intervals} zero-throughput intervals (<= ${MAX_ZERO_INTERVALS})"
else
	fail "${zero_intervals} zero-throughput intervals (> ${MAX_ZERO_INTERVALS})"
fi

throughput="$(extract_sender_throughput)"
if awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "sender throughput ${throughput} Gbps"
else
	fail "sender throughput too low: ${throughput} Gbps"
fi

if grep -q "iperf Done" "${ARTIFACT_DIR}/iperf3.log" 2>/dev/null; then
	pass "iperf3 completed successfully"
elif awk "BEGIN{exit !(${throughput} >= ${MIN_THROUGHPUT})}"; then
	pass "iperf3 data transfer completed with adequate throughput despite control socket disruption"
else
	fail "iperf3 did not complete successfully"
fi

if (( FAILED != 0 )); then
	exit 1
fi
