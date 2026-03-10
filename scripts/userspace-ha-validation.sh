#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
RUNS="${RUNS:-3}"
DURATION="${DURATION:-5}"
PARALLEL="${PARALLEL:-4}"
MIN_GBPS_V4="${MIN_GBPS_V4:-18.0}"
MIN_GBPS_V6="${MIN_GBPS_V6:-18.0}"
MARGINAL_GBPS_EPSILON="${MARGINAL_GBPS_EPSILON:-0.25}"
PREFERRED_ACTIVE_NODE="${PREFERRED_ACTIVE_NODE:-0}"
PREFERRED_ACTIVE_RGS="${PREFERRED_ACTIVE_RGS:-1 2}"
IPERF_TIMEOUT="${IPERF_TIMEOUT:-$((DURATION + 15))}"
WITH_PERF=0
DEPLOY=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--perf) WITH_PERF=1 ;;
	--deploy) DEPLOY=1 ;;
	--env) ENV_FILE="$2"; shift ;;
	--runs) RUNS="$2"; shift ;;
	--duration) DURATION="$2"; shift ;;
	--parallel) PARALLEL="$2"; shift ;;
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
ACTIVE_FW="${FW0}"

info() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$1")"
}

run_fw0() {
	run_vm "${FW0}" "$1"
}

run_fw1() {
	run_vm "${FW1}" "$1"
}

run_active_fw() {
	run_vm "${ACTIVE_FW}" "$1"
}

wait_for_vm_cli() {
	local vm="$1"
	local tries=30
	while (( tries > 0 )); do
		if run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics" >/tmp/userspace-cli-ready.out 2>/dev/null'; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

runtime_mode() {
	local tries=20
	local prog_check helper_stats
	while (( tries > 0 )); do
		prog_check="$(run_fw0 'ip -details link show dev ge-0-0-1; echo ---; ip -details link show dev ge-0-0-2')"
		helper_stats="$(run_fw0 'cli -c "show chassis cluster data-plane statistics"')"
		if grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$helper_stats" &&
			[[ "$prog_check" == *"name xdp_userspace_p"* ]]; then
			printf 'supported\n'
			return 0
		fi
		if [[ "$prog_check" == *"name xdp_main_p"* ]] &&
			grep -Eq 'Forwarding supported:[[:space:]]+false' <<<"$helper_stats" &&
			grep -Eq 'Enabled:[[:space:]]+false' <<<"$helper_stats" &&
			grep -Eq 'Bound bindings:[[:space:]]+0/[0-9]+' <<<"$helper_stats"; then
			printf 'legacy\n'
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	printf '%s\n---\n%s\n' "$prog_check" "$helper_stats" >&2
	return 1
}

enabled_userspace_vm() {
	local vm="$1"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"')"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

active_owner_vm() {
	local vm stats
	for vm in "$FW0" "$FW1"; do
		stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
		if grep -Eq 'HA groups:[[:space:]].*rg[1-9][0-9]* active=true' <<<"$stats"; then
			printf '%s\n' "$vm"
			return 0
		fi
	done
	return 1
}

rg_primary_node() {
	local vm="$1"
	local rg="$2"
	local status
	status="$(run_vm "$vm" 'cli -c "show chassis cluster status"' 2>/dev/null || true)"
	if grep -Eq "Redundancy group: ${rg} " <<<"$status"; then
		if awk -v rg="$rg" '
			$0 ~ ("Redundancy group: " rg " ") { in_rg=1; next }
			in_rg && /^Redundancy group:/ { in_rg=0 }
			in_rg && /primary/ { print $1; exit }
		' <<<"$status"; then
			return 0
		fi
	fi
	return 1
}

ensure_preferred_active_node() {
	local preferred_vm="$FW0"
	local preferred_name="node0"
	if [[ "$PREFERRED_ACTIVE_NODE" == "1" ]]; then
		preferred_vm="$FW1"
		preferred_name="node1"
	fi
	info "pinning userspace validation to ${preferred_name} for RGs:${PREFERRED_ACTIVE_RGS}"
	run_host 'sysctl -qw net.ipv6.conf.eth0.accept_ra=2 || true'
	for rg in $PREFERRED_ACTIVE_RGS; do
		local current=""
		current="$(rg_primary_node "$FW0" "$rg" || true)"
		if [[ "$current" == "$preferred_name" ]]; then
			continue
		fi
		run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${rg} node ${PREFERRED_ACTIVE_NODE}\" >/tmp/userspace-failover-rg${rg}.out"
	done
	local tries=45
	while (( tries > 0 )); do
		local all_good=1
		for rg in $PREFERRED_ACTIVE_RGS; do
			local current=""
			current="$(rg_primary_node "$FW0" "$rg" || true)"
			if [[ "$current" != "$preferred_name" ]]; then
				all_good=0
				break
			fi
		done
		if (( all_good == 1 )); then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	die "preferred validation owner ${preferred_name} did not take over RGs:${PREFERRED_ACTIVE_RGS}"
}

wait_for_active_supported_runtime() {
	local tries=30
	while (( tries > 0 )); do
		local vm
		for vm in "$FW0" "$FW1"; do
			if enabled_userspace_vm "$vm" >/dev/null 2>&1; then
				printf '%s\n' "$vm"
				return 0
			fi
		done
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

arm_supported_runtime() {
	local owner
	owner="$(active_owner_vm || true)"
	if [[ -z "$owner" ]]; then
		owner="$FW0"
	fi
	info "waiting for userspace forwarding to auto-arm on the active node"
	if ACTIVE_FW="$(wait_for_active_supported_runtime)"; then
		info "active userspace firewall: ${ACTIVE_FW}"
		return 0
	fi
	info "auto-arm did not settle, forcing forwarding arm on ${owner}"
	run_vm "$owner" 'cli -c "request chassis cluster data-plane userspace forwarding arm" >/tmp/userspace-arm.out'
	if ACTIVE_FW="$(wait_for_active_supported_runtime)"; then
		info "active userspace firewall: ${ACTIVE_FW}"
		return 0
	fi
	run_vm "$owner" 'cli -c "show chassis cluster data-plane statistics" >&2 || true'
	die "userspace forwarding did not become enabled on the active node"
}

wait_for_ipv6_default_route() {
	local tries=20
	while (( tries > 0 )); do
		local route
		route="$(run_host 'ip -6 route show default || true')"
		if [[ -n "$route" ]]; then
			return 0
		fi
		run_host 'timeout 8 rdisc6 -1 eth0 >/tmp/userspace-rdisc6.out 2>/dev/null || true'
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

if [[ $DEPLOY -eq 1 ]]; then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

info "waiting for bpfrxd gRPC/CLI readiness"
wait_for_vm_cli "$FW0" || die "fw0 bpfrxd did not become reachable in time"
wait_for_vm_cli "$FW1" || die "fw1 bpfrxd did not become reachable in time"

info "detecting userspace runtime mode"
MODE="$(runtime_mode)" || die "userspace runtime mode did not settle in time"
info "runtime mode: ${MODE}"
if [[ "${MODE}" == "legacy" ]]; then
	info "validating legacy fallback state"
else
	info "supported userspace runtime detected"
	ensure_preferred_active_node
	arm_supported_runtime
fi

info "ensuring IPv6 default route via router advertisement"
wait_for_ipv6_default_route || die "cluster userspace host still has no IPv6 default route after repeated RA solicitation"

info "basic reachability checks"
run_host 'ping -c 2 -W 1 172.16.80.200 >/tmp/userspace-ping-v4.out'
run_host 'ping -6 -c 2 -W 1 2001:559:8585:80::200 >/tmp/userspace-ping-v6.out'

summary_file="$(mktemp)"
cleanup() { rm -f "$summary_file"; }
trap cleanup EXIT

run_iperf_json() {
	local family="$1" target="$2" outfile="$3"
	local cmd tmpfile timeout_sec
	tmpfile="${outfile}.tmp"
	timeout_sec="${IPERF_TIMEOUT}s"
	if [[ "$family" == "6" ]]; then
		cmd="rm -f ${outfile} ${outfile}.err ${tmpfile}; if timeout -k 2 ${timeout_sec} iperf3 -6 -J -c ${target} -P ${PARALLEL} -t ${DURATION} > ${tmpfile} 2>${outfile}.err; then mv ${tmpfile} ${outfile}; else rc=\$?; rm -f ${tmpfile} ${outfile}; if [[ \$rc -eq 124 || \$rc -eq 137 ]]; then echo \"iperf3 timed out after ${timeout_sec}\" >> ${outfile}.err; else echo \"iperf3 exited with status \$rc\" >> ${outfile}.err; fi; fi"
	else
		cmd="rm -f ${outfile} ${outfile}.err ${tmpfile}; if timeout -k 2 ${timeout_sec} iperf3 -J -c ${target} -P ${PARALLEL} -t ${DURATION} > ${tmpfile} 2>${outfile}.err; then mv ${tmpfile} ${outfile}; else rc=\$?; rm -f ${tmpfile} ${outfile}; if [[ \$rc -eq 124 || \$rc -eq 137 ]]; then echo \"iperf3 timed out after ${timeout_sec}\" >> ${outfile}.err; else echo \"iperf3 exited with status \$rc\" >> ${outfile}.err; fi; fi"
	fi
	run_host "$cmd"
}

parse_gbps() {
	local path="$1"
	if [[ "$(run_host "test -s ${path}; echo $?")" != "0" ]]; then
		local err
		err="$(run_host "cat ${path}.err 2>/dev/null || true")"
		if [[ -z "$err" ]]; then
			err="iperf3 produced no JSON output"
		fi
		printf 'ERROR:%s\n' "$err"
		return 0
	fi
	run_host "cat ${path}" | python3 -c '
import json
import sys
data = json.load(sys.stdin)
err = data.get("error")
if err:
    print("ERROR:" + err)
    raise SystemExit(0)
end = data["end"]
bps = end.get("sum_sent", {}).get("bits_per_second", 0) or end.get("sum", {}).get("bits_per_second", 0)
print(f"{bps / 1e9:.3f}")
'
}

validate_threshold() {
	python3 - <<'PY' "$1" "$2" "$3" "$4"
import sys
actual = float(sys.argv[1])
minimum = float(sys.argv[2])
label = sys.argv[3]
run = sys.argv[4]
if actual < minimum:
    raise SystemExit(f"{label} run {run} below threshold: {actual:.3f} < {minimum:.3f} Gbps")
PY
}

warm_up_family() {
	local label="$1" target="$2" family="$3"
	local json="/tmp/${label}-warmup.json"
	info "warming up ${label} path"
	run_iperf_json "$family" "$target" "$json"
}

validate_family() {
	local label="$1" target="$2" family="$3" min_gbps="$4"
	local i json gbps
	for i in $(seq 1 "$RUNS"); do
		local attempt=1
		while true; do
			json="/tmp/${label}-${i}.json"
			info "running ${label} iperf iteration ${i}/${RUNS}"
			run_iperf_json "$family" "$target" "$json"
			gbps="$(parse_gbps "$json")"
			if [[ "$gbps" == ERROR:* ]]; then
				die "${label} iperf failed: ${gbps#ERROR:}"
			fi
			if python3 - <<'PY' "$gbps" "$min_gbps" "$MARGINAL_GBPS_EPSILON"
import sys
actual = float(sys.argv[1])
minimum = float(sys.argv[2])
epsilon = float(sys.argv[3])
sys.exit(0 if actual + epsilon >= minimum else 1)
PY
			then
				printf '%s run %s: %s Gbps\n' "$label" "$i" "$gbps" | tee -a "$summary_file"
				if python3 - <<'PY' "$gbps" "$min_gbps"
import sys
actual = float(sys.argv[1])
minimum = float(sys.argv[2])
sys.exit(0 if actual >= minimum else 1)
PY
				then
					break
				fi
				if (( attempt == 1 )); then
					info "${label} iteration ${i} was marginal (${gbps} Gbps); rerunning once"
					attempt=2
					continue
				fi
				break
			fi
			printf '%s run %s: %s Gbps\n' "$label" "$i" "$gbps" | tee -a "$summary_file"
			validate_threshold "$gbps" "$min_gbps" "$label" "$i"
		done
	done
}

run_perf_pair() {
	local label="$1" target="$2" family="$3"
	local perf_data="/tmp/${label}.data"
	local perf_report="/tmp/${label}.report"
	local iperf_json="/tmp/${label}.json"
	local perf_pid

	info "profiling ${label}"
	sg incus-admin -c "incus exec ${ACTIVE_FW} -- bash -lc $(printf %q "rm -f ${perf_data} ${perf_report}; perf record -a -g -F 997 -o ${perf_data} -- sleep $((DURATION + 2))")" &
	perf_pid=$!
	sleep 1
	run_iperf_json "$family" "$target" "$iperf_json"
	wait "$perf_pid" || true
	run_active_fw "perf report --stdio -i ${perf_data} --sort symbol | sed -n '1,80p' > ${perf_report}"
}

warm_up_family ipv4 172.16.80.200 4
warm_up_family ipv6 2001:559:8585:80::200 6

validate_family ipv4 172.16.80.200 4 "$MIN_GBPS_V4"
validate_family ipv6 2001:559:8585:80::200 6 "$MIN_GBPS_V6"

if [[ $WITH_PERF -eq 1 ]]; then
	run_perf_pair perf-userspace-ipv4 172.16.80.200 4
	run_perf_pair perf-userspace-ipv6 2001:559:8585:80::200 6
fi

info "validation summary"
printf 'active fw: %s\n' "${ACTIVE_FW}" | tee -a "$summary_file"
cat "$summary_file"
if [[ $WITH_PERF -eq 1 ]]; then
	info "perf artifacts on ${ACTIVE_FW}: /tmp/perf-userspace-ipv4.{data,report} /tmp/perf-userspace-ipv6.{data,report}"
fi
