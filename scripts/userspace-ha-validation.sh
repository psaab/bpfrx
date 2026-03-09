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
HOST="${REMOTE_PREFIX}${LAN_HOST}"

info() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_fw0() {
	sg incus-admin -c "incus exec ${FW0} -- bash -lc $(printf %q "$1")"
}

if [[ $DEPLOY -eq 1 ]]; then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

info "validating unsupported userspace configs stay on legacy XDP"
prog_check="$(run_fw0 'ip -details link show dev ge-0-0-1; echo ---; ip -details link show dev ge-0-0-2')"
[[ "$prog_check" == *"name xdp_main_prog"* ]] || die "fw0 is not attached to xdp_main_prog on data interfaces"

helper_stats="$(run_fw0 'cli -c "show chassis cluster data-plane statistics"')"
grep -Eq 'Forwarding supported:[[:space:]]+false' <<<"$helper_stats" || die "unexpected helper capability state on fw0"
grep -Eq 'Enabled:[[:space:]]+false' <<<"$helper_stats" || die "userspace forwarding unexpectedly enabled on fw0"
grep -Eq 'Bound bindings:[[:space:]]+0/8' <<<"$helper_stats" || die "AF_XDP bindings should be 0/8 for unsupported config"

info "ensuring IPv6 default route via router advertisement"
route_before="$(run_host 'ip -6 route show default || true')"
if [[ -z "$route_before" ]]; then
	run_host 'timeout 8 rdisc6 -1 eth0 >/tmp/userspace-rdisc6.out 2>/dev/null || true'
fi
route_after="$(run_host 'ip -6 route show default || true')"
[[ -n "$route_after" ]] || die "cluster userspace host still has no IPv6 default route after RA solicitation"

info "basic reachability checks"
run_host 'ping -c 2 -W 1 172.16.80.200 >/tmp/userspace-ping-v4.out'
run_host 'ping -6 -c 2 -W 1 2001:559:8585:80::200 >/tmp/userspace-ping-v6.out'

summary_file="$(mktemp)"
cleanup() { rm -f "$summary_file"; }
trap cleanup EXIT

run_iperf_json() {
	local family="$1" target="$2" outfile="$3"
	local cmd
	if [[ "$family" == "6" ]]; then
		cmd="rm -f ${outfile} ${outfile}.err; iperf3 -6 -J -c ${target} -P ${PARALLEL} -t ${DURATION} > ${outfile} 2>${outfile}.err"
	else
		cmd="rm -f ${outfile} ${outfile}.err; iperf3 -J -c ${target} -P ${PARALLEL} -t ${DURATION} > ${outfile} 2>${outfile}.err"
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
		json="/tmp/${label}-${i}.json"
		info "running ${label} iperf iteration ${i}/${RUNS}"
		run_iperf_json "$family" "$target" "$json"
		gbps="$(parse_gbps "$json")"
		if [[ "$gbps" == ERROR:* ]]; then
			die "${label} iperf failed: ${gbps#ERROR:}"
		fi
		printf '%s run %s: %s Gbps\n' "$label" "$i" "$gbps" | tee -a "$summary_file"
		validate_threshold "$gbps" "$min_gbps" "$label" "$i"
	done
}

run_perf_pair() {
	local label="$1" target="$2" family="$3"
	local perf_data="/tmp/${label}.data"
	local perf_report="/tmp/${label}.report"
	local iperf_json="/tmp/${label}.json"
	local perf_pid

	info "profiling ${label}"
	sg incus-admin -c "incus exec ${FW0} -- bash -lc $(printf %q "rm -f ${perf_data} ${perf_report}; perf record -a -g -F 997 -o ${perf_data} -- sleep $((DURATION + 2))")" &
	perf_pid=$!
	sleep 1
	run_iperf_json "$family" "$target" "$iperf_json"
	wait "$perf_pid" || true
	run_fw0 "perf report --stdio -i ${perf_data} --sort symbol | sed -n '1,80p' > ${perf_report}"
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
cat "$summary_file"
if [[ $WITH_PERF -eq 1 ]]; then
	info "perf artifacts on fw0: /tmp/perf-userspace-ipv4.{data,report} /tmp/perf-userspace-ipv6.{data,report}"
fi
