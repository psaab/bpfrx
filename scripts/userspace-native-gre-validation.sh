#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
DEPLOY=0
FAILOVER=0
GRE_TARGET="${GRE_TARGET:-10.255.192.41}"
GRE_TCP_TARGET="${GRE_TCP_TARGET:-${GRE_TARGET}}"
GRE_TCP_PORT="${GRE_TCP_PORT:-22}"
GRE_OUTER_REMOTE="${GRE_OUTER_REMOTE:-2602:ffd3:0:2::7}"
GRE_LOGICAL_DEV="${GRE_LOGICAL_DEV:-gr-0-0-0}"
PING_COUNT="${PING_COUNT:-5}"
FAILOVER_PING_COUNT="${FAILOVER_PING_COUNT:-40}"
FAILOVER_PREP_SECS="${FAILOVER_PREP_SECS:-3}"
PREFERRED_ACTIVE_NODE="${PREFERRED_ACTIVE_NODE:-1}"
PREFERRED_ACTIVE_RGS="${PREFERRED_ACTIVE_RGS:-1 2}"
TRANSIT_PING_ID="${TRANSIT_PING_ID:-$(( ( ( $$ + RANDOM ) % 60000 ) + 1024 ))}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--deploy) DEPLOY=1 ;;
	--failover) FAILOVER=1 ;;
	--env) ENV_FILE="$2"; shift ;;
	--target) GRE_TARGET="$2"; shift ;;
	--outer-remote) GRE_OUTER_REMOTE="$2"; shift ;;
	--logical-dev) GRE_LOGICAL_DEV="$2"; shift ;;
	--count) PING_COUNT="$2"; shift ;;
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
pass() { printf 'PASS  %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

tcp_probe_cmd() {
	local target="$1"
	local port="$2"
	printf 'timeout 2 bash -lc %q' "exec 3<>/dev/tcp/${target}/${port}"
}

run_host() {
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "$1")"
}

run_vm() {
	local vm="$1"
	shift
	sg incus-admin -c "incus exec ${vm} -- bash -lc $(printf %q "$1")"
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

rg_primary_node() {
	local vm="$1"
	local rg="$2"
	local status
	status="$(run_vm "$vm" 'cli -c "show chassis cluster status"' 2>/dev/null || true)"
	if grep -Eq "Redundancy group: ${rg} " <<<"$status"; then
		awk -v rg="$rg" '
			$0 ~ ("Redundancy group: " rg " ") { in_rg=1; next }
			in_rg && /^Redundancy group:/ { in_rg=0 }
			in_rg && /primary/ { print $1; exit }
		' <<<"$status"
	fi
}

cluster_rg_primary_node() {
	local rg="$1"
	local primary=""
	primary="$(rg_primary_node "$FW0" "$rg" || true)"
	if [[ -n "$primary" ]]; then
		printf '%s\n' "$primary"
		return 0
	fi
	primary="$(rg_primary_node "$FW1" "$rg" || true)"
	if [[ -n "$primary" ]]; then
		printf '%s\n' "$primary"
		return 0
	fi
	return 1
}

primary_vm_for_rg() {
	local rg="$1"
	local primary=""
	primary="$(cluster_rg_primary_node "$rg" || true)"
	case "$primary" in
	node0) printf '%s\n' "$FW0" ;;
	node1) printf '%s\n' "$FW1" ;;
	esac
}

pin_active_node() {
	local target_node="$1"
	local preferred_name="node0"
	if [[ "$target_node" == "1" ]]; then
		preferred_name="node1"
	fi
	info "pinning native GRE validation to ${preferred_name} for RGs:${PREFERRED_ACTIVE_RGS}"
	for rg in $PREFERRED_ACTIVE_RGS; do
		local current=""
		current="$(cluster_rg_primary_node "$rg" || true)"
		if [[ "$current" == "$preferred_name" ]]; then
			continue
		fi
		run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${rg} node ${target_node}\" >/tmp/userspace-native-gre-rg${rg}.out"
	done
	local tries=45
	while (( tries > 0 )); do
		local all_good=1
		for rg in $PREFERRED_ACTIVE_RGS; do
			local current=""
			current="$(cluster_rg_primary_node "$rg" || true)"
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
	die "preferred active node ${preferred_name} did not take over RGs:${PREFERRED_ACTIVE_RGS}"
}

enabled_userspace_vm() {
	local vm="$1"
	local stats
	stats="$(run_vm "$vm" 'cli -c "show chassis cluster data-plane statistics"' 2>/dev/null || true)"
	grep -Eq 'Enabled:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Forwarding supported:[[:space:]]+true' <<<"$stats" &&
		grep -Eq 'Ready bindings:[[:space:]]+[1-9][0-9]*/[0-9]+' <<<"$stats"
}

wait_for_userspace_vm() {
	local vm="$1"
	local tries=45
	while (( tries > 0 )); do
		if enabled_userspace_vm "$vm" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

arm_supported_runtime() {
	local primary_rg primary_vm
	primary_rg="${PREFERRED_ACTIVE_RGS%% *}"
	[[ -n "$primary_rg" ]] || die "no preferred active RG configured"
	primary_vm="$(primary_vm_for_rg "$primary_rg")"
	[[ -n "$primary_vm" ]] || die "failed to determine RG${primary_rg} primary VM"
	info "waiting for userspace forwarding to arm"
	if wait_for_userspace_vm "$primary_vm"; then
		ACTIVE_FW="$primary_vm"
		info "active userspace firewall: ${ACTIVE_FW}"
		return 0
	fi
	run_vm "$FW0" 'cli -c "request chassis cluster data-plane userspace forwarding arm" >/tmp/userspace-native-gre-arm.out'
	wait_for_userspace_vm "$primary_vm" || die "userspace runtime did not arm on ${primary_vm}"
	ACTIVE_FW="$primary_vm"
	info "active userspace firewall: ${ACTIVE_FW}"
}

read_link_packets() {
	local vm="$1"
	local dev="$2"
	run_vm "$vm" "printf '%s %s\n' \$(cat /sys/class/net/${dev}/statistics/rx_packets) \$(cat /sys/class/net/${dev}/statistics/tx_packets)"
}

start_logical_transit_capture() {
	local vm="$1"
	local outfile="$2"
	run_vm "$vm" "rm -f ${outfile}; nohup sh -c \"timeout 6 tcpdump -n -i ${GRE_LOGICAL_DEV} -vv 'icmp and host ${GRE_TARGET} and icmp[4:2] == ${TRANSIT_PING_ID}' >${outfile} 2>&1\" >/dev/null 2>&1 &"
}

logical_transit_matches() {
	local vm="$1"
	local outfile="$2"
	local capture
	capture="$(run_vm "$vm" "cat ${outfile} 2>/dev/null || true")"
	printf '%s\n' "$capture" >&2
	grep -c 'ICMP echo' <<<"$capture" || true
}

if (( DEPLOY == 1 )); then
	info "deploying isolated userspace cluster from ${ENV_FILE}"
	BPFRX_CLUSTER_ENV="$ENV_FILE" "${PROJECT_ROOT}/test/incus/cluster-setup.sh" deploy all
fi

wait_for_vm_cli "$FW0" || die "fw0 bpfrxd did not become reachable in time"
wait_for_vm_cli "$FW1" || die "fw1 bpfrxd did not become reachable in time"
wait_for_cluster_primary() {
	local rg="$1"
	local tries=60
	while (( tries > 0 )); do
		if cluster_rg_primary_node "$rg" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		tries=$((tries - 1))
	done
	return 1
}

wait_for_cluster_settle() {
	info "waiting for cluster primaries to settle"
	for rg in $PREFERRED_ACTIVE_RGS; do
		wait_for_cluster_primary "$rg" || die "RG${rg} did not elect a primary after deploy"
	done
}

if (( DEPLOY == 1 )); then
	wait_for_cluster_settle
fi
pin_active_node "$PREFERRED_ACTIVE_NODE"
arm_supported_runtime

OUTER_DEV="$(run_vm "$ACTIVE_FW" "set -- \$(ip -6 route get ${GRE_OUTER_REMOTE} 2>/dev/null); while (( \$# > 0 )); do if [[ \$1 == dev ]]; then printf '%s\n' \"\$2\"; break; fi; shift; done | head -n 1")"
[[ -n "$OUTER_DEV" ]] || die "failed to derive outer device for ${GRE_OUTER_REMOTE}"
run_vm "$ACTIVE_FW" "[ -d /sys/class/net/${GRE_LOGICAL_DEV} ]" >/dev/null 2>&1 || die "missing logical GRE device ${GRE_LOGICAL_DEV}"

before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
logical_capture_file="/tmp/userspace-native-gre-logical-capture.out"
start_logical_transit_capture "$ACTIVE_FW" "$logical_capture_file"

info "running GRE transit probe to ${GRE_TARGET} from ${HOST}"
run_host "ping -c ${PING_COUNT} -W 1 -e ${TRANSIT_PING_ID} ${GRE_TARGET} >/tmp/userspace-native-gre-ping.out 2>&1 || true"
ping_output="$(run_host 'cat /tmp/userspace-native-gre-ping.out')"
printf '%s\n' "$ping_output"
grep -q 'bytes from' <<<"$ping_output" || die "GRE ping failed"
sleep 4

after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"
logical_matches="$(logical_transit_matches "$ACTIVE_FW" "$logical_capture_file")"

read -r outer_rx_before outer_tx_before <<<"$before_outer"
read -r outer_rx_after outer_tx_after <<<"$after_outer"
read -r logical_rx_before logical_tx_before <<<"$before_logical"
read -r logical_rx_after logical_tx_after <<<"$after_logical"

outer_rx_delta=$((outer_rx_after - outer_rx_before))
outer_tx_delta=$((outer_tx_after - outer_tx_before))
logical_rx_delta=$((logical_rx_after - logical_rx_before))
logical_tx_delta=$((logical_tx_after - logical_tx_before))

printf 'outer_dev=%s outer_rx_delta=%d outer_tx_delta=%d logical_dev=%s logical_rx_delta=%d logical_tx_delta=%d logical_probe_matches=%d ping_id=%d\n' \
	"$OUTER_DEV" "$outer_rx_delta" "$outer_tx_delta" "$GRE_LOGICAL_DEV" "$logical_rx_delta" "$logical_tx_delta" "$logical_matches" "$TRANSIT_PING_ID"

(( outer_rx_delta > 0 )) || die "outer device ${OUTER_DEV} saw no GRE receive traffic"
(( outer_tx_delta > 0 )) || die "outer device ${OUTER_DEV} saw no GRE transmit traffic"
(( logical_matches == 0 )) || die "logical GRE device ${GRE_LOGICAL_DEV} still received tagged transit packets"

pass "native GRE transit stayed on ${OUTER_DEV} and off ${GRE_LOGICAL_DEV}"

info "running GRE TCP probe to ${GRE_TCP_TARGET}:${GRE_TCP_PORT} from ${HOST}"
run_host "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/tmp/userspace-native-gre-host-tcp.out 2>&1 || true"
host_tcp_output="$(run_host 'cat /tmp/userspace-native-gre-host-tcp.out 2>/dev/null || true')"
printf '%s\n' "$host_tcp_output"
run_host "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1" || die "GRE TCP connect from ${HOST} failed"

pass "native GRE transit TCP connect works from ${HOST}"

info "running firewall-originated GRE probe from ${ACTIVE_FW}"
run_vm "$ACTIVE_FW" "ping -c ${PING_COUNT} -W 1 ${GRE_TARGET} >/tmp/userspace-native-gre-host-ping.out 2>&1 || true"
host_ping_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-host-ping.out')"
printf '%s\n' "$host_ping_output"
grep -q 'bytes from' <<<"$host_ping_output" || die "firewall-originated GRE ping failed"

pass "native GRE host/control-plane traffic still works on ${ACTIVE_FW}"

info "running firewall-originated GRE TCP probe from ${ACTIVE_FW}"
run_vm "$ACTIVE_FW" "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/tmp/userspace-native-gre-fw-tcp.out 2>&1 || true"
host_tcp_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-fw-tcp.out 2>/dev/null || true')"
printf '%s\n' "$host_tcp_output"
run_vm "$ACTIVE_FW" "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1" || die "firewall-originated GRE TCP connect failed"

pass "native GRE host/control-plane TCP connect works on ${ACTIVE_FW}"

if (( FAILOVER == 1 )); then
	current_node="$PREFERRED_ACTIVE_NODE"
	failover_node=0
	if [[ "$current_node" == "0" ]]; then
		failover_node=1
	fi
	info "running active GRE failover probe from ${HOST} while moving RGs to node${failover_node}"
	failover_ping_log="$(mktemp)"
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "ping -i 0.2 -c ${FAILOVER_PING_COUNT} -W 1 ${GRE_TARGET}")" >"${failover_ping_log}" 2>&1 &
	failover_ping_pid=$!
	failover_tcp_log="$(mktemp)"
	sg incus-admin -c "incus exec ${HOST} -- bash -lc $(printf %q "for seq in \$(seq 1 ${FAILOVER_PING_COUNT}); do if $(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1; then echo ok seq=\${seq}; else echo fail seq=\${seq}; fi; sleep 0.2; done")" >"${failover_tcp_log}" 2>&1 &
	failover_tcp_pid=$!
	sleep "$FAILOVER_PREP_SECS"
	pin_active_node "$failover_node"
	arm_supported_runtime
	wait "$failover_ping_pid" || true
	wait "$failover_tcp_pid" || true
	failover_ping_output="$(cat "${failover_ping_log}")"
	rm -f "${failover_ping_log}"
	failover_tcp_output="$(cat "${failover_tcp_log}")"
	rm -f "${failover_tcp_log}"
	printf '%s\n' "$failover_ping_output"
	max_seq="$(awk -F'icmp_seq=' '/bytes from/ { split($2, a, /[[:space:]]+/); if (a[1] > max) max=a[1] } END { print max+0 }' <<<"$failover_ping_output")"
	[[ "$max_seq" -ge $((FAILOVER_PING_COUNT - 5)) ]] || die "active GRE failover ping did not recover near the tail (max_seq=${max_seq})"
	grep -q 'bytes from' <<<"$failover_ping_output" || die "active GRE failover ping produced no replies"
	printf '%s\n' "$failover_tcp_output"
	max_tcp_seq="$(awk -F'seq=' '/^ok seq=/ { if ($2 > max) max = $2 } END { print max+0 }' <<<"$failover_tcp_output")"
	[[ "$max_tcp_seq" -ge $((FAILOVER_PING_COUNT - 5)) ]] || die "active GRE failover TCP did not recover near the tail (max_seq=${max_tcp_seq})"
	grep -q '^ok seq=' <<<"$failover_tcp_output" || die "active GRE failover TCP produced no successful connects"
	run_vm "$ACTIVE_FW" "ping -c ${PING_COUNT} -W 1 ${GRE_TARGET} >/tmp/userspace-native-gre-post-failover-host-ping.out 2>&1 || true"
	post_failover_host_ping_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-post-failover-host-ping.out')"
	printf '%s\n' "$post_failover_host_ping_output"
	grep -q 'bytes from' <<<"$post_failover_host_ping_output" || die "post-failover firewall-originated GRE ping failed"
	run_vm "$ACTIVE_FW" "$(tcp_probe_cmd "${GRE_TCP_TARGET}" "${GRE_TCP_PORT}") >/dev/null 2>&1" || die "post-failover firewall-originated GRE TCP connect failed"
	pass "native GRE active tunnel traffic survived failover to ${ACTIVE_FW}"
fi
