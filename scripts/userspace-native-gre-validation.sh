#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${BPFRX_CLUSTER_ENV:-${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env}"
DEPLOY=0
GRE_TARGET="${GRE_TARGET:-10.255.192.41}"
GRE_OUTER_REMOTE="${GRE_OUTER_REMOTE:-2602:ffd3:0:2::7}"
GRE_LOGICAL_DEV="${GRE_LOGICAL_DEV:-gr-0-0-0}"
PING_COUNT="${PING_COUNT:-5}"
PREFERRED_ACTIVE_NODE="${PREFERRED_ACTIVE_NODE:-1}"
PREFERRED_ACTIVE_RGS="${PREFERRED_ACTIVE_RGS:-1 2}"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--deploy) DEPLOY=1 ;;
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

ensure_preferred_active_node() {
	local preferred_name="node0"
	if [[ "$PREFERRED_ACTIVE_NODE" == "1" ]]; then
		preferred_name="node1"
	fi
	info "pinning native GRE validation to ${preferred_name} for RGs:${PREFERRED_ACTIVE_RGS}"
	for rg in $PREFERRED_ACTIVE_RGS; do
		local current=""
		current="$(cluster_rg_primary_node "$rg" || true)"
		if [[ "$current" == "$preferred_name" ]]; then
			continue
		fi
		run_vm "$FW0" "cli -c \"request chassis cluster failover redundancy-group ${rg} node ${PREFERRED_ACTIVE_NODE}\" >/tmp/userspace-native-gre-rg${rg}.out"
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
ensure_preferred_active_node
arm_supported_runtime

OUTER_DEV="$(run_vm "$ACTIVE_FW" "set -- \$(ip -6 route get ${GRE_OUTER_REMOTE} 2>/dev/null); while (( \$# > 0 )); do if [[ \$1 == dev ]]; then printf '%s\n' \"\$2\"; break; fi; shift; done | head -n 1")"
[[ -n "$OUTER_DEV" ]] || die "failed to derive outer device for ${GRE_OUTER_REMOTE}"
run_vm "$ACTIVE_FW" "[ -d /sys/class/net/${GRE_LOGICAL_DEV} ]" >/dev/null 2>&1 || die "missing logical GRE device ${GRE_LOGICAL_DEV}"

before_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
before_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"

info "running GRE transit probe to ${GRE_TARGET} from ${HOST}"
run_host "ping -c ${PING_COUNT} -W 1 ${GRE_TARGET} >/tmp/userspace-native-gre-ping.out 2>&1 || true"
ping_output="$(run_host 'cat /tmp/userspace-native-gre-ping.out')"
printf '%s\n' "$ping_output"
grep -q 'bytes from' <<<"$ping_output" || die "GRE ping failed"

after_outer="$(read_link_packets "$ACTIVE_FW" "$OUTER_DEV")"
after_logical="$(read_link_packets "$ACTIVE_FW" "$GRE_LOGICAL_DEV")"

read -r outer_rx_before outer_tx_before <<<"$before_outer"
read -r outer_rx_after outer_tx_after <<<"$after_outer"
read -r logical_rx_before logical_tx_before <<<"$before_logical"
read -r logical_rx_after logical_tx_after <<<"$after_logical"

outer_rx_delta=$((outer_rx_after - outer_rx_before))
outer_tx_delta=$((outer_tx_after - outer_tx_before))
logical_rx_delta=$((logical_rx_after - logical_rx_before))
logical_tx_delta=$((logical_tx_after - logical_tx_before))

printf 'outer_dev=%s outer_rx_delta=%d outer_tx_delta=%d logical_dev=%s logical_rx_delta=%d logical_tx_delta=%d\n' \
	"$OUTER_DEV" "$outer_rx_delta" "$outer_tx_delta" "$GRE_LOGICAL_DEV" "$logical_rx_delta" "$logical_tx_delta"

(( outer_rx_delta > 0 )) || die "outer device ${OUTER_DEV} saw no GRE receive traffic"
(( outer_tx_delta > 0 )) || die "outer device ${OUTER_DEV} saw no GRE transmit traffic"
(( logical_rx_delta == 0 )) || die "logical GRE device ${GRE_LOGICAL_DEV} still received transit packets"
(( logical_tx_delta == 0 )) || die "logical GRE device ${GRE_LOGICAL_DEV} still transmitted transit packets"

pass "native GRE transit stayed on ${OUTER_DEV} and off ${GRE_LOGICAL_DEV}"

info "running firewall-originated GRE probe from ${ACTIVE_FW}"
run_vm "$ACTIVE_FW" "ping -c ${PING_COUNT} -W 1 ${GRE_TARGET} >/tmp/userspace-native-gre-host-ping.out 2>&1 || true"
host_ping_output="$(run_vm "$ACTIVE_FW" 'cat /tmp/userspace-native-gre-host-ping.out')"
printf '%s\n' "$host_ping_output"
grep -q 'bytes from' <<<"$host_ping_output" || die "firewall-originated GRE ping failed"

pass "native GRE host/control-plane traffic still works on ${ACTIVE_FW}"
