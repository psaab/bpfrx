#!/usr/bin/env bash
# #8341 severity triage: does retargeting the CATCH-ALL source-NAT rule to a
# pool break only the probe's flow, or ALL transit?
#
# WHY THIS RUNS BEFORE ANY BISECT. The mint-observability probe (#8440) measured
# zero sessions for its own flow once `lan-to-wan/snat` was retargeted from
# `then source-nat interface` to `then source-nat pool`. If that means zero
# sessions for EVERY transit flow, this is not a persistent-NAT observability
# bug — it is a total forwarding outage on a config an operator would plausibly
# write, and it deserves its own issue at a severity #8341 does not carry.
#
# Three probes under the SAME committed config, so the answer is comparative
# rather than a single observation:
#   1. ICMP across the firewall  (does anything transit at all?)
#   2. a TCP flow to the iperf target  (the #8440 probe's own shape)
#   3. a TCP flow to a DIFFERENT port  (rules out a per-port artifact)
#
# The interface-SNAT control runs in the SAME cell, before and after, because a
# baseline taken once at the start cannot tell "the pool broke it" from "the
# cluster was already unhealthy when this cell started".
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-catchall-outage-check-8341 $*" "$0" "$@"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

LAN_CLIENT="${LAN_CLIENT:-$CLUSTER_LAN_HOST}"
TARGET="${TARGET:-$IPERF_TARGET4}"
POOL_NAME="${POOL_NAME:-pnat8341o}"
POOL_ADDR="${POOL_ADDR:-172.16.80.13}"
POOL_LOW="${POOL_LOW:-51300}"; POOL_HIGH="${POOL_HIGH:-51399}"
# #8440 measured ZERO sessions under a catch-all pool; this script measured
# pool-translated sessions under one. The pools differed in exactly one thing —
# #8440's carried `persistent-nat`. PERSISTENT=1 adds that stanza so the two can
# be run back to back with nothing else changed.
PERSISTENT="${PERSISTENT:-0}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
SNAT_RULESET="${SNAT_RULESET:-lan-to-wan}"; SNAT_RULE="${SNAT_RULE:-snat}"
PORT_A="${PORT_A:-5201}"; PORT_B="${PORT_B:-5202}"

info() { echo "==> $*"; }
fw_cli() { incus exec "$1" -- /usr/local/sbin/cli -c "$2" 2>/dev/null; }
primary_node() {
	local status secondary
	status="$(fw_cli "$FW0" "show chassis cluster status" || true)"
	secondary="$(printf '%s\n' "$status" | deploy_rolling_secondary_node)"
	if [ "$secondary" = "0" ]; then echo "$FW1"; else echo "$FW0"; fi
}
PRIMARY="$(primary_node)"
SRC_IP="$(incus exec "$LAN_CLIENT" -- bash -lc "ip -4 -o addr show scope global | awk 'NR==1{split(\$4,a,\"/\"); print a[1]}'")"

restore_config() {
	info "Restoring interface SNAT on both nodes"
	local node
	for node in "$FW0" "$FW1"; do
		incus exec "$node" -- /usr/local/sbin/cli >/dev/null 2>&1 <<EOF || true
configure
rollback 0
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
delete security nat source pool ${POOL_NAME}
commit
exit
quit
EOF
	done
}
trap restore_config EXIT

# Sessions live 1800s, so a count taken in a later phase includes every session
# the EARLIER phases created. Measured: the first run of this script reported
# "sess=2" during the pool phase and concluded "sessions still install" — those
# were the baseline's own sessions, unchanged, while ICMP and both TCP connects
# were failing. Clearing per phase is what makes a count phase-local.
clear_sessions() { fw_cli "$PRIMARY" "clear security flow session" >/dev/null 2>&1 || true; }

# One TCP probe: hold the socket, count OUR scoped session, report reachability.
# `n` is the phase-local session count; `pool_n` counts sessions translated to the
# POOL address, which ONLY a new pool-mode session can produce — a count alone
# cannot tell a fresh pool session from a stale interface one.
probe_tcp() {   # port -> "connect sessions poolsessions"
	local port="$1" c n pn
	incus exec "$LAN_CLIENT" -- bash -lc \
		"nohup timeout 20 bash -c 'exec 3<>/dev/tcp/${TARGET}/${port}; sleep 15' >/dev/null 2>&1 &" || true
	sleep 4
	c="$(incus exec "$LAN_CLIENT" -- bash -lc \
		"timeout 4 bash -c 'exec 3<>/dev/tcp/${TARGET}/${port}' >/dev/null 2>&1 && echo OK || echo FAILED")"
	n="$(fw_cli "$PRIMARY" "show security flow session destination-prefix ${TARGET}" \
		| grep -F "$SRC_IP" | grep -c "tcp" || true)"
	pn="$(fw_cli "$PRIMARY" "show security flow session destination-prefix ${TARGET}" \
		| grep -c "${POOL_ADDR}" || true)"
	echo "${c} ${n:-0} ${pn:-0}"
}
probe_icmp() {
	incus exec "$LAN_CLIENT" -- bash -lc \
		"ping -c3 -W2 ${TARGET} >/dev/null 2>&1 && echo OK || echo LOSS"
}

report() { printf '  %-26s icmp=%-5s tcp%s=%-7s sess=%-3s pool=%-3s tcp%s=%-7s sess=%-3s pool=%s\n' "$@"; }

info "#8341 outage triage on $PRIMARY (client $SRC_IP -> $TARGET)"

info "BASELINE: interface SNAT (control — sessions MUST be > 0 or this cell is void)"
b_icmp="$(probe_icmp)"; clear_sessions; read -r b_a b_an b_ap <<<"$(probe_tcp "$PORT_A")"; read -r b_b b_bn b_bp <<<"$(probe_tcp "$PORT_B")"
report "before / interface" "$b_icmp" "$PORT_A" "$b_a" "$b_an" "$b_ap" "$PORT_B" "$b_b" "$b_bn" "$b_bp"
if [ "${b_an:-0}" -eq 0 ] && [ "${b_bn:-0}" -eq 0 ]; then
	echo "FATAL: the interface-SNAT control installed no sessions, so this cell would be" >&2
	echo "measuring an already-unhealthy cluster rather than the pool config." >&2
	exit 2
fi

PNAT_LINES=""
if [ "$PERSISTENT" = 1 ]; then
	PNAT_LINES="set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}"
fi
info "Applying: catch-all ${SNAT_RULESET}/${SNAT_RULE} -> pool ${POOL_NAME} (${POOL_ADDR}) persistent-nat=${PERSISTENT}"
incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/pnat8341o.out 2>&1 <<EOF || true
configure
rollback 0
delete security nat source pool ${POOL_NAME}
set security nat source pool ${POOL_NAME} address ${POOL_ADDR}/32
set security nat source pool ${POOL_NAME} port range low ${POOL_LOW} high ${POOL_HIGH}
${PNAT_LINES}
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool ${POOL_NAME}
commit
exit
quit
EOF
# #6440: marker gate, not exit status — the piped CLI is a REPL that prints
# "error: ..." and still exits 0.
cos_require_markers "pool apply on $PRIMARY" /tmp/pnat8341o.out "$COS_MARKER_COMMIT" || {
	echo "FATAL: the pool config did not commit; not reporting an outage from a config never applied" >&2
	sed -n '1,30p' /tmp/pnat8341o.out >&2; exit 2; }

p_icmp="$(probe_icmp)"; clear_sessions; read -r p_a p_an p_ap <<<"$(probe_tcp "$PORT_A")"; read -r p_b p_bn p_bp <<<"$(probe_tcp "$PORT_B")"
report "during / catch-all pool" "$p_icmp" "$PORT_A" "$p_a" "$p_an" "$p_ap" "$PORT_B" "$p_b" "$p_bn" "$p_bp"

restore_config; trap - EXIT; sleep 4
a_icmp="$(probe_icmp)"; clear_sessions; read -r a_a a_an a_ap <<<"$(probe_tcp "$PORT_A")"; read -r a_b a_bn a_bp <<<"$(probe_tcp "$PORT_B")"
report "after / interface" "$a_icmp" "$PORT_A" "$a_a" "$a_an" "$a_ap" "$PORT_B" "$a_b" "$a_bn" "$a_bp"

echo
echo "======================================"
if [ "$p_icmp" != "OK" ] && [ "${p_ap:-0}" -eq 0 ] && [ "${p_bp:-0}" -eq 0 ]; then
	echo "OUTAGE: with the catch-all retargeted to a pool, NOTHING transits — ICMP and"
	echo "  both TCP ports. This is a forwarding outage on a plausible operator config,"
	echo "  not a persistent-NAT observability bug. File separately, above #8341."
elif [ "${p_ap:-0}" -eq 0 ] && [ "${p_bp:-0}" -eq 0 ]; then
	echo "TCP-ONLY: no TCP session installs under the catch-all pool, but ICMP still"
	echo "  transits (icmp=$p_icmp). Narrower than an outage and consistent with #8341's"
	echo "  original 'ICMP works, TCP does not' framing."
else
	echo "NOT AN OUTAGE: sessions still install under the catch-all pool"
	echo "  (tcp${PORT_A}=${p_an}, tcp${PORT_B}=${p_bn}). The #8440 zero was narrower than"
	echo "  the config change — re-examine what differed in that run."
fi
echo "  after-restore control: icmp=$a_icmp tcp${PORT_A} sess=$a_an (must be > 0)"
echo "======================================"
