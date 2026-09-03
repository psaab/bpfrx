#!/usr/bin/env bash
# #8341 diagnostic: is a pool-mode persistent-NAT binding NEVER MINTED, or
# minted and RECLAIMED before it can be observed?
#
# WHY THE DISTINCTION IS THE WHOLE QUESTION. #7360's acceptance smoke reports
# "the ACTIVE minted no persistent-NAT binding", but its evidence is a single
# query taken ~3s AFTER three transient `exec 3<>/dev/tcp` opens have already
# returned. That supports "no binding observable at t+3s" and not "no binding
# was ever minted" -- and the two have different fixes. On this same cluster the
# #8280 phase of `make test-failover` DOES observe a pool-mode session
# (`PortAllocator::claim ran`), and the difference between the runs is that
# iperf3 keeps retrying, so a session is present when the query lands.
#
# THREE STATES, NOT TWO. The obvious framing is minted-vs-not, but there is a
# third that the existing message cannot express and that has a different cause:
#
#   A. no SESSION at all for the client -> the packet never reached the NAT
#      path; the defect is upstream of the allocator entirely.
#   B. session present, no BINDING at any tick -> the flow reaches NAT and
#      persistent-NAT declines to mint. The current story.
#   C. binding present at some tick, absent later -> minted then reclaimed.
#      The current story is WRONG and #8405's GARP is aimed at the wrong half.
#
# METHOD. Hold the observation window open rather than sampling faster: a
# BLOCKING connect to a port that never answers keeps the kernel retransmitting
# SYNs for ~2 minutes, so the half-open session (and any binding it mints) is
# live for the whole poll rather than for a few milliseconds. Sampling faster
# against a transient open would only make the race narrower, not decidable.
#
# Read-only with respect to traffic; it applies the same pool config #7360's
# smoke does and restores on exit. It does NOT fail anything over.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-mint-observability-8341 $*" "$0" "$@"
# cluster-env.sh resolves FW0/FW1/CLUSTER_LAN_HOST and remote-qualifies them
# (#5024); deploy-lib.sh provides deploy_rolling_secondary_node.
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

LAN_CLIENT="${LAN_CLIENT:-$CLUSTER_LAN_HOST}"
TARGET="${TARGET:-$IPERF_TARGET4}"
POOL_NAME="${POOL_NAME:-pnat8341}"
POOL_ADDR="${POOL_ADDR:-$WAN_VIP4}"
POOL_LOW="${POOL_LOW:-51200}"
POOL_HIGH="${POOL_HIGH:-51299}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
SNAT_RULESET="${SNAT_RULESET:-lan-to-wan}"
SNAT_RULE="${SNAT_RULE:-snat}"
# The port to hold a connection to. DEFAULTS TO A LIVE LISTENER (5201), not a
# dead one, and that is a correction rather than a preference: a dead port makes
# connect() sit in SYN-retransmit, which holds the window open but ALSO changes
# whether a session is installed at all. Measured with a dead port the probe
# reported "no session at any tick" — a verdict that could equally have been
# caused by the dead port as by the pool, which is a confound of the probe's own
# making. With a live listener the only variable left is interface-SNAT vs pool.
PROBE_PORT="${PROBE_PORT:-5201}"
POLL_SECS="${POLL_SECS:-40}"

info() { echo "==> $*"; }
fw_cli() { incus exec "$1" -- /usr/local/sbin/cli -c "$2" 2>/dev/null; }

primary_node() {
	local status secondary
	status="$(fw_cli "$FW0" "show chassis cluster status" || true)"
	secondary="$(printf '%s\n' "$status" | deploy_rolling_secondary_node)"
	if [ "$secondary" = "0" ]; then echo "$FW1"; else echo "$FW0"; fi
}
PRIMARY="$(primary_node)"

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

info "#8341 mint-observability probe on $PRIMARY (client $LAN_CLIENT -> $TARGET:$PROBE_PORT)"
incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/pnat8341-apply.out 2>&1 <<EOF || true
configure
rollback 0
delete security nat source pool ${POOL_NAME}
set security nat source pool ${POOL_NAME} address ${POOL_ADDR}/32
set security nat source pool ${POOL_NAME} port range low ${POOL_LOW} high ${POOL_HIGH}
set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}
delete security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat interface
set security nat source rule-set ${SNAT_RULESET} rule ${SNAT_RULE} then source-nat pool ${POOL_NAME}
commit
exit
quit
EOF
if ! grep -q "commit complete" /tmp/pnat8341-apply.out; then
	echo "FATAL: pool config did not commit; not probing a fixture that was never applied" >&2
	sed -n '1,40p' /tmp/pnat8341-apply.out >&2
	exit 2
fi
info "pool ${POOL_NAME} (${POOL_ADDR}:${POOL_LOW}-${POOL_HIGH}) committed"

SRC_IP="$(incus exec "$LAN_CLIENT" -- bash -lc "ip -4 -o addr show scope global | awk 'NR==1{split(\$4,a,\"/\"); print a[1]}'")"
info "client source IP: $SRC_IP"

# Hold the window open: a blocking connect that will sit in SYN-retransmit.
info "starting a BLOCKING connect (held ~${POLL_SECS}s) so the observation window is stable"
incus exec "$LAN_CLIENT" -- bash -lc \
	"nohup timeout $((POLL_SECS + 20)) bash -c 'exec 3<>/dev/tcp/${TARGET}/${PROBE_PORT}; sleep $((POLL_SECS + 10))' >/dev/null 2>&1 &" || true

echo
printf '%-6s %-10s %-12s %-28s %s\n' "t(s)" "sessions" "bindings" "translated to" "our binding (src -> natport)"
FIRST_SEEN=""; LAST_SEEN=""; ANY_SESSION=0
t=0
while [ "$t" -lt "$POLL_SECS" ]; do
	# COUNT THIS PROBE'S FLOW, NOT EVERY SESSION MENTIONING THE CLIENT.
	# Measured: a bare `grep -c "$SRC_IP"` counts unrelated background UDP from
	# the same host (seen translated to 172.16.50.8/udp) and reported 1-2
	# "sessions" on a run where the probe's own TCP flow produced none — a
	# count that looks like evidence while measuring something else. Scope it
	# to the destination and protocol this probe actually generates.
	sess="$(fw_cli "$PRIMARY" "show security flow session destination-prefix ${TARGET}" 2>/dev/null \
		| grep -F "$SRC_IP" | grep -c "tcp" || true)"
	tbl="$(fw_cli "$PRIMARY" "show security nat source persistent-nat-table" 2>/dev/null)"
	nb="$(printf '%s\n' "$tbl" | awk '/^Total persistent NAT bindings:/ {print $5; exit} /^No persistent NAT bindings/ {print 0; exit}')"
	ours="$(printf '%s\n' "$tbl" | awk -v ip="$SRC_IP" '$1 == ip {print $1" -> "$4; exit}')"
	# CONTROL: which address did the session actually get translated to? A
	# "no binding" verdict is only about persistent NAT if the POOL rule
	# matched at all — an interface-translated session (reth0.80's own
	# 172.16.80.8) would explain the absent binding without implicating the
	# mint path, and the two are indistinguishable from a session COUNT.
	xlat="$(fw_cli "$PRIMARY" "show security flow session destination-prefix ${TARGET}" 2>/dev/null \
		| grep -A2 -F "$SRC_IP" | awk '/Out:/ {print $4}' | head -1)"
	[ "${sess:-0}" -gt 0 ] && ANY_SESSION=1
	if [ -n "$ours" ]; then
		[ -z "$FIRST_SEEN" ] && FIRST_SEEN="$t"
		LAST_SEEN="$t"
	fi
	printf '%-6s %-10s %-12s %-28s %s\n' "$t" "${sess:-?}" "${nb:-?}" "${xlat:-<none>}" "${ours:-<none>}"
	sleep 2; t=$((t + 2))
done

echo
echo "======================================"
if [ -n "$FIRST_SEEN" ]; then
	echo "VERDICT C: the binding WAS minted — first observed at t=${FIRST_SEEN}s, last at t=${LAST_SEEN}s."
	echo "  '#8341: the active minted no binding' is therefore an artifact of WHEN the"
	echo "  query was taken, not of minting. The defect is downstream of the allocator."
elif [ "$ANY_SESSION" = 1 ]; then
	echo "VERDICT B: sessions for $SRC_IP existed but NO binding appeared at any tick."
	echo "  The flow reaches the NAT path and persistent-NAT declines to mint. The"
	echo "  current story holds, and the mint path is where to look."
else
	echo "VERDICT A: no session for $SRC_IP at any tick, so no binding could be minted."
	echo "  The packet never reached the NAT path — the defect is upstream of the"
	echo "  allocator entirely, and neither the mint path nor #8405's GARP is implicated."
fi
echo "======================================"
