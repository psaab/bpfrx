#!/usr/bin/env bash
# #8447: is the forwarding stop a WEDGE or a TRANSIENT, and what does the apply
# itself report?
#
# Established: applying a persistent-nat source pool takes transit rx to 0. Two
# things an operator hitting this needs that the previous runs did not answer:
#
#   1. DOES IT RECOVER without a restart? Removing the stanza is the obvious
#      remedy, and whether that is enough decides whether this is a
#      configuration mistake you can back out of or a node you have to bounce.
#      Earlier runs restored config on exit and the cluster was healthy
#      afterwards, which HINTS at recovery -- but that was cleanup, never a
#      measurement, and a hint from a teardown path is not evidence.
#
#   2. WHAT DOES THE APPLY SAY? A reconcile that fails and logs, and one that
#      reports success while leaving nothing bound, are different bugs with
#      different fixes. The helper's own log is cheaper than any new counter.
#
# THREE PHASES, and the third is the point: plain -> persistent -> plain again,
# each measured the same way. Phase 3 sharing phase 1's configuration is what
# makes "recovered" mean something: it is the same fixture, so a difference
# between them is the node's state rather than the config's.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-wedge-recovery-8447 $*" "$0" "$@"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

LAN_CLIENT="${LAN_CLIENT:-$CLUSTER_LAN_HOST}"
TARGET="${TARGET:-$IPERF_TARGET4}"
POOL_SRC="${POOL_SRC:-10.0.61.240}"
POOL_PORT="${POOL_PORT:-5210}"
POOL_NAME="${POOL_NAME:-wedge8447}"
POOL_ADDR="${POOL_ADDR:-172.16.80.13}"
POOL_LOW="${POOL_LOW:-51900}"; POOL_HIGH="${POOL_HIGH:-51999}"
PNAT_TIMEOUT="${PNAT_TIMEOUT:-300}"
SNAT_RULESET="${SNAT_RULESET:-lan-to-wan}"; SHAPE_RULE="${SHAPE_RULE:-pool-snat}"
ORIG_POOL="${ORIG_POOL:-pool-snat-pool}"

info() { echo "==> $*"; }
fw_cli() { incus exec "$1" -- /usr/local/sbin/cli -c "$2" 2>/dev/null; }
primary_node() {
	local status secondary
	status="$(fw_cli "$FW0" "show chassis cluster status" || true)"
	secondary="$(printf '%s\n' "$status" | deploy_rolling_secondary_node)"
	if [ "$secondary" = "0" ]; then echo "$FW1"; else echo "$FW0"; fi
}
PRIMARY="$(primary_node)"
LAN_IF="$(incus exec "$LAN_CLIENT" -- bash -c \
	"ip -4 -o route get ${LAN_GW:-10.0.61.1} 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p'" | tr -d '\r')"
[ -n "$LAN_IF" ] || { echo "FATAL: could not resolve the LAN interface" >&2; exit 2; }

restore() {
	info "Restoring ${SHAPE_RULE} -> ${ORIG_POOL}"
	incus exec "$LAN_CLIENT" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	incus exec "$LAN_CLIENT" -- bash -c "ip addr del ${POOL_SRC}/24 dev ${LAN_IF} 2>/dev/null" || true
	local node
	for node in "$FW0" "$FW1"; do
		incus exec "$node" -- /usr/local/sbin/cli >/dev/null 2>&1 <<EOF || true
configure
rollback 0
delete security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool ${ORIG_POOL}
delete security nat source pool ${POOL_NAME}
commit
exit
quit
EOF
	done
}
trap restore EXIT
incus exec "$LAN_CLIENT" -- bash -c "ip addr add ${POOL_SRC}/24 dev ${LAN_IF} 2>/dev/null" || true

rx_now() {
	incus exec "$PRIMARY" -- bash -lc "curl -s --max-time 8 http://127.0.0.1:8080/metrics" 2>/dev/null \
		| awk '/^xpf_packets_total\{direction="rx"\}/ {print $2; f=1} END{ if(!f) print "ABSENT" }'
}

phase() {   # label, persistent(0|1) -> prints one row
	local label="$1" persistent="$2" pnat="" seen r0 r1 since
	if [ "$persistent" = 1 ]; then
		pnat="set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}"
	fi
	since="$(incus exec "$PRIMARY" -- date '+%Y-%m-%d %H:%M:%S')"
	incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/wedge.out 2>&1 <<EOF || true
configure
rollback 0
delete security nat source pool ${POOL_NAME}
set security nat source pool ${POOL_NAME} address ${POOL_ADDR}/32
set security nat source pool ${POOL_NAME} port range low ${POOL_LOW} high ${POOL_HIGH}
${pnat}
delete security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool
set security nat source rule-set ${SNAT_RULESET} rule ${SHAPE_RULE} then source-nat pool ${POOL_NAME}
commit
exit
quit
EOF
	if ! cos_require_markers "phase ${label} apply" /tmp/wedge.out "$COS_MARKER_COMMIT" >/dev/null; then
		printf '  %-26s %-12s %s\n' "$label" "COMMIT-FAILED" "-"; return
	fi
	seen="$(fw_cli "$PRIMARY" "show configuration security nat source" \
		| awk -v p="pool ${POOL_NAME} {" '
			index($0,p){f=1} f{d+=gsub(/{/,"{"); d-=gsub(/}/,"}")}
			f&&/persistent-nat/{print "yes"; exit} f&&d<=0{exit}')"
	if { [ "$persistent" = 1 ] && [ "$seen" != yes ]; } || { [ "$persistent" = 0 ] && [ "$seen" = yes ]; }; then
		printf '  %-26s %-12s %s\n' "$label" "FIXTURE-MISMATCH" "-"; return
	fi
	# What did the apply itself say? Captured per phase, not just for the
	# persistent one — a message that appears in every phase is not evidence
	# about persistent-nat.
	incus exec "$PRIMARY" -- bash -lc \
		"journalctl -u xpfd --since '${since}' --no-pager 2>/dev/null | grep -icE 'error|warn|fail|reconcile'" \
		> "/tmp/wedge-log-${label// /_}.count" 2>/dev/null || echo 0 > "/tmp/wedge-log-${label// /_}.count"
	incus exec "$PRIMARY" -- bash -lc \
		"journalctl -u xpfd --since '${since}' --no-pager 2>/dev/null | grep -iE 'error|warn|fail' | tail -6" \
		> "/tmp/wedge-log-${label// /_}.txt" 2>/dev/null || true
	fw_cli "$PRIMARY" "clear security flow session" >/dev/null 2>&1 || true
	r0="$(rx_now)"
	incus exec "$LAN_CLIENT" -- bash -c \
		"nohup iperf3 --forceflush --connect-timeout 5000 -B ${POOL_SRC} -t 15 -c ${TARGET} -p ${POOL_PORT} -P 2 >/dev/null 2>&1 &" || true
	sleep 12
	r1="$(rx_now)"
	incus exec "$LAN_CLIENT" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	if [ "$r0" = ABSENT ] || [ "$r1" = ABSENT ]; then
		printf '  %-26s %-12s %s\n' "$label" "RX-ABSENT" "$(cat "/tmp/wedge-log-${label// /_}.count")"
	else
		printf '  %-26s %-12s %s\n' "$label" "$((r1-r0))" "$(cat "/tmp/wedge-log-${label// /_}.count")"
	fi
}

info "#8447 wedge/recovery probe on $PRIMARY"
echo
printf '  %-26s %-12s %s\n' "phase" "rx delta" "log lines(err/warn/fail/reconcile)"
phase "1 plain (baseline)" 0
phase "2 persistent-nat" 1
# TIME IS A CONFOUND FOR RECOVERY. Phase 3 runs later than phase 2, so "rx came
# back" is equally consistent with "removing the stanza fixed it" and "the stop
# was transient in TIME and would have cleared anyway". Phase 2b re-measures
# with persistent-nat STILL APPLIED, after the same interval phase 3 would have
# waited: if rx is still 0 here, elapsed time is not the remedy and phase 3's
# recovery is attributable to the config change.
phase "2b persistent (still, later)" 1
phase "3 plain again (recovery)" 0
echo
echo "=== what the apply logged during phase 2 ==="
sed -n '1,6p' /tmp/wedge-log-2_persistent-nat.txt 2>/dev/null || echo "(none captured)"
echo
echo "======================================"
echo "Phase 3 shares phase 1's configuration exactly, so comparing them is a"
echo "comparison of NODE STATE, not of config. rx recovering in phase 3 means the"
echo "stop is a TRANSIENT the operator can back out of; rx still 0 means the node"
echo "is WEDGED and a config revert is not enough."
echo "======================================"
