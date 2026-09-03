#!/usr/bin/env bash
# #8447: WHICH upstream stage drops the flow?
#
# The rule-match counters showed `consulted = 0` under a persistent-NAT pool
# while the plain-pool control saw 1: no flow reaches source-NAT at all. This
# locates the stage that does.
#
# IT ADDS NO INSTRUMENT. Before building a counter for a stage I would have to
# GUESS (policy, route/egress resolution, snapshot apply), this diffs EVERY
# counter the node already publishes across the same traffic in both arms. A
# stage that drops the flow almost certainly already counts it somewhere, and
# a shotgun over the existing surface finds that without committing to a
# hypothesis first. Only if nothing moves is a new counter warranted -- and
# then "nothing moved anywhere" is itself the finding.
#
# READ AS A DIFFERENCE OF DELTAS. Absolute counters include everything since
# boot; a per-arm delta includes background traffic. What localises the stage is
# a counter whose delta is materially different between the two arms, because
# the arms differ only by the persistent-nat stanza.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-cell.sh
source "${SCRIPT_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "pnat-upstream-stage-8447 $*" "$0" "$@"
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
POOL_NAME="${POOL_NAME:-up8447}"
POOL_ADDR="${POOL_ADDR:-172.16.80.13}"
POOL_LOW="${POOL_LOW:-51700}"; POOL_HIGH="${POOL_HIGH:-51799}"
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

# All numeric metrics, one "name value" per line, unlabelled names only so the
# arithmetic below cannot silently sum across label sets.
snap_metrics() {
	incus exec "$PRIMARY" -- bash -lc "curl -s --max-time 8 http://127.0.0.1:8080/metrics" 2>/dev/null \
		| awk '/^xpf_/ && NF==2 && $2 ~ /^-?[0-9.e+]+$/ { print $1, $2 }' | sort
}

run_arm() {   # persistent(0|1), outfile
	local persistent="$1" out="$2" pnat=""
	if [ "$persistent" = 1 ]; then
		pnat="set security nat source pool ${POOL_NAME} persistent-nat permit any-remote-host
set security nat source pool ${POOL_NAME} persistent-nat inactivity-timeout ${PNAT_TIMEOUT}"
	fi
	incus exec "$PRIMARY" -- /usr/local/sbin/cli >/tmp/up8447.out 2>&1 <<EOF || true
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
	cos_require_markers "arm apply on $PRIMARY" /tmp/up8447.out "$COS_MARKER_COMMIT" \
		|| { echo "COMMIT-FAILED" > "$out"; return; }
	# The fixture must BE what it claims: an arm whose persistent-nat did not
	# take is indistinguishable from persistent-nat working.
	local seen
	seen="$(fw_cli "$PRIMARY" "show configuration security nat source" \
		| awk -v p="pool ${POOL_NAME} {" '
			index($0,p){f=1} f{d+=gsub(/{/,"{"); d-=gsub(/}/,"}")}
			f&&/persistent-nat/{print "yes"; exit} f&&d<=0{exit}')"
	if { [ "$persistent" = 1 ] && [ "$seen" != yes ]; } || { [ "$persistent" = 0 ] && [ "$seen" = yes ]; }; then
		echo "FIXTURE-MISMATCH" > "$out"; return
	fi
	fw_cli "$PRIMARY" "clear security flow session" >/dev/null 2>&1 || true
	snap_metrics > "${out}.before"
	incus exec "$LAN_CLIENT" -- bash -c \
		"nohup iperf3 --forceflush --connect-timeout 5000 -B ${POOL_SRC} -t 15 -c ${TARGET} -p ${POOL_PORT} -P 2 >/dev/null 2>&1 &" || true
	sleep 12
	snap_metrics > "${out}.after"
	incus exec "$LAN_CLIENT" -- pkill -9 -f "iperf3.*-B ${POOL_SRC}" 2>/dev/null || true
	join "${out}.before" "${out}.after" | awk '{d=$3-$2; if (d != 0) print $1, d}' | sort > "$out"
}

# ARM ORDER IS A CONFOUND, so it is a variable. The arms run sequentially, and
# a run where the second arm reads zero everywhere is equally consistent with
# "the stanza did it" and "the cluster degraded during the first arm". ORDER=
# reverse runs persistent FIRST: if the zeros follow the STANZA they move with
# it, and if they follow the POSITION they stay in the second slot.
ORDER="${ORDER:-normal}"
info "#8447 upstream-stage probe on $PRIMARY (arm order: ${ORDER})"
if [ "$ORDER" = reverse ]; then
	run_arm 1 /tmp/up-pnat
	run_arm 0 /tmp/up-plain
else
	run_arm 0 /tmp/up-plain
	run_arm 1 /tmp/up-pnat
fi
for f in /tmp/up-plain /tmp/up-pnat; do
	if grep -qE "COMMIT-FAILED|FIXTURE-MISMATCH" "$f" 2>/dev/null; then
		echo "VOID: $(cat "$f") in $(basename "$f") — not comparing arms that were not what they claimed."
		exit 0
	fi
done

echo
echo "=== counters that MOVED in each arm (delta != 0) ==="
printf '%-64s %10s %10s\n' "metric" "plain" "persistent"
join -a1 -a2 -e0 -o 0,1.2,2.2 /tmp/up-plain /tmp/up-pnat | while read -r name a b; do
	[ "$a" = "$b" ] && continue
	printf '%-64s %10s %10s\n' "$name" "$a" "$b"
done
echo
echo "======================================"
echo "Read the rows where the two columns DIFFER: the arms are one stanza apart,"
echo "so a counter that moves in one and not the other is the stage that reacted."
echo "If no row differs, no existing counter observes this and a new one is owed."
echo "======================================"
