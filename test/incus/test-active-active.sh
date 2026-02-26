#!/usr/bin/env bash
# bpfrx cluster active/active RG failover test
#
# Validates that active TCP connections survive when a single redundancy
# group is moved to the peer node (active/active per-RG split).
#
# This tests fabric cross-chassis forwarding: traffic entering on the
# LAN (RG2, fw0) must cross the fabric link to exit on the WAN (RG1, fw1)
# when the RGs are split across nodes.
#
# Requires: bpfrx-fw0, bpfrx-fw1, cluster-lan-host running.
# Requires: iperf3 server reachable at IPERF_TARGET (default 172.16.100.247).
#
# Tests:
#   1. Start iperf3 from LAN host through the firewall to WAN target
#   2. Failover RG1 (WAN) to fw1 — LAN stays on fw0 (active/active split)
#   3. Verify iperf3 survives the split (fabric cross-forwarding)
#   4. Failover RG1 back to fw0 — all RGs on fw0 again
#   5. Verify iperf3 survives the reunification
#
# Usage:
#   ./test/incus/test-active-active.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-active-active.sh

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

IPERF_TARGET="${IPERF_TARGET:-172.16.100.247}"
IPERF_DURATION=60       # seconds — enough to span two failovers
IPERF_STREAMS=4
SETTLE_WAIT=3           # seconds to let VRRP + election settle
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this

PASS=0
FAIL=0
ERRORS=()

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }

die() { echo "FATAL: $*" >&2; exit 2; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

cleanup() {
	# Kill iperf3 on LAN host
	incus exec cluster-lan-host -- pkill -9 iperf3 2>/dev/null || true
	# Reset any manual failovers
	incus exec bpfrx-fw0 -- cli -c 'request chassis cluster failover reset redundancy-group 1' 2>/dev/null || true
	incus exec bpfrx-fw1 -- cli -c 'request chassis cluster failover reset redundancy-group 1' 2>/dev/null || true
}

trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"

for inst in bpfrx-fw0 bpfrx-fw1 cluster-lan-host; do
	instance_running "$inst" || die "$inst is not running"
done

# Verify fw0 is primary for all RGs
fw0_status=$(incus exec bpfrx-fw0 -- cli -c 'show chassis cluster status' 2>/dev/null)
rg0_primary=$(echo "$fw0_status" | grep -A2 "Redundancy group: 0" | grep "node0" | grep -c "primary" || true)
rg1_primary=$(echo "$fw0_status" | grep -A2 "Redundancy group: 1" | grep "node0" | grep -c "primary" || true)
rg2_primary=$(echo "$fw0_status" | grep -A2 "Redundancy group: 2" | grep "node0" | grep -c "primary" || true)

if [[ "$rg0_primary" -eq 1 && "$rg1_primary" -eq 1 && "$rg2_primary" -eq 1 ]]; then
	pass "fw0 is primary for all RGs"
else
	die "fw0 is not primary for all RGs — reset cluster state first"
fi

# Verify iperf target reachable
if incus exec cluster-lan-host -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from cluster-lan-host"
fi

# Kill any stale iperf3
incus exec cluster-lan-host -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

info "Phase 1: Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} → ${IPERF_TARGET}"

incus exec cluster-lan-host -- bash -c \
	"iperf3 --connect-timeout 2000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -P ${IPERF_STREAMS} > /tmp/iperf3-active-active.log 2>&1 &"

sleep 3

# Verify iperf3 is running
if incus exec cluster-lan-host -- pgrep -x iperf3 &>/dev/null; then
	pass "iperf3 running"
else
	die "iperf3 failed to start — check /tmp/iperf3-active-active.log on cluster-lan-host"
fi

# ── Phase 2: Failover RG1 (WAN) to fw1 ──────────────────────────────

info "Phase 2: Failover RG1 (WAN) to node1 — creating active/active split"

incus exec bpfrx-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1' 2>/dev/null || true
sleep "$SETTLE_WAIT"

# Verify RG split: RG1 on fw1, RG2 on fw0
fw0_status=$(incus exec bpfrx-fw0 -- cli -c 'show chassis cluster status' 2>/dev/null)

rg1_node0=$(echo "$fw0_status" | grep -A2 "Redundancy group: 1" | grep "node0" | awk '{print $3}')
rg2_node0=$(echo "$fw0_status" | grep -A2 "Redundancy group: 2" | grep "node0" | awk '{print $3}')

if [[ "$rg1_node0" == "secondary" ]]; then
	pass "RG1 (WAN) moved to fw1"
else
	fail "RG1 did not move to fw1 (node0 state: $rg1_node0)"
fi

if [[ "$rg2_node0" == "primary" ]]; then
	pass "RG2 (LAN) stayed on fw0"
else
	fail "RG2 unexpectedly moved (node0 state: $rg2_node0)"
fi

# Verify VRRP states match cluster state
fw0_vrrp=$(incus exec bpfrx-fw0 -- cli -c 'show security vrrp' 2>/dev/null)

vrrp_101=$(echo "$fw0_vrrp" | grep "101" | head -1)
vrrp_102=$(echo "$fw0_vrrp" | grep "102" | head -1)

if echo "$vrrp_101" | grep -qi "BACKUP"; then
	pass "VRRP 101 (WAN) is BACKUP on fw0"
else
	fail "VRRP 101 (WAN) not BACKUP on fw0: $vrrp_101"
fi

if echo "$vrrp_102" | grep -qi "MASTER"; then
	pass "VRRP 102 (LAN) is MASTER on fw0"
else
	fail "VRRP 102 (LAN) not MASTER on fw0: $vrrp_102"
fi

# ── Phase 3: Verify iperf3 survives the split ────────────────────────

info "Phase 3: Verify traffic survives active/active split (fabric forwarding)"

sleep 5  # let traffic settle after failover

if incus exec cluster-lan-host -- pgrep -x iperf3 &>/dev/null; then
	# Check last few seconds of iperf3 output for throughput
	last_sum=$(incus exec cluster-lan-host -- tail -5 /tmp/iperf3-active-active.log 2>/dev/null | grep "SUM" | tail -1 || true)
	if echo "$last_sum" | grep -qiE "[0-9]+ [MG]bits/sec"; then
		bps=$(echo "$last_sum" | grep -oiE "[0-9.]+ [MG]bits/sec" | head -1)
		pass "iperf3 survived RG split ($bps)"
	else
		fail "iperf3 running but no throughput after RG split"
	fi
else
	fail "iperf3 died after RG split (active/active fabric forwarding broken)"
fi

# ── Phase 4: Failover RG1 back to fw0 ───────────────────────────────

info "Phase 4: Failover RG1 (WAN) back to node0 — reunifying all RGs"

incus exec bpfrx-fw0 -- cli -c 'request chassis cluster failover redundancy-group 1 node 0' 2>/dev/null || true
sleep "$SETTLE_WAIT"

# Verify all RGs back on fw0
fw0_status=$(incus exec bpfrx-fw0 -- cli -c 'show chassis cluster status' 2>/dev/null)

rg1_node0=$(echo "$fw0_status" | grep -A2 "Redundancy group: 1" | grep "node0" | awk '{print $3}')

if [[ "$rg1_node0" == "primary" ]]; then
	pass "RG1 (WAN) back on fw0"
else
	fail "RG1 did not return to fw0 (node0 state: $rg1_node0)"
fi

# ── Phase 5: Verify iperf3 survives reunification ────────────────────

info "Phase 5: Verify traffic survives RG reunification"

sleep 5

if incus exec cluster-lan-host -- pgrep -x iperf3 &>/dev/null; then
	last_sum=$(incus exec cluster-lan-host -- tail -5 /tmp/iperf3-active-active.log 2>/dev/null | grep "SUM" | tail -1 || true)
	if echo "$last_sum" | grep -qiE "[0-9]+ [MG]bits/sec"; then
		bps=$(echo "$last_sum" | grep -oiE "[0-9.]+ [MG]bits/sec" | head -1)
		pass "iperf3 survived RG reunification ($bps)"
	else
		fail "iperf3 running but no throughput after reunification"
	fi
else
	fail "iperf3 died after RG reunification"
fi

# ── Cleanup & Results ────────────────────────────────────────────────

# Kill iperf3
incus exec cluster-lan-host -- pkill -9 iperf3 2>/dev/null || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ ${FAIL} -gt 0 ]]; then
	echo ""
	echo "Failures:"
	for e in "${ERRORS[@]}"; do
		echo "  - $e"
	done
	exit 1
fi
