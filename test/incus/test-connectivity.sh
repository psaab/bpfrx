#!/usr/bin/env bash
# bpfrx connectivity test suite
#
# Validates end-to-end connectivity for standalone and cluster deployments.
# Handles VRF-aware pinging automatically — interfaces in a VRF use
# "ip vrf exec <vrf> ping" so tests work without manual intervention.
#
# Usage:
#   ./test/incus/test-connectivity.sh              # Run all tests
#   ./test/incus/test-connectivity.sh standalone    # Standalone only
#   ./test/incus/test-connectivity.sh cluster       # Cluster only

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

PASS=0
FAIL=0
SKIP=0
ERRORS=()

# ── Helpers ──────────────────────────────────────────────────────────

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
skip()  { echo "  SKIP  $*"; SKIP=$((SKIP + 1)); }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

# ping_vrf_aware <instance> <ping_args...>
# Tries ping in default table first, then each VRF until one succeeds.
# Returns 0 on success, 1 on failure.
ping_vrf_aware() {
	local inst="$1"; shift
	# Try default table
	if incus exec "$inst" -- ping "$@" </dev/null &>/dev/null; then
		return 0
	fi
	# Collect VRFs into array (avoid stdin issues with incus exec in loops)
	local vrfs
	vrfs=$(incus exec "$inst" -- ip vrf show 2>/dev/null | awk '/^[a-zA-Z]/ && NR>1{print $1}' || true)
	local vrf
	for vrf in $vrfs; do
		if incus exec "$inst" -- ip vrf exec "$vrf" ping "$@" </dev/null &>/dev/null; then
			return 0
		fi
	done
	return 1
}

# ping_test <instance> <target_ip> <description>
# VRF-aware ping — automatically tries all VRFs if default table fails.
ping_test() {
	local inst="$1" ip="$2" desc="$3"
	if ping_vrf_aware "$inst" -c 2 -W 2 "$ip"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# ping6_test <instance> <target_ip> <description>
ping6_test() {
	local inst="$1" ip="$2" desc="$3"
	if ping_vrf_aware "$inst" -6 -c 2 -W 2 "$ip"; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# service_check <instance> <description>
# Verifies bpfrxd is running and not in a crash loop.
service_check() {
	local inst="$1" desc="$2"
	if incus exec "$inst" -- systemctl is-active --quiet bpfrxd 2>/dev/null; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

# ── Standalone Tests ─────────────────────────────────────────────────

test_standalone() {
	info "Standalone firewall (bpfrx-fw)"

	if ! instance_running "bpfrx-fw"; then
		skip "bpfrx-fw not running — skipping standalone tests"
		return
	fi

	# Service health
	service_check "bpfrx-fw" "standalone: bpfrxd service active"

	# Direct host reachability (from firewall, auto VRF detection)
	ping_test "bpfrx-fw" "10.0.1.102"  "standalone: fw → trust-host (10.0.1.102)"
	ping_test "bpfrx-fw" "10.0.2.102"  "standalone: fw → untrust-host (10.0.2.102)"
	ping_test "bpfrx-fw" "10.0.30.101" "standalone: fw → dmz-host (10.0.30.101)"
	ping_test "bpfrx-fw" "172.16.50.1" "standalone: fw → WAN gateway (172.16.50.1)"

	# Cross-zone: trust → untrust (requires policy permit + SNAT)
	if instance_running "trust-host" && instance_running "untrust-host"; then
		ping_test "trust-host" "10.0.2.102" "standalone: trust-host → untrust-host IPv4"
		ping6_test "trust-host" "2001:559:8585:bf02::102" "standalone: trust-host → untrust-host IPv6"
	else
		skip "standalone: cross-zone tests (trust-host or untrust-host not running)"
	fi

	# Cross-zone: trust → dmz (skipped — DMZ is in vrf-dmz-vr,
	# inter-VRF cross-zone routing not configured in test env)
}

# ── Cluster Tests ────────────────────────────────────────────────────

test_cluster() {
	info "Cluster HA (bpfrx-fw0 + bpfrx-fw1)"

	if ! instance_running "bpfrx-fw0" || ! instance_running "bpfrx-fw1"; then
		skip "bpfrx-fw0 or bpfrx-fw1 not running — skipping cluster tests"
		return
	fi

	# Service health
	service_check "bpfrx-fw0" "cluster: bpfrxd service active on fw0"
	service_check "bpfrx-fw1" "cluster: bpfrxd service active on fw1"

	# Heartbeat connectivity (auto VRF — fxp1/fab0 may be in vrf-mgmt)
	ping_test "bpfrx-fw0" "10.99.0.2" "cluster: fw0 → fw1 heartbeat (10.99.0.2)"
	ping_test "bpfrx-fw1" "10.99.0.1" "cluster: fw1 → fw0 heartbeat (10.99.0.1)"

	# Fabric connectivity
	ping_test "bpfrx-fw0" "10.99.1.2" "cluster: fw0 → fw1 fabric (10.99.1.2)"
	ping_test "bpfrx-fw1" "10.99.1.1" "cluster: fw1 → fw0 fabric (10.99.1.1)"

	# WAN gateway
	ping_test "bpfrx-fw0" "172.16.50.1" "cluster: fw0 → WAN gateway (172.16.50.1)"

	# LAN host connectivity
	if instance_running "cluster-lan-host"; then
		# From firewall to LAN host
		ping_test "bpfrx-fw0" "10.0.60.102" "cluster: fw0 → LAN host (10.0.60.102)"

		# From LAN host to RETH VIP (proves VRRP is working)
		ping_test "cluster-lan-host" "10.0.60.1" "cluster: LAN host → RETH VIP (10.0.60.1)"

		# Cross-zone: LAN host through firewall to WAN gateway
		ping_test "cluster-lan-host" "172.16.50.1" "cluster: LAN host → WAN gateway cross-zone (172.16.50.1)"

		# IPv6 LAN connectivity
		ping6_test "cluster-lan-host" "2001:559:8585:cf01::1" "cluster: LAN host → RETH VIP IPv6"
	else
		skip "cluster: LAN host tests (cluster-lan-host not running)"
	fi
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
	local mode="${1:-all}"

	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  bpfrx connectivity test suite"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo

	case "$mode" in
		standalone) test_standalone ;;
		cluster)    test_cluster ;;
		all)        test_standalone; echo; test_cluster ;;
		*)          echo "Usage: $0 [standalone|cluster|all]"; exit 1 ;;
	esac

	echo
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped"
	echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

	if [[ $FAIL -gt 0 ]]; then
		echo
		echo "Failures:"
		for err in "${ERRORS[@]}"; do
			echo "  - $err"
		done
		exit 1
	fi
}

main "$@"
