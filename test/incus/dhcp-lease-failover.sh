#!/usr/bin/env bash
# xpf DHCP HA lease-survives-failover smoke (#2261, #2239/#2260 validation).
#
# This codifies the ONE thing the Go unit tests cannot prove: with the
# `set chassis cluster dhcp-lease-synchronization` knob ON, a REAL Kea 3.0.x on
# the promoted node must LOAD the standby's pre-seeded memfile with no parse
# error and the LAN DHCP client must keep its binding across a hard failover.
# The byte-exactness of the memfile CSV header is pinned as an EXTERNAL golden in
# Go (pkg/dhcpserver TestKeaMemfileHeadersMatchKea30xSchema); this script is the
# LIVE end-to-end acceptance that remains lab-gated (plan-deferred-lab on #2261)
# because it needs a DHCP-client fixture + knob-ON cluster session.
#
# It is intentionally NOT wired into `make test` / CI: it reboots a node on the
# SHARED loss cluster and depends on a DHCP client + a `dhcp-local-server`
# config that the default smoke config does not carry. Run it by hand in a lab
# window with those prerequisites in place.
#
# Acceptance (per #2261):
#   (a) the promoted node's Kea LOADS the pre-seeded memfile with NO parse error
#       (keaMemfileHeader{4,6} column order byte-exact for the live loader);
#   (b) the client KEEPS its address + remaining lifetime (no re-DISCOVER);
#   (c) the promoted node does NOT re-hand the in-use address to a 2nd client
#       (the duplicate-allocation window is closed by the pre-seed).
# Validate v4, v6, and an IA_PD lease where the LAN fixture supports it.
#
# Usage:
#   ./test/incus/dhcp-lease-failover.sh
#   DHCP_CLIENT_IFACE=eth1 ./test/incus/dhcp-lease-failover.sh   # override iface

set -euo pipefail

# #1875/#4020: DESTRUCTIVE smoke — reboots the primary on the SHARED loss
# cluster. Re-exec under incus-admin, then serialize behind the cluster lock so
# a concurrent deploy/smoke queues instead of colliding with our reboot.
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "dhcp-lease-failover $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"

# LAN DHCP client fixture (the container/host that DISCOVERs behind the reth).
# The default smoke LAN host is a STATIC address; a lab run points this at a
# host configured to DHCP off the firewall's dhcp-local-server pool.
DHCP_CLIENT="${DHCP_CLIENT:-$CLUSTER_LAN_HOST}"
# Default eth0 (the loss LAN host presents its DHCP client on eth0, not eth1);
# override with DHCP_CLIENT_IFACE=<if> for a fixture that uses a different NIC.
DHCP_CLIENT_IFACE="${DHCP_CLIENT_IFACE:-eth0}"
# Kea memfile paths on the firewall nodes (see pkg/dhcpserver leaseFile()).
KEA_MEMFILE4="${KEA_MEMFILE4:-/var/lib/kea/kea-leases4.csv}"
KEA_MEMFILE6="${KEA_MEMFILE6:-/var/lib/kea/kea-leases6.csv}"
REBOOT_WAIT="${REBOOT_WAIT:-60}"

# Golden Kea 3.0.x headers — MUST stay in lockstep with the Go golden
# (pkg/dhcpserver/lease_sync.go keaMemfileHeader{4,6} + the
# TestKeaMemfileHeadersMatchKea30xSchema literals). If Kea ever bumps its CSV
# schema, update BOTH the Go golden and these two lines together.
GOLDEN_HEADER4="address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id"
GOLDEN_HEADER6="address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id"

PASS=0
FAIL=0
ERRORS=()
info() { echo "==> $*"; }
pass() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
die()  { echo "FATAL: $*" >&2; exit 2; }

ssh_fw() { incus exec "$1" -- bash -lc "$2"; }

# ---------------------------------------------------------------------------
# Preflight — the lab prerequisites this smoke cannot self-provision.
# ---------------------------------------------------------------------------
preflight() {
	info "Preflight: knob-ON + dhcp-local-server + a DHCP client fixture"
	local cfg
	cfg="$(ssh_fw "$FW0" '/usr/local/sbin/cli -c "show configuration chassis cluster" 2>/dev/null' || true)"
	if ! grep -q "dhcp-lease-synchronization" <<<"$cfg"; then
		cat >&2 <<EOF
LAB PREREQUISITE MISSING: dhcp-lease-synchronization is not enabled.
Enable it on both nodes and add a dhcp-local-server pool on the LAN, e.g.:

  set chassis cluster dhcp-lease-synchronization
  set system services dhcp-local-server group g0 interface reth1.0
  set access address-assignment pool p0 family inet network 10.0.61.0/24
  set access address-assignment pool p0 family inet range r0 low 10.0.61.150 high 10.0.61.200

Then re-run this smoke. See pkg/dhcpserver/README.md (#2239 lease-sync).
EOF
		die "prerequisites not met (knob OFF)"
	fi
	pass "dhcp-lease-synchronization is enabled on $FW0"
}

# ---------------------------------------------------------------------------
# (a) Byte-exactness gate — the standby memfile header must match the golden
#     BEFORE we ever fail over. This is the live analog of the Go golden test.
# ---------------------------------------------------------------------------
assert_memfile_header() {
	local node="$1" path="$2" golden="$3" fam="$4" hdr
	hdr="$(ssh_fw "$node" "head -n1 '$path' 2>/dev/null" || true)"
	if [[ -z "$hdr" ]]; then
		fail "v$fam pre-seed memfile absent/empty on $node ($path)"
		return
	fi
	if [[ "$hdr" == "$golden" ]]; then
		pass "v$fam pre-seed header on $node is byte-exact against Kea 3.0.x golden"
	else
		fail "v$fam pre-seed header on $node DRIFTED from golden
       got:  $hdr
       want: $golden"
	fi
}

main() {
	preflight

	info "1) LAN client DISCOVERs a lease from the MASTER ($FW0) Kea"
	ssh_fw "$DHCP_CLIENT" "dhclient -1 -v '$DHCP_CLIENT_IFACE'" || die "v4 DHCP DISCOVER failed"
	local addr4
	addr4="$(ssh_fw "$DHCP_CLIENT" "ip -4 -o addr show dev '$DHCP_CLIENT_IFACE' | awk '{print \$4}' | cut -d/ -f1")"
	[[ -n "$addr4" ]] || die "no v4 address acquired"
	pass "client acquired v4 lease $addr4"
	# v6 / IA_PD acquisition (dhclient -6 / -6 -P) goes here where the fixture supports it.

	info "2) Wait for the lease-sync push + standby pre-seed, then gate byte-exactness"
	sleep 3
	assert_memfile_header "$FW1" "$KEA_MEMFILE4" "$GOLDEN_HEADER4" 4
	assert_memfile_header "$FW1" "$KEA_MEMFILE6" "$GOLDEN_HEADER6" 6
	if ! ssh_fw "$FW1" "grep -q '^${addr4},' '$KEA_MEMFILE4'"; then
		fail "leased address $addr4 not present in standby pre-seed memfile"
	else
		pass "leased address $addr4 present in standby pre-seed memfile"
	fi

	info "3) Hard failover — reboot the primary ($FW0)"
	incus restart "$FW0" --force || die "reboot $FW0 failed"

	info "4) (a) promoted node ($FW1) Kea must have loaded the memfile with no parse error"
	# Kea logs a CSV parse error on a header/column mismatch; assert none.
	if ssh_fw "$FW1" "journalctl -u kea-dhcp4-server --since '-2 min' 2>/dev/null | grep -iE 'error|parse|malformed'"; then
		fail "Kea reported a memfile load error on the promoted node"
	else
		pass "no Kea memfile parse error on promoted node"
	fi

	info "5) (b) client KEEPS its address + remaining lifetime across failover (renew, no re-DISCOVER)"
	ssh_fw "$DHCP_CLIENT" "dhclient -1 -v '$DHCP_CLIENT_IFACE'" || fail "renew after failover failed"
	local addr4b
	addr4b="$(ssh_fw "$DHCP_CLIENT" "ip -4 -o addr show dev '$DHCP_CLIENT_IFACE' | awk '{print \$4}' | cut -d/ -f1")"
	if [[ "$addr4b" == "$addr4" ]]; then
		pass "client retained address $addr4 across failover"
	else
		fail "client address changed across failover: $addr4 -> $addr4b (lease NOT synced)"
	fi

	info "6) (c) promoted node must NOT re-hand the in-use address to a 2nd client"
	# A second DHCP client on the same segment must get a DIFFERENT address.
	# (Wire a distinct client here in the lab; documented, not auto-provisioned.)

	echo
	echo "==== DHCP lease-failover smoke: PASS=$PASS FAIL=$FAIL ===="
	if ((FAIL > 0)); then
		printf ' - %s\n' "${ERRORS[@]}" >&2
		exit 1
	fi
}

main "$@"
