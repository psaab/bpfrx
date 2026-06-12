#!/usr/bin/env bash
# xpf appliance image validation (#1879 Path C).
#
# Boots the baked artifacts under LOCAL incus (instance names
# xpf-image-* — never the shared loss cluster) and proves the
# first-boot contract:
#
#   a  no config drive  -> factory bootstrap: boots, xpfd active, fxp0
#      DHCP, sshd listening, AND the in-guest `xpfd verify-dataplane`
#      gate PASSES against the image's own kernel (the bake gate: the
#      image must never ship a verifier-failing shim).
#   b  valid day-0 drive -> config validated + installed + committed at
#      first boot (hostname applied, cli shows it); a reboot does NOT
#      re-apply (stamp).
#   c  invalid day-0 drive -> commit-check REJECT logged, nothing
#      installed, boot survives, factory bootstrap still reachable.
#
# Usage:
#   scripts/image/validate-image.sh --qcow2 <img> --metadata <tar.gz> [a|b|c|all]
#
# The same qcow2 backs both deliverables (incus import + libvirt), so
# these boots validate the shared root disk; boot the qcow2 under plain
# QEMU/libvirt additionally to exercise the non-incus path.

set -euo pipefail

# Re-exec under incus-admin group if needed (mirrors test/incus/setup.sh).
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

QCOW2=""
METADATA=""
SCENARIO="all"
KEEP=0

while [ $# -gt 0 ]; do
	case "$1" in
	--qcow2)    QCOW2="${2:?}"; shift 2 ;;
	--metadata) METADATA="${2:?}"; shift 2 ;;
	--keep)     KEEP=1; shift ;;
	a|b|c|all)  SCENARIO="$1"; shift ;;
	*)          fail "unknown argument: $1" ;;
	esac
done
[ -f "${QCOW2:-}" ] || fail "--qcow2 <image> required"
[ -f "${METADATA:-}" ] || fail "--metadata <tar.gz> required"

ALIAS="xpf-image-validate"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/xpf-validate.XXXXXX")
INSTANCES=()

cleanup() {
	if [ "$KEEP" -eq 1 ]; then
		echo "keeping instances: ${INSTANCES[*]:-none} and alias $ALIAS"
	else
		for i in "${INSTANCES[@]:-}"; do
			[ -n "$i" ] && incus delete -f "$i" 2>/dev/null || true
		done
		incus image delete "$ALIAS" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# guest <inst> <cmd...> — exec in guest via the incus agent.
guest() {
	local inst="$1"; shift
	incus exec "$inst" -- "$@"
}

wait_agent() {
	local inst="$1" tries=0
	while ! incus exec "$inst" -- true &>/dev/null; do
		sleep 3
		tries=$((tries + 1))
		[ $tries -ge 80 ] && fail "$inst: incus agent not ready after 240s"
	done
}

wait_unit_settled() {
	# Wait for xpfd to be active and the day-0 unit to have finished.
	local inst="$1" tries=0
	while ! guest "$inst" systemctl is-active --quiet xpfd 2>/dev/null; do
		sleep 3
		tries=$((tries + 1))
		[ $tries -ge 40 ] && fail "$inst: xpfd not active after 120s"
	done
}

wait_fxp0_dhcp() {
	local inst="$1" tries=0
	while ! guest "$inst" sh -c 'ip -4 addr show fxp0 2>/dev/null | grep -q "inet "'; do
		sleep 3
		tries=$((tries + 1))
		[ $tries -ge 30 ] && fail "$inst: fxp0 has no IPv4 DHCP address after 90s"
	done
}

launch() {
	# launch <name> [iso]
	local name="$1" iso="${2:-}"
	incus delete -f "$name" 2>/dev/null || true
	incus init "$ALIAS" "$name" --vm \
		-c limits.cpu=2 -c limits.memory=2GiB >/dev/null
	if [ -n "$iso" ]; then
		incus config device add "$name" day0 disk source="$(realpath "$iso")" >/dev/null
	fi
	INSTANCES+=("$name")
	incus start "$name"
	wait_agent "$name"
}

import_image() {
	incus image delete "$ALIAS" 2>/dev/null || true
	info "Importing image into local incus as $ALIAS..."
	incus image import "$METADATA" "$QCOW2" --alias "$ALIAS"
}

scenario_a() {
	info "── Scenario A: first boot, NO config drive ──"
	launch xpf-image-a
	wait_unit_settled xpf-image-a

	local kver
	kver=$(guest xpf-image-a uname -r)
	info "guest kernel: $kver"
	case "$kver" in
	6.1[8-9]*|6.[2-9]*|[7-9]*) : ;;
	*) fail "guest kernel $kver < 6.18" ;;
	esac

	info "in-guest verify-dataplane (the bake gate, image kernel)..."
	guest xpf-image-a nice -n 19 /usr/local/sbin/xpfd verify-dataplane ||
		fail "in-guest verify-dataplane REJECTED — image must not ship"

	wait_fxp0_dhcp xpf-image-a
	guest xpf-image-a sh -c 'ss -tln | grep -q ":22 "' || fail "sshd not listening"
	guest xpf-image-a test ! -e /etc/xpf/xpf.conf || fail "unexpected /etc/xpf/xpf.conf"
	guest xpf-image-a test ! -e /etc/xpf/.day0-config-applied || fail "unexpected day-0 stamp"
	guest xpf-image-a sh -c 'journalctl -u xpf-day0-config -b --no-pager | grep -q "no config medium found"' ||
		fail "day-0 loader did not log the no-medium fallback"
	info "Scenario A PASS (fxp0 $(guest xpf-image-a sh -c 'ip -4 addr show fxp0 | awk "/inet /{print \$2}"'))"
	[ "$KEEP" -eq 1 ] || { incus delete -f xpf-image-a; INSTANCES=("${INSTANCES[@]/xpf-image-a}"); }
}

scenario_b() {
	info "── Scenario B: first boot WITH valid day-0 config drive ──"
	cat >"$WORK/day0-valid.conf" <<'EOF'
system {
    host-name xpf-day0-b;
}
interfaces {
    fxp0 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}
EOF
	"$SCRIPT_DIR/make-config-drive.sh" --no-validate -o "$WORK/day0-valid.iso" "$WORK/day0-valid.conf" >/dev/null
	launch xpf-image-b "$WORK/day0-valid.iso"
	wait_unit_settled xpf-image-b

	guest xpf-image-b test -e /etc/xpf/.day0-config-applied || fail "day-0 stamp missing"
	guest xpf-image-b test -s /etc/xpf/xpf.conf || fail "/etc/xpf/xpf.conf missing"
	guest xpf-image-b sh -c 'journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"' ||
		fail "day-0 loader did not log the install"
	# Committed by xpfd's bootstrap-from-file: hostname applied + CLI shows it.
	local tries=0
	while ! guest xpf-image-b sh -c '/usr/local/sbin/cli show configuration 2>/dev/null | grep -q "host-name xpf-day0-b"'; do
		sleep 3
		tries=$((tries + 1))
		[ $tries -ge 20 ] && fail "committed config does not show host-name xpf-day0-b"
	done
	guest xpf-image-b sh -c '[ "$(hostname)" = xpf-day0-b ]' || fail "hostname not applied"

	info "Rebooting xpf-image-b — second boot must NOT re-apply..."
	incus restart xpf-image-b
	wait_agent xpf-image-b
	wait_unit_settled xpf-image-b
	guest xpf-image-b sh -c '! journalctl -u xpf-day0-config -b --no-pager | grep -q "day-0 config installed"' ||
		fail "second boot re-applied the day-0 config"
	guest xpf-image-b sh -c 'systemctl show -p ConditionResult xpf-day0-config | grep -q "ConditionResult=no" || journalctl -u xpf-day0-config -b --no-pager | grep -q "already applied"' ||
		fail "second boot: day-0 loader neither condition-skipped nor stamp-skipped"
	info "Scenario B PASS"
	[ "$KEEP" -eq 1 ] || { incus delete -f xpf-image-b; INSTANCES=("${INSTANCES[@]/xpf-image-b}"); }
}

scenario_c() {
	info "── Scenario C: first boot WITH INVALID day-0 config drive ──"
	cat >"$WORK/day0-invalid.conf" <<'EOF'
system {
    host-name xpf-day0-c;
    dataplane-type ebpf;
}
EOF
	"$SCRIPT_DIR/make-config-drive.sh" --no-validate -o "$WORK/day0-invalid.iso" "$WORK/day0-invalid.conf" >/dev/null
	launch xpf-image-c "$WORK/day0-invalid.iso"
	wait_unit_settled xpf-image-c

	guest xpf-image-c sh -c 'journalctl -u xpf-day0-config -b --no-pager | grep -q "REJECTED by commit-check"' ||
		fail "day-0 loader did not log the commit-check REJECT"
	guest xpf-image-c test ! -e /etc/xpf/xpf.conf || fail "invalid config was installed"
	guest xpf-image-c test ! -e /etc/xpf/.day0-config-applied || fail "stamp written on REJECT"
	wait_fxp0_dhcp xpf-image-c
	guest xpf-image-c sh -c '[ "$(hostname)" != xpf-day0-c ]' || fail "invalid config changed the hostname"
	info "Scenario C PASS (fallback reachable, boot survived)"
	[ "$KEEP" -eq 1 ] || { incus delete -f xpf-image-c; INSTANCES=("${INSTANCES[@]/xpf-image-c}"); }
}

import_image
case "$SCENARIO" in
a)   scenario_a ;;
b)   scenario_b ;;
c)   scenario_c ;;
all) scenario_a; scenario_b; scenario_c ;;
esac
info "Validation complete."
