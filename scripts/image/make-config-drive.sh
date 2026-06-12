#!/usr/bin/env bash
# Build an xpf day-0 config drive ISO (#1879 Path C).
#
# The vSRX analog of "ISO with juniper.conf at the root": produces an
# ISO9660 volume labeled `xpf-config` carrying the given config as
# xpf.conf (plus an optional node-id file for cluster members). Attach
# it to the appliance VM as a CD-ROM (libvirt) or a disk device (incus)
# and the first-boot loader applies it — see docs/install-images.md.
#
# Usage:
#   scripts/image/make-config-drive.sh [-n 0|1] [-o out.iso] [--no-validate] <config-file>
#
# Validation: if an xpfd binary is available (./xpfd or $XPFD), the
# config is run through the real commit-check gate (`xpfd check-config`)
# and the build FAILS on reject — catching a bad day-0 config on the
# build host instead of on the appliance console. --no-validate skips
# this (the first-boot loader still validates on the appliance; an
# invalid config there falls back to factory bootstrap).

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

NODE_ID=""
OUT=""
VALIDATE=1
CONF=""

while [ $# -gt 0 ]; do
	case "$1" in
	-n|--node-id)
		NODE_ID="${2:?-n needs a value}"; shift 2 ;;
	-o|--out)
		OUT="${2:?-o needs a value}"; shift 2 ;;
	--no-validate)
		VALIDATE=0; shift ;;
	-h|--help)
		sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	-*)
		die "unknown option: $1" ;;
	*)
		[ -z "$CONF" ] || die "exactly one config file expected"
		CONF="$1"; shift ;;
	esac
done

[ -n "$CONF" ] || die "usage: $0 [-n 0|1] [-o out.iso] [--no-validate] <config-file>"
[ -f "$CONF" ] || die "config file not found: $CONF"
if [ -n "$NODE_ID" ] && [ "$NODE_ID" != "0" ] && [ "$NODE_ID" != "1" ]; then
	die "node-id must be 0 or 1"
fi
[ -n "$OUT" ] || OUT="$(basename "${CONF%.*}")-config.iso"

MKISO=""
for tool in xorriso genisoimage mkisofs; do
	if command -v "$tool" >/dev/null 2>&1; then MKISO="$tool"; break; fi
done
[ -n "$MKISO" ] || die "need xorriso, genisoimage, or mkisofs (apt-get install xorriso)"

if [ "$VALIDATE" -eq 1 ]; then
	XPFD_BIN="${XPFD:-$PROJECT_ROOT/xpfd}"
	if [ -x "$XPFD_BIN" ]; then
		info "Validating $CONF with the strict commit-check gate ($XPFD_BIN check-config)"
		nodearg=()
		[ -n "$NODE_ID" ] && nodearg=(-node-id "$NODE_ID")
		"$XPFD_BIN" check-config "${nodearg[@]}" "$CONF" ||
			die "config REJECTED by commit-check — fix it or pass --no-validate (the appliance would refuse it anyway)"
	else
		echo "WARNING: no xpfd binary at $XPFD_BIN — skipping build-host validation." >&2
		echo "         The appliance still validates at first boot (invalid -> factory bootstrap)." >&2
	fi
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
install -m 0644 "$CONF" "$STAGE/xpf.conf"
[ -n "$NODE_ID" ] && printf '%s\n' "$NODE_ID" >"$STAGE/node-id"

info "Building $OUT (volume label xpf-config)"
case "$MKISO" in
xorriso)
	xorriso -as mkisofs -quiet -V xpf-config -J -r -o "$OUT" "$STAGE" ;;
*)
	"$MKISO" -quiet -V xpf-config -J -r -o "$OUT" "$STAGE" ;;
esac

info "Done: $OUT"
info "  libvirt: virt-install ... --disk path=$OUT,device=cdrom"
info "  incus:   incus config device add <vm> day0 disk source=\$(realpath $OUT)"
