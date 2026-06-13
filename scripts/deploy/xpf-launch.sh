#!/usr/bin/env bash
# xpf-launch.sh — launch an xpf appliance VM on incus in one command.
#
# The whole deployment contract is NIC ORDER. The order of --nic flags
# is the guest PCI order, and xpf names interfaces by PCI order:
#
#   --nic #1               -> fxp0 (management, DHCP)
#   --nic #2 (cluster)     -> em0  (HA control link; only with --node-id)
#   remaining --nic flags  -> ge-0/0/0, ge-0/0/1, ... (node 1: ge-7/0/N)
#
# so the config you ship on the day-0 drive and the --nic list you
# launch with are two views of the same table. Write the table once,
# use it in both places.
#
# Usage:
#   scripts/deploy/xpf-launch.sh --name fw1 --conf site.conf \
#       --nic net:mgmt --nic bridge:br-trust --nic sriov:enp9s0f0np0
#
#   # HA member (second NIC becomes em0):
#   scripts/deploy/xpf-launch.sh --name fw0 --node-id 0 --conf ha.conf \
#       --nic net:mgmt --nic net:ha-control --nic net:ha-fabric \
#       --nic pci:0000:65:00.2,mac=02:bf:72:00:00:10 \
#       --nic pci:0000:65:00.3,mac=02:bf:72:00:00:11
#
# NIC spec forms (ordered, repeatable):
#   net:<network>        incus managed network (bare "<network>" also works)
#   bridge:<host-br>     existing host bridge (nictype=bridged)
#   macvlan:<dev>        macvlan off a host device
#   sriov:<PF>[,mac=..]  incus-allocated VF on that PF; incus pins the
#                        MAC on the PF before passthrough, so the guest
#                        MAC is stable across host reboots
#   pci:<addr>[,mac=..]  VFIO passthrough of a whole PF or a pre-carved
#                        VF by PCI address. For VFs, pass mac= — a bare
#                        VF gets a NEW RANDOM MAC every host reboot;
#                        the launcher pins it on the parent PF
#                        (ip link set <pf> vf <n> mac ..) when given
#   physical:<dev>       pass a host netdev (nictype=physical)
#
# ORDERING RULE: qemu places virtio NICs on lower PCI slots than
# passthrough devices, so all net:/bridge:/macvlan:/sriov:/physical:
# specs must come BEFORE any pci: specs. The launcher enforces this.
# Verify the final mapping any time with:
#   incus exec <name> -- cli -c "show interfaces terse"
#
# Options:
#   --name <vm>         instance name (required)
#   --conf <file>       day-0 config; validated with `xpfd check-config`
#                       and shipped as a config drive. Omit to boot
#                       factory-default (fxp0 DHCP + console login).
#   --node-id 0|1       cluster member id; adds node-id to the drive and
#                       shifts NIC #2 to em0
#   --image <alias>     incus image alias        (default: xpf-appliance)
#   --cpu <n>           vCPUs                    (default: 4)
#   --mem <size>        memory                   (default: 4GiB)
#   --no-start          create everything, don't start
#   --dry-run           print the incus commands instead of running them
#
# Scale-out is a loop over this script — see docs/deploy-quickstart.md.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MAKE_DRIVE="${SCRIPT_DIR}/../image/make-config-drive.sh"

# Re-exec under the incus-admin group when needed (same pattern as
# scripts/image/validate-image.sh).
if [ -z "${XPF_LAUNCH_DRY:-}" ] && ! incus list >/dev/null 2>&1; then
	if getent group incus-admin >/dev/null 2>&1 && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

NAME="" CONF="" NODE_ID="" IMAGE="xpf-appliance" CPU=4 MEM="4GiB"
START=1 DRY=0
NICS=()

while [ $# -gt 0 ]; do
	case "$1" in
	--name)     NAME="${2:?}"; shift 2 ;;
	--conf)     CONF="${2:?}"; shift 2 ;;
	--node-id)  NODE_ID="${2:?}"; shift 2 ;;
	--image)    IMAGE="${2:?}"; shift 2 ;;
	--cpu)      CPU="${2:?}"; shift 2 ;;
	--mem)      MEM="${2:?}"; shift 2 ;;
	--nic)      NICS+=("${2:?}"); shift 2 ;;
	--no-start) START=0; shift ;;
	--dry-run)  DRY=1; export XPF_LAUNCH_DRY=1; shift ;;
	-h|--help)  sed -n '2,68p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*)          die "unknown argument: $1 (see --help)" ;;
	esac
done

[ -n "$NAME" ] || die "--name is required"
[ ${#NICS[@]} -ge 1 ] || die "at least one --nic is required (NIC #1 = fxp0 management)"
if [ -n "$NODE_ID" ]; then
	{ [ "$NODE_ID" = "0" ] || [ "$NODE_ID" = "1" ]; } || die "--node-id must be 0 or 1"
	[ ${#NICS[@]} -ge 2 ] || die "cluster members need >= 2 NICs (fxp0 + em0)"
fi
[ -z "$CONF" ] || [ -f "$CONF" ] || die "config file not found: $CONF"

run() {
	if [ "$DRY" -eq 1 ]; then
		printf '%q ' "$@"; printf '\n'
	else
		"$@"
	fi
}

# --- Parse NIC specs into device-add argument lists -------------------
# Virtio-backed devices are named eth00, eth01, ... — incus sorts
# devices lexicographically when building the VM, so zero-padded names
# pin the PCI order to the --nic order. Passthrough (pci:) devices are
# named pt00, pt01, ... and always land on higher PCI slots than the
# virtio group, which is why they must come last in the spec list.
VIRTIO_ADDS=()   # serialized "name|type|k=v|k=v" entries
PCI_ADDS=()
PIN_CMDS=()      # host-side VF MAC pin commands (run before start)
seen_pci=0
idx_v=0 idx_p=0

resolve_vf_parent() {
	# resolve_vf_parent <vf-pci-addr> -> "PF VFNUM" or fails
	local addr="$1" pf vfp
	for pf in /sys/class/net/*/device/virtfn*; do
		[ -e "$pf" ] || continue
		vfp="$(readlink -f "$pf")"
		if [ "$(basename "$vfp")" = "$addr" ]; then
			echo "$(echo "$pf" | cut -d/ -f5) $(basename "$pf" | sed 's/virtfn//')"
			return 0
		fi
	done
	return 1
}

for spec in "${NICS[@]}"; do
	kind="${spec%%:*}"
	rest="${spec#*:}"
	[ "$kind" != "$spec" ] || { kind="net"; rest="$spec"; }
	arg="${rest%%,*}"
	mac=""
	case "$rest" in *,mac=*) mac="${rest#*,mac=}" ;; esac

	case "$kind" in
	net)
		dev=$(printf 'eth%02d' "$idx_v"); idx_v=$((idx_v+1))
		[ "$seen_pci" -eq 0 ] || die "virtio NIC '$spec' after a pci: spec — virtio always enumerates below passthrough; reorder your --nic list"
		e="$dev|nic|network=$arg"; [ -n "$mac" ] && e="$e|hwaddr=$mac"
		VIRTIO_ADDS+=("$e") ;;
	bridge)
		dev=$(printf 'eth%02d' "$idx_v"); idx_v=$((idx_v+1))
		[ "$seen_pci" -eq 0 ] || die "virtio NIC '$spec' after a pci: spec — reorder"
		e="$dev|nic|nictype=bridged|parent=$arg"; [ -n "$mac" ] && e="$e|hwaddr=$mac"
		VIRTIO_ADDS+=("$e") ;;
	macvlan)
		dev=$(printf 'eth%02d' "$idx_v"); idx_v=$((idx_v+1))
		[ "$seen_pci" -eq 0 ] || die "virtio NIC '$spec' after a pci: spec — reorder"
		e="$dev|nic|nictype=macvlan|parent=$arg"; [ -n "$mac" ] && e="$e|hwaddr=$mac"
		VIRTIO_ADDS+=("$e") ;;
	physical)
		dev=$(printf 'eth%02d' "$idx_v"); idx_v=$((idx_v+1))
		[ "$seen_pci" -eq 0 ] || die "NIC '$spec' after a pci: spec — reorder"
		VIRTIO_ADDS+=("$dev|nic|nictype=physical|parent=$arg") ;;
	sriov)
		dev=$(printf 'eth%02d' "$idx_v"); idx_v=$((idx_v+1))
		[ "$seen_pci" -eq 0 ] || die "NIC '$spec' after a pci: spec — reorder"
		e="$dev|nic|nictype=sriov|parent=$arg"; [ -n "$mac" ] && e="$e|hwaddr=$mac"
		VIRTIO_ADDS+=("$e") ;;
	pci)
		seen_pci=1
		dev=$(printf 'pt%02d' "$idx_p"); idx_p=$((idx_p+1))
		PCI_ADDS+=("$dev|pci|address=$arg")
		if [ -n "$mac" ]; then
			if pv=$(resolve_vf_parent "$arg"); then
				PIN_CMDS+=("ip link set dev ${pv% *} vf ${pv#* } mac $mac")
			else
				die "pci:$arg,mac=: $arg is not an SR-IOV VF on this host (whole-PF passthrough keeps its burned-in MAC; drop mac=)"
			fi
		else
			if resolve_vf_parent "$arg" >/dev/null 2>&1; then
				echo "WARNING: pci:$arg is an SR-IOV VF with NO mac= pin — its MAC randomizes every host reboot. Pass ,mac=02:xx:.. for a stable guest identity." >&2
			fi
		fi ;;
	*)
		die "unknown NIC spec '$spec' (forms: net:|bridge:|macvlan:|sriov:|pci:|physical:)" ;;
	esac
done

# --- Day-0 config drive ------------------------------------------------
ISO=""
if [ -n "$CONF" ]; then
	ISO="$(pwd)/${NAME}-day0.iso"
	nodearg=()
	[ -n "$NODE_ID" ] && nodearg=(-n "$NODE_ID")
	info "Building day-0 config drive ($ISO) — validated with check-config"
	run "$MAKE_DRIVE" "${nodearg[@]}" -o "$ISO" "$CONF"
fi

# --- Create the VM -----------------------------------------------------
info "Creating $NAME (image $IMAGE, ${CPU} vCPU, ${MEM})"
run incus init "$IMAGE" "$NAME" --vm \
	-c limits.cpu="$CPU" -c limits.memory="$MEM"

add_devices() {
	local entry
	local -a parts
	for entry in "$@"; do
		IFS='|' read -ra parts <<<"$entry"
		run incus config device add "$NAME" "${parts[0]}" "${parts[1]}" "${parts[@]:2}"
	done
}
[ ${#VIRTIO_ADDS[@]} -eq 0 ] || add_devices "${VIRTIO_ADDS[@]}"
[ ${#PCI_ADDS[@]} -eq 0 ] || add_devices "${PCI_ADDS[@]}"

if [ -n "$ISO" ]; then
	run incus config device add "$NAME" day0 disk source="$ISO"
fi

for cmd in "${PIN_CMDS[@]:-}"; do
	[ -n "$cmd" ] || continue
	info "Pinning VF MAC on host: $cmd"
	# shellcheck disable=SC2086
	run sudo $cmd
done

if [ "$START" -eq 1 ]; then
	info "Starting $NAME"
	run incus start "$NAME"
	if [ "$DRY" -eq 0 ]; then
		info "Waiting for the guest agent..."
		tries=0
		until incus exec "$NAME" -- true >/dev/null 2>&1; do
			sleep 3; tries=$((tries+1))
			[ $tries -lt 60 ] || { echo "WARNING: agent not up after 180s — check 'incus console $NAME'" >&2; break; }
		done
	fi
	cat <<EOF

$NAME is up. Next steps:
  incus exec $NAME -- cli -c "show interfaces terse"   # verify the NIC->role map
  incus exec $NAME -- cli                              # Junos-style CLI
  journalctl: incus exec $NAME -- journalctl -u xpf-day0-config -u xpfd -n 50
EOF
else
	info "$NAME created (not started). Start with: incus start $NAME"
fi
