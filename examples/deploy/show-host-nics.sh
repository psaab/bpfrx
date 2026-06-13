#!/usr/bin/env bash
# show-host-nics.sh — inventory the host's NICs, SR-IOV VFs, and bridges
# so you can fill in the deployment recipes in this directory's README.
#
# Prints, for every physical netdev: driver, MAC, PCI address, link
# state, native-XDP capability hint, and (for SR-IOV PFs) the carved
# VFs with their PCI addresses. Then lists host bridges. Read-only.
#
# Usage:  examples/deploy/show-host-nics.sh
#
# The three columns you copy into recipes:
#   - "bridge:<name>"  from the BRIDGES list
#   - "sriov:<PF>"     a PF NAME that has VFs (numvfs > 0)
#   - "pci:<addr>"     a PCI ADDRESS (PF for whole-card, or a VF row)

set -euo pipefail

is_phys() {  # exclude virtual/software devices
	local d="$1"
	[ -e "/sys/class/net/$d/device" ] || return 1
	case "$d" in lo|veth*|tap*|br-*|virbr*|docker*|incusbr*) return 1 ;; esac
	return 0
}

native_xdp_hint() {  # crude: driver name -> likely native XDP
	case "$1" in
	mlx5_core|i40e|ice|ixgbe|bnxt_en|nfp) echo "native" ;;
	iavf|ixgbevf|virtio_net)              echo "no (generic only)" ;;
	*)                                    echo "unknown" ;;
	esac
}

echo "=== Physical NICs ==="
printf '%-14s %-10s %-19s %-14s %-7s %s\n' NETDEV DRIVER PCI MAC LINK NATIVE-XDP
for path in /sys/class/net/*; do
	d="$(basename "$path")"
	is_phys "$d" || continue
	drv="$(basename "$(readlink -f "/sys/class/net/$d/device/driver" 2>/dev/null)" 2>/dev/null || echo '?')"
	pci="$(basename "$(readlink -f "/sys/class/net/$d/device" 2>/dev/null)" 2>/dev/null || echo '?')"
	mac="$(cat "/sys/class/net/$d/address" 2>/dev/null || echo '?')"
	link="$(cat "/sys/class/net/$d/operstate" 2>/dev/null || echo '?')"
	printf '%-14s %-10s %-19s %-14s %-7s %s\n' \
		"$d" "$drv" "$pci" "$mac" "$link" "$(native_xdp_hint "$drv")"

	# SR-IOV: report VFs if this PF has any
	totalvfs="$(cat "/sys/class/net/$d/device/sriov_totalvfs" 2>/dev/null || echo 0)"
	numvfs="$(cat "/sys/class/net/$d/device/sriov_numvfs" 2>/dev/null || echo 0)"
	if [ "${totalvfs:-0}" -gt 0 ]; then
		echo "                 SR-IOV: ${numvfs}/${totalvfs} VFs active.  Create N with:  echo N | sudo tee /sys/class/net/$d/device/sriov_numvfs"
		for vfp in "/sys/class/net/$d/device"/virtfn*; do
			[ -e "$vfp" ] || break
			vfn="$(basename "$vfp" | sed 's/virtfn//')"
			vfpci="$(basename "$(readlink -f "$vfp")")"
			printf '                   vf%-3s pci:%-16s (incus: sriov:%s   raw: pci:%s,mac=02:..)\n' \
				"$vfn" "$vfpci" "$d" "$vfpci"
		done
	fi
done

echo
echo "=== Host bridges (for bridge:<name>) ==="
found=0
for path in /sys/class/net/*/bridge; do
	[ -d "$path" ] || continue
	b="$(basename "$(dirname "$path")")"
	echo "  bridge:$b"
	found=1
done
[ "$found" -eq 1 ] || echo "  (none — create one: sudo ip link add br-lan type bridge && sudo ip link set br-lan up,"
[ "$found" -eq 1 ] || echo "   or an incus managed network: incus network create lan)"

echo
echo "Notes:"
echo "  * Whole-PF passthrough (pci:<PF-addr>) gives the guest the real driver"
echo "    => native XDP, but claims the entire card (its VFs become unusable by"
echo "    the host/other VMs)."
echo "  * SR-IOV VF: 'sriov:<PF>' lets incus pick a free VF and pin its MAC."
echo "    'pci:<vf-addr>,mac=02:..' passes a specific VF; ALWAYS pin mac= or it"
echo "    randomizes every host reboot."
echo "  * mgmt (fxp0) and HA control/fabric (em0/fab) do NOT need line rate —"
echo "    leave them on bridges/virtio and reserve passthrough for ge dataplane."
