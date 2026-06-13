#!/usr/bin/env bash
# ha-physical.sh — launch an xpf HA pair with EVERY interface backed by
# a whole physical card via VFIO passthrough: fxp0, em0, fab, and the
# ge dataplane ports each get a dedicated NIC. Maximum isolation and
# native XDP on every port; the cost is one physical card per interface
# per node and a hard determinism caveat (read below).
#
# Per-node NIC order (identical wiring on both VMs) -> xpf name:
#   1 fxp0   2 em0   3 ge-X/0/0 (fab)   4 ge-X/0/1 (LAN)   5 ge-X/0/2 (WAN)
#
# DETERMINISM CAVEAT (important): xpf names interfaces by guest PCI
# order. The launcher names passthrough devices pt00,pt01,... in --nic
# order to give incus a stable ordering key, and this matches the
# proven 2-VF reference cluster. But ordering among MANY passthrough
# devices on incus is best-effort, not contractual. For an all-physical
# build you have three safe options, in order of preference:
#   (a) Keep fxp0/em0/fab on virtio (ha-sriov.sh / ha-bridges.sh) and
#       pass through ONLY the ge dataplane ports — far fewer passthrough
#       devices to order, and the non-revenue links don't need it.
#   (b) Use libvirt with PINNED guest PCI addresses (see README "Full
#       physical cards (libvirt, pinned order)") — fully deterministic.
#   (c) Use this script, then ALWAYS verify the realized map with
#       'show interfaces terse' and adjust --nic order until it matches.
#
# Hotplug of passthrough devices doesn't work, so the launcher adds
# them while the VM is stopped (init -> add -> start) — already handled.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH="$HERE/../../scripts/deploy/xpf-launch.sh"
CONF="$HERE/ha-pair.conf"

# ── EDIT THESE: one PCI address per interface, PER NODE ──────────────
# Find them with examples/deploy/show-host-nics.sh (the PCI column).
# These are whole-card PFs (burned-in MAC, no mac= pin needed). For
# a TWO-HOST cluster, set the node-1 column to that host's PCI addrs
# and run this script on each host with NODES set accordingly.
#
#                     node0 PCI            node1 PCI
declare -A MGMT_PCI=( [0]=0000:01:00.0     [1]=0000:01:00.0 )
declare -A EM0_PCI=(  [0]=0000:01:00.1     [1]=0000:01:00.1 )
declare -A FAB_PCI=(  [0]=0000:02:00.0     [1]=0000:02:00.0 )
declare -A LAN_PCI=(  [0]=0000:03:00.0     [1]=0000:03:00.0 )
declare -A WAN_PCI=(  [0]=0000:04:00.0     [1]=0000:04:00.0 )
NODES="${NODES:-0 1}"   # set to "0" or "1" to launch one host at a time
# ─────────────────────────────────────────────────────────────────────

for node in $NODES; do
	"$LAUNCH" --name "fw$node" --node-id "$node" --conf "$CONF" \
		"$@" \
		--nic "pci:${MGMT_PCI[$node]}" \
		--nic "pci:${EM0_PCI[$node]}" \
		--nic "pci:${FAB_PCI[$node]}" \
		--nic "pci:${LAN_PCI[$node]}" \
		--nic "pci:${WAN_PCI[$node]}"
done

echo
echo "ALL interfaces are passthrough cards. VERIFY the NIC->name map:"
echo "  incus exec fw0 -- cli -c 'show interfaces terse'"
echo "If fxp0/em0/fab/ge are not in the expected slots, reorder the --nic"
echo "list (or switch to the libvirt pinned-address recipe in the README)."
