#!/usr/bin/env bash
# ha-sriov.sh — launch an xpf HA pair with mgmt/control/fabric on
# virtio and the LAN+WAN dataplane ports on SR-IOV VFs, for a line-rate
# dataplane (native XDP on mlx5 VFs) while the non-revenue links stay
# simple and host-portable.
#
# Per-node NIC order (identical on both VMs) -> xpf interface name:
#   1 fxp0   2 em0   3 ge-X/0/0 (fab)   4 ge-X/0/1 (LAN, VF)   5 ge-X/0/2 (WAN, VF)
#
# incus 'sriov:<PF>' allocates a free VF on that PF and pins its MAC
# host-side before passthrough, so the guest identity is stable across
# host reboots. Each node gets its own VF on the (per-host) PF.
#
# ORDERING (verified against pkg/daemon/linksetup.go): the guest names
# all virtio NICs first, then all hardware NICs, each class by PCI bus.
# Here the 3 virtio links (mgmt/em0/fabric) take fxp0/em0/ge-0-0-0 and
# the 2 VFs (hardware-class) take ge-0-0-1/ge-0-0-2 — which is exactly
# the intended map because the dataplane roles are listed last. The
# reference cluster (test/incus/cluster-setup.sh) passes VM VFs as raw
# 'pci:<vf-addr>' (also hardware-class); 'pci:<vf-addr>,mac=02:..' is the
# equivalent if you prefer to pin a specific VF. ALWAYS confirm the
# realized map with 'show interfaces terse' after first boot.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH="$HERE/../../scripts/deploy/xpf-launch.sh"
CONF="$HERE/ha-pair.conf"

# ── EDIT THESE for your host ─────────────────────────────────────────
MGMT="${MGMT:-mgmt}"
HA_CTRL="${HA_CTRL:-ha-control}"
HA_FAB="${HA_FAB:-ha-fabric}"
# SR-IOV PFs. Best XDP on mlx5_core; iavf VFs work but are generic-only.
# Create VFs first if needed:
#   echo 4 | sudo tee /sys/class/net/<PF>/device/sriov_numvfs
LAN_PF="${LAN_PF:-enp8s0}"     # PF backing the LAN-side VF
WAN_PF="${WAN_PF:-enp9s0}"     # PF backing the WAN-side VF
# ─────────────────────────────────────────────────────────────────────

for node in 0 1; do
	"$LAUNCH" --name "fw$node" --node-id "$node" --conf "$CONF" \
		"$@" \
		--nic "net:$MGMT" \
		--nic "net:$HA_CTRL" \
		--nic "net:$HA_FAB" \
		--nic "sriov:$LAN_PF" \
		--nic "sriov:$WAN_PF"
done

echo
echo "Both nodes use a VF on $LAN_PF (LAN) and $WAN_PF (WAN);"
echo "incus picks a free VF per node and pins its MAC."
echo "Verify:  incus exec fw0 -- cli -c 'show chassis cluster status'"
echo "         incus exec fw0 -- ethtool -i ge-0-0-2   # expect mlx5_core for native XDP"
