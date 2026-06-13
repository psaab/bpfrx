#!/usr/bin/env bash
# ha-bridges.sh — launch an xpf HA pair with ALL interfaces on host
# bridges (virtio). The simplest topology: no SR-IOV, no passthrough,
# works on any host. Dataplane runs virtio native XDP (vhost) — fine
# for labs and sub-10G WANs; for line rate use ha-sriov.sh / ha-physical.sh.
#
# Per-node NIC order (identical on both VMs) -> xpf interface name:
#   1 fxp0   2 em0   3 ge-X/0/0 (fab)   4 ge-X/0/1 (LAN)   5 ge-X/0/2 (WAN)
#
# Uses examples/deploy/ha-pair.conf as-is (check-config-valid for both
# node-ids). Run examples/deploy/show-host-nics.sh to see your bridges.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCH="$HERE/../../scripts/deploy/xpf-launch.sh"
CONF="$HERE/ha-pair.conf"

# ── EDIT THESE for your host ─────────────────────────────────────────
MGMT="${MGMT:-mgmt}"            # incus managed net OR a bridge name
HA_CTRL="${HA_CTRL:-ha-control}"  # dedicated point-to-point L2, both nodes
HA_FAB="${HA_FAB:-ha-fabric}"     # dedicated point-to-point L2, both nodes
BR_LAN="${BR_LAN:-br-lan}"     # host bridge for the LAN segment
BR_WAN="${BR_WAN:-br-wan}"     # host bridge for the WAN segment
# ─────────────────────────────────────────────────────────────────────

# The two point-to-point links carry ONLY heartbeats/sync/fabric — give
# them dedicated, address-less networks if they don't exist:
#   incus network create ha-control ipv4.address=none ipv6.address=none
#   incus network create ha-fabric  ipv4.address=none ipv6.address=none

for node in 0 1; do
	"$LAUNCH" --name "fw$node" --node-id "$node" --conf "$CONF" \
		"$@" \
		--nic "net:$MGMT" \
		--nic "net:$HA_CTRL" \
		--nic "net:$HA_FAB" \
		--nic "bridge:$BR_LAN" \
		--nic "bridge:$BR_WAN"
done

echo
echo "Verify:  incus exec fw0 -- cli -c 'show chassis cluster status'"
echo "         incus exec fw0 -- cli -c 'show interfaces terse'"
