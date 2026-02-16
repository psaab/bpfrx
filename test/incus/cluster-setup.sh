#!/usr/bin/env bash
# bpfrx Chassis Cluster (HA) test environment management
#
# Creates a two-VM HA cluster with heartbeat, fabric, and shared LAN
# networks, plus a test container on the cluster LAN.
#
# Single-config model: both nodes share docs/ha-cluster.conf with
# apply-groups "${node}" expansion. Node ID comes from /etc/bpfrx/node-id.
# Interface names follow vSRX conventions: fxp0, fxp1, fab0, ge-X/Y/Z.
#
# Usage:
#   ./test/incus/cluster-setup.sh init              # Create networks + profile
#   ./test/incus/cluster-setup.sh create             # Launch both VMs + test container
#   ./test/incus/cluster-setup.sh destroy            # Tear down VMs + container
#   ./test/incus/cluster-setup.sh deploy [0|1|all]   # Build and push to VM(s)
#   ./test/incus/cluster-setup.sh ssh 0|1            # Shell into VM
#   ./test/incus/cluster-setup.sh status             # Show all VM status
#   ./test/incus/cluster-setup.sh logs 0|1           # Show bpfrxd logs
#   ./test/incus/cluster-setup.sh start [0|1|all]    # Start bpfrxd service
#   ./test/incus/cluster-setup.sh stop [0|1|all]     # Stop bpfrxd service
#   ./test/incus/cluster-setup.sh restart [0|1|all]  # Restart bpfrxd service

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

VM0="bpfrx-fw0"
VM1="bpfrx-fw1"
LAN_HOST="cluster-lan-host"
PROFILE="bpfrx-cluster"
IMAGE_VM="images:debian/13"
IMAGE_CT="images:debian/13"
SRIOV_PARENT="eno6np1"
# PCI addresses for SR-IOV VFs (one per VM, from $SRIOV_PARENT)
VF_PCI=("0000:b7:06.0" "0000:b7:06.1")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Network definitions: name:subnet:nat
NETWORKS=(
	"bpfrx-heartbeat:none:false"
	"bpfrx-fabric:none:false"
	"bpfrx-clan:none:false"
)

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }
die()   { echo "ERROR: $*" >&2; exit 1; }

# Resolve VM name from node index (0 or 1)
vm_name() {
	case "$1" in
		0) echo "$VM0" ;;
		1) echo "$VM1" ;;
		*) die "Invalid node index: $1 (must be 0 or 1)" ;;
	esac
}

# vSRX LAN interface name for a given node index
# Node 0: ge-0-0-0, Node 1: ge-7-0-0
lan_ifname() {
	local idx="$1"
	if [[ "$idx" == "0" ]]; then echo "ge-0-0-0"; else echo "ge-7-0-0"; fi
}

# vSRX WAN interface name for a given node index
# Node 0: ge-0-0-1, Node 1: ge-7-0-1
wan_ifname() {
	local idx="$1"
	if [[ "$idx" == "0" ]]; then echo "ge-0-0-1"; else echo "ge-7-0-1"; fi
}

# ── Init ─────────────────────────────────────────────────────────────

cmd_init() {
	create_networks
	create_profile
	info "Init complete. Run '$0 create' next."
}

create_networks() {
	for entry in "${NETWORKS[@]}"; do
		IFS=: read -r name subnet nat <<< "$entry"
		if incus network show "$name" &>/dev/null 2>&1; then
			info "Network $name already exists"
			continue
		fi
		info "Creating network $name (subnet=$subnet, nat=$nat)"
		incus network create "$name" \
			ipv4.address="$subnet" \
			ipv4.nat="$nat" \
			ipv6.address=none
	done
}

create_profile() {
	if incus profile show "$PROFILE" &>/dev/null 2>&1; then
		info "Profile $PROFILE already exists, updating..."
		incus profile delete "$PROFILE" 2>/dev/null || true
	fi
	info "Creating profile $PROFILE"
	incus profile create "$PROFILE"
	incus profile edit "$PROFILE" <<'YAML'
config:
  limits.cpu: "4"
  limits.memory: 4GB
devices:
  root:
    path: /
    pool: default
    size: 20GB
    type: disk
  eth0:
    name: enp5s0
    network: incusbr0
    type: nic
  eth1:
    name: enp6s0
    network: bpfrx-heartbeat
    type: nic
  eth2:
    name: enp7s0
    network: bpfrx-fabric
    type: nic
  eth3:
    name: enp8s0
    network: bpfrx-clan
    type: nic
YAML
}

# ── Instance Management ──────────────────────────────────────────────

cmd_create() {
	# Create both VMs
	for idx in 0 1; do
		create_vm "$idx"
	done

	# Create test container on cluster LAN
	create_lan_host

	info "Cluster environment ready. Run '$0 deploy all' to push bpfrxd."
}

create_vm() {
	local idx="$1"
	local vm
	vm=$(vm_name "$idx")

	if incus info "$vm" &>/dev/null 2>&1; then
		die "Instance $vm already exists. Run '$0 destroy' first."
	fi

	info "Launching VM $vm..."
	incus launch "$IMAGE_VM" "$vm" --vm --profile "$PROFILE"

	info "Waiting for VM agent ($vm)..."
	local tries=0
	while ! incus exec "$vm" -- true &>/dev/null; do
		sleep 2
		tries=$((tries + 1))
		if [[ $tries -ge 30 ]]; then
			die "VM agent for $vm did not become ready after 60 seconds"
		fi
	done

	# Stop VM to add SR-IOV VF via PCI passthrough (hotplug doesn't work)
	info "Stopping VM to add SR-IOV VF..."
	incus stop "$vm" --force
	sleep 2

	local pci="${VF_PCI[$idx]}"
	info "Adding SR-IOV VF PCI $pci to $vm..."
	incus config device add "$vm" wan-vf pci address="$pci"

	info "Starting VM with VF..."
	incus start "$vm"

	# Wait for agent again after restart
	tries=0
	while ! incus exec "$vm" -- true &>/dev/null; do
		sleep 2
		tries=$((tries + 1))
		if [[ $tries -ge 30 ]]; then
			die "VM agent for $vm did not become ready after 60 seconds"
		fi
	done

	provision_vm "$vm" "$idx"
	info "VM $vm ready."
}

provision_vm() {
	local vm="$1"
	local idx="$2"

	# Wait for systemd to be ready
	info "Waiting for system to be ready ($vm)..."
	local stries=0
	while ! incus exec "$vm" -- systemctl is-system-running &>/dev/null 2>&1; do
		sleep 2
		stries=$((stries + 1))
		if [[ $stries -ge 30 ]]; then
			warn "systemd did not become ready after 60 seconds on $vm, continuing anyway"
			break
		fi
	done

	# Bootstrap systemd-networkd .link files for interface renaming
	# Uses vSRX naming: fxp0 (mgmt), fxp1 (heartbeat), fab0 (fabric),
	# ge-X-0-0 (LAN), ge-X-0-1 (WAN/SR-IOV)
	info "Writing bootstrap networkd .link files ($vm, node $idx)..."
	local mac_fxp0 mac_fxp1 mac_fab0 mac_lan
	mac_fxp0=$(incus exec "$vm" -- cat /sys/class/net/enp5s0/address 2>/dev/null || true)
	mac_fxp1=$(incus exec "$vm" -- cat /sys/class/net/enp6s0/address 2>/dev/null || true)
	mac_fab0=$(incus exec "$vm" -- cat /sys/class/net/enp7s0/address 2>/dev/null || true)
	mac_lan=$(incus exec "$vm" -- cat /sys/class/net/enp8s0/address 2>/dev/null || true)

	# SR-IOV VF interface name varies — find it by exclusion
	local mac_wan
	mac_wan=$(incus exec "$vm" -- bash -c '
		for iface in /sys/class/net/enp*/address; do
			name=$(basename $(dirname "$iface"))
			case "$name" in
				enp5s0|enp6s0|enp7s0|enp8s0|lo) continue ;;
				*) cat "$iface" 2>/dev/null; break ;;
			esac
		done
	' 2>/dev/null || true)

	local lan_name wan_name
	lan_name=$(lan_ifname "$idx")
	wan_name=$(wan_ifname "$idx")

	for pair in "fxp0:$mac_fxp0" "fxp1:$mac_fxp1" "fab0:$mac_fab0" "${lan_name}:$mac_lan" "${wan_name}:$mac_wan"; do
		local name="${pair%%:*}" mac="${pair#*:}"
		if [[ -n "$mac" ]]; then
			incus exec "$vm" -- bash -c "cat > /etc/systemd/network/10-bpfrx-${name}.link << LINKEOF
# Managed by bpfrxd — do not edit
[Match]
MACAddress=${mac}

[Link]
Name=${name}
LINKEOF"
		fi
	done

	incus exec "$vm" -- networkctl reload
	sleep 1

	# Bring up interfaces
	info "Bringing up interfaces ($vm)..."
	for iface in fxp0 fxp1 fab0 "$lan_name" "$wan_name"; do
		incus exec "$vm" -- ip link set "$iface" up 2>/dev/null || true
	done

	info "Configuring sysctl ($vm)..."
	incus exec "$vm" -- bash -c 'cat > /etc/sysctl.d/99-bpf.conf <<EOF
net.core.bpf_jit_enable=1
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
EOF'
	incus exec "$vm" -- sysctl --system

	info "Installing packages ($vm, this may take a few minutes)..."
	incus exec "$vm" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev linux-headers-amd64 golang tcpdump iproute2 iperf3 bpftool frr strongswan strongswan-swanctl kea-dhcp4-server kea-dhcp6-server radvd chrony ethtool'

	# Upgrade kernel to latest from Debian unstable
	info "Adding Debian unstable repo for kernel upgrade ($vm)..."
	incus exec "$vm" -- bash -c 'cat > /etc/apt/sources.list.d/unstable.list <<EOF
deb http://deb.debian.org/debian unstable main
EOF
cat > /etc/apt/preferences.d/pin-stable <<EOF
Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: linux-image-amd64 linux-headers-amd64 linux-image-* linux-headers-*
Pin: release a=unstable
Pin-Priority: 990
EOF'
	info "Installing latest kernel from unstable ($vm)..."
	incus exec "$vm" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-image-amd64 linux-headers-amd64'

	# Disable init_on_alloc for XDP performance
	info "Disabling init_on_alloc for XDP performance ($vm)..."
	incus exec "$vm" -- sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"/GRUB_CMDLINE_LINUX_DEFAULT="quiet init_on_alloc=0"/' /etc/default/grub
	incus exec "$vm" -- update-grub

	info "Rebooting VM for new kernel ($vm)..."
	incus restart "$vm"
	local ktries=0
	while ! incus exec "$vm" -- true &>/dev/null; do
		sleep 2
		ktries=$((ktries + 1))
		if [[ $ktries -ge 30 ]]; then
			warn "VM $vm did not come back after kernel upgrade reboot"
			break
		fi
	done
	incus exec "$vm" -- uname -r

	incus exec "$vm" -- systemctl enable frr

	# Chrony: enable and clear default pool sources
	incus exec "$vm" -- systemctl enable chrony
	incus exec "$vm" -- bash -c 'sed -i "s/^pool /#pool /" /etc/chrony/chrony.conf; sed -i "s/^server /#server /" /etc/chrony/chrony.conf'
	incus exec "$vm" -- mkdir -p /etc/chrony/sources.d

	# Write cluster node ID file for ${node} variable expansion
	info "Writing node-id file ($vm, node $idx)..."
	incus exec "$vm" -- mkdir -p /etc/bpfrx
	incus exec "$vm" -- bash -c "echo $idx > /etc/bpfrx/node-id"
}

create_lan_host() {
	if incus info "$LAN_HOST" &>/dev/null 2>&1; then
		info "Container $LAN_HOST already exists, skipping"
		return
	fi

	info "Launching test container $LAN_HOST..."
	incus launch "$IMAGE_CT" "$LAN_HOST" -s default

	# Attach only the cluster LAN network
	incus config device add "$LAN_HOST" eth0 nic network=bpfrx-clan
	incus restart "$LAN_HOST"

	info "Waiting for container to start..."
	sleep 3

	# Configure static IP
	info "Configuring static IP on $LAN_HOST..."
	incus exec "$LAN_HOST" -- bash -c 'cat > /etc/systemd/network/10-cluster-lan.network <<EOF
[Match]
Name=eth0

[Network]
Address=10.0.60.102/24
Gateway=10.0.60.1

[Link]
RequiredForOnline=no
EOF'
	incus exec "$LAN_HOST" -- systemctl restart systemd-networkd
	info "Container $LAN_HOST ready (10.0.60.102/24)."
}

# ── Destroy ──────────────────────────────────────────────────────────

cmd_destroy() {
	for inst in "$VM0" "$VM1" "$LAN_HOST"; do
		if incus info "$inst" &>/dev/null 2>&1; then
			info "Stopping and deleting $inst..."
			incus stop "$inst" --force 2>/dev/null || true
			incus delete "$inst" --force
		else
			info "$inst does not exist"
		fi
	done

	# Optionally clean up networks and profile
	read -rp "Also remove networks and profile? [y/N] " answer
	if [[ "${answer,,}" == "y" ]]; then
		for entry in "${NETWORKS[@]}"; do
			IFS=: read -r name _ _ <<< "$entry"
			if incus network show "$name" &>/dev/null 2>&1; then
				info "Deleting network $name"
				incus network delete "$name"
			fi
		done
		if incus profile show "$PROFILE" &>/dev/null 2>&1; then
			info "Deleting profile $PROFILE"
			incus profile delete "$PROFILE"
		fi
	fi
	info "Destroy complete."
}

# ── Deploy ───────────────────────────────────────────────────────────

cmd_deploy() {
	local target="${1:-all}"

	info "Building bpfrxd and cli..."
	make -C "$PROJECT_ROOT" build build-ctl

	case "$target" in
		0)   deploy_vm 0 ;;
		1)   deploy_vm 1 ;;
		all) deploy_vm 0; deploy_vm 1 ;;
		*)   die "Usage: $0 deploy [0|1|all]" ;;
	esac
}

deploy_vm() {
	local idx="$1"
	local vm
	vm=$(vm_name "$idx")

	if ! incus info "$vm" &>/dev/null 2>&1; then
		die "Instance $vm does not exist. Run '$0 create' first."
	fi

	# Stop running service before pushing binaries (avoids "text file busy")
	incus exec "$vm" -- systemctl stop bpfrxd 2>/dev/null || true
	incus exec "$vm" -- pkill -9 bpfrxd 2>/dev/null || true
	incus exec "$vm" -- pkill -9 cli 2>/dev/null || true
	sleep 1

	info "Pushing bpfrxd to $vm..."
	incus file push "$PROJECT_ROOT/bpfrxd" "$vm/usr/local/sbin/bpfrxd" --mode 0755

	info "Pushing cli to $vm..."
	incus file push "$PROJECT_ROOT/cli" "$vm/usr/local/sbin/cli" --mode 0755

	# Push the single unified HA config (same file for both nodes)
	local conf="${PROJECT_ROOT}/docs/ha-cluster.conf"
	if [[ -f "$conf" ]]; then
		info "Pushing unified HA config to $vm..."
		incus exec "$vm" -- mkdir -p /etc/bpfrx
		incus file push "$conf" "$vm/etc/bpfrx/bpfrx.conf"
	else
		warn "Config file $conf not found"
	fi

	# Ensure node-id file exists
	incus exec "$vm" -- bash -c "echo $idx > /etc/bpfrx/node-id"

	# Install systemd unit
	info "Installing systemd service on $vm..."
	incus file push "${SCRIPT_DIR}/bpfrxd.service" "$vm/etc/systemd/system/bpfrxd.service"
	incus exec "$vm" -- systemctl daemon-reload
	incus exec "$vm" -- systemctl enable --now bpfrxd

	info "Deploy complete for $vm."
}

# ── SSH / Status / Service ───────────────────────────────────────────

cmd_ssh() {
	local idx="${1:-}"
	[[ -z "$idx" ]] && die "Usage: $0 ssh 0|1"
	local vm
	vm=$(vm_name "$idx")
	if ! incus info "$vm" &>/dev/null 2>&1; then
		die "Instance $vm does not exist."
	fi
	exec incus exec "$vm" -- bash -l
}

cmd_status() {
	echo "── Instances ──"
	for inst in "$VM0" "$VM1" "$LAN_HOST"; do
		if incus info "$inst" &>/dev/null 2>&1; then
			local state
			state=$(incus list "$inst" -f csv -c s 2>/dev/null || echo "unknown")
			echo "  $inst: $state"
		else
			echo "  $inst: not created"
		fi
	done

	echo ""
	echo "── Service Status ──"
	for idx in 0 1; do
		local vm
		vm=$(vm_name "$idx")
		if incus info "$vm" &>/dev/null 2>&1; then
			echo "  $vm:"
			incus exec "$vm" -- systemctl is-active bpfrxd 2>/dev/null || echo "    (not installed)"
		fi
	done

	echo ""
	echo "── Networks ──"
	for entry in "${NETWORKS[@]}"; do
		IFS=: read -r name _ _ <<< "$entry"
		if incus network show "$name" &>/dev/null 2>&1; then
			echo "  $name: $(incus network get "$name" ipv4.address) nat=$(incus network get "$name" ipv4.nat)"
		else
			echo "  $name: not created"
		fi
	done

	echo ""
	echo "── Profile ──"
	if incus profile show "$PROFILE" &>/dev/null 2>&1; then
		echo "  $PROFILE: exists"
	else
		echo "  $PROFILE: not created"
	fi
}

cmd_logs() {
	local idx="${1:-}"
	[[ -z "$idx" ]] && die "Usage: $0 logs 0|1"
	local vm
	vm=$(vm_name "$idx")
	incus exec "$vm" -- journalctl -u bpfrxd -n 50 --no-pager
}

cmd_journal() {
	local idx="${1:-}"
	[[ -z "$idx" ]] && die "Usage: $0 journal 0|1"
	local vm
	vm=$(vm_name "$idx")
	incus exec "$vm" -- journalctl -u bpfrxd -f
}

cmd_start() {
	local target="${1:-all}"
	case "$target" in
		0)   incus exec "$VM0" -- systemctl start bpfrxd; info "bpfrxd started on $VM0" ;;
		1)   incus exec "$VM1" -- systemctl start bpfrxd; info "bpfrxd started on $VM1" ;;
		all) incus exec "$VM0" -- systemctl start bpfrxd; incus exec "$VM1" -- systemctl start bpfrxd; info "bpfrxd started on both VMs" ;;
		*)   die "Usage: $0 start [0|1|all]" ;;
	esac
}

cmd_stop() {
	local target="${1:-all}"
	case "$target" in
		0)   incus exec "$VM0" -- systemctl stop bpfrxd; info "bpfrxd stopped on $VM0" ;;
		1)   incus exec "$VM1" -- systemctl stop bpfrxd; info "bpfrxd stopped on $VM1" ;;
		all) incus exec "$VM0" -- systemctl stop bpfrxd; incus exec "$VM1" -- systemctl stop bpfrxd; info "bpfrxd stopped on both VMs" ;;
		*)   die "Usage: $0 stop [0|1|all]" ;;
	esac
}

cmd_restart() {
	local target="${1:-all}"
	case "$target" in
		0)   incus exec "$VM0" -- systemctl restart bpfrxd; info "bpfrxd restarted on $VM0" ;;
		1)   incus exec "$VM1" -- systemctl restart bpfrxd; info "bpfrxd restarted on $VM1" ;;
		all) incus exec "$VM0" -- systemctl restart bpfrxd; incus exec "$VM1" -- systemctl restart bpfrxd; info "bpfrxd restarted on both VMs" ;;
		*)   die "Usage: $0 restart [0|1|all]" ;;
	esac
}

# ── Main ─────────────────────────────────────────────────────────────

usage() {
	echo "Usage: $0 {init|create|destroy|deploy|ssh|status|logs|journal|start|stop|restart} [args]"
	echo ""
	echo "Commands:"
	echo "  init                 Create networks and profile"
	echo "  create               Launch both VMs + test container"
	echo "  destroy              Tear down VMs + container, optionally networks/profile"
	echo "  deploy [0|1|all]     Build bpfrxd and push to VM(s) (default: all)"
	echo "  ssh 0|1              Shell into VM"
	echo "  status               Show all VM/container/network status"
	echo "  logs 0|1             Show recent bpfrxd logs for VM"
	echo "  journal 0|1          Follow bpfrxd logs (live) for VM"
	echo "  start [0|1|all]      Start bpfrxd service (default: all)"
	echo "  stop [0|1|all]       Stop bpfrxd service (default: all)"
	echo "  restart [0|1|all]    Restart bpfrxd service (default: all)"
	exit 1
}

case "${1:-}" in
	init)       cmd_init ;;
	create)     cmd_create ;;
	destroy)    cmd_destroy ;;
	deploy)     cmd_deploy "${2:-all}" ;;
	ssh)        cmd_ssh "${2:-}" ;;
	status)     cmd_status ;;
	logs)       cmd_logs "${2:-}" ;;
	journal)    cmd_journal "${2:-}" ;;
	start)      cmd_start "${2:-all}" ;;
	stop)       cmd_stop "${2:-all}" ;;
	restart)    cmd_restart "${2:-all}" ;;
	*)          usage ;;
esac
