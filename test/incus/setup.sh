#!/usr/bin/env bash
# bpfrx Incus test environment management
#
# Creates an isolated VM or privileged container with multiple network
# interfaces for testing the bpfrx eBPF firewall.
#
# Usage:
#   ./test/incus/setup.sh init        # Install incus, create networks + profiles
#   ./test/incus/setup.sh create-vm   # Launch bpfrx-fw VM
#   ./test/incus/setup.sh create-ct   # Launch bpfrx-fw container
#   ./test/incus/setup.sh destroy     # Tear down instance + networks + profiles
#   ./test/incus/setup.sh deploy      # Build bpfrx, push binary to instance
#   ./test/incus/setup.sh ssh         # Shell into the instance
#   ./test/incus/setup.sh status      # Show instance and network status

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

INSTANCE_NAME="bpfrx-fw"
VM_PROFILE="bpfrx-vm"
CT_PROFILE="bpfrx-container"
IMAGE_VM="images:debian/13"
IMAGE_CT="images:debian/13"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Network definitions: name:subnet:nat
# Dataplane networks use none — DHCP comes from the firewall VM, not the bridge.
NETWORKS=(
	"bpfrx-trust:none:false"
	"bpfrx-untrust:none:false"
	"bpfrx-dmz:none:false"
	"bpfrx-tunnel:10.0.40.1/24:false"
)

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }
die()   { echo "ERROR: $*" >&2; exit 1; }

# ── Install & Initialize ──────────────────────────────────────────────

cmd_init() {
	install_incus
	init_incus
	create_networks
	create_profiles
	info "Init complete. Run '$0 create-vm' or '$0 create-ct' next."
}

install_incus() {
	if command -v incus &>/dev/null; then
		info "Incus already installed: $(incus version)"
		return
	fi
	info "Installing incus..."
	sudo apt-get update -qq
	sudo apt-get install -y -qq incus
	info "Incus installed: $(incus version)"
}

init_incus() {
	# Check if incus is already initialized by looking for the default pool
	if incus storage show default &>/dev/null 2>&1; then
		info "Incus already initialized"
		return
	fi
	info "Initializing incus storage..."
	# Try creating the default storage pool directly (works if daemon is running)
	if incus storage create default dir 2>/dev/null; then
		info "Created default storage pool"
	else
		info "Running incus admin init..."
		sudo incus admin init --minimal
	fi
	# Ensure current user can talk to incus
	if ! incus list &>/dev/null 2>&1; then
		warn "Cannot connect to incus. You may need to add yourself to the 'incus-admin' group:"
		warn "  sudo usermod -aG incus-admin $USER && newgrp incus-admin"
	fi
}

create_networks() {
	for entry in "${NETWORKS[@]}"; do
		IFS=: read -r name subnet nat <<< "$entry"
		if incus network show "$name" &>/dev/null 2>&1; then
			info "Network $name already exists"
			continue
		fi
		info "Creating network $name ($subnet, nat=$nat)"
		incus network create "$name" \
			ipv4.address="$subnet" \
			ipv4.nat="$nat" \
			ipv6.address=none
	done
}

create_profiles() {
	create_vm_profile
	create_ct_profile
}

create_vm_profile() {
	if incus profile show "$VM_PROFILE" &>/dev/null 2>&1; then
		info "Profile $VM_PROFILE already exists, updating..."
		incus profile delete "$VM_PROFILE" 2>/dev/null || true
	fi
	info "Creating profile $VM_PROFILE"
	incus profile create "$VM_PROFILE"
	incus profile edit "$VM_PROFILE" <<'YAML'
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
    network: bpfrx-trust
    type: nic
  eth2:
    name: enp7s0
    network: bpfrx-untrust
    type: nic
  eth3:
    name: enp8s0
    network: bpfrx-dmz
    type: nic
  eth4:
    name: enp9s0
    network: bpfrx-tunnel
    type: nic
YAML
}

create_ct_profile() {
	if incus profile show "$CT_PROFILE" &>/dev/null 2>&1; then
		info "Profile $CT_PROFILE already exists, updating..."
		incus profile delete "$CT_PROFILE" 2>/dev/null || true
	fi
	info "Creating profile $CT_PROFILE"
	incus profile create "$CT_PROFILE"
	incus profile edit "$CT_PROFILE" <<'YAML'
config:
  security.privileged: "true"
  security.nesting: "true"
  limits.cpu: "4"
  limits.memory: 4GB
  raw.lxc: |
    lxc.mount.auto = proc:rw sys:rw cgroup:rw
    lxc.cap.drop =
devices:
  root:
    path: /
    pool: default
    size: 20GB
    type: disk
  eth0:
    name: eth0
    network: incusbr0
    type: nic
  eth1:
    name: eth1
    network: bpfrx-trust
    type: nic
  eth2:
    name: eth2
    network: bpfrx-untrust
    type: nic
  eth3:
    name: eth3
    network: bpfrx-dmz
    type: nic
  eth4:
    name: eth4
    network: bpfrx-tunnel
    type: nic
YAML
}

# ── Instance Management ───────────────────────────────────────────────

cmd_create_vm() {
	if incus info "$INSTANCE_NAME" &>/dev/null 2>&1; then
		die "Instance $INSTANCE_NAME already exists. Run '$0 destroy' first."
	fi
	info "Launching VM $INSTANCE_NAME..."
	incus launch "$IMAGE_VM" "$INSTANCE_NAME" --vm --profile "$VM_PROFILE"

	info "Waiting for VM agent..."
	local tries=0
	while ! incus exec "$INSTANCE_NAME" -- true &>/dev/null; do
		sleep 2
		tries=$((tries + 1))
		if [[ $tries -ge 30 ]]; then
			die "VM agent did not become ready after 60 seconds"
		fi
	done

	# Hot-add PCI passthrough NICs after boot
	# (NIC type fails with agent race; PCI type does raw VFIO passthrough)
	# Capture MACs before passthrough (host sysfs disappears after VFIO bind)
	local wan_pci wan_mac loss_pci loss_mac
	wan_pci=$(readlink -f /sys/class/net/enp101s0f0v0/device 2>/dev/null | xargs basename 2>/dev/null)
	wan_mac=$(cat /sys/class/net/enp101s0f0v0/address 2>/dev/null || echo "")
	if [[ -n "$wan_pci" ]]; then
		info "Adding WAN NIC ($wan_pci, MAC=$wan_mac) to VM via PCI passthrough..."
		incus config device add "$INSTANCE_NAME" internet pci address="$wan_pci"
	else
		warn "WAN interface enp101s0f0v0 not found, skipping"
	fi

	loss_pci=$(readlink -f /sys/class/net/enp101s0f1np1/device 2>/dev/null | xargs basename 2>/dev/null)
	loss_mac=$(cat /sys/class/net/enp101s0f1np1/address 2>/dev/null || echo "")
	if [[ -n "$loss_pci" ]]; then
		info "Adding loss NIC ($loss_pci, MAC=$loss_mac) to VM via PCI passthrough..."
		incus config device add "$INSTANCE_NAME" loss pci address="$loss_pci"
	else
		warn "Loss interface enp101s0f1np1 not found, skipping"
	fi

	provision_instance vm "$wan_mac" "$loss_mac"
	info "VM ready. Run '$0 deploy' to push bpfrxd binary."
}

provision_instance() {
	local type="$1"  # "vm" or "ct"
	local wan_mac_arg="${2:-}"
	local loss_mac_arg="${3:-}"

	# Interface names differ between VM (PCI enumeration) and container
	local iface_mgmt iface_trust iface_untrust iface_dmz iface_tunnel
	if [[ "$type" == "vm" ]]; then
		iface_mgmt=enp5s0; iface_trust=enp6s0; iface_untrust=enp7s0
		iface_dmz=enp8s0; iface_tunnel=enp9s0
	else
		iface_mgmt=eth0; iface_trust=eth1; iface_untrust=eth2
		iface_dmz=eth3; iface_tunnel=eth4
	fi

	# Wait for systemd to be ready (VM agent may respond before systemd is up)
	info "Waiting for system to be ready..."
	local stries=0
	while ! incus exec "$INSTANCE_NAME" -- systemctl is-system-running &>/dev/null 2>&1; do
		sleep 2
		stries=$((stries + 1))
		if [[ $stries -ge 30 ]]; then
			warn "systemd did not become ready after 60 seconds, continuing anyway"
			break
		fi
	done

	# Bootstrap systemd-networkd .link files for interface renaming.
	# bpfrxd writes the same files once running, but these bootstrap files
	# ensure interfaces are renamed before the daemon's first start.
	# All interfaces (including mgmt) are fully managed by bpfrxd.
	info "Writing bootstrap networkd .link files..."
	if [[ "$type" == "vm" ]]; then
		# Read MAC addresses from kernel interfaces
		local mac_mgmt mac_trust mac_untrust mac_dmz mac_tunnel mac_wan
		mac_mgmt=$(incus exec "$INSTANCE_NAME" -- cat /sys/class/net/"$iface_mgmt"/address 2>/dev/null || true)
		mac_trust=$(incus exec "$INSTANCE_NAME" -- cat /sys/class/net/"$iface_trust"/address 2>/dev/null || true)
		mac_untrust=$(incus exec "$INSTANCE_NAME" -- cat /sys/class/net/"$iface_untrust"/address 2>/dev/null || true)
		mac_dmz=$(incus exec "$INSTANCE_NAME" -- cat /sys/class/net/"$iface_dmz"/address 2>/dev/null || true)
		mac_tunnel=$(incus exec "$INSTANCE_NAME" -- cat /sys/class/net/"$iface_tunnel"/address 2>/dev/null || true)
		mac_wan=$(incus exec "$INSTANCE_NAME" -- cat /sys/class/net/enp10s0f0np0/address 2>/dev/null || true)
		# loss0 MAC: try reading from VM, fall back to arg passed from host
		local mac_loss
		mac_loss=$(incus exec "$INSTANCE_NAME" -- bash -c 'for i in /sys/class/net/enp*s0*np1/address; do cat "$i" 2>/dev/null && break; done' 2>/dev/null || true)
		[[ -z "$mac_loss" ]] && mac_loss="$loss_mac_arg"

		# Write .link files (same format bpfrxd generates)
		for pair in "mgmt0:$mac_mgmt" "trust0:$mac_trust" "untrust0:$mac_untrust" \
			"dmz0:$mac_dmz" "tunnel0:$mac_tunnel" "wan0:$mac_wan" "loss0:$mac_loss"; do
			local name="${pair%%:*}" mac="${pair#*:}"
			if [[ -n "$mac" ]]; then
				incus exec "$INSTANCE_NAME" -- bash -c "cat > /etc/systemd/network/10-bpfrx-${name}.link << LINKEOF
# Managed by bpfrxd — do not edit
[Match]
MACAddress=${mac}

[Link]
Name=${name}
LINKEOF"
			fi
		done

		# Remove any stale non-bpfrx networkd files for firewall interfaces
		incus exec "$INSTANCE_NAME" -- rm -f \
			/etc/systemd/network/enp5s0.network \
			/etc/systemd/network/10-mgmt0.network \
			/etc/systemd/network/10-mgmt0.link 2>/dev/null || true

		incus exec "$INSTANCE_NAME" -- networkctl reload
		sleep 1
	fi

	# Bring up interfaces (IPs are assigned by bpfrxd from config)
	info "Bringing up interfaces..."
	incus exec "$INSTANCE_NAME" -- ip link set mgmt0 up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set trust0 up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set untrust0 up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set dmz0 up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set tunnel0 up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set wan0 up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set loss0 up 2>/dev/null || true

	info "Configuring sysctl..."
	incus exec "$INSTANCE_NAME" -- bash -c 'cat > /etc/sysctl.d/99-bpf.conf <<EOF
net.core.bpf_jit_enable=1
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
EOF'
	incus exec "$INSTANCE_NAME" -- sysctl --system

	info "Installing packages (this may take a few minutes)..."
	incus exec "$INSTANCE_NAME" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev linux-headers-amd64 golang tcpdump iproute2 iperf3 bpftool frr strongswan strongswan-swanctl kea-dhcp4-server kea-dhcp6-server radvd chrony'

	# Upgrade kernel to latest from Debian unstable for full BPF verifier support
	info "Adding Debian unstable repo for kernel upgrade..."
	incus exec "$INSTANCE_NAME" -- bash -c 'cat > /etc/apt/sources.list.d/unstable.list <<EOF
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
	info "Installing latest kernel from unstable..."
	incus exec "$INSTANCE_NAME" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-image-amd64 linux-headers-amd64'

	# Disable init_on_alloc — Debian enables CONFIG_INIT_ON_ALLOC_DEFAULT_ON which
	# zeros every allocated page, costing ~20% CPU in the virtio-net XDP path.
	info "Disabling init_on_alloc for XDP performance..."
	incus exec "$INSTANCE_NAME" -- sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"/GRUB_CMDLINE_LINUX_DEFAULT="quiet init_on_alloc=0"/' /etc/default/grub
	incus exec "$INSTANCE_NAME" -- update-grub

	info "Rebooting VM for new kernel..."
	incus restart "$INSTANCE_NAME"
	local ktries=0
	while ! incus exec "$INSTANCE_NAME" -- true &>/dev/null; do
		sleep 2
		ktries=$((ktries + 1))
		if [[ $ktries -ge 30 ]]; then
			warn "VM did not come back after kernel upgrade reboot"
			break
		fi
	done
	incus exec "$INSTANCE_NAME" -- uname -r

	incus exec "$INSTANCE_NAME" -- systemctl enable frr
}

cmd_create_ct() {
	if incus info "$INSTANCE_NAME" &>/dev/null 2>&1; then
		die "Instance $INSTANCE_NAME already exists. Run '$0 destroy' first."
	fi
	info "Launching container $INSTANCE_NAME..."
	incus launch "$IMAGE_CT" "$INSTANCE_NAME" --profile "$CT_PROFILE"
	info "Waiting for container to start..."
	sleep 3
	provision_instance ct
	info "Container ready. Run '$0 deploy' to push bpfrxd binary."
}

cmd_destroy() {
	if incus info "$INSTANCE_NAME" &>/dev/null 2>&1; then
		info "Stopping and deleting instance $INSTANCE_NAME..."
		incus stop "$INSTANCE_NAME" --force 2>/dev/null || true
		incus delete "$INSTANCE_NAME" --force
	else
		info "Instance $INSTANCE_NAME does not exist"
	fi

	# Optionally clean up networks and profiles
	read -rp "Also remove networks and profiles? [y/N] " answer
	if [[ "${answer,,}" == "y" ]]; then
		for entry in "${NETWORKS[@]}"; do
			IFS=: read -r name _ _ <<< "$entry"
			if incus network show "$name" &>/dev/null 2>&1; then
				info "Deleting network $name"
				incus network delete "$name"
			fi
		done
		for profile in "$VM_PROFILE" "$CT_PROFILE"; do
			if incus profile show "$profile" &>/dev/null 2>&1; then
				info "Deleting profile $profile"
				incus profile delete "$profile"
			fi
		done
	fi
	info "Destroy complete."
}

# ── Deploy ────────────────────────────────────────────────────────────

cmd_deploy() {
	if ! incus info "$INSTANCE_NAME" &>/dev/null 2>&1; then
		die "Instance $INSTANCE_NAME does not exist. Run '$0 create-vm' or '$0 create-ct' first."
	fi

	info "Building bpfrxd and cli..."
	make -C "$PROJECT_ROOT" build build-ctl

	# Stop running service before pushing binaries (avoids "text file busy")
	incus exec "$INSTANCE_NAME" -- systemctl stop bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 cli 2>/dev/null || true
	sleep 1

	info "Pushing bpfrxd to $INSTANCE_NAME..."
	incus file push "$PROJECT_ROOT/bpfrxd" "$INSTANCE_NAME/usr/local/sbin/bpfrxd" --mode 0755

	info "Pushing cli to $INSTANCE_NAME..."
	incus file push "$PROJECT_ROOT/cli" "$INSTANCE_NAME/usr/local/sbin/cli" --mode 0755

	# Push test config if it exists
	if [[ -f "${SCRIPT_DIR}/bpfrx-test.conf" ]]; then
		info "Pushing test config..."
		incus exec "$INSTANCE_NAME" -- mkdir -p /etc/bpfrx
		incus file push "${SCRIPT_DIR}/bpfrx-test.conf" "$INSTANCE_NAME/etc/bpfrx/bpfrx.conf"
	fi

	# Install systemd unit file
	info "Installing systemd service..."
	incus file push "${SCRIPT_DIR}/bpfrxd.service" "$INSTANCE_NAME/etc/systemd/system/bpfrxd.service"
	incus exec "$INSTANCE_NAME" -- systemctl daemon-reload
	incus exec "$INSTANCE_NAME" -- systemctl enable --now bpfrxd

	# Suppress management interface default route so FRR-managed routes take effect.
	# The permanent fix is UseRoutes=false in networkd, but on existing VMs the
	# kernel DHCP route may already be installed.
	incus exec "$INSTANCE_NAME" -- ip route del default via 10.0.100.1 dev enp5s0 2>/dev/null || true

	info "Deploy complete. Service started via systemd."
	info "  Logs:    $0 logs"
	info "  Status:  $0 status"
	info "  SSH:     $0 ssh"
}

# ── SSH / Status ──────────────────────────────────────────────────────

cmd_ssh() {
	if ! incus info "$INSTANCE_NAME" &>/dev/null 2>&1; then
		die "Instance $INSTANCE_NAME does not exist."
	fi
	exec incus exec "$INSTANCE_NAME" -- bash -l
}

cmd_start() {
	incus exec "$INSTANCE_NAME" -- systemctl start bpfrxd
	info "bpfrxd started"
}

cmd_stop() {
	incus exec "$INSTANCE_NAME" -- systemctl stop bpfrxd
	info "bpfrxd stopped"
}

cmd_restart() {
	incus exec "$INSTANCE_NAME" -- systemctl restart bpfrxd
	info "bpfrxd restarted"
}

cmd_logs() {
	incus exec "$INSTANCE_NAME" -- journalctl -u bpfrxd -n 50 --no-pager
}

cmd_journal() {
	incus exec "$INSTANCE_NAME" -- journalctl -u bpfrxd -f
}

cmd_status() {
	echo "── Service ──"
	incus exec "$INSTANCE_NAME" -- systemctl status bpfrxd --no-pager 2>/dev/null || echo "(service not installed)"
	echo ""
	echo "── Instance ──"
	incus list "$INSTANCE_NAME" -f table 2>/dev/null || echo "(no instance)"
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
	echo "── Profiles ──"
	for profile in "$VM_PROFILE" "$CT_PROFILE"; do
		if incus profile show "$profile" &>/dev/null 2>&1; then
			echo "  $profile: exists"
		else
			echo "  $profile: not created"
		fi
	done
}

# ── Main ──────────────────────────────────────────────────────────────

usage() {
	echo "Usage: $0 {init|create-vm|create-ct|destroy|deploy|ssh|status|start|stop|restart|logs|journal}"
	echo ""
	echo "Commands:"
	echo "  init        Install incus, create networks and profiles"
	echo "  create-vm   Launch a QEMU VM (full BPF support)"
	echo "  create-ct   Launch a privileged container (quick testing)"
	echo "  destroy     Tear down instance, optionally networks/profiles"
	echo "  deploy      Build bpfrxd and push to instance"
	echo "  ssh         Shell into the instance"
	echo "  status      Show instance, service, and network status"
	echo "  start       Start bpfrxd service"
	echo "  stop        Stop bpfrxd service"
	echo "  restart     Restart bpfrxd service"
	echo "  logs        Show recent bpfrxd logs"
	echo "  journal     Follow bpfrxd logs (live)"
	exit 1
}

case "${1:-}" in
	init)       cmd_init ;;
	create-vm)  cmd_create_vm ;;
	create-ct)  cmd_create_ct ;;
	destroy)    cmd_destroy ;;
	deploy)     cmd_deploy ;;
	ssh)        cmd_ssh ;;
	status)     cmd_status ;;
	start)      cmd_start ;;
	stop)       cmd_stop ;;
	restart)    cmd_restart ;;
	logs)       cmd_logs ;;
	journal)    cmd_journal ;;
	*)          usage ;;
esac
