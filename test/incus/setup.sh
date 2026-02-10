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

# Network definitions: name subnet nat
NETWORKS=(
	"bpfrx-trust:10.0.1.1/24:false"
	"bpfrx-untrust:10.0.2.1/24:true"
	"bpfrx-dmz:10.0.30.1/24:false"
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
  eth5:
    name: enp10s0
    nictype: macvlan
    parent: ge3
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

	provision_instance vm
	info "VM ready. Run '$0 deploy' to push bpfrxd binary."
}

provision_instance() {
	local type="$1"  # "vm" or "ct"

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

	# Bring up interfaces (IPs are assigned by bpfrxd from config)
	info "Bringing up interfaces..."
	incus exec "$INSTANCE_NAME" -- ip link set "$iface_trust" up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set "$iface_untrust" up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set "$iface_dmz" up 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- ip link set "$iface_tunnel" up 2>/dev/null || true

	# Internet-facing interface: disable RequiredForOnline (DHCP handled by bpfrxd)
	if [[ "$type" == "vm" ]]; then
		local use_networkd=false
		if incus exec "$INSTANCE_NAME" -- systemctl is-active systemd-networkd &>/dev/null; then
			use_networkd=true
		fi
		if [[ "$use_networkd" == "true" ]]; then
			incus exec "$INSTANCE_NAME" -- bash -c "cat > /etc/systemd/network/50-internet.network" <<-EOF
			[Match]
			Name=enp10s0
			[Link]
			RequiredForOnline=no
			EOF
			incus exec "$INSTANCE_NAME" -- networkctl reload
		fi
	fi

	info "Configuring sysctl..."
	incus exec "$INSTANCE_NAME" -- bash -c 'cat > /etc/sysctl.d/99-bpf.conf <<EOF
net.core.bpf_jit_enable=1
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF'
	incus exec "$INSTANCE_NAME" -- sysctl --system

	info "Installing packages (this may take a few minutes)..."
	incus exec "$INSTANCE_NAME" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev linux-headers-amd64 golang tcpdump iproute2 iperf3 bpftool frr strongswan strongswan-swanctl'

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

	info "Building bpfrxd and bpfrxctl..."
	make -C "$PROJECT_ROOT" build build-ctl

	# Stop running bpfrxd if any (avoids "text file busy")
	incus exec "$INSTANCE_NAME" -- pkill -9 bpfrxd 2>/dev/null || true
	sleep 1

	info "Pushing bpfrxd to $INSTANCE_NAME..."
	incus file push "$PROJECT_ROOT/bpfrxd" "$INSTANCE_NAME/usr/local/sbin/bpfrxd" --mode 0755

	info "Pushing bpfrxctl to $INSTANCE_NAME..."
	incus file push "$PROJECT_ROOT/bpfrxctl" "$INSTANCE_NAME/usr/local/bin/bpfrxctl" --mode 0755

	# Push test config if it exists
	if [[ -f "${SCRIPT_DIR}/bpfrx-test.conf" ]]; then
		info "Pushing test config..."
		incus exec "$INSTANCE_NAME" -- mkdir -p /etc/bpfrx
		incus file push "${SCRIPT_DIR}/bpfrx-test.conf" "$INSTANCE_NAME/etc/bpfrx/bpfrx.conf"
	fi

	info "Deploy complete. Run '$0 ssh' then 'bpfrxd' to start."
}

# ── SSH / Status ──────────────────────────────────────────────────────

cmd_ssh() {
	if ! incus info "$INSTANCE_NAME" &>/dev/null 2>&1; then
		die "Instance $INSTANCE_NAME does not exist."
	fi
	exec incus exec "$INSTANCE_NAME" -- bash -l
}

cmd_status() {
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
	echo "Usage: $0 {init|create-vm|create-ct|destroy|deploy|ssh|status}"
	echo ""
	echo "Commands:"
	echo "  init        Install incus, create networks and profiles"
	echo "  create-vm   Launch a QEMU VM (full BPF support)"
	echo "  create-ct   Launch a privileged container (quick testing)"
	echo "  destroy     Tear down instance, optionally networks/profiles"
	echo "  deploy      Build bpfrxd and push to instance"
	echo "  ssh         Shell into the instance"
	echo "  status      Show instance and network status"
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
	*)          usage ;;
esac
