#!/usr/bin/env bash
# xpf Incus test environment management
#
# Creates an isolated VM or privileged container with multiple network
# interfaces for testing the xpf eBPF firewall.
#
# Usage:
#   ./test/incus/setup.sh init        # Install incus, create networks + profiles
#   ./test/incus/setup.sh create-vm   # Launch xpf-fw VM
#   ./test/incus/setup.sh create-ct   # Launch xpf-fw container
#   ./test/incus/setup.sh destroy     # Tear down instance + networks + profiles
#   ./test/incus/setup.sh deploy      # Build xpf, push binary to instance
#   ./test/incus/setup.sh ssh         # Shell into the instance
#   ./test/incus/setup.sh status      # Show instance and network status

set -euo pipefail

# Re-exec under incus-admin group if needed
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		exec sg incus-admin -c "$(printf '%q ' "$0" "$@")"
	fi
fi

INSTANCE_NAME="xpf-fw"
VM_PROFILE="xpf-vm"
CT_PROFILE="xpf-container"
IMAGE_VM="images:debian/13"
IMAGE_CT="images:debian/13"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Network definitions: name:subnet:nat
# Dataplane networks use none — DHCP comes from the firewall VM, not the bridge.
NETWORKS=(
	"xpf-trust:none:false"
	"xpf-untrust:none:false"
	"xpf-dmz:none:false"
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
	# Only fxp0 (mgmt) in profile — em0 and data NICs are added in
	# cmd_create_vm while the VM is stopped, to control PCI bus ordering.
	# em0 can't share incusbr0 with fxp0 (Incus DNS name conflict).
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
YAML
}

create_ct_profile() {
	if ! incus profile show "$CT_PROFILE" &>/dev/null 2>&1; then
		info "Creating profile $CT_PROFILE"
		incus profile create "$CT_PROFILE"
	else
		info "Updating profile $CT_PROFILE"
	fi
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
    network: incusbr0
    type: nic
  eth2:
    name: eth2
    network: xpf-trust
    type: nic
  eth3:
    name: eth3
    network: xpf-untrust
    type: nic
  eth4:
    name: eth4
    network: xpf-dmz
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
		if [[ $tries -ge 90 ]]; then
			die "VM agent did not become ready after 180 seconds"
		fi
	done

	# Stop VM to add PCI passthrough devices (can't be hotplugged) and
	# extra virtio data NICs. Profile only has fxp0. Standalone has no em0.
	# Note: PCI passthrough always gets higher bus numbers than virtio (QEMU).
	info "Stopping VM to add NICs and PCI devices..."
	incus stop "$INSTANCE_NAME"

	# Add virtio data NICs
	info "Adding virtio data NICs (trust, untrust, dmz)..."
	incus config device add "$INSTANCE_NAME" eth1 nic network=xpf-trust
	incus config device add "$INSTANCE_NAME" eth2 nic network=xpf-untrust
	incus config device add "$INSTANCE_NAME" eth3 nic network=xpf-dmz

	# Add PCI passthrough devices
	local wan_pci loss_pci
	wan_pci=$(readlink -f /sys/class/net/enp101s0f0np0/device 2>/dev/null | xargs basename 2>/dev/null)
	if [[ -n "$wan_pci" ]]; then
		info "Adding WAN PF ($wan_pci)..."
		incus config device add "$INSTANCE_NAME" internet pci address="$wan_pci"
	else
		warn "WAN interface enp101s0f0np0 not found, skipping"
	fi

	loss_pci=$(readlink -f /sys/class/net/enp101s0f1np1/device 2>/dev/null | xargs basename 2>/dev/null)
	if [[ -n "$loss_pci" ]]; then
		info "Adding loss PF ($loss_pci)..."
		incus config device add "$INSTANCE_NAME" loss pci address="$loss_pci"
	else
		warn "Loss interface enp101s0f1np1 not found, skipping"
	fi

	# Start VM with all devices
	info "Starting VM..."
	incus start "$INSTANCE_NAME"
	info "Waiting for VM agent..."
	tries=0
	while ! incus exec "$INSTANCE_NAME" -- true &>/dev/null; do
		sleep 2
		tries=$((tries + 1))
		if [[ $tries -ge 90 ]]; then
			die "VM agent did not become ready after 180 seconds"
		fi
	done

	provision_instance vm
	info "VM ready. Run '$0 deploy' to push xpfd binary."
}

provision_instance() {
	local type="$1"  # "vm" or "ct"

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

	# Interface naming (fxp0, em0, ge-X/0/Y) is now handled by xpfd itself
	# at startup — no external script needed.
	incus exec "$INSTANCE_NAME" -- mkdir -p /etc/xpf

	# Remove any stale non-xpf networkd files
	incus exec "$INSTANCE_NAME" -- rm -f \
		/etc/systemd/network/enp5s0.network \
		/etc/systemd/network/10-mgmt0.network \
		/etc/systemd/network/10-mgmt0.link 2>/dev/null || true

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
	incus exec "$INSTANCE_NAME" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev linux-headers-amd64 golang tcpdump iproute2 iperf3 bpftool frr strongswan strongswan-swanctl kea-dhcp4-server kea-dhcp6-server chrony mtr-tiny linux-perf host pciutils'

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

	# Chrony: enable service and clear default pool sources so only
	# xpfd-managed servers (via sources.d/xpf.sources) are used.
	incus exec "$INSTANCE_NAME" -- systemctl enable chrony
	incus exec "$INSTANCE_NAME" -- bash -c 'sed -i "s/^pool /#pool /" /etc/chrony/chrony.conf; sed -i "s/^server /#server /" /etc/chrony/chrony.conf'
	incus exec "$INSTANCE_NAME" -- mkdir -p /etc/chrony/sources.d
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
	info "Container ready. Run '$0 deploy' to push xpfd binary."
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

	info "Building xpfd and cli..."
	make -C "$PROJECT_ROOT" build build-ctl

	# Migrate from old bpfrxd naming if present.
	incus exec "$INSTANCE_NAME" -- systemctl stop bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- systemctl disable bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- rm -f /etc/systemd/system/bpfrxd.service 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- rm -f /usr/local/sbin/bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- bash -c 'if [ -d /etc/bpfrx ] && [ ! -d /etc/xpf ]; then mv /etc/bpfrx /etc/xpf; fi' 2>/dev/null || true

	# Stop service gracefully, then clean BPF state for binary upgrade.
	# Order matters: systemctl stop sends SIGTERM (graceful socket close),
	# then xpfd cleanup removes pinned BPF maps/links.  The final
	# pkill -9 is a safety net for "text file busy" on push.
	incus exec "$INSTANCE_NAME" -- systemctl stop xpfd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- xpfd cleanup 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 xpfd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 xpf-userspace 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 cli 2>/dev/null || true
	sleep 1

	info "Pushing xpfd to $INSTANCE_NAME..."
	incus file push "$PROJECT_ROOT/xpfd" "$INSTANCE_NAME/usr/local/sbin/xpfd" --mode 0755

	info "Pushing cli to $INSTANCE_NAME..."
	incus file push "$PROJECT_ROOT/cli" "$INSTANCE_NAME/usr/local/sbin/cli" --mode 0755

	# Push test config if it exists
	if [[ -f "${SCRIPT_DIR}/xpf-test.conf" ]]; then
		info "Pushing test config..."
		incus exec "$INSTANCE_NAME" -- mkdir -p /etc/xpf
		incus file push "${SCRIPT_DIR}/xpf-test.conf" "$INSTANCE_NAME/etc/xpf/xpf.conf"
	fi

	# Install systemd unit file
	info "Installing systemd service..."
	incus file push "${SCRIPT_DIR}/xpfd.service" "$INSTANCE_NAME/etc/systemd/system/xpfd.service"
	incus exec "$INSTANCE_NAME" -- systemctl daemon-reload
	incus exec "$INSTANCE_NAME" -- systemctl enable --now xpfd

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
	incus exec "$INSTANCE_NAME" -- systemctl start xpfd
	info "xpfd started"
}

cmd_stop() {
	incus exec "$INSTANCE_NAME" -- systemctl stop xpfd
	info "xpfd stopped"
}

cmd_restart() {
	incus exec "$INSTANCE_NAME" -- systemctl restart xpfd
	info "xpfd restarted"
}

cmd_logs() {
	incus exec "$INSTANCE_NAME" -- journalctl -u xpfd -n 50 --no-pager
}

cmd_journal() {
	incus exec "$INSTANCE_NAME" -- journalctl -u xpfd -f
}

cmd_status() {
	echo "── Service ──"
	incus exec "$INSTANCE_NAME" -- systemctl status xpfd --no-pager 2>/dev/null || echo "(service not installed)"
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
	echo "  deploy      Build xpfd and push to instance"
	echo "  ssh         Shell into the instance"
	echo "  status      Show instance, service, and network status"
	echo "  start       Start xpfd service"
	echo "  stop        Stop xpfd service"
	echo "  restart     Restart xpfd service"
	echo "  logs        Show recent xpfd logs"
	echo "  journal     Follow xpfd logs (live)"
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
