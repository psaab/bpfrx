#!/usr/bin/env bash
# xpf Incus test environment management
#
# Creates an isolated VM or privileged container with multiple network
# interfaces for testing the xpf userspace dataplane firewall.
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

# Re-exec under incus-admin group if needed. Forward XPF_* scalar vars
# (e.g. XPF_BASE_RELEASE / IMAGE_VM / IMAGE_CT) across the re-exec: sg's
# env preservation is not guaranteed on every platform, so without this a
# `XPF_BASE_RELEASE=... make test-vm` would silently fall back to the
# default after the sg re-exec (Copilot r2). Mirrors cluster-setup.sh.
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		local_env=""
		for _v in "${!XPF_@}" "${!IMAGE_@}"; do
			local_env+="${_v}=$(printf '%q' "${!_v}") "
		done
		exec sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"
	fi
fi

INSTANCE_NAME="xpf-fw"
VM_PROFILE="xpf-vm"
CT_PROFILE="xpf-container"
# Ubuntu 26.04 to match the production appliance base (scripts/image/bake.py).
# XPF_BASE_RELEASE pins the Ubuntu release the way bake.py's same-named knob
# does; the *test* VM must track whatever release production was last baked at
# (a deliberate, reviewed bump), NOT silently follow the newest Ubuntu the day
# you run `make test-vm`. IMAGE_VM/IMAGE_CT stay env-overridable for pinning a
# different *Ubuntu* release — they are NOT a Debian fallback path (#1943): the
# script now uses Ubuntu package names and a >= 6.18 kernel floor, so a Debian
# image would fail. Rollback is `git revert`, not a runtime IMAGE_VM override.
#
# VM uses the /cloud (cloud-init) variant to match bake.py's cloudimg base; the
# container uses the plain non-cloud alias — both aliases publish a CONTAINER
# rootfs, but the non-cloud one avoids dragging cloud-init into a container that
# does not need it (Copilot r2). Both are env-overridable for a different Ubuntu
# release (NOT a Debian fallback — Ubuntu package names + the 6.18 floor apply).
XPF_BASE_RELEASE="${XPF_BASE_RELEASE:-26.04}"
IMAGE_VM="${IMAGE_VM:-images:ubuntu/${XPF_BASE_RELEASE}/cloud}"
IMAGE_CT="${IMAGE_CT:-images:ubuntu/${XPF_BASE_RELEASE}}"
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
  # Secure Boot ON to match the production posture (#1943). The Ubuntu 26.04
  # base ships a Canonical-signed shim->grub->kernel chain that boots under
  # OVMF Secure Boot with no MOK enrollment, and the kernel locks down. The
  # AF_XDP shim is a BPF_PROG_TYPE_XDP program (not a signed kernel module), so
  # lockdown does not reject it. Validated on images:ubuntu/26.04/cloud.
  # NOTE: a vanilla Secure-Boot VM proves only "shim->grub->kernel boots + the
  # AF_XDP shim loads under SB"; the #1930 A4 promote/rollback channel needs the
  # baked qcow2 (xpf-uefi-slots/09_xpf A/B-ESP substrate) — see XPF_BAKED_IMAGE.
  security.secureboot: "true"
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

	# Userspace tooling installed in BOTH the VM and the container. Ubuntu 26.04
	# package names (#1943): host -> bind9-host; golang dropped (the instance
	# never compiles Go — `make build` runs on the host, `test-deploy` pushes the
	# binary). clang/llvm/libbpf-dev kept for ad-hoc in-instance debugging.
	info "Installing packages (this may take a few minutes)..."
	incus exec "$INSTANCE_NAME" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev tcpdump iproute2 iperf3 bpftool frr strongswan strongswan-swanctl kea-dhcp4-server kea-dhcp6-server chrony mtr-tiny bind9-host pciutils curl wget ripgrep'

	# Kernel-coupled provisioning is VM-ONLY (Codex r1 HIGH). A container shares
	# the HOST kernel, so `uname -r` inside it is the host's (here a Debian
	# kernel) — installing linux-headers/linux-tools-$(uname -r), asserting guest
	# module dirs, editing grub, or rebooting are all meaningless or actively
	# wrong in a container. Containers get only the userspace tooling above; the
	# frr/chrony enable below still runs for both instance types.
	if [[ "$type" == "vm" ]]; then
		# Kernel-version-exact packages so `perf`/headers match `uname -r` and
		# no metapackage pulls a NEWER kernel (bake.py ships exactly one kernel).
		# Deltas vs the old Debian list: linux-headers-amd64 ->
		# linux-headers-$(uname -r); linux-perf -> linux-tools-$(uname -r). NO
		# linux-modules-extra: on images:ubuntu/26.04/cloud the NIC drivers
		# (mlx5/i40e/ixgbe) ship in the base linux-modules package already in the
		# image, and no linux-modules-extra-* exists for this kernel (verified by
		# live `apt-cache policy`, #1943).
		info "Installing kernel-version-exact packages (VM)..."
		incus exec "$INSTANCE_NAME" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-headers-$(uname -r) linux-tools-$(uname -r)'

		# Ubuntu 26.04 already ships a stock kernel >= 6.18 (the AF_XDP shim
		# verifier floor), so the old Debian-unstable kernel-pinning dance is
		# gone. Assert the floor so the VM fails loudly if the base ever
		# regresses below it, mirroring bake.py:233-242.
		info "Asserting kernel >= 6.18 (AF_XDP shim verifier floor)..."
		incus exec "$INSTANCE_NAME" -- bash -c 'kver=$(uname -r); dpkg --compare-versions "${kver%%-*}" ge 6.18 || { echo "FATAL: base kernel $kver < 6.18 (verifier floor)" >&2; exit 1; }' \
			|| die "base image kernel below the 6.18 AF_XDP verifier floor"

		# Assert the dataplane NIC drivers are present. On Ubuntu these ship in
		# the in-image linux-modules package, NOT a separate linux-modules-extra;
		# without them the WAN/loss PFs never bind. Gate on the mellanox (mlx5)
		# directory only, mirroring the production image gate
		# (scripts/image/validate.py:188 + bake.py:227-228) — the full ethernet
		# driver set (i40e/ixgbe/iavf/ice) ships in the same linux-modules
		# package, so the mellanox dir presence is the representative check and
		# a stricter AND on i40e could false-negative on an otherwise-fine base.
		info "Asserting dataplane NIC driver modules present..."
		incus exec "$INSTANCE_NAME" -- bash -c 'test -d "/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/mellanox" || { echo "FATAL: mlx5 driver modules missing" >&2; exit 1; }' \
			|| die "dataplane NIC driver modules missing from base image"

		# Disable init_on_alloc — the default CONFIG_INIT_ON_ALLOC_DEFAULT_ON
		# zeros every allocated page, costing ~20% CPU in the virtio-net XDP
		# path. Use a grub.d drop-in (NOT a sed on /etc/default/grub): the Ubuntu
		# image's /etc/default/grub.d/50-*.cfg re-sets GRUB_CMDLINE_LINUX_DEFAULT,
		# so a sed is silently lost. The drop-in appends instead of fighting that
		# override. Mirrors bake.py's GRUB_DROPIN. Verified to reach
		# /proc/cmdline on images:ubuntu/26.04/cloud (#1943).
		info "Disabling init_on_alloc for XDP performance (grub.d drop-in)..."
		incus exec "$INSTANCE_NAME" -- bash -c 'cat > /etc/default/grub.d/99-xpf.cfg <<EOF
# xpf (#1943/#1879): init_on_alloc=0 in the virtio-net XDP path.
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT init_on_alloc=0"
EOF'
		incus exec "$INSTANCE_NAME" -- update-grub

		# A reboot is still required so the init_on_alloc=0 cmdline takes
		# effect — the kernel-install dance is gone, but the grub change is not
		# live until the next boot. Skipping it leaves every test running with
		# init_on_alloc=1.
		info "Rebooting VM to apply the init_on_alloc=0 grub change..."
		incus restart "$INSTANCE_NAME"
		local ktries=0
		while ! incus exec "$INSTANCE_NAME" -- true &>/dev/null; do
			sleep 2
			ktries=$((ktries + 1))
			if [[ $ktries -ge 30 ]]; then
				warn "VM did not come back after the grub-apply reboot"
				break
			fi
		done
		incus exec "$INSTANCE_NAME" -- uname -r
		# Confirm the tuning actually reached the running kernel cmdline.
		incus exec "$INSTANCE_NAME" -- bash -c 'grep -q init_on_alloc=0 /proc/cmdline || echo "WARNING: init_on_alloc=0 not in /proc/cmdline" >&2'
	fi

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
	incus exec "$INSTANCE_NAME" -- /usr/local/sbin/bpfrxd cleanup 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- systemctl disable bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- rm -f /etc/systemd/system/bpfrxd.service 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- rm -f /usr/local/sbin/bpfrxd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- rm -f /usr/local/sbin/bpfrx-userspace-dp 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- bash -c 'if [ -d /etc/bpfrx ] && [ ! -d /etc/xpf ]; then mv /etc/bpfrx /etc/xpf; elif [ -d /etc/bpfrx ] && [ -d /etc/xpf ]; then shopt -s dotglob nullglob; for f in /etc/bpfrx/*; do base=$(basename "$f"); if [ ! -e "/etc/xpf/$base" ]; then cp -a "$f" "/etc/xpf/$base"; fi; done; shopt -u dotglob nullglob; rm -rf /etc/bpfrx; fi; if [ -f /etc/xpf/bpfrx.conf ] && [ ! -f /etc/xpf/xpf.conf ]; then mv /etc/xpf/bpfrx.conf /etc/xpf/xpf.conf; fi' 2>/dev/null || true

	# Stop service gracefully, then clean BPF state for binary upgrade.
	# Order matters: systemctl stop sends SIGTERM (graceful socket close),
	# then xpfd cleanup removes pinned BPF maps/links.  The final
	# pkill -9 is a safety net for "text file busy" on push.
	incus exec "$INSTANCE_NAME" -- systemctl stop xpfd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- xpfd cleanup 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 xpfd 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 xpf-userspace-dp 2>/dev/null || true
	incus exec "$INSTANCE_NAME" -- pkill -9 bpfrx-userspace-dp 2>/dev/null || true
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
		# Clear configstore DB so daemon bootstraps from the new text file.
		incus exec "$INSTANCE_NAME" -- rm -rf /etc/xpf/.configdb
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
