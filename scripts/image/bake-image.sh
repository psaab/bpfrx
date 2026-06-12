#!/usr/bin/env bash
# xpf appliance image bake (#1879 Path C — vSRX-style prebuilt image).
#
# Builds ONE bootable root-disk image OFFLINE (no boot-and-snapshot, no
# post-launch provisioning) and exports it for both target hypervisors:
#
#   dist/xpf-<ver>.qcow2                  - libvirt/KVM (virt-install)
#   dist/xpf-<ver>.incus-metadata.tar.gz  - incus VM image metadata;
#                                           `incus image import <meta> <qcow2>`
#   dist/SHA256SUMS
#
# Pipeline (offline, libguestfs — never boots the image to provision it):
#   1. make build / build-ctl / build-userspace-dp on the build host.
#      `make build` embeds the git-tracked pinned-toolchain shim object
#      (#1864) — the bake never runs `make generate`.
#   2. Fetch + SHA512-verify the official Debian 13 genericcloud qcow2
#      (the upstream image owns partitioning + UEFI/BIOS GRUB; we never
#      hand-roll a bootloader).
#   3. virt-resize the root partition into a larger work disk.
#   4. virt-customize: runtime package set (the Depends/Recommends
#      matrix from the #1879 plan — cross-check test/incus/setup.sh
#      provision_instance(), which is the package-inventory reference;
#      the image deliberately ships NO build toolchain), kernel >= 6.18
#      from Debian unstable then REMOVE the unstable apt source (a
#      shipped appliance must not track unstable), purge cloud-init +
#      the cloud kernel, enable systemd-networkd (xpfd owns all
#      interfaces), sysctls, init_on_alloc=0, install xpfd + cli +
#      xpf-userspace-dp + units, enable xpfd + the day-0 loader +
#      the (incus-only, otherwise inert) incus-agent loader.
#   5. virt-sysprep seal: machine-id, ssh host keys, logs, tmp, bash
#      history, package caches, random seed. First boot regenerates
#      machine-id (systemd) and ssh host keys (day-0 loader unit).
#   6. Export artifacts + checksums.
#   7. Validation gate (default ON): boot the imported image under
#      LOCAL incus and run `xpfd verify-dataplane` IN-GUEST against the
#      image's own kernel — the #1869-style gate; the image must never
#      ship a verifier-failing shim. scripts/image/validate-image.sh
#      runs this plus the full day-0 scenario matrix.
#
# Requirements (build host): make/go/cargo toolchain, libguestfs-tools
# (virt-customize, virt-resize, virt-sysprep, virt-filesystems),
# qemu-utils (qemu-img), curl; incus for the validation gate. KVM access
# (/dev/kvm) makes libguestfs fast; without it libguestfs falls back to
# TCG (slow but works).
#
# Usage:
#   scripts/image/bake-image.sh [--version <v>] [--out <dir>]
#       [--skip-build] [--skip-validate] [--keep-work]
#
# Day-0 quickstarts (details + recovery: docs/install-images.md):
#   libvirt: virt-install --name xpf --memory 4096 --vcpus 4 \
#       --import --disk path=xpf-<ver>.qcow2 \
#       --disk path=day0-config.iso,device=cdrom --osinfo debian13
#   incus:   incus image import xpf-<ver>.incus-metadata.tar.gz \
#       xpf-<ver>.qcow2 --alias xpf-appliance
#            incus init xpf-appliance xpf1 --vm
#            incus config device add xpf1 day0 disk source=$PWD/day0-config.iso
#            incus start xpf1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

info() { echo "==> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

VERSION="$(git -C "$PROJECT_ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
OUT_DIR="$PROJECT_ROOT/dist"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/xpf-image-bake"
SKIP_BUILD=0
SKIP_VALIDATE=0
KEEP_WORK=0

while [ $# -gt 0 ]; do
	case "$1" in
	--version)       VERSION="${2:?}"; shift 2 ;;
	--out)           OUT_DIR="${2:?}"; shift 2 ;;
	--skip-build)    SKIP_BUILD=1; shift ;;
	--skip-validate) SKIP_VALIDATE=1; shift ;;
	--keep-work)     KEEP_WORK=1; shift ;;
	-h|--help)       sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*)               die "unknown option: $1" ;;
	esac
done

# Debian 13 genericcloud base. The base owns partitioning + bootloader;
# pin a specific dated release for reproducible bakes (override via env
# to track a newer point release).
BASE_RELEASE="${XPF_BASE_RELEASE:-latest}"
BASE_URL="${XPF_BASE_URL:-https://cloud.debian.org/images/cloud/trixie/${BASE_RELEASE}}"
BASE_IMG="debian-13-genericcloud-amd64.qcow2"

# Runtime dependency set (the #1879 plan §5 exec-grounded matrix:
# Depends-level frr/iproute2/nftables/ethtool + Recommends-level
# strongswan/kea/chrony/rsyslog/openssh/ping/traceroute). NO build
# toolchain — this is the shipped appliance, not the test VM.
RUNTIME_PACKAGES=(
	frr
	strongswan strongswan-swanctl
	kea-dhcp4-server kea-dhcp6-server
	chrony
	iproute2 nftables ethtool
	tcpdump pciutils
	iputils-ping traceroute
	openssh-server openssh-client
	systemd-resolved
	rsyslog
	curl ca-certificates
)

require() {
	command -v "$1" >/dev/null 2>&1 || die "$1 not found — $2"
}

require qemu-img      "apt-get install qemu-utils"
require virt-customize "apt-get install libguestfs-tools"
require virt-resize   "apt-get install libguestfs-tools"
require virt-sysprep  "apt-get install libguestfs-tools"
require virt-filesystems "apt-get install libguestfs-tools"
require curl          "apt-get install curl"

if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
	echo "WARNING: no /dev/kvm access — libguestfs will use TCG (slow)." >&2
fi

mkdir -p "$OUT_DIR" "$CACHE_DIR"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xpf-bake.XXXXXX")"
cleanup() {
	if [ "$KEEP_WORK" -eq 1 ]; then
		echo "keeping work dir: $WORK_DIR"
	else
		rm -rf "$WORK_DIR"
	fi
}
trap cleanup EXIT

# ── 1. Build artifacts (pinned-toolchain contract: no make generate) ──
if [ "$SKIP_BUILD" -eq 0 ]; then
	info "Building xpfd, cli, xpf-userspace-dp..."
	make -C "$PROJECT_ROOT" build build-ctl build-userspace-dp
fi
for bin in xpfd cli xpf-userspace-dp; do
	[ -x "$PROJECT_ROOT/$bin" ] || die "missing $PROJECT_ROOT/$bin (run without --skip-build)"
done

# Fast-fail pre-gate: if the BUILD HOST kernel is >= 6.18 and we can get
# CAP_BPF, verify the embedded shim here before spending minutes baking.
# Best-effort only — the authoritative gate runs IN-GUEST against the
# image's own kernel during validation.
if sudo -n true 2>/dev/null; then
	info "Build-host pre-gate: xpfd verify-dataplane (host kernel $(uname -r))..."
	if ! sudo -n nice -n 19 "$PROJECT_ROOT/xpfd" verify-dataplane; then
		die "embedded shim REJECTED by the build-host kernel verifier — refusing to bake (#1864: rebuild with 'make generate' on the pinned toolchain or restore the tracked object)"
	fi
else
	echo "NOTE: passwordless sudo unavailable — skipping build-host verify pre-gate (in-guest gate still enforces)." >&2
fi

# ── 2. Fetch + verify the base image ──────────────────────────────────
info "Fetching Debian 13 genericcloud base ($BASE_URL)..."
if [ ! -f "$CACHE_DIR/$BASE_IMG" ]; then
	curl -fsSL -o "$CACHE_DIR/$BASE_IMG.tmp" "$BASE_URL/$BASE_IMG"
	mv "$CACHE_DIR/$BASE_IMG.tmp" "$CACHE_DIR/$BASE_IMG"
fi
# Always re-verify the cached base against the upstream checksum file
# (supply-chain hygiene: the cache is not trusted either).
curl -fsSL -o "$WORK_DIR/SHA512SUMS.upstream" "$BASE_URL/SHA512SUMS"
expected=$(awk -v img="$BASE_IMG" '$2 == img {print $1}' "$WORK_DIR/SHA512SUMS.upstream")
[ -n "$expected" ] || die "no SHA512 for $BASE_IMG in upstream SHA512SUMS"
actual=$(sha512sum "$CACHE_DIR/$BASE_IMG" | awk '{print $1}')
if [ "$expected" != "$actual" ]; then
	rm -f "$CACHE_DIR/$BASE_IMG"
	die "base image SHA512 mismatch (cache removed — re-run; if it persists, upstream and mirror disagree)"
fi
info "Base image checksum verified."

# ── 3. Resize root into the work disk ─────────────────────────────────
DISK_SIZE="${XPF_IMAGE_DISK_SIZE:-8G}"
info "Creating $DISK_SIZE work disk + expanding root partition..."
ROOT_PART=$(virt-filesystems -a "$CACHE_DIR/$BASE_IMG" --filesystems --long --no-title |
	awk '$3 == "ext4" {print $1; exit}')
[ -n "$ROOT_PART" ] || die "could not locate the ext4 root partition in the base image"
qemu-img create -f qcow2 -o preallocation=off "$WORK_DIR/work.qcow2" "$DISK_SIZE" >/dev/null
virt-resize --quiet --expand "$ROOT_PART" "$CACHE_DIR/$BASE_IMG" "$WORK_DIR/work.qcow2"

# ── 4. Offline customize ──────────────────────────────────────────────
info "Customizing image offline (packages, kernel >= 6.18, xpf install)..."

SYSCTL_CONF='net.core.bpf_jit_enable=1
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0'

UNSTABLE_LIST='deb http://deb.debian.org/debian unstable main'
PIN_PREF='Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: linux-image-amd64 linux-headers-amd64 linux-image-* linux-headers-*
Pin: release a=unstable
Pin-Priority: 990'

virt-customize -a "$WORK_DIR/work.qcow2" \
	--smp 4 --memsize 2048 \
	--hostname xpf \
	--copy-in "$PROJECT_ROOT/xpfd:/usr/local/sbin" \
	--copy-in "$PROJECT_ROOT/cli:/usr/local/sbin" \
	--copy-in "$PROJECT_ROOT/xpf-userspace-dp:/usr/local/sbin" \
	--copy-in "$SCRIPT_DIR/xpf-day0-config:/usr/local/sbin" \
	--copy-in "$SCRIPT_DIR/incus-agent-setup:/usr/local/sbin" \
	--copy-in "$PROJECT_ROOT/test/incus/xpfd.service:/etc/systemd/system" \
	--copy-in "$SCRIPT_DIR/xpf-day0-config.service:/etc/systemd/system" \
	--copy-in "$SCRIPT_DIR/incus-agent.service:/etc/systemd/system" \
	--run-command 'chmod 0755 /usr/local/sbin/xpfd /usr/local/sbin/cli /usr/local/sbin/xpf-userspace-dp /usr/local/sbin/xpf-day0-config /usr/local/sbin/incus-agent-setup' \
	--write "/etc/sysctl.d/99-xpf.conf:$SYSCTL_CONF" \
	--run-command 'mkdir -p /etc/xpf && chmod 0750 /etc/xpf' \
	--run-command 'export DEBIAN_FRONTEND=noninteractive && apt-get update -qq' \
	--run-command "export DEBIAN_FRONTEND=noninteractive && apt-get install -y -qq ${RUNTIME_PACKAGES[*]}" \
	--write "/etc/apt/sources.list.d/unstable.list:$UNSTABLE_LIST" \
	--write "/etc/apt/preferences.d/pin-stable:$PIN_PREF" \
	--run-command 'export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && apt-get install -y -qq linux-image-amd64' \
	--run-command 'rm -f /etc/apt/sources.list.d/unstable.list /etc/apt/preferences.d/pin-stable' \
	--run-command 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "linux-image-*cloud*" 2>/dev/null || true' \
	--run-command 'export DEBIAN_FRONTEND=noninteractive && apt-get purge -y -qq "cloud-init*" 2>/dev/null || true; rm -rf /etc/cloud /var/lib/cloud' \
	--run-command 'rm -f /etc/network/interfaces.d/* /etc/netplan/*.yaml 2>/dev/null || true' \
	--run-command 'export DEBIAN_FRONTEND=noninteractive && apt-get autoremove -y -qq && apt-get update -qq' \
	--run-command 'systemctl enable systemd-networkd systemd-resolved' \
	--run-command 'ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf' \
	--run-command 'systemctl enable frr chrony' \
	--run-command 'sed -i "s/^pool /#pool /; s/^server /#server /" /etc/chrony/chrony.conf && mkdir -p /etc/chrony/sources.d' \
	--run-command 'systemctl enable xpfd xpf-day0-config incus-agent' \
	--run-command 'sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 init_on_alloc=0\"/" /etc/default/grub && update-grub' \
	--run-command 'passwd -d root' \
	--run-command '/usr/local/sbin/xpfd version && /usr/local/sbin/xpf-day0-config --help 2>/dev/null; true'

# Factory-default credential posture (vSRX parity, documented in
# docs/install-images.md): root password is EMPTY -> login works on the
# hypervisor console only; sshd refuses empty passwords and root
# password auth by default. Headless/SSH access requires day-0 config
# (system root-authentication / login users).

# ── 5. Seal ───────────────────────────────────────────────────────────
info "Sealing image (virt-sysprep)..."
virt-sysprep -a "$WORK_DIR/work.qcow2" --quiet \
	--enable machine-id,ssh-hostkeys,logfiles,tmp-files,bash-history,package-manager-cache,random-seed,backup-files \
	--run-command 'rm -rf /etc/xpf/.configdb /etc/xpf/xpf.conf /etc/xpf/.day0-config-applied /root/.ssh 2>/dev/null || true'

# ── 6. Export artifacts ───────────────────────────────────────────────
QCOW_OUT="$OUT_DIR/xpf-$VERSION.qcow2"
META_OUT="$OUT_DIR/xpf-$VERSION.incus-metadata.tar.gz"

info "Exporting $QCOW_OUT (compressed qcow2)..."
qemu-img convert -O qcow2 -c "$WORK_DIR/work.qcow2" "$QCOW_OUT"

info "Exporting $META_OUT (incus VM image metadata)..."
cat >"$WORK_DIR/metadata.yaml" <<EOF
architecture: x86_64
creation_date: $(date +%s)
properties:
  description: xpf appliance $VERSION (Debian 13, kernel >= 6.18, AF_XDP userspace dataplane)
  os: Debian
  release: trixie
  variant: xpf-appliance
EOF
tar -C "$WORK_DIR" -czf "$META_OUT" metadata.yaml

(cd "$OUT_DIR" && sha256sum "$(basename "$QCOW_OUT")" "$(basename "$META_OUT")" >SHA256SUMS)
info "Checksums:"
cat "$OUT_DIR/SHA256SUMS"

# ── 7. Validation gate (in-guest verify-dataplane + first-boot smoke) ─
if [ "$SKIP_VALIDATE" -eq 1 ]; then
	echo "WARNING: --skip-validate — these artifacts have NOT passed the in-guest verify-dataplane gate; do not publish them." >&2
else
	info "Running validation gate (scenario A: boot + in-guest verify-dataplane)..."
	"$SCRIPT_DIR/validate-image.sh" --qcow2 "$QCOW_OUT" --metadata "$META_OUT" a ||
		die "validation gate FAILED — artifacts in $OUT_DIR are NOT publishable"
fi

info "Bake complete: $QCOW_OUT"
info "Deploy quickstarts: docs/install-images.md"
