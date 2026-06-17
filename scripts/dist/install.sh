#!/bin/sh
# xpf appliance installer (#1924 §5.4) — Tailscale-style one-command install.
#
#   curl -fsSL <XPF_IMAGE_BASE_URL>/install.sh | sh        # Tier A (one-liner)
#
# Tier B (verify-before-run): get xpf-image.pub from the SOURCE REPO (git
# clone / GitHub — the out-of-band trust root, NEVER from the dist host),
# then `minisign -V -p xpf-image.pub -m install.sh -x install.sh.minisig`,
# read this script, and run it.
#
# What it does:
#   1. PREFLIGHT: amd64 + Debian-family + kernel >= 6.18 + systemd-networkd.
#      xpf's verifier floor is kernel >= 6.18 with a native-XDP NIC; this
#      installer does NOT install a kernel. A host below the floor is refused
#      with a clear message (use the appliance image instead).
#   2. Install the pinned apt archive keyring to /usr/share/keyrings (inline).
#   3. Write /etc/apt/sources.list.d/xpf.sources (deb822, Signed-By).
#   4. apt-get update && apt-get install -y xpf-appliance.
#   5. Print next steps + the interface-takeover caveat (#1879).
#
# Config inputs (the operator decisions — NOT hardcoded):
#   XPF_APT_BASE_URL   apt repo base (dists/+pool/ host). REQUIRED to install.
#   XPF_CHANNEL        stable (default) | edge
#   XPF_DRY_RUN=1      print the actions, mutate nothing (CI / review).
#
# The archive keyring below is a PLACEHOLDER (its secret is held by no one).
# The release build substitutes the real ASCII-armored archive public key
# between the BEGIN/END markers. The SAME keyring also ships in the xpf
# package (/usr/share/keyrings via debian/rules) so existing hosts get
# rotated keys via `apt upgrade` even though they never re-run this script.
set -eu

CHANNEL="${XPF_CHANNEL:-stable}"
DRY="${XPF_DRY_RUN:-0}"
# /usr/share/keyrings (NOT /etc/apt/keyrings): the xpf package ships the same
# keyring here as a package-owned (non-conffile) file, so this bootstrap write
# and the later `apt install` agree without a dpkg conffile prompt, and key
# rotation lands seamlessly on `apt upgrade` (AGY-A1).
KEYRING=/usr/share/keyrings/xpf-archive-keyring.asc
SRC=/etc/apt/sources.list.d/xpf.sources

die() { echo "xpf-install ERROR: $*" >&2; exit 1; }
info() { echo "xpf-install: $*"; }
run() {
    if [ "$DRY" = "1" ]; then echo "  (dry-run) $*"; else eval "$*"; fi
}

# ── embedded archive public key (PLACEHOLDER until release) ──────────────
# Replace the block between the markers with the real ASCII-armored key.
ARCHIVE_KEY=$(cat <<'KEYEOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

PLACEHOLDER-xpf-archive-keyring-not-yet-issued
This is a #1924 placeholder. The release build substitutes the real
ASCII-armored OpenPGP archive public key here. With this placeholder in
place, `apt-get update` will reject the repo's signature — which is the
correct fail-safe until a real key is issued (OQ-2).
-----END PGP PUBLIC KEY BLOCK-----
KEYEOF
)

is_placeholder_key() {
    printf '%s' "$ARCHIVE_KEY" | grep -q "PLACEHOLDER-xpf-archive-keyring"
}

# ── 1. preflight ─────────────────────────────────────────────────────────
preflight() {
    info "preflight: arch, distro, kernel, networkd"
    arch=$(uname -m)
    [ "$arch" = "x86_64" ] || die "unsupported arch '$arch' — xpf ships amd64 only."

    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-} ${ID_LIKE:-}" in
            *debian*|*ubuntu*) : ;;
            *) die "unsupported distro '${ID:-?}' — xpf needs a Debian-family host." ;;
        esac
    else
        die "no /etc/os-release — cannot confirm a Debian-family host."
    fi

    # kernel >= 6.18 (the AF_XDP verifier floor). Compare major.minor.
    kver=$(uname -r)
    kmaj=$(echo "$kver" | cut -d. -f1)
    kmin=$(echo "$kver" | cut -d. -f2)
    case "$kmaj$kmin" in *[!0-9]*) die "cannot parse kernel version '$kver'";; esac
    if [ "$kmaj" -lt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -lt 18 ]; }; then
        die "kernel $kver < 6.18 — xpf requires kernel >= 6.18 + a native-XDP NIC. \
Upgrade the host kernel, or deploy the appliance image (docs/install-images.md), \
which ships its own >= 6.18 kernel."
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemd not found — xpf requires systemd + systemd-networkd."
    fi
    # networkd need not be ACTIVE yet (the package enables it), but the unit
    # must EXIST — a host without systemd-networkd cannot run xpf's interface
    # management.
    if ! systemctl list-unit-files systemd-networkd.service >/dev/null 2>&1; then
        info "WARNING: systemd-networkd unit not found; the xpf package pulls it \
in, but verify the host can run networkd (xpfd owns all interfaces)."
    fi
    info "preflight OK (arch=$arch kernel=$kver)"
}

# ── 2. keyring ─────────────────────────────────────────────────────────────
install_keyring() {
    if is_placeholder_key; then
        if [ "$DRY" = "1" ]; then
            info "WARNING (dry-run): archive key is the #1924 PLACEHOLDER — a \
real install would fail at apt update until the release key is issued (OQ-2)."
        else
            die "archive key is the #1924 PLACEHOLDER — refusing to install a \
keyring that cannot verify the repo. A release build substitutes the real key."
        fi
    fi
    info "installing archive keyring -> $KEYRING"
    run "install -d -m 0755 /usr/share/keyrings"
    if [ "$DRY" = "1" ]; then
        echo "  (dry-run) write $KEYRING (mode 0644) from embedded key"
    else
        umask 022
        printf '%s\n' "$ARCHIVE_KEY" > "$KEYRING"
        chmod 0644 "$KEYRING"
    fi
}

# ── 3. apt source ──────────────────────────────────────────────────────────
write_source() {
    [ -n "${XPF_APT_BASE_URL:-}" ] || die "XPF_APT_BASE_URL is required \
(the apt repo base URL — a dists/+pool/ directory host). Set it and re-run."
    case "$CHANNEL" in stable|edge) ;; *) die "XPF_CHANNEL must be stable|edge";; esac
    info "writing apt source -> $SRC (suite=$CHANNEL uri=$XPF_APT_BASE_URL)"
    body=$(cat <<EOF
# xpf appliance apt source (#1924). Managed by install.sh.
Types: deb
URIs: $XPF_APT_BASE_URL
Suites: $CHANNEL
Components: main
Architectures: amd64
Signed-By: $KEYRING
EOF
)
    if [ "$DRY" = "1" ]; then
        echo "  (dry-run) $SRC contents:"; printf '%s\n' "$body" | sed 's/^/      /'
    else
        printf '%s\n' "$body" > "$SRC"
    fi
}

# ── 4. install ─────────────────────────────────────────────────────────────
do_install() {
    info "apt-get update && install xpf-appliance"
    run "apt-get update"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y xpf-appliance"
}

# ── 5. next steps ──────────────────────────────────────────────────────────
next_steps() {
    cat <<'EOF'

xpf-install: done. Next steps:
  - Seed a day-0 config:  see docs/distribution.md and docs/deploy-quickstart.md
  - Operate:              cli   (Junos-style CLI)
  - Status:               systemctl status xpfd

  CAUTION (#1879 interface takeover): xpfd OWNS and RENAMES every interface
  on this host. On a remote box, an incorrect fxp0 mapping can cut your
  management path. Seed a safe day-0 config (fxp0 = mgmt DHCP) BEFORE relying
  on remote access, or use console.

  Upgrades: `apt upgrade xpf-appliance` cuts the dataplane on a STANDALONE
  node (a bounded blip; mgmt/SSH is not cut). Use XPF_NO_POSTINST_CUT=1
  apt-get upgrade to stage-only and run `xpfd upgrade` at a chosen time. HA
  nodes stage only; cut with `xpfd upgrade --rolling`.
EOF
}

main() {
    [ "$(id -u)" = "0" ] || [ "$DRY" = "1" ] || die "run as root (or sudo)."
    preflight
    install_keyring
    write_source
    do_install
    next_steps
}

main "$@"
