#!/usr/bin/env bash
# Migrate a deployed bpfrx system to xpf naming.
# Run on each firewall VM (or via incus exec) after deploying the renamed binary.
#
# Usage:
#   ./scripts/migrate-bpfrx-to-xpf.sh          # local
#   incus exec xpf-fw0 -- bash < scripts/migrate-bpfrx-to-xpf.sh  # remote

set -euo pipefail

info()  { echo "[migrate] $*"; }
warn()  { echo "[migrate] WARNING: $*" >&2; }

# --- Stop old service ---
if systemctl is-active bpfrxd &>/dev/null; then
    info "Stopping bpfrxd service..."
    systemctl stop bpfrxd
fi

# --- Clean old BPF state ---
if [ -x /usr/local/sbin/bpfrxd ]; then
    info "Cleaning old BPF state..."
    /usr/local/sbin/bpfrxd cleanup 2>/dev/null || true
elif [ -x /usr/local/sbin/xpfd ]; then
    info "Cleaning BPF state with xpfd..."
    /usr/local/sbin/xpfd cleanup 2>/dev/null || true
fi

# --- Remove old binary ---
if [ -f /usr/local/sbin/bpfrxd ]; then
    info "Removing /usr/local/sbin/bpfrxd"
    rm -f /usr/local/sbin/bpfrxd
fi

# --- Remove old systemd unit ---
if [ -f /etc/systemd/system/bpfrxd.service ]; then
    info "Disabling and removing bpfrxd.service"
    systemctl disable bpfrxd 2>/dev/null || true
    rm -f /etc/systemd/system/bpfrxd.service
    systemctl daemon-reload
fi

# --- Migrate config directory ---
if [ -d /etc/bpfrx ] && [ ! -d /etc/xpf ]; then
    info "Renaming /etc/bpfrx -> /etc/xpf"
    mv /etc/bpfrx /etc/xpf
elif [ -d /etc/bpfrx ] && [ -d /etc/xpf ]; then
    # Both exist — copy any files from old that aren't in new
    info "Both /etc/bpfrx and /etc/xpf exist, merging..."
    for f in /etc/bpfrx/*; do
        base=$(basename "$f")
        if [ ! -e "/etc/xpf/$base" ]; then
            cp -a "$f" "/etc/xpf/$base"
            info "  Copied $base to /etc/xpf/"
        fi
    done
    info "Removing /etc/bpfrx (merged into /etc/xpf)"
    rm -rf /etc/bpfrx
fi

# The daemon now defaults to /etc/xpf/xpf.conf. Preserve the active config
# filename during rename so upgraded systems still boot the existing config.
if [ -f /etc/xpf/bpfrx.conf ] && [ ! -f /etc/xpf/xpf.conf ]; then
    info "Renaming /etc/xpf/bpfrx.conf -> /etc/xpf/xpf.conf"
    mv /etc/xpf/bpfrx.conf /etc/xpf/xpf.conf
fi

# --- Migrate networkd files ---
renamed=0
for f in /etc/systemd/network/10-bpfrx-*; do
    [ -e "$f" ] || continue
    newname=$(echo "$f" | sed 's/10-bpfrx-/10-xpf-/')
    if [ ! -e "$newname" ]; then
        info "Renaming $(basename "$f") -> $(basename "$newname")"
        mv "$f" "$newname"
        renamed=$((renamed + 1))
    fi
done
if [ "$renamed" -gt 0 ]; then
    info "Renamed $renamed networkd files, reloading networkctl"
    networkctl reload 2>/dev/null || true
fi

# --- Migrate CLI history ---
if [ -f ~/.bpfrx_cli_history ] && [ ! -f ~/.xpf_cli_history ]; then
    info "Renaming ~/.bpfrx_cli_history -> ~/.xpf_cli_history"
    mv ~/.bpfrx_cli_history ~/.xpf_cli_history
elif [ -f ~/.bpfrx_history ] && [ ! -f ~/.xpf_cli_history ]; then
    info "Renaming legacy ~/.bpfrx_history -> ~/.xpf_cli_history"
    mv ~/.bpfrx_history ~/.xpf_cli_history
fi

# --- Migrate userspace helper binary ---
if [ -f /usr/local/sbin/bpfrx-userspace-dp ]; then
    info "Removing old /usr/local/sbin/bpfrx-userspace-dp"
    rm -f /usr/local/sbin/bpfrx-userspace-dp
fi
pkill -9 bpfrx-userspace-dp 2>/dev/null || true
pkill -9 xpf-userspace-dp 2>/dev/null || true

# --- Migrate nftables table ---
if nft list table inet bpfrx_dp_rst &>/dev/null 2>&1; then
    info "Flushing old nftables table bpfrx_dp_rst"
    nft delete table inet bpfrx_dp_rst 2>/dev/null || true
fi

# --- Ensure new service is enabled ---
if [ -f /etc/systemd/system/xpfd.service ]; then
    info "Enabling xpfd.service"
    systemctl daemon-reload
    systemctl enable xpfd
fi

info "Migration complete. Start xpfd with: systemctl start xpfd"
