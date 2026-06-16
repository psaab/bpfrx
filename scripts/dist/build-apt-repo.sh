#!/bin/sh
# xpf signed apt repository builder (#1924 §5.3).
#
# Default: a FLAT signed repo (apt-ftparchive + gpg) — stateless-CI-safe
# (no reprepro Berkeley DB to carry between runs). Opt into reprepro with
# XPF_APT_TOOL=reprepro for a persistent publisher.
#
# Produces a standard dists/+pool/ tree under <out>/apt, ready to publish to
# XPF_APT_BASE_URL (a directory-serving host — NOT GitHub Releases flat
# assets). The on-disk layout is identical for both tools so install.sh's
# deb822 source is unaffected by the choice.
#
# Usage:
#   build-apt-repo.sh [--out DIR] [--suite stable|edge] [--debs GLOB...]
#
# Env / config inputs (the operator decisions, OQ-2 / §5.6):
#   XPF_GPG_KEY        OpenPGP key id/fingerprint that signs Release.
#                      Unset -> repo is built UNSIGNED (dev only; loud warning;
#                      publish.py refuses an unsigned InRelease).
#   XPF_APT_TOOL       flat (default) | reprepro
#   XPF_APT_SUITE      stable (default) | edge          (overridden by --suite)
#   XPF_APT_COMPONENT  main (default)
#   XPF_APT_ARCH       amd64 (default)
#   XPF_APT_VALID_DAYS Valid-Until horizon in days (default 365 — long, for a
#                      manual/air-gap signing cadence; a short window REQUIRES
#                      an automated re-sign job, §5.6 NIT-1).
#   XPF_APT_ORIGIN     Origin/Label/Suite text (default "xpf").
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT="$ROOT/dist"
SUITE="${XPF_APT_SUITE:-stable}"
COMPONENT="${XPF_APT_COMPONENT:-main}"
ARCH="${XPF_APT_ARCH:-amd64}"
TOOL="${XPF_APT_TOOL:-flat}"
VALID_DAYS="${XPF_APT_VALID_DAYS:-365}"
ORIGIN="${XPF_APT_ORIGIN:-xpf}"
DEBS=""

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --suite) SUITE="$2"; shift 2 ;;
        --debs) shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do DEBS="$DEBS $1"; shift; done ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
done

case "$SUITE" in stable|edge) ;; *) die "suite must be stable|edge (got $SUITE)";; esac

# Default deb set: the freshly built binary + appliance packages.
if [ -z "$DEBS" ]; then
    DEBS=$(ls "$ROOT"/dist/deb/xpf_*.deb "$ROOT"/dist/deb/xpf-appliance_*.deb 2>/dev/null || true)
    [ -n "$DEBS" ] || die "no debs in dist/deb (run 'make deb' first, or pass --debs)"
fi

APT="$OUT/apt"
POOL="$APT/pool/$COMPONENT/x/xpf"
DISTDIR="$APT/dists/$SUITE/$COMPONENT/binary-$ARCH"
mkdir -p "$POOL" "$DISTDIR"

info "apt repo tool: $TOOL, suite: $SUITE, arch: $ARCH, out: $APT"

if [ "$TOOL" = "reprepro" ]; then
    command -v reprepro >/dev/null 2>&1 || die "reprepro not found (apt-get install reprepro)"
    [ -n "${XPF_GPG_KEY:-}" ] || die "reprepro path requires XPF_GPG_KEY (signs Release)"
    CONF="$APT/conf"
    mkdir -p "$CONF"
    cat > "$CONF/distributions" <<EOF
Origin: $ORIGIN
Label: $ORIGIN
Suite: $SUITE
Codename: $SUITE
Architectures: $ARCH
Components: $COMPONENT
Description: xpf firewall appliance ($SUITE channel)
SignWith: $XPF_GPG_KEY
ValidFor: ${VALID_DAYS}d
EOF
    for d in $DEBS; do
        info "reprepro includedeb $SUITE $d"
        reprepro -b "$APT" includedeb "$SUITE" "$d"
    done
    info "reprepro repo built at $APT"
    exit 0
fi

# ── flat signed repo (default) ───────────────────────────────────────────
command -v apt-ftparchive >/dev/null 2>&1 || die "apt-ftparchive not found (apt-get install apt-utils)"

for d in $DEBS; do
    cp -f "$d" "$POOL/"
    info "pooled $(basename "$d")"
done

# Packages index (paths in the index are relative to the repo root $APT).
( cd "$APT" && apt-ftparchive packages "pool/$COMPONENT" > "dists/$SUITE/$COMPONENT/binary-$ARCH/Packages" )
gzip -9 -kf "$DISTDIR/Packages"
info "wrote Packages ($(wc -l < "$DISTDIR/Packages") lines) + Packages.gz"

# Release over the suite tree. apt-ftparchive computes the per-index
# checksums; we add the descriptive + freshness fields via -o overrides.
NOW=$(date -u +%s)
UNTIL=$(date -u -d "@$((NOW + VALID_DAYS * 86400))" +"%a, %d %b %Y %H:%M:%S UTC" 2>/dev/null \
        || date -u -r "$((NOW + VALID_DAYS * 86400))" +"%a, %d %b %Y %H:%M:%S UTC")
NOWSTR=$(date -u -d "@$NOW" +"%a, %d %b %Y %H:%M:%S UTC" 2>/dev/null \
        || date -u -r "$NOW" +"%a, %d %b %Y %H:%M:%S UTC")
( cd "$APT" && apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
    -o "APT::FTPArchive::Release::Label=$ORIGIN" \
    -o "APT::FTPArchive::Release::Suite=$SUITE" \
    -o "APT::FTPArchive::Release::Codename=$SUITE" \
    -o "APT::FTPArchive::Release::Architectures=$ARCH" \
    -o "APT::FTPArchive::Release::Components=$COMPONENT" \
    -o "APT::FTPArchive::Release::Date=$NOWSTR" \
    -o "APT::FTPArchive::Release::ValidUntil=$UNTIL" \
    release "dists/$SUITE" > "dists/$SUITE/Release" )
info "wrote Release (Valid-Until $UNTIL)"

# Sign Release -> InRelease (inline) + Release.gpg (detached).
if [ -n "${XPF_GPG_KEY:-}" ]; then
    REL="$APT/dists/$SUITE/Release"
    gpg --batch --yes --local-user "$XPF_GPG_KEY" --clearsign \
        -o "$APT/dists/$SUITE/InRelease" "$REL"
    gpg --batch --yes --local-user "$XPF_GPG_KEY" -abs \
        -o "$APT/dists/$SUITE/Release.gpg" "$REL"
    info "signed: InRelease + Release.gpg (key $XPF_GPG_KEY)"
else
    echo "WARNING: XPF_GPG_KEY unset — Release is UNSIGNED. Dev only; this repo "
    echo "         is NOT publishable (publish.py refuses an unsigned InRelease)." >&2
fi

info "flat signed apt repo built at $APT"
info "publish dists/+pool/ to XPF_APT_BASE_URL (a directory-serving host)"
