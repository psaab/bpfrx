#!/bin/sh
# #1964 mechanism B — legacy-migration crash-interleaving / idempotency test
# for debian/xpf.preinst's migrate_legacy_layout. The migration is
# self-contained POSIX shell (the preinst runs before the new package is
# unpacked, so the new Go-seed-capable xpfd is not on disk yet), so it is
# tested in shell. Run:
#
#   sh   test/debian/preinst-migrate-test.sh
#   dash test/debian/preinst-migrate-test.sh   # Debian default /bin/sh
#
# It extracts the helper functions from debian/xpf.preinst, overrides the
# layout path vars to a temp root, and exercises:
#   - basic legacy -> snapshot to running version
#   - idempotent re-run (no re-snapshot)
#   - resume after current created but sbin not repointed
#   - rename-collision retry (versions/<oldver> exists, current absent)
#   - fall back to sanitized dpkg $2 when the old xpfd won't exec
#   - skip (never fail) when no safe version can be determined
#   - no-op when there is no staged tree
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREINST="${1:-$HERE/../../debian/xpf.preinst}"

if [ ! -f "$PREINST" ]; then
    echo "preinst not found: $PREINST" >&2
    exit 1
fi

# Extract the block between `set -e` and `case "$1" in` — the path vars +
# helper function definitions.
FUNCS=$(awk '
  /^set -e$/{started=1; next}
  /^case "\$1" in$/{exit}
  started{print}
' "$PREINST")

run_scenario() {
    name="$1"
    ROOT=$(mktemp -d)
    eval "$FUNCS"
    STAGED="$ROOT/usr/local/share/xpf/staged"
    SBIN="$ROOT/usr/local/sbin"
    VERSIONS="$ROOT/var/lib/xpf/versions"
    CURRENT="$VERSIONS/current"
    BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
    "scenario_$name"
    rm -rf "$ROOT"
    echo "PASS $name"
}

build_legacy() {
    ver="$1"
    mkdir -p "$STAGED" "$SBIN"
    cat > "$STAGED/xpfd" <<EOF
#!/bin/sh
[ "\$1" = version ] && echo "xpfd $ver (commit x, built y)"
EOF
    chmod +x "$STAGED/xpfd"
    for b in cli xpf-userspace-dp xpf-day0-config; do
        echo "bin-$b-$ver" > "$STAGED/$b"
        chmod +x "$STAGED/$b"
    done
    for b in $BINS; do
        ln -sf "$STAGED/$b" "$SBIN/$b"
    done
}

assert_seeded_to() {
    ver="$1"
    [ "$(readlink "$CURRENT")" = "$ver" ] || { echo "FAIL: current -> $(readlink "$CURRENT"), want $ver"; exit 1; }
    for b in $BINS; do
        [ -f "$VERSIONS/$ver/$b" ] || { echo "FAIL: missing $VERSIONS/$ver/$b"; exit 1; }
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$CURRENT/$b" ] || { echo "FAIL: sbin $b -> $tgt, want $CURRENT/$b"; exit 1; }
        [ -r "$SBIN/$b" ] || { echo "FAIL: sbin $b does not resolve to readable"; exit 1; }
    done
    [ "$("$SBIN/xpfd" version | awk '{print $2}')" = "$ver" ] || { echo "FAIL: xpfd via sbin wrong version"; exit 1; }
    for p in "$VERSIONS"/*.partial; do
        [ -e "$p" ] && { echo "FAIL: leftover partial $p"; exit 1; } || true
    done
}

scenario_basic() {
    build_legacy "1.0.0"
    migrate_legacy_layout upgrade "0.9.0"
    assert_seeded_to "1.0.0"
}

scenario_idempotent() {
    build_legacy "1.0.0"
    migrate_legacy_layout upgrade "0.9.0"
    before=$(ls -i "$VERSIONS/1.0.0/xpfd" | awk '{print $1}')
    migrate_legacy_layout upgrade "0.9.0"
    after=$(ls -i "$VERSIONS/1.0.0/xpfd" | awk '{print $1}')
    [ "$before" = "$after" ] || { echo "FAIL: re-run recreated version dir"; exit 1; }
    assert_seeded_to "1.0.0"
}

scenario_resume_after_current() {
    build_legacy "1.0.0"
    mkdir -p "$VERSIONS/1.0.0"
    cp -a "$STAGED/." "$VERSIONS/1.0.0/"
    ln -sf "1.0.0" "$CURRENT"
    [ "$(readlink "$SBIN/xpfd")" = "$STAGED/xpfd" ] || { echo "FAIL setup"; exit 1; }
    migrate_legacy_layout upgrade "0.9.0"
    assert_seeded_to "1.0.0"
}

scenario_rename_collision() {
    build_legacy "1.0.0"
    mkdir -p "$VERSIONS/1.0.0"
    cp -a "$STAGED/." "$VERSIONS/1.0.0/"
    echo "SENTINEL" > "$VERSIONS/1.0.0/xpfd"
    [ ! -e "$CURRENT" ] || { echo "FAIL setup: current exists"; exit 1; }
    migrate_legacy_layout upgrade "0.9.0"
    [ "$(cat "$VERSIONS/1.0.0/xpfd")" = "SENTINEL" ] || { echo "FAIL: re-copied over existing version dir"; exit 1; }
    [ "$(readlink "$CURRENT")" = "1.0.0" ] || { echo "FAIL: current not created on collision-retry"; exit 1; }
    for b in $BINS; do
        [ "$(readlink "$SBIN/$b")" = "$CURRENT/$b" ] || { echo "FAIL: sbin $b not repointed"; exit 1; }
    done
}

scenario_fallback_dpkg_version() {
    build_legacy "1.0.0"
    echo "not a script" > "$STAGED/xpfd"
    chmod -x "$STAGED/xpfd"
    migrate_legacy_layout upgrade "0.9.0+deb1"
    [ "$(readlink "$CURRENT")" = "0.9.0+deb1" ] || { echo "FAIL: did not fall back to dpkg version, current=$(readlink "$CURRENT")"; exit 1; }
}

scenario_no_safe_version() {
    build_legacy "1.0.0"
    echo "not a script" > "$STAGED/xpfd"; chmod -x "$STAGED/xpfd"
    migrate_legacy_layout upgrade "/// "
    [ ! -e "$CURRENT" ] || { echo "FAIL: created current with no safe version"; exit 1; }
    [ "$(readlink "$SBIN/xpfd")" = "$STAGED/xpfd" ] || { echo "FAIL: sbin mutated despite skip"; exit 1; }
}

scenario_no_staged() {
    mkdir -p "$SBIN"
    migrate_legacy_layout upgrade "0.9.0"
    [ ! -e "$CURRENT" ] || { echo "FAIL: created current with no staged"; exit 1; }
}

run_scenario basic
run_scenario idempotent
run_scenario resume_after_current
run_scenario rename_collision
run_scenario fallback_dpkg_version
run_scenario no_safe_version
run_scenario no_staged
echo "ALL PREINST-MIGRATE SCENARIOS PASSED"
