#!/bin/sh
# #1964 — debian/xpf.postrm lifecycle test (remove/purge sbin cleanup,
# purge versions/ removal, downgrade cleanup). The postrm is shell, so it is
# tested in shell. Run:
#
#   sh   test/debian/postrm-test.sh
#   dash test/debian/postrm-test.sh
#
# It extracts the helper functions from debian/xpf.postrm, overrides the
# layout path vars to a temp root, and drives the case-branch bodies via a
# small re-implementation of the dispatch (the real case branches use the
# overridden vars through the sourced functions).
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
POSTRM="${1:-$HERE/../../debian/xpf.postrm}"
[ -f "$POSTRM" ] || { echo "postrm not found: $POSTRM" >&2; exit 1; }

# Run the REAL postrm with overridden absolute path vars by editing the
# script's var assignments to point under a temp ROOT. We do this by
# generating a patched copy per scenario.
patched_postrm() {
    sed \
      -e "s#^STAGED=.*#STAGED=$ROOT/usr/local/share/xpf/staged#" \
      -e "s#^SBIN=.*#SBIN=$ROOT/usr/local/sbin#" \
      -e "s#^VERSIONS=.*#VERSIONS=$ROOT/var/lib/xpf/versions#" \
      -e "s#^CURRENT=.*#CURRENT=\"\$VERSIONS/current\"#" \
      -e "s#^DROPIN=.*#DROPIN=$ROOT/etc/systemd/system/xpfd.service.d/10-xpf-version.conf#" \
      -e "s#\\[ -d /run/systemd/system \\]#false#" \
      "$POSTRM" > "$ROOT/postrm"
    chmod +x "$ROOT/postrm"
}

run_scenario() {
    name="$1"
    ROOT=$(mktemp -d)
    STAGED="$ROOT/usr/local/share/xpf/staged"
    SBIN="$ROOT/usr/local/sbin"
    VERSIONS="$ROOT/var/lib/xpf/versions"
    CURRENT="$VERSIONS/current"
    DROPIN="$ROOT/etc/systemd/system/xpfd.service.d/10-xpf-version.conf"
    BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
    patched_postrm
    "scenario_$name"
    rm -rf "$ROOT"
    echo "PASS $name"
}

# Build a hardened layout: versions/<ver>/<bin>, current -> <ver>, sbin ->
# versions/current/<bin>, drop-in present. xpfd in the version dir + staged
# both respond to seed-runtime --capability-check.
build_hardened() {
    ver="$1"
    mkdir -p "$STAGED" "$SBIN" "$VERSIONS/$ver" "$(dirname "$DROPIN")"
    make_xpfd() {
        cat > "$1" <<'EOF'
#!/bin/sh
if [ "$1" = seed-runtime ] && [ "$2" = --capability-check ]; then
    echo "seed-runtime supported"; exit 0
fi
[ "$1" = version ] && { echo "xpfd VER (commit x, built y)"; exit 0; }
echo "unknown command" >&2; exit 1
EOF
        sed -i "s/VER/$ver/" "$1"
        chmod +x "$1"
    }
    make_xpfd "$VERSIONS/$ver/xpfd"
    make_xpfd "$STAGED/xpfd"
    for b in cli xpf-userspace-dp xpf-day0-config; do
        echo "bin-$b" > "$VERSIONS/$ver/$b"; chmod +x "$VERSIONS/$ver/$b"
        echo "bin-$b" > "$STAGED/$b"; chmod +x "$STAGED/$b"
    done
    ln -sf "$ver" "$CURRENT"
    for b in $BINS; do
        ln -sf "$CURRENT/$b" "$SBIN/$b"
    done
    echo "[Service]" > "$DROPIN"
}

# Replace staged/xpfd with a PRE-#1964 binary (no seed-runtime support).
make_staged_prehardened() {
    cat > "$STAGED/xpfd" <<'EOF'
#!/bin/sh
[ "$1" = version ] && { echo "xpfd 0.9.0 (commit x)"; exit 0; }
echo "xpfd: unknown command \"$1\"" >&2; exit 1
EOF
    chmod +x "$STAGED/xpfd"
}

# remove leaves versions/ but removes the through-current sbin links AND the
# runtime unit drop-in (#1967).
scenario_remove_keeps_versions() {
    build_hardened "1.0.0"
    "$ROOT/postrm" remove
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: sbin $b not removed"; exit 1; } || true
    done
    [ -d "$VERSIONS/1.0.0" ] || { echo "FAIL: versions/ removed on remove"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current removed on remove"; exit 1; }
    # #1967: the versioned-runtime unit drop-in must be removed on remove.
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed on remove"; exit 1; } || true
    # The empty .service.d dir should be rmdir'd too.
    [ -d "$(dirname "$DROPIN")" ] && { echo "FAIL: empty .service.d not rmdir'd on remove"; exit 1; } || true
}

# purge removes the through-current sbin links, the runtime drop-in (#1967),
# AND the versions/ tree.
scenario_purge_removes_versions() {
    build_hardened "1.0.0"
    "$ROOT/postrm" purge
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: sbin $b not removed"; exit 1; } || true
    done
    [ -e "$VERSIONS" ] && { echo "FAIL: versions/ not removed on purge"; exit 1; } || true
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed on purge"; exit 1; } || true
}

# remove with a NON-empty .service.d (a foreign drop-in) removes only OUR
# drop-in and leaves the dir + foreign file intact (#1967 rmdir is best-effort).
scenario_remove_keeps_foreign_dropin() {
    build_hardened "1.0.0"
    foreign="$(dirname "$DROPIN")/99-operator.conf"
    echo "[Service]" > "$foreign"
    "$ROOT/postrm" remove
    [ -e "$DROPIN" ] && { echo "FAIL: our drop-in not removed"; exit 1; } || true
    [ -e "$foreign" ] || { echo "FAIL: foreign drop-in removed"; exit 1; }
    [ -d "$(dirname "$DROPIN")" ] || { echo "FAIL: non-empty .service.d rmdir'd"; exit 1; }
}

# remove on a legacy/never-seeded host (no drop-in present) is a clean no-op
# for the drop-in step (#1967 — must be safe if absent).
scenario_remove_no_dropin_ok() {
    mkdir -p "$STAGED" "$SBIN"
    for b in $BINS; do echo x > "$STAGED/$b"; ln -sf "$STAGED/$b" "$SBIN/$b"; done
    # No DROPIN, no versions/.
    "$ROOT/postrm" remove
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: legacy sbin $b not removed"; exit 1; } || true
    done
}

# downgrade to a pre-hardened package: drop-in removed, sbin repointed to
# staged, current deleted.
scenario_downgrade_to_prehardened() {
    build_hardened "2.0.0"
    make_staged_prehardened
    "$ROOT/postrm" upgrade "0.9.0"
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed"; exit 1; } || true
    # The .d dir must be rmdir'd when empty (exercises dirname "$DROPIN").
    [ -e "$(dirname "$DROPIN")" ] && { echo "FAIL: empty drop-in .d dir not removed"; exit 1; } || true
    for b in $BINS; do
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$STAGED/$b" ] || { echo "FAIL: sbin $b -> $tgt, want staged"; exit 1; }
    done
    [ -e "$CURRENT" ] && { echo "FAIL: current not deleted"; exit 1; } || true
}

# downgrade/upgrade to ANOTHER hardened package: layout untouched.
scenario_upgrade_to_hardened_noop() {
    build_hardened "1.0.0"
    # staged xpfd still supports the capability check (build_hardened set it).
    "$ROOT/postrm" upgrade "0.9.0"
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed on hardened->hardened"; exit 1; }
    for b in $BINS; do
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$CURRENT/$b" ] || { echo "FAIL: sbin $b repointed on hardened->hardened ($tgt)"; exit 1; }
    done
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted on hardened->hardened"; exit 1; }
}

# operator-repointed sbin link is NOT removed (not owned).
scenario_remove_skips_foreign_link() {
    build_hardened "1.0.0"
    ln -sf "/opt/custom/xpfd" "$SBIN/xpfd"
    "$ROOT/postrm" remove
    [ "$(readlink "$SBIN/xpfd")" = "/opt/custom/xpfd" ] || { echo "FAIL: removed a foreign sbin link"; exit 1; }
}

# legacy direct-to-staged sbin links are still removed (back-compat).
scenario_remove_legacy_links() {
    mkdir -p "$STAGED" "$SBIN"
    for b in $BINS; do echo x > "$STAGED/$b"; ln -sf "$STAGED/$b" "$SBIN/$b"; done
    "$ROOT/postrm" remove
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: legacy sbin $b not removed"; exit 1; } || true
    done
}

# downgrade must NOT clobber a foreign/operator-repointed sbin link (Codex).
scenario_downgrade_skips_foreign_link() {
    build_hardened "2.0.0"
    make_staged_prehardened
    # Operator repointed xpfd elsewhere; the others stay package-owned.
    ln -sf "/opt/custom/xpfd" "$SBIN/xpfd"
    "$ROOT/postrm" upgrade "0.9.0"
    [ "$(readlink "$SBIN/xpfd")" = "/opt/custom/xpfd" ] || { echo "FAIL: downgrade clobbered a foreign sbin link"; exit 1; }
    # The owned ones are repointed to staged.
    for b in cli xpf-userspace-dp xpf-day0-config; do
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || { echo "FAIL: owned sbin $b not repointed to staged"; exit 1; }
    done
}

run_scenario remove_keeps_versions
run_scenario purge_removes_versions
run_scenario remove_keeps_foreign_dropin
run_scenario remove_no_dropin_ok
run_scenario downgrade_to_prehardened
run_scenario downgrade_skips_foreign_link
run_scenario upgrade_to_hardened_noop
run_scenario remove_skips_foreign_link
run_scenario remove_legacy_links
echo "ALL POSTRM SCENARIOS PASSED"
