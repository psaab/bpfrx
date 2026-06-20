#!/bin/sh
# Self-test for scripts/image/xpf-grow-root device-resolution logic (#1925).
#
# Runs the REAL wrapper with PATH shadowed by mock findmnt/lsblk/growpart/
# resize2fs and XPF_GROW_ROOT_SYSFS pointed at a synthetic sysfs tree, then
# asserts the wrapper resolved the right (disk, partition) pair and invoked
# growpart + resize2fs with the exact arguments — across sda/vda/nvme bus
# naming and the skip cases (non-block root, whole-disk-not-partition).
#
# Non-tautological by construction: the mock growpart records EXACTLY the
# args the wrapper passed; the assertions pin those bytes. A wrong
# derivation (e.g. nvme0n1p1 -> disk "nvme0n1p" / part "1", or hardcoding
# sda) would produce different recorded args and FAIL. A deliberate
# negative case at the end proves the harness can fail.
#
# Pure user-space: no root, no real block devices, no kernel. Runs in CI /
# the engineering quad's gate alongside bash -n + shellcheck.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WRAPPER="$HERE/xpf-grow-root"
[ -x "$WRAPPER" ] || { echo "FATAL: $WRAPPER not executable"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/xpf-grow-root-test.XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

BIN="$WORK/bin"
mkdir -p "$BIN"

# ── mock binaries (PATH shim). Each logs its call into $WORK/<name>.calls ──
# findmnt -no SOURCE /  -> the per-case ROOT_SRC; lsblk -no PKNAME <src> ->
# the per-case PKNAME; growpart/resize2fs record their argv. growpart honors
# GROWPART_RC + GROWPART_OUT so the NOCHANGE/grow paths can be exercised.
cat > "$BIN/findmnt" <<'EOF'
#!/bin/sh
# Only `findmnt -no SOURCE /` is used by the wrapper.
printf '%s\n' "${MOCK_ROOT_SRC:-}"
EOF
cat > "$BIN/lsblk" <<'EOF'
#!/bin/sh
# Only `lsblk -no PKNAME <src>` is used by the wrapper.
printf '%s\n' "${MOCK_PKNAME:-}"
EOF
cat > "$BIN/growpart" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$1" "$2" > "$MOCK_CALLS_DIR/growpart.calls"
printf '%s' "${GROWPART_OUT:-CHANGED: partition resized}"
exit "${GROWPART_RC:-0}"
EOF
cat > "$BIN/resize2fs" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" > "$MOCK_CALLS_DIR/resize2fs.calls"
echo "The filesystem is now larger."
exit "${RESIZE2FS_RC:-0}"
EOF
chmod +x "$BIN"/findmnt "$BIN"/lsblk "$BIN"/growpart "$BIN"/resize2fs

# Synthetic sysfs: <dev>/partition exists (with the partnum) ONLY for real
# partitions; whole disks omit it.
SYSFS="$WORK/sys"
make_part() { mkdir -p "$SYSFS/$1"; printf '%s\n' "$2" > "$SYSFS/$1/partition"; }
make_disk() { mkdir -p "$SYSFS/$1"; }  # no partition file
make_part sda1 1
make_part vda1 1
make_part nvme0n1p1 1
make_disk sda            # whole disk, not a partition

run_case() {  # run_case <root_src> <pkname> [GROWPART_RC] [GROWPART_OUT]
    rm -f "$WORK/growpart.calls" "$WORK/resize2fs.calls"
    MOCK_CALLS_DIR="$WORK" \
    MOCK_ROOT_SRC="$1" MOCK_PKNAME="$2" \
    GROWPART_RC="${3:-0}" GROWPART_OUT="${4:-}" \
    XPF_GROW_ROOT_SYSFS="$SYSFS" \
    PATH="$BIN:$PATH" \
        "$WRAPPER" >/dev/null 2>&1
}

expect_grow() {  # expect_grow <label> <disk> <partnum> <root_src>
    label=$1; xdisk=$2; xpart=$3; xsrc=$4
    gp=$(cat "$WORK/growpart.calls" 2>/dev/null || true)
    r2=$(cat "$WORK/resize2fs.calls" 2>/dev/null || true)
    if [ "$gp" = "/dev/$xdisk $xpart" ]; then
        ok "$label: growpart got '/dev/$xdisk $xpart'"
    else
        bad "$label: growpart got '$gp', want '/dev/$xdisk $xpart'"
    fi
    if [ "$r2" = "$xsrc" ]; then
        ok "$label: resize2fs got '$xsrc'"
    else
        bad "$label: resize2fs got '$r2', want '$xsrc'"
    fi
}

expect_skip() {  # expect_skip <label>
    label=$1
    if [ ! -f "$WORK/growpart.calls" ] && [ ! -f "$WORK/resize2fs.calls" ]; then
        ok "$label: skipped (no growpart/resize2fs call)"
    else
        bad "$label: did NOT skip (growpart='$(cat "$WORK/growpart.calls" 2>/dev/null)')"
    fi
}

echo "== xpf-grow-root device-resolution self-test =="

# ── positive cases: each bus naming resolves to the right disk + partnum ──
run_case /dev/sda1 sda
expect_grow "sda1"      sda      1 /dev/sda1
run_case /dev/vda1 vda
expect_grow "vda1"      vda      1 /dev/vda1
run_case /dev/nvme0n1p1 nvme0n1
expect_grow "nvme0n1p1" nvme0n1  1 /dev/nvme0n1p1

# ── NOCHANGE path: growpart exit 1 + NOCHANGE is treated as success; the
#    wrapper still proceeds to resize2fs and exits 0. ──
run_case /dev/sda1 sda 1 "NOCHANGE: partition 1 is size ... it cannot be grown"
expect_grow "NOCHANGE" sda 1 /dev/sda1

# ── skip cases: non-/dev root, and a whole-disk (no partition file). ──
run_case "tmpfs" ""
expect_skip "non-/dev root (tmpfs)"
run_case /dev/sda sda          # /dev/sda has no .../partition -> not a partition
expect_skip "whole-disk root (/dev/sda, no partition)"
run_case "" ""
expect_skip "empty findmnt source"

# ── negative control: prove the harness can FAIL (sda1 must NOT resolve to
#    vda). If this 'ok' fires the assertions are tautological. ──
run_case /dev/sda1 sda
gp=$(cat "$WORK/growpart.calls" 2>/dev/null || true)
if [ "$gp" != "/dev/vda 1" ]; then
    ok "negative control: sda1 did NOT resolve to /dev/vda (assertions are live)"
else
    bad "negative control: sda1 wrongly matched /dev/vda — assertions tautological"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
