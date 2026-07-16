#!/bin/sh
# preinst-safe-segment-test.sh — parity test for debian/xpf.preinst's
# is_safe_segment() version-grammar validator (#5713 M41).
#
# is_safe_segment MUST accept exactly the same version strings as the Go
# pkg/upgrade.ValidateVersionSegment allowlist ([A-Za-z0-9] + . _ + ~ - :) and
# reject everything else — crucially '%' (a systemd unit specifier that would
# rewrite the pinned ExecStart path) and the other systemd argv metacharacters.
# A drift between the two validators is a real bug (one side accepts what the
# other rejects), so this asserts the shell half char-for-char.
#
# It SOURCES the REAL function out of debian/xpf.preinst (not a copy) so a change
# to the shell allowlist that breaks parity turns this red.
#
# Run: sh test/debian/preinst-safe-segment-test.sh   (or dash — Debian /bin/sh)
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREINST="$HERE/../../debian/xpf.preinst"
[ -f "$PREINST" ] || { echo "FATAL: $PREINST not found" >&2; exit 1; }

# Extract just the is_safe_segment() function definition and eval it, so we test
# the shipped function body without running the preinst's top-level logic.
fn=$(awk '/^is_safe_segment\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$PREINST")
[ -n "$fn" ] || { echo "FATAL: could not extract is_safe_segment from $PREINST" >&2; exit 1; }
eval "$fn"

fail=0

expect_accept() {
    if is_safe_segment "$1"; then
        echo "PASS accept  $1"
    else
        echo "FAIL accept  $1 (legit version rejected — parity/regression)"; fail=1
    fi
}
expect_reject() {
    if is_safe_segment "$1"; then
        echo "FAIL reject  $1 (unsafe version accepted — #5713 M41 / parity)"; fail=1
    else
        echo "PASS reject  $1"
    fi
}

# Must ACCEPT — every version in the Go valid-test set (no regression).
expect_accept "1.0.0"
expect_accept "2.4.1-rc3"
expect_accept "1.0.0+build.7"
expect_accept "1:2.3.4-1"      # Debian epoch
expect_accept "1.0.0~beta1"    # pre-release
expect_accept "dev"
expect_accept "0.0.1_snapshot"
expect_accept "v1.2.3"
expect_accept "0.9.0+deb1"

# Must REJECT — '%' (M41) + the other systemd/exec metacharacters + path escapes.
expect_reject "%i"             # systemd instance specifier
expect_reject "1.0%n"          # %n = unit name
expect_reject "100%"
expect_reject '1.0.0$x'        # env-var expansion
expect_reject '1.0.0"x'        # argv quote
expect_reject '1.0.0`x'        # backtick
expect_reject "1.0*"           # glob
expect_reject "1.0.0;rm"       # shell metachar
expect_reject "1.0 2.0"        # embedded space
expect_reject "../evil"        # traversal
expect_reject "a/b"            # path separator
expect_reject ".hidden"        # leading dot
expect_reject ""               # empty

if [ "$fail" -ne 0 ]; then
    echo "SOME is_safe_segment PARITY CASES FAILED" >&2
    exit 1
fi
echo "ALL is_safe_segment PARITY CASES PASSED"
