#!/bin/sh
# Fail-on-revert gate for #6289 M2: selftest-compile.sh must probe a trial LINK
# (against the static archives `make check` links), NOT just header syntax, so a
# host with dev HEADERS present but a static archive MISSING (e.g. no libzstd.a)
# SKIPs cleanly instead of proceeding to `make check` and producing a false-RED.
#
# Method (hermetic — needs no real libbpf/libxdp): point selftest-compile.sh at
# a FAKE compiler that models exactly that host —
#   * `-fsyntax-only`   -> exit 0   (headers "present")
#   * any real compile/link -> exit 1 (static archive "missing")
# With the fix, the LINK probe runs the real compile/link and FAILs under the
# fake cc, so the script SKIPs (exit 77) with the link-probe message BEFORE it
# ever reaches `make check`.
#
# Revert direction (why this binds): revert the fix so the probe is
# `-fsyntax-only` again — the fake cc exits 0 there ("headers present"), the
# script proceeds to `make check`, and make invokes the fake cc for the real
# build, which exits 1 -> `make check` FAILs -> the script exits 1 (FAIL), not
# 77. The exit==77 assertion below then goes RED. That is the fail-on-revert.
#
# Tool-gated: SKIPs (exit 77) when make / xxd are unavailable, because the
# script-under-test's own tool gate would then SKIP for a DIFFERENT reason and
# this test could not attribute the SKIP to the link probe.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || { echo "FATAL: cannot cd to $HERE" >&2; exit 1; }

SUT="$HERE/selftest-compile.sh"
[ -f "$SUT" ] || { echo "SKIP: selftest-compile.sh not present"; exit 77; }

# The script-under-test's tool gate probes make + xxd before the link probe; if
# either is missing it SKIPs for that reason and we cannot bind the link probe.
for tool in make xxd; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "SKIP: $tool not installed (cannot reach the link probe)"
		exit 77
	}
done

WORK=$(mktemp -d) || { echo "FATAL: mktemp -d failed" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

# Fake compiler: headers present (syntax-only OK), static archive missing (any
# real compile or link fails). Mirrors a host that passes a header-only probe
# but fails the static link.
cat > "$WORK/fakecc" <<'EOF'
#!/bin/sh
for a in "$@"; do
	[ "$a" = "-fsyntax-only" ] && exit 0
done
echo "fakecc: cannot find -lzstd (static archive missing)" >&2
exit 1
EOF
chmod +x "$WORK/fakecc"

out=$(CC="$WORK/fakecc" sh "$SUT" 2>&1)
rc=$?

fail=0
if [ "$rc" -ne 77 ]; then
	echo "FAIL: expected SKIP (exit 77) from the link probe, got exit $rc" >&2
	fail=1
fi
# Attribute the SKIP to the LINK probe (not the tool gate) via its message.
if ! printf '%s\n' "$out" | grep -qi 'static archives not available'; then
	echo "FAIL: SKIP did not come from the link probe (missing 'static archives" \
	     "not available' message)" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out" | sed 's/^/      /' >&2
	echo "FAIL: #6289 M2 link-probe SKIP gate" >&2
	exit 1
fi

echo "PASS: #6289 M2 link-probe SKIP gate (headers-present/static-missing -> SKIP)"
exit 0
