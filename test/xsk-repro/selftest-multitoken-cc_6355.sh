#!/bin/sh
# Fail-on-revert gate for #6355: selftest-compile.sh's tool gate and trial-link
# probe must WORD-SPLIT $CC exactly like the Makefile's $(CC), so a multi-token
# wrapper compiler (`ccache gcc`, `env cc`, `gcc -flag`) that `make check`
# accepts runs through the SKIP probes instead of false-SKIPping.
#
# The bug (#6353 Codex M2): the probes used "$CC" quoted, treating the whole
# string as one executable. `command -v "ccache gcc"` and `"ccache gcc" -x c -`
# both fail for a wrapper CC -> the script SKIPs (exit 77) even though
# `make check CC="ccache gcc"` (which word-splits) would BUILD. The fix strips
# the first word for the `command -v` existence check (CC_BIN=${CC%% *}) and
# leaves $CC unquoted for the trial link.
#
# Method (hermetic — needs no real libbpf/libxdp): point selftest-compile.sh at
# a multi-token CC = "env <fakecc>", where the fake compiler models a fully
# working toolchain — the trial link and every `make check` build succeed. With
# the fix, `env` (first word) is found by the tool gate, the link probe and the
# build word-split to run the fake cc, and the script reaches PASS (exit 0).
#
# Revert direction (why this binds): re-quote either probe as "$CC" and the
# multi-token string is treated as a single binary that does not exist / cannot
# exec — the tool gate prints "SKIP: env <fakecc> not installed" (or the link
# probe SKIPs) and the script exits 77, not 0. The exit==0 / PASS assertions
# below then go RED. That is the fail-on-revert.
#
# Tool-gated: SKIPs (exit 77) when make / xxd / env are unavailable, because the
# script-under-test would then SKIP for a DIFFERENT reason and this test could
# not attribute the outcome to $CC word-splitting.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || { echo "FATAL: cannot cd to $HERE" >&2; exit 1; }

SUT="$HERE/selftest-compile.sh"
[ -f "$SUT" ] || { echo "SKIP: selftest-compile.sh not present"; exit 77; }

# make + xxd: the script-under-test builds the embedded-object header (xxd) and
# runs the strict-warning build (make). env: the multi-token wrapper front-end.
# Missing any of them means the SUT would SKIP for that reason, not $CC-split.
for tool in make xxd env; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "SKIP: $tool not installed (cannot bind the multi-token-CC probe)"
		exit 77
	}
done

WORK=$(mktemp -d) || { echo "FATAL: mktemp -d failed" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

# Fake compiler modelling a fully working toolchain: the trial link and every
# `make check` build succeed. For any `-o <file>` other than /dev/null, create
# the target so `make` sees the tool built; always exit 0.
cat > "$WORK/fakecc" <<'EOF'
#!/bin/sh
out=
prev=
for a in "$@"; do
	[ "$prev" = "-o" ] && out=$a
	prev=$a
done
if [ -n "$out" ] && [ "$out" != /dev/null ]; then
	: > "$out" 2>/dev/null || true
fi
exit 0
EOF
chmod +x "$WORK/fakecc"

# A genuine multi-token wrapper CC: `env` (a real on-PATH binary) runs the fake
# compiler. This is exactly the shape `make check` word-splits and runs.
out=$(CC="env $WORK/fakecc" sh "$SUT" 2>&1)
rc=$?

fail=0
if [ "$rc" -ne 0 ]; then
	echo "FAIL: a multi-token CC that make-check accepts should reach PASS" \
	     "(exit 0), got exit $rc" >&2
	fail=1
fi
if ! printf '%s\n' "$out" | grep -qi 'PASS: xsk-repro strict-warning build'; then
	echo "FAIL: expected the strict-warning build PASS line from a wrapper CC" >&2
	fail=1
fi
# Name the tool-gate revert signature directly: the probe must not report the
# multi-token compiler string as an uninstalled tool.
if printf '%s\n' "$out" | grep -qi 'not installed'; then
	echo "FAIL: tool gate false-SKIPped a multi-token CC ('... not installed')" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	printf '%s\n' "$out" | sed 's/^/      /' >&2
	echo "FAIL: #6355 multi-token-CC word-split gate" >&2
	exit 1
fi

echo "PASS: #6355 multi-token-CC word-split gate (wrapper CC -> build, not SKIP)"
exit 0
