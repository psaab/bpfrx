#!/bin/sh
# Fail-on-revert gate for the AF_XDP reproducer safety fixes (#4906).
#
# Builds the C reproducers with the strict-warning flags from the Makefile
# (-Wall -Wextra -Werror -Wjump-misses-init). This is the compile-time gate for
# #4906 HC-081: the uninitialized-counter false PASS. Reverting that fix (moving
# the rx1/rx2 declarations back past `goto cleanup`) reintroduces
# -Werror=jump-misses-init / -Werror=maybe-uninitialized and this leg goes RED.
# The unused-parameter and other strict-warning fixes in the same cohort are
# likewise held by -Werror.
#
# Tool-gated: exits 77 (SKIP) when cc / make / xxd or the libbpf/libxdp dev
# headers are unavailable, so the runner stays green on a minimal host.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || { echo "FATAL: cannot cd to $HERE" >&2; exit 1; }

# --- tool gate ---
for tool in cc make xxd; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "SKIP: $tool not installed"
		exit 77
	}
done
# Header gate: probe the two headers the reproducers include.
if ! printf '#include <bpf/bpf.h>\n#include <xdp/xsk.h>\nint main(void){return 0;}\n' \
	| cc -x c -fsyntax-only - >/dev/null 2>&1; then
	echo "SKIP: libbpf-dev / libxdp-dev headers not available"
	exit 77
fi

# --- the actual gate: strict-warning build must succeed ---
rc=0
if out=$(make -s check 2>&1); then
	echo "PASS: xsk-repro strict-warning build"
else
	rc=1
	echo "FAIL: xsk-repro strict-warning build" >&2
	echo "$out" | sed 's/^/      /' >&2
fi

# Tidy: remove the generated header + built binaries (all gitignored anyway).
make -s clean >/dev/null 2>&1 || true
exit "$rc"
