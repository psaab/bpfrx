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

# Honor $CC (defaulting to cc) like the Makefile's `CC ?= cc`, so the SKIP
# probe and `make check` use the SAME compiler/toolchain. The #6289 M2 gate
# test drives this by pointing CC at a fake compiler.
CC=${CC:-cc}

# $CC may be a multi-token wrapper ("ccache gcc", "env cc", "gcc -flag") — the
# Makefile's $(CC) word-splits, so `make check` runs the first token as the
# executable with the rest as arguments. The `command -v` existence check below
# and the trial-link probe must therefore split $CC the same way, or a wrapper
# CC that `make check` accepts would false-SKIP here (#6355). Extract the first
# word for the tool gate; word-split the whole string for the link/build.
CC_BIN=${CC%% *}

# --- tool gate ---
for tool in "$CC_BIN" make xxd; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "SKIP: $tool not installed"
		exit 77
	}
done
# Link gate (#6289 M2): probe a trial LINK against the SAME static archives
# `make check` links, not just header syntax. The static build recipe
# (Makefile LIBS_SHARED) links `-Wl,-Bstatic -lxdp -lbpf -lelf -lz -lzstd`; a
# host with the dev HEADERS present but a static archive MISSING (e.g. no
# libzstd.a) passed the old header-only -fsyntax-only probe and then FAILed the
# `make check` static link → a false-RED for this leg. Probing the actual link
# makes such a host SKIP cleanly. -o /dev/null discards the trial binary.
# $CC is intentionally unquoted so a multi-token wrapper CC word-splits exactly
# like the Makefile's $(CC) (#6355). Quoting it would exec the whole string as a
# single binary and false-SKIP a wrapper `make check` would accept.
# shellcheck disable=SC2086
if ! printf '#include <bpf/bpf.h>\n#include <xdp/xsk.h>\nint main(void){return 0;}\n' \
	| $CC -x c - -o /dev/null \
		-Wl,-Bstatic -lxdp -lbpf -lelf -lz -lzstd -Wl,-Bdynamic -lpthread \
		>/dev/null 2>&1; then
	echo "SKIP: libbpf-dev / libxdp-dev headers or static archives not available"
	exit 77
fi

# --- the actual gate: strict-warning build must succeed ---
rc=0
if out=$(make -s check CC="$CC" 2>&1); then
	echo "PASS: xsk-repro strict-warning build"
else
	rc=1
	echo "FAIL: xsk-repro strict-warning build" >&2
	echo "$out" | sed 's/^/      /' >&2
fi

# Tidy: remove the generated header + built binaries (all gitignored anyway).
make -s clean >/dev/null 2>&1 || true
exit "$rc"
