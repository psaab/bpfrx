#!/bin/sh
# Single entry point for the day-0 / image / dist / deploy self-tests
# (fable-165 H-19).
#
# These self-tests (grow-root stamp discipline, bake sign-ordering, the
# signed-distribution roundtrip, and the xpf-deploy pure-function + mixed-base
# HA gate coverage) all pass but were wired into NOTHING: `make test` runs only
# the Go + Rust suites (#4006), there is no CI, and each self-test could only be
# run by hand. A regression re-introducing sign-before-validate (#4017) or
# breaking the grow-root stamp discipline (#2047) merged green.
#
# This runner DISCOVERS and runs every hermetic self-test with one command
# (`make selftest`). It is fast (<a few seconds) and needs no root, no incus, no
# cluster, no network. A leg whose external tool is missing SKIPs (exit 77 from
# a shell leg, or unittest skips) instead of failing, so the runner is green on
# a minimal host and only goes RED on a genuine regression.
#
# Scope: the pure/hermetic self-tests only. The incus/QEMU image boot matrix
# (scripts/image/validate.py) and the loss-cluster smoke targets need a
# hypervisor and are NOT run here — they have their own entry points.
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
cd "$ROOT" || { echo "FATAL: cannot cd to repo root $ROOT" >&2; exit 1; }

PASS=0
FAIL=0
SKIP=0
FAILED_LEGS=""

hdr()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
passl() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
skipl() { echo "  SKIP: $*"; SKIP=$((SKIP + 1)); }
faill() { echo "  FAIL: $*" >&2; FAIL=$((FAIL + 1)); FAILED_LEGS="$FAILED_LEGS $1"; }

# run_shell <script> [args...] — run a shell self-test. Exit 0 = PASS,
# exit 77 = SKIP (a leg self-reported a missing tool), anything else = FAIL.
run_shell() {
	script=$1
	shift
	if [ ! -f "$script" ]; then
		skipl "$script (not present)"
		return
	fi
	out=$(sh "$script" "$@" 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		passl "$script"
	elif [ "$rc" -eq 77 ]; then
		skipl "$script ($(echo "$out" | grep -m1 -i skip || echo 'tool unavailable'))"
	else
		faill "$script"
		echo "$out" | sed 's/^/      /'
	fi
}

# run_py <test_file.py> — run a python unittest file directly (each has a
# `unittest.main()` __main__ and resolves its target import relative to its own
# path, so cwd is irrelevant). Skips are reported by unittest itself (exit 0).
run_py() {
	script=$1
	if [ ! -f "$script" ]; then
		skipl "$script (not present)"
		return
	fi
	out=$(python3 "$script" 2>&1)
	rc=$?
	if [ "$rc" -eq 0 ]; then
		# Surface any unittest-level skips in the summary line.
		nskip=$(echo "$out" | grep -c 'skipped=' 2>/dev/null || true)
		if [ "$nskip" -gt 0 ] 2>/dev/null; then
			passl "$script ($(echo "$out" | grep -o 'skipped=[0-9]*' | head -1))"
		else
			passl "$script"
		fi
	else
		faill "$script"
		echo "$out" | sed 's/^/      /'
	fi
}

# ── 1. shell-syntax lint (<interp> -n) over the image/dist/day-0 scripts ──
# The interpreter is chosen from each script's shebang: xpf-day0-config is
# bash (uses arrays), the rest are POSIX sh — linting a bash script with dash
# would false-fail on array syntax.
hdr "shell syntax (parse check)"
SH_SCRIPTS="
scripts/image/xpf-day0-config
scripts/image/xpf-grow-root
scripts/image/xpf-uefi-slots
scripts/image/xpf-kernel-promote
scripts/image/incus-agent-setup
scripts/image/test-grow-root.sh
scripts/dist/selftest.sh
scripts/dist/install.sh
scripts/dist/build-apt-repo.sh
scripts/run-selftests.sh
"
for s in $SH_SCRIPTS; do
	[ -f "$s" ] || continue
	case $(head -1 "$s") in
	*bash*) interp="bash" ;;
	*) interp="sh" ;;
	esac
	if ! command -v "$interp" >/dev/null 2>&1; then
		skipl "$interp -n $s ($interp not installed)"
		continue
	fi
	if "$interp" -n "$s" 2>/tmp/xpf-selftest-shn.$$; then
		passl "$interp -n $s"
	else
		faill "$interp -n $s"
		sed 's/^/      /' /tmp/xpf-selftest-shn.$$
	fi
done
rm -f /tmp/xpf-selftest-shn.$$

# ── 2. optional shellcheck lint (SKIP if not installed) ──
hdr "shellcheck (optional)"
if command -v shellcheck >/dev/null 2>&1; then
	for s in $SH_SCRIPTS; do
		[ -f "$s" ] || continue
		if out=$(shellcheck -S warning "$s" 2>&1); then
			passl "shellcheck $s"
		else
			faill "shellcheck $s"
			echo "$out" | sed 's/^/      /'
		fi
	done
else
	skipl "shellcheck not installed (apt-get install shellcheck)"
fi

# ── 3. python unittest self-tests (image / deploy / scripts root) ──
hdr "python self-tests"
for t in scripts/image/test_*.py scripts/dist/test_*.py scripts/deploy/test_*.py scripts/test_*.py; do
	[ -f "$t" ] || continue
	run_py "$t"
done

# ── 4. shell self-tests ──
hdr "shell self-tests"
run_shell scripts/image/test-grow-root.sh
run_shell scripts/dist/selftest.sh
# AF_XDP reproducer strict-warning build — fail-on-revert gate for #4906
# (HC-081 uninitialized-counter false PASS). SKIPs on a host without a C
# toolchain / libbpf-dev / libxdp-dev / xxd.
run_shell test/xsk-repro/selftest-compile.sh
# #6289 M2: the selftest-compile.sh SKIP gate must probe a trial LINK (static
# archives), not just header syntax, so a headers-present/static-missing host
# SKIPs cleanly instead of false-RED. Hermetic (fake cc); SKIPs without make/xxd.
run_shell test/xsk-repro/selftest-skipgate_6289.sh
# #6355: selftest-compile.sh must WORD-SPLIT $CC like the Makefile's $(CC) so a
# multi-token wrapper CC (`ccache gcc`, `env cc`) that `make check` accepts runs
# through instead of false-SKIPping. Hermetic (fake cc via `env`); SKIPs without
# make/xxd/env.
run_shell test/xsk-repro/selftest-multitoken-cc_6355.sh
# #6898 A10-b5-F1: BEHAVIOURAL gate (not a strict-warning compile) for the
# reproducer's probe filter. The XDP program redirects every packet on the queue,
# so the receive counters used to count all interface traffic and `rx > 0` was
# satisfiable by an ARP or an IPv6 RA while the tool's own probes never arrived —
# the exact failure the reproducer exists to detect, reported as PASS. SKIPs
# without cargo or offline-buildable deps.
run_shell test/xsk-repro/selftest-probe-filter_6898.sh

# ── summary ──
printf '\n\033[1m== selftest summary ==\033[0m\n'
echo "  passed=$PASS  skipped=$SKIP  failed=$FAIL"
if [ "$FAIL" -ne 0 ]; then
	echo "  FAILED legs:$FAILED_LEGS" >&2
	exit 1
fi
echo "  OK — all self-tests passed (or SKIP-gated on missing tools)"
