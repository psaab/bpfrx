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
# run_bash: like run_shell, but invokes the script with bash.
#
# run_shell forces `sh` regardless of the script's shebang, which is correct
# for the POSIX self-tests it was written for. A self-test that legitimately
# needs bash (arrays, [[ ]], <<< herestrings, ${var//pat/}) fails under dash
# with "Bad substitution" — a syntax error, not a real result. Rather than
# rewrite a bash library into POSIX so its own test can run, run it with the
# interpreter it is written for, and SKIP rather than fail when bash is absent.
run_bash() {
	script=$1
	shift
	if [ ! -f "$script" ]; then
		skipl "$script (not present)"
		return
	fi
	if ! command -v bash >/dev/null 2>&1; then
		skipl "$script (bash not installed)"
		return
	fi
	out=$(bash "$script" "$@" 2>&1)
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
scripts/mutate-lib.sh
scripts/mutate.sh
scripts/mutate-selftest.sh
test/incus/fbf-steering-lib.sh
test/incus/fbf-steering-selftest.sh
test/incus/test-fbf-steering.sh
test/incus/newflow-ceiling-lib.sh
test/incus/newflow-ceiling-selftest.sh
test/incus/newflow-ceiling-harness.sh
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
# #7423: the mutation harness's scoring library. Hermetic (fixture logs). The
# refusal cell is the one that matters -- a runner that gates in one language
# scores every cross-language mutation as an ESCAPE, which is a claim that the
# code is untested.
run_bash scripts/mutate-selftest.sh
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
# #6923: the chokepoint argument for the v6 conntrack publish path rests on
# `refresh_bpf_conntrack_last_seen` being unable to CREATE a key, because it
# updates with BPF_EXIST. "The flag is named EXIST" and "the kernel refuses
# creation under this flag" are different claims; this asks the kernel, with a
# BPF_ANY positive control so an ENOENT cannot come from a broken fixture.
# SKIPs without cc, passwordless sudo, or CAP_BPF.
run_shell test/mutation/selftest-bpf-exist-cannot-create_6923.sh
# #6936: FBF two-upstream steering verdicts. Hermetic — no incus, no cluster,
# no network. Guards a negative cell that used to fail to a HEALTHY value:
# "no leak" and "the probe returned nothing" both scored PASS. Needs bash.
run_bash test/incus/fbf-steering-selftest.sh
# #6962: the new-flow ceiling harness's node selection. Hermetic — no incus, no
# cluster. Guards a grep that matched the PEER's row in `show chassis cluster
# status` and therefore always selected $FW0: it failed to a PLAUSIBLE VALUE
# (a node name), not to an error, so the run completed and was refused three
# layers later by the analyzer as if the dataplane were at fault. Needs bash.
run_bash test/incus/newflow-ceiling-selftest.sh

# #7296: the remaining hermetic test/incus self-tests. Every one was on disk and
# green, and NONE was reached by this runner -- so `make selftest` reported a
# clean pass while 192 cases across seven files never executed. The issue named
# ONE of them; there were seven, which is why the census below exists rather
# than a longer list alone.
run_bash test/incus/deploy-lib-selftest.sh
run_bash test/incus/cluster-cell-selftest.sh
run_bash test/incus/cluster-env-selftest.sh
run_bash test/incus/cos-apply-lib-selftest.sh
run_bash test/incus/host-inbound-selftest.sh
run_bash test/incus/iperf-throughput-selftest.sh
run_bash test/incus/target-services-selftest.sh
run_bash test/incus/with-cluster-selftest.sh

# -- interpreter census (#8153) --
#
# run_shell forces `sh` regardless of the script's shebang. That is correct for
# the POSIX legs, and it is a SYNTAX ERROR for a bash script: dash reports
# "Bad substitution" on ${BASH_SOURCE[0]} and the leg fails for a reason that
# has nothing to do with what it tests.
#
# scripts/mutate-selftest.sh was registered with run_shell and had been failing
# that way on every `make selftest`. The doc comment on run_shell above already
# describes this failure by name and run_bash already exists for it, so the
# contract was written down and the registration did not follow it.
#
# The #7296 census below cannot catch this. It globs test/incus/*-selftest.sh,
# and this script lives in scripts/ -- but even inside that glob it asks a
# different question. "Is every self-test INVOKED" and "is every self-test
# invoked with the interpreter it DECLARES" are different properties: a script
# can be listed, be invoked, and execute none of what it tests.
interp_mismatch=""
interp_seen=0
for reg in $(sed 's/#.*//' scripts/run-selftests.sh | sed -n 's/^run_shell \([^ ]*\).*/\1/p'); do
	[ -f "$reg" ] || continue
	interp_seen=$((interp_seen + 1))
	case $(head -1 "$reg") in
	*bash*) interp_mismatch="$interp_mismatch $reg" ;;
	esac
done
if [ "$interp_seen" -eq 0 ]; then
	# Matching no run_shell registrations would report a clean census over an
	# empty set -- the swept-nothing pass #7296 guards against.
	faill "interpreter census (matched NO run_shell registrations -- the sed is wrong)"
elif [ -n "$interp_mismatch" ]; then
	faill "interpreter census (bash-shebang scripts registered with run_shell, which forces sh:$interp_mismatch)"
else
	passl "interpreter census ($interp_seen run_shell legs, none declaring bash)"
fi

# -- self-test census (#7296) --
#
# The defect was not "one script was forgotten" -- it was that NOTHING NOTICED.
# Seven hermetic self-tests accumulated unreached because this runner carries a
# hand-maintained list with no check that the list covers what is on disk.
# Adding the seven without this census would leave the eighth to repeat it.
#
# Matches the `run_bash <path>` CALL form with comments stripped: a bare
# filename mention would otherwise be satisfied by the comment block above that
# names these very scripts -- the shape where a source-scanning gate passes on
# its own documentation.
census_missing=""
census_seen=0
runner_code=$(sed 's/#.*//' scripts/run-selftests.sh)
for st in test/incus/*-selftest.sh; do
	[ -f "$st" ] || continue
	census_seen=$((census_seen + 1))
	case "$runner_code" in
	*"run_bash $st"*) ;;
	*) census_missing="$census_missing $st" ;;
	esac
done
if [ "$census_seen" -eq 0 ]; then
	# A glob matching nothing would otherwise report a complete census over an
	# empty set -- a clean pass that swept nothing.
	faill "self-test census (matched NO test/incus/*-selftest.sh -- the glob is wrong)"
elif [ -n "$census_missing" ]; then
	faill "self-test census (not invoked by this runner:$census_missing)"
else
	passl "self-test census ($census_seen hermetic test/incus self-tests, all invoked)"
fi

# ── summary ──
printf '\n\033[1m== selftest summary ==\033[0m\n'
echo "  passed=$PASS  skipped=$SKIP  failed=$FAIL"
if [ "$FAIL" -ne 0 ]; then
	echo "  FAILED legs:$FAILED_LEGS" >&2
	exit 1
fi
echo "  OK — all self-tests passed (or SKIP-gated on missing tools)"
