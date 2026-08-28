#!/bin/sh
# #6898 A10-b5-F1: behavioural gate for the reproducer's probe filter.
#
# The XDP program redirects EVERY packet on the queue to the XSK, so the receive
# counters used to count all interface traffic. `rx > 0` was then satisfiable by
# an ARP or an IPv6 RA while the tool's own probes never arrived — the exact
# failure the reproducer exists to detect, reported as PASS.
#
# This runs the crate's unit tests for `is_probe_frame`. Reverting the filter
# (counting every descriptor) or splitting the marker into two literals makes
# them RED.
#
# Unlike its sibling selftests this is a BEHAVIOURAL gate, not a strict-warning
# compile: the defect it guards compiles perfectly.
#
# SKIPs (77) on a host without cargo, or without the vendored deps to build
# offline — matching the tool-gating convention of the other legs.
set -e
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
	echo "SKIP: cargo not available"
	exit 77
fi

if ! out=$(cargo test --offline --quiet 2>&1); then
	case "$out" in
	*"no matching package"*|*"failed to download"*|*"offline"*)
		echo "SKIP: cargo cannot build offline (deps unavailable)"
		exit 77
		;;
	esac
	echo "FAIL: xsk-repro unit tests"
	echo "$out"
	exit 1
fi

# Guard against a vacuous pass: cargo reports ok for zero tests just as happily.
if ! echo "$out" | grep -qE "test result: ok\. [1-9][0-9]* passed"; then
	echo "FAIL: no tests ran (a filter matching nothing reports ok and exits 0)"
	echo "$out"
	exit 1
fi
echo "PASS: xsk-repro probe-filter tests"
exit 0
