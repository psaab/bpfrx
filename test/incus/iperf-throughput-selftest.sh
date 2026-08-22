#!/usr/bin/env bash
#
# #6897 — self-test for test/incus/iperf-throughput-lib.sh.
#
# The defect this guards is a MISSING CELL, not a wrong number, so the
# load-bearing assertion is TOTALITY: every input class must yield exactly
# one verdict. A test that only checked the arithmetic would have passed
# against the buggy version, because the buggy version's arithmetic was fine
# for the one unit it recognised.
#
# Hermetic — sources the lib and feeds it literal [SUM] lines. No incus, no
# cluster, no network, no iperf3.
#
# Usage: ./test/incus/iperf-throughput-selftest.sh   (rc 0 = all pass)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/iperf-throughput-lib.sh"
[[ -f "$LIB" ]] || { echo "FAIL: lib not found at $LIB" >&2; exit 1; }
# shellcheck source=/dev/null
source "$LIB"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
bad()  { echo "FAIL: $*" >&2; exit 1; }

# --- unit normalisation -------------------------------------------------
# Real [SUM] sender lines. The Mbits row is the #6897 case: the old parser
# matched only "Gbits" and silently produced no cell for it.
check_rate() { # <desc> <expected> <line>
	local got; got="$(iperf_sum_rate_gbps "$3")"
	[[ "$got" == "$2" ]] || bad "$1: want $2 Gbps, got '${got:-<empty>}' from: $3"
	ok "$1 -> $got Gbps"
}
check_rate "Gbits normalises"  "22.9000"  '[SUM]   0.00-120.00  sec   320 GBytes  22.9 Gbits/sec   12  sender'
check_rate "Mbits normalises"  "0.0860"   '[SUM]   0.00-120.00  sec  1.20 GBytes   86.0 Mbits/sec   0   sender'
check_rate "Kbits normalises"  "0.000500" '[SUM]   0.00-10.00   sec  0.00 GBytes  500 Kbits/sec    0   sender'
check_rate "integer rate"      "10.0000"  '[SUM]   0.00-10.00   sec   12 GBytes    10 Gbits/sec    0   sender'

got="$(iperf_sum_rate_gbps '[SUM]   0.00-120.00  sec  no rate here  sender')"
[[ -z "$got" ]] || bad "a line with no rate/unit pair must yield nothing, got '$got'"
ok "unrecognised line yields no rate"

got="$(iperf_sum_rate_gbps '')"
[[ -z "$got" ]] || bad "an empty line must yield nothing, got '$got'"
ok "empty line yields no rate"

# --- TOTALITY: every input class emits exactly one verdict ---------------
# This is the #6897 regression guard. Under the pre-fix logic the Mbits row
# and the unparseable row emitted NOTHING.
check_verdict() { # <desc> <want-status> <min> <line>
	local out status n
	out="$(iperf_throughput_verdict "$3" "$4")"
	n="$(printf '%s\n' "$out" | grep -c .)"
	[[ "$n" == "1" ]] || bad "$1: want exactly ONE verdict line, got $n:
$out"
	status="${out%% *}"
	[[ "$status" == "$2" ]] || bad "$1: want $2, got $status ($out)"
	ok "$1 -> $status"
}
check_verdict "healthy Gbits run passes"      PASS 5 '[SUM] 0.00-120.00 sec 320 GBytes 22.9 Gbits/sec 12 sender'
check_verdict "sub-Gbit run FAILS not silent" FAIL 5 '[SUM] 0.00-120.00 sec 1.20 GBytes 86.0 Mbits/sec 0 sender'
check_verdict "Gbits below the floor fails"   FAIL 5 '[SUM] 0.00-120.00 sec 40 GBytes 2.5 Gbits/sec 0 sender'
check_verdict "exactly at the floor passes"   PASS 5 '[SUM] 0.00-120.00 sec 70 GBytes 5.0 Gbits/sec 0 sender'
check_verdict "unparseable line FAILS"        FAIL 5 '[SUM] 0.00-120.00 sec garbage sender'
check_verdict "absent [SUM] line FAILS"       FAIL 5 ''

# A sub-Gbit result must be reported with its REAL value, not as "0" and not
# as an absence — the number is what tells an operator how far it fell.
out="$(iperf_throughput_verdict 5 '[SUM] 0.00-120.00 sec 1.20 GBytes 86.0 Mbits/sec 0 sender')"
[[ "$out" == *"0.0860 Gbps"* ]] || bad "a sub-Gbit verdict must carry the normalised value, got: $out"
ok "sub-Gbit verdict carries its measured value"

# The absent-line and unparseable verdicts must be DISTINGUISHABLE, so a
# reader can tell "iperf3 produced nothing" from "iperf3 produced something
# this parser did not understand" — different causes, different next step.
a="$(iperf_throughput_verdict 5 '')"
b="$(iperf_throughput_verdict 5 '[SUM] garbage')"
[[ "$a" != "$b" ]] || bad "absent and unparseable must not render identically"
[[ "$a" == *"no measurement at all"* ]] || bad "absent verdict must say so, got: $a"
[[ "$b" == *"unparseable"* ]] || bad "unparseable verdict must say so, got: $b"
ok "absent and unparseable verdicts are distinguishable"

# --- WIRING: the lib must actually be reached from test-failover.sh --------
# Binding the lib alone would leave a green if someone deleted the CALL from
# the production path — the shape that has repeatedly produced false
# confidence. A behavioural probe of test-failover.sh needs a cluster, so this
# is a structural guard on the one caller, and it is deliberately narrow:
# it asserts the wiring exists, not that the surrounding logic is correct.
FAILOVER="${SCRIPT_DIR}/test-failover.sh"
[[ -f "$FAILOVER" ]] || bad "test-failover.sh not found at $FAILOVER"

grep -q 'source "${SCRIPT_DIR}/iperf-throughput-lib.sh"' "$FAILOVER" \
	|| bad "test-failover.sh does not source iperf-throughput-lib.sh"
ok "test-failover.sh sources the lib"

grep -q 'iperf_throughput_verdict "$MIN_THROUGHPUT" "$sum_line"' "$FAILOVER" \
	|| bad "test-failover.sh does not call iperf_throughput_verdict — the cell would go silent again"
ok "test-failover.sh calls iperf_throughput_verdict"

# The catch-all is what makes the caller total. Without it an unknown status
# falls through the case and emits nothing — reintroducing #6897 one level up.
awk '/^throughput_verdict=/,/^esac$/' "$FAILOVER" | grep -qE '^\*\)[[:space:]]+fail ' \
	|| bad "the throughput verdict case has no catch-all '*) fail' — an unhandled status would emit no cell"
ok "the verdict case has a catch-all that fails loudly"

# The old Gbits-only parse must be gone; if it comes back it silently
# reintroduces the literal "0" that matched neither branch.
if grep -q "grep -oP '\[\\d.\]+\\s+Gbits'" "$FAILOVER"; then
	bad "the Gbits-only inline parse is back in test-failover.sh"
fi
ok "the Gbits-only inline parse is gone"

echo
echo "iperf-throughput-lib self-test: $PASS passed"
