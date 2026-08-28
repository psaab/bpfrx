#!/usr/bin/env bash
# Hermetic self-test for test/incus/fbf-steering-lib.sh (#6936).
#
# No cluster, no incus, no network. Runs in `make test-fbf-steering-lib`.
#
# The row that matters is PROBE_BLIND. Under the counting form this smoke
# shipped with, that input produced the same verdict as a healthy table, which
# is why the defect was invisible to review: only a table that includes the
# middle row can distinguish "there is no leak" from "I could not look".
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./fbf-steering-lib.sh
. "${SCRIPT_DIR}/fbf-steering-lib.sh"

pass=0
fail=0
GW="172.16.80.1"

check() {
	local name="$1" want="$2" gw="$3" routes="$4" got verdict
	got="$(fbf_main_default_leak_verdict "$gw" "$routes")"
	verdict="${got%% *}"
	if [[ "$verdict" == "$want" ]]; then
		pass=$((pass + 1))
		printf 'ok   %-26s -> %s\n' "$name" "$verdict"
	else
		fail=$((fail + 1))
		printf 'FAIL %-26s -> want %s got %s (%s)\n' "$name" "$want" "$verdict" "$got"
	fi
	# TOTALITY: exactly one verdict line, and it is one of the two known words.
	if [[ "$(grep -c . <<<"$got")" -ne 1 ]]; then
		fail=$((fail + 1))
		printf 'FAIL %-26s -> verdict was not exactly one line: %q\n' "$name" "$got"
	fi
	if [[ "$verdict" != "PASS" && "$verdict" != "FAIL" ]]; then
		fail=$((fail + 1))
		printf 'FAIL %-26s -> verdict word %q is neither PASS nor FAIL\n' "$name" "$verdict"
	fi
}

# --- the healthy case: a main table with an unrelated (ISP-A) default -------
check CLEAN_ONE_DEFAULT   PASS "$GW" "default via 172.16.50.1 dev ge-0-0-2 proto static"
check CLEAN_TWO_DEFAULTS  PASS "$GW" "default via 172.16.50.1 dev ge-0-0-2
default via 10.0.61.254 dev ge-0-0-1 metric 100"

# --- the defect the cell exists to catch -----------------------------------
check LEAK_EXACT          FAIL "$GW" "default via 172.16.80.1 dev ge-0-0-2 proto static"
check LEAK_AMONG_OTHERS   FAIL "$GW" "default via 172.16.50.1 dev ge-0-0-2
default via 172.16.80.1 dev ge-0-0-2 metric 200"

# --- THE MIDDLE ROW: the counting form scored every one of these as healthy -
check PROBE_BLIND_EMPTY   FAIL "$GW" ""
check PROBE_BLIND_WS      FAIL "$GW" "   "
check PROBE_BLIND_NEWLINE FAIL "$GW" "
"
# A cell with no needle cannot certify absence either.
check NO_GATEWAY_GIVEN    FAIL ""    "default via 172.16.50.1 dev ge-0-0-2"

# --- the positive control must not be satisfiable by a near-miss -----------
# A different gateway on the same /24 must NOT read as a leak.
check NEAR_MISS_GW        PASS "$GW" "default via 172.16.80.11 dev ge-0-0-2"

# --- fbf_table_holds_default: pick the PBR table by CONTENT, not position ---
checkt() {
	local name="$1" want="$2" gw="$3" routes="$4" got
	if fbf_table_holds_default "$gw" "$routes"; then got=YES; else got=NO; fi
	if [[ "$got" == "$want" ]]; then
		pass=$((pass + 1)); printf 'ok   %-26s -> %s\n' "$name" "$got"
	else
		fail=$((fail + 1)); printf 'FAIL %-26s -> want %s got %s\n' "$name" "$want" "$got"
	fi
}

# The real ISP-B table.
checkt TBL_HAS_ISP_B_DEFAULT  YES "$GW" "default via 172.16.80.1 dev ge-0-0-2 proto static metric 20
172.16.80.0/24 dev ge-0-0-2 proto kernel scope link"
# The PRE-EXISTING GRE table that sits at priority 31000 on the loss cluster and
# that the old first-match discovery bound instead. Verbatim shape.
checkt TBL_GRE_NOT_ISP_B      NO  "$GW" "default nhid 101 via 10.255.192.41 dev gr-0-0-0 proto static metric 20
10.255.192.40/30 dev gr-0-0-0 proto kernel scope link src 10.255.192.42
local 10.255.192.42 dev gr-0-0-0 proto kernel scope host src 10.255.192.42"
# A table with routes but no default at all.
checkt TBL_NO_DEFAULT         NO  "$GW" "172.16.80.0/24 dev ge-0-0-2 proto kernel scope link"
# Empty / unreadable table must not select.
checkt TBL_EMPTY              NO  "$GW" ""
# The gateway must match as a whole token here too.
checkt TBL_NEAR_MISS_GW       NO  "$GW" "default via 172.16.80.11 dev ge-0-0-2"
# The gateway may appear on a NON-default route without selecting the table.
checkt TBL_GW_ONLY_NONDEFAULT NO  "$GW" "172.16.80.0/24 via 172.16.80.1 dev ge-0-0-2"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
