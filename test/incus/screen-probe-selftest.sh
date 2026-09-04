#!/usr/bin/env bash
#
# #8336 — self-test for test/incus/screen-probe-lib.sh.
#
# Hermetic: sources the lib and feeds it literal counter samples. No incus, no
# cluster, no network, no crafted frames.
#
# The load-bearing property is TOTALITY plus ORDERING.
#
# Totality, because the defect this class of harness produces is a MISSING
# CELL: two attempts at #8298 produced a flat aggregate that was reported as
# neither a pass nor a failure, and a flat number with no verdict reads as "we
# did not find anything" when the truth was "we did not measure anything".
#
# Ordering, because the VOID checks are not independent. An unarmed profile
# makes the witness meaningless and a flat witness makes the subject
# meaningless, so a layer that evaluated the subject first would report
# "PASSED" -- the frame was not dropped -- for a frame that never arrived.
# That is the exact false finding this issue exists to prevent, and it is why
# several cells below assert which VOID reason is chosen when more than one
# condition holds.

set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=screen-probe-lib.sh
source ./screen-probe-lib.sh

fails=0
check() {
	local name="$1" want="$2" got="$3"
	if [[ "$got" == "$want"* ]]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n     want prefix: %s\n     got:         %s\n' "$name" "$want" "$got"
		fails=$((fails + 1))
	fi
}

# --- the three verdicts, each reachable -----------------------------------

check "a dropped subject with a live witness is DROPPED" DROPPED \
	"$(screen_probe_verdict armed 10 11 100 101)"

check "a flat subject with a live witness is PASSED, a RESULT" PASSED \
	"$(screen_probe_verdict armed 10 11 100 100)"

check "a flat witness is VOID, never PASSED" VOID \
	"$(screen_probe_verdict armed 10 10 100 100)"

# THE CELL THAT MATTERS MOST. Without the witness ordering this input reads
# as "the frame was not dropped" -- a finding -- when nothing arrived at all.
# Both earlier #8298 attempts produced exactly this shape.
got="$(screen_probe_verdict armed 10 10 100 100)"
check "a flat witness AND a flat subject is VOID, not PASSED" VOID "$got"
case "$got" in
	*PASSED*) printf 'FAIL the flat-witness case must not mention PASSED\n'; fails=$((fails + 1));;
esac

# --- trap 1: the unarmed profile ------------------------------------------

check "an unarmed profile is VOID before anything else is read" VOID \
	"$(screen_probe_verdict not-armed 10 11 100 101)"

# ORDERING: armed is checked FIRST. Here the witness is live and the subject
# moved -- every downstream signal says "dropped" -- and the verdict must
# still be VOID, because with no screen configured stage_screen_check never
# ran and whatever dropped the frame was not the code under test.
got="$(screen_probe_verdict "" 10 11 100 101)"
check "an unarmed profile beats a moving subject counter" VOID "$got"
case "$got" in
	*DROPPED*) printf 'FAIL an unarmed run must not report DROPPED\n'; fails=$((fails + 1));;
esac

# --- trap 3: unreadable samples are not zero ------------------------------

check "a missing witness sample is VOID" VOID \
	"$(screen_probe_verdict armed "" 11 100 101)"
check "a non-numeric witness sample is VOID" VOID \
	"$(screen_probe_verdict armed 10 '<html>error</html>' 100 101)"
check "a missing subject sample with a live witness is VOID" VOID \
	"$(screen_probe_verdict armed 10 11 100 "")"

# A counter that went BACKWARDS is a helper restart mid-probe: the two samples
# describe different processes, so the difference is not a drop count. Without
# this the subtraction underflows into a huge positive in some shells, or a
# negative that compares as "no drops" -- either way a fabricated result.
check "a witness counter that went backwards is VOID" VOID \
	"$(screen_probe_verdict armed 10 4 100 101)"
check "a subject counter that went backwards is VOID" VOID \
	"$(screen_probe_verdict armed 10 11 100 4)"

# --- delta helper, directly ------------------------------------------------

check_eq() {
	local name="$1" want="$2" got="$3"
	if [[ "$got" == "$want" ]]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s: want %q got %q\n' "$name" "$want" "$got"
		fails=$((fails + 1))
	fi
}
check_eq "delta of two integers" 7 "$(screen_probe_delta 3 10)"
check_eq "delta of equal integers is 0, not empty" 0 "$(screen_probe_delta 5 5)"
check_eq "delta with a non-numeric before is empty" "" "$(screen_probe_delta x 10)"
check_eq "delta with a non-numeric after is empty" "" "$(screen_probe_delta 3 y)"
check_eq "delta of a backwards counter is empty" "" "$(screen_probe_delta 10 3)"

# The distinction the whole layer rests on: "did not move" and "cannot be
# read" are DIFFERENT, and only the first is a measurement.
if [[ "$(screen_probe_delta 5 5)" == "$(screen_probe_delta x 5)" ]]; then
	printf 'FAIL a flat counter and an unreadable one must not render alike\n'
	fails=$((fails + 1))
else
	printf 'ok   a flat counter and an unreadable one are distinguishable\n'
fi

# --- the disarm check, on a SHARED cluster --------------------------------

check "both nodes clean is PASS" PASS "$(screen_probe_disarm_verdict 0 0)"
check "a leftover on node0 is FAIL" FAIL "$(screen_probe_disarm_verdict 1 0)"
# The cell an aggregate count would fail: config syncs to the peer, so a
# profile can survive on node1 alone. A single summed check reading 0+1 as
# "mostly clean", or a check of node0 only, would pass here.
check "a leftover on node1 ALONE is FAIL" FAIL "$(screen_probe_disarm_verdict 0 1)"
check "an unreadable disarm count is FAIL, not PASS" FAIL "$(screen_probe_disarm_verdict 0 "")"

# --- totality --------------------------------------------------------------
#
# Every verdict call must produce exactly one line beginning with one of the
# three tokens. A silent return is the failure mode that started this issue.
for args in \
	"armed 10 11 100 101" "armed 10 11 100 100" "armed 10 10 100 100" \
	"not-armed 0 0 0 0" "armed x y z w" "armed 10 11 100 x" \
	" 1 2 3 4" "armed 0 0 0 0" "armed 1 2 3" "armed" ""
do
	# shellcheck disable=SC2086
	out="$(screen_probe_verdict $args)"
	lines="$(printf '%s' "$out" | grep -c . || true)"
	if [[ "$lines" != "1" ]]; then
		printf 'FAIL totality: args=[%s] produced %s lines, want exactly 1\n' "$args" "$lines"
		fails=$((fails + 1))
		continue
	fi
	case "$out" in
		VOID\ *|DROPPED\ *|PASSED\ *) ;;
		*) printf 'FAIL totality: args=[%s] produced an unrecognised verdict: %s\n' "$args" "$out"
		   fails=$((fails + 1));;
	esac
done
if (( fails == 0 )); then
	printf 'ok   totality: every input class yields exactly one recognised verdict\n'
fi

if (( fails > 0 )); then
	printf '\n%d check(s) failed\n' "$fails"
	exit 1
fi
printf '\nall screen-probe-lib checks passed\n'
