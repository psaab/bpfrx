#!/bin/sh
# scripts/ignored-cell-census.sh — census over `#[ignore]`d Rust cells (#8352).
#
# WHAT IT ASSERTS
#
#   1. Every `#[ignore]` carries a REASON. A bare `#[ignore]` says nothing about
#      why the cell is off or when it should come back.
#   2. Every reason DECLARES ITS KIND with an explicit marker:
#        `#[ignore = "MEASUREMENT: ..."]`  a measurement, not an assertion;
#                                          stays ignored forever, exempt from (3)
#        `#[ignore = "#N: ..."]`           fail-until-fixed; reactivate when
#                                          issue N closes
#   3. (--check-issues) Every issue named that way is still OPEN. When it
#      closes, this census REDS, and whoever closed it must un-ignore the cell
#      or restate why it stays ignored.
#
# WHY IT EXISTS
#
#   An `#[ignore]`d fail-until-fixed cell has no wake-up. `#[ignore]` is
#   invisible to `make test-rust`, so when the defect it documents is fixed the
#   cell stays ignored, stays green, and guards nothing -- permanently. It is a
#   done-signal arranged in advance at a layer the completing change never
#   reaches: the cell is correct, and its trigger does not exist.
#
#   Check (3) puts the trigger at the layer that actually fires. Closing the
#   issue IS the event, so the signal arrives on the event that matters rather
#   than on someone remembering to re-read an attribute during a refactor.
#
#   The failure is silent and its evidence looks identical to success: a green
#   `make test-rust` with the cell ignored is byte-identical to a green one with
#   the cell passing.
#
# WHY A MARKER AND NOT PROSE
#
#   Two legitimate kinds of `#[ignore]` exist here -- fail-until-fixed and
#   measurement-not-assertion -- and before this census the distinction lived
#   only in free text, so no tool could tell them apart. Exempting measurements
#   by matching a PHRASE ("measurement, not an assertion") would die to
#   paraphrase: rewording the comment silently converts a measurement into an
#   unchecked cell, or an issue-linked cell into an exempt one. The marker is a
#   declaration, and an undeclared reason is a FAIL rather than a default.
#
# FALSIFIABILITY — what this reports when the property is FALSE
#
#   * A bare `#[ignore]`, or a reason that declares no kind, is printed by
#     file:line under UNDECLARED and the census exits 1. It never defaults an
#     undeclared reason into either kind.
#   * A `#N:` cell whose issue has CLOSED is printed with the issue number and
#     the census exits 1 (with --check-issues).
#   * If the scan finds ZERO `#[ignore]` cells the census FAILS. A census that
#     sweeps an empty set and reports a clean board is the failure mode
#     run-selftests.sh already guards against in four other places, and it is
#     the one a broken pattern produces.
#   * If the CLASSIFIER breaks so that nothing is ever issue-linked, every cell
#     would look exempt and the board would read clean over an inverted world.
#     The POSITIVE CONTROL below runs the classifier over three synthetic
#     probes -- one of each kind -- and trips first. It is synthetic on purpose:
#     a control keyed to a real cell in the tree would break legitimately the
#     day that cell is fixed and un-ignored, which is the outcome this census
#     exists to cause.
#   * "The measurement did not happen" is a real state for check (3) only: with
#     no `gh` it exits 77 (SKIP) rather than reporting the issues as open.
#     Checks (1) and (2) are hermetic -- a pure file scan -- and always run.
#
# USAGE
#   sh scripts/ignored-cell-census.sh                 # hermetic checks (1)+(2)
#   sh scripts/ignored-cell-census.sh --check-issues  # also (3); needs gh
set -u

# shellcheck disable=SC1007
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1007
DEFAULT_ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

ROOT=${IGN_CENSUS_ROOT:-$DEFAULT_ROOT}
cd "$ROOT" || { echo "FATAL: cannot cd to $ROOT" >&2; exit 2; }

# Directories scanned for Rust cells. Env-overridable so the self-test can point
# the census at a fixture tree.
SCAN_DIRS=${IGN_CENSUS_DIRS:-"userspace-dp userspace-xdp"}
# The command used to ask whether an issue is open. Overridable so the self-test
# can drive the CLOSED branch without a network.
GH_STATE_CMD=${IGN_CENSUS_GH_STATE:-}

CHECK_ISSUES=0
[ "${1:-}" = "--check-issues" ] && CHECK_ISSUES=1

# ── the classifier ───────────────────────────────────────────────────
# classify <reason>  ->  prints "MEASUREMENT" | "ISSUE <n>" | "UNDECLARED"
# An EMPTY reason (a bare `#[ignore]`) is UNDECLARED, not a third state: the
# remedy is the same, and giving it its own bucket would let it be exempted
# separately later.
classify() {
	reason=$1
	case "$reason" in
	"MEASUREMENT:"*) echo "MEASUREMENT"; return 0 ;;
	esac
	# `#<digits>:` at the START. Requiring the start makes it unambiguous:
	# a reason that merely MENTIONS #1234 in passing is not thereby a
	# fail-until-fixed declaration.
	n=$(printf '%s' "$reason" | sed -n 's/^#\([0-9][0-9]*\):.*/\1/p')
	if [ -n "$n" ]; then
		echo "ISSUE $n"
		return 0
	fi
	echo "UNDECLARED"
}

# ── positive control: the classifier itself ──────────────────────────
control_fail=""
[ "$(classify 'MEASUREMENT: not an assertion')" = "MEASUREMENT" ] ||
	control_fail="$control_fail measurement-probe"
[ "$(classify '#7209: reds until the mutex is split')" = "ISSUE 7209" ] ||
	control_fail="$control_fail issue-probe"
[ "$(classify 'just because')" = "UNDECLARED" ] ||
	control_fail="$control_fail undeclared-probe"
[ "$(classify '')" = "UNDECLARED" ] ||
	control_fail="$control_fail bare-probe"
# A reason that only MENTIONS an issue must NOT be read as a declaration --
# otherwise any prose containing a #number silently becomes issue-linked.
[ "$(classify 'flaky, see #7209 for context')" = "UNDECLARED" ] ||
	control_fail="$control_fail mention-not-declaration-probe"
if [ -n "$control_fail" ]; then
	echo "FAIL: positive control — the classifier is broken:$control_fail" >&2
	echo "  Every verdict below would be meaningless, so none was computed." >&2
	exit 1
fi
echo "  PASS: positive control — the classifier scores all five probes correctly"

# ── scan ─────────────────────────────────────────────────────────────
SCAN_LIST=""
for d in $SCAN_DIRS; do
	[ -d "$d" ] && SCAN_LIST="$SCAN_LIST $d"
done
if [ -z "$SCAN_LIST" ]; then
	echo "FAIL: none of the scan directories exist ($SCAN_DIRS)" >&2
	exit 1
fi

# shellcheck disable=SC2086
HITS=$(grep -rn --include='*.rs' '#\[ignore' $SCAN_LIST 2>/dev/null)

TOTAL=0
UNDECLARED=""
MEASUREMENTS=0
ISSUE_NUMS=""
ISSUE_LINES=""

# The reason is extracted with sed rather than a shell case so that an
# `#[ignore = "..."]` written with either quoting style yields the same text.
OLDIFS=$IFS
IFS='
'
for hit in $HITS; do
	TOTAL=$((TOTAL + 1))
	loc=$(printf '%s' "$hit" | cut -d: -f1,2)
	body=$(printf '%s' "$hit" | cut -d: -f3-)
	reason=$(printf '%s' "$body" | sed -n 's/.*#\[ignore *= *"\(.*\)"\].*/\1/p')
	kind=$(classify "$reason")
	case "$kind" in
	MEASUREMENT)
		MEASUREMENTS=$((MEASUREMENTS + 1))
		;;
	"ISSUE "*)
		num=${kind#ISSUE }
		ISSUE_NUMS="$ISSUE_NUMS $num"
		ISSUE_LINES="$ISSUE_LINES
$num $loc"
		;;
	*)
		UNDECLARED="$UNDECLARED
  $loc"
		;;
	esac
done
IFS=$OLDIFS

if [ "$TOTAL" -eq 0 ]; then
	# An empty sweep is not a clean board. If the tree genuinely has no
	# ignored cells this census has nothing to protect and should be removed
	# deliberately, not pass silently on a broken pattern.
	echo "FAIL: the scan found ZERO #[ignore] cells in$SCAN_LIST — the pattern or the glob is wrong" >&2
	exit 1
fi

rc=0
if [ -n "$UNDECLARED" ]; then
	echo "FAIL: #[ignore] cells with no reason, or a reason that declares no kind:$UNDECLARED" >&2
	echo "  Use  #[ignore = \"MEASUREMENT: <why>\"]        for a measurement, not an assertion" >&2
	echo "  or   #[ignore = \"#<issue>: <why it reds>\"]   for a cell that must come back when that issue closes" >&2
	rc=1
fi

# ── (3) the wake-up: every named issue must still be OPEN ────────────
if [ "$CHECK_ISSUES" -eq 1 ]; then
	if [ -z "$GH_STATE_CMD" ] && ! command -v gh >/dev/null 2>&1; then
		# The one genuinely un-runnable check. SKIP rather than report the
		# issues as open -- "we could not ask" and "they are open" are
		# different answers and the second is the dangerous one.
		echo "SKIP: gh not installed — cannot check whether the named issues are still open" >&2
		[ "$rc" -eq 0 ] && exit 77
		exit 1
	fi
	uniq_nums=$(printf '%s\n' $ISSUE_NUMS | sort -un)
	for n in $uniq_nums; do
		[ -n "$n" ] || continue
		if [ -n "$GH_STATE_CMD" ]; then
			state=$($GH_STATE_CMD "$n" 2>/dev/null)
		else
			state=$(gh issue view "$n" --json state --jq .state 2>/dev/null)
		fi
		if [ -z "$state" ]; then
			echo "FAIL: could not read the state of issue #$n — a cell is pinned to an issue that cannot be resolved" >&2
			rc=1
			continue
		fi
		if [ "$state" != "OPEN" ]; then
			cells=$(printf '%s' "$ISSUE_LINES" | awk -v n="$n" '$1==n {print "    " $2}')
			echo "FAIL: issue #$n is $state, but these cells are still ignored waiting for it:" >&2
			echo "$cells" >&2
			echo "  Un-ignore them, or restate the reason for why they stay ignored." >&2
			rc=1
		fi
	done
fi

echo
echo "ignored-cell census: $TOTAL #[ignore] cell(s) — $MEASUREMENTS measurement(s), $(printf '%s\n' $ISSUE_NUMS | sed '/^$/d' | wc -l) issue-linked, $(printf '%s' "$UNDECLARED" | grep -c . || true) undeclared"
if [ "$rc" -eq 0 ]; then
	echo "ignored-cell census: OK"
fi
exit $rc
