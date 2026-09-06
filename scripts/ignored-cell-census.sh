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
# #9052 item 2: test/incus/cold-path-flooder is a THIRD Rust crate, outside
# both dataplane workspaces, and it carried a bare `#[ignore]` that this census
# could not see BY CONSTRUCTION — the scan list named only the two dataplane
# crates, so the census reported a clean board over a population it had never
# looked at. Widened here rather than left to the next crate to rediscover.
SCAN_DIRS=${IGN_CENSUS_DIRS:-"userspace-dp userspace-xdp test/incus/cold-path-flooder"}
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

# THE scan expression, in three named pieces so the control below exercises the
# SAME regex and the SAME filter the real sweep uses rather than copies of them.
#
#   IGNORE_ATTR_RE  matches the attribute in either spelling (`#[ignore]`,
#                   `#[ignore = "..."]`) while \b keeps `#[ignored_x]` out.
#   drop_comment_lines  reads `file:line:content` and drops lines whose CONTENT
#                   starts with `//` -- so `//`, `///` and `//!` prose that
#                   merely MENTIONS the attribute is not counted as a cell
#                   (#8980). An attribute in code position survives.
IGNORE_ATTR_RE='#\[ignore\b'

drop_comment_lines() {
	grep -vE '^[^:]*:[0-9]+:[[:space:]]*//'
}

# scan_ignores [paths...]
#   with paths: walk them. with NO args: filter stdin, which is how the control
#   below drives it. Both arms feed ONE `| drop_comment_lines`, so the control
#   exercises the real composition -- dropping the filter cannot be a mutation
#   the control survives, which it would be if the control called the pieces.
scan_ignores() {
	if [ "$#" -eq 0 ]; then
		grep -E "$IGNORE_ATTR_RE"
	else
		# -H is load-bearing: with a SINGLE file argument grep omits the
		# filename and emits `line:content`, so a filter (or the
		# `cut -d: -f1,2` below) written for `file:line:content` silently
		# reads the wrong fields.
		grep -rHnE --include='*.rs' "$IGNORE_ATTR_RE" "$@" 2>/dev/null
	fi | drop_comment_lines
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

# ── control: the SCAN PATTERN, in both directions (#8980) ────────────
#
# The classifier control above bounds `classify`. Nothing bounded the scan
# expression, and the census already had one control for it -- the ZERO-hits
# check further down. That control is real, but it is blind BY CONSTRUCTION to
# half the failure space: a non-zero-hits check detects a pattern that is too
# TIGHT and can never detect one that is too LOOSE. #8980 was the loose kind.
# The pattern matched `#[ignore` anywhere, including inside a doc comment, so
# prose reading "UN-`#[ignore]`d by the change that satisfies it" -- written by
# a change that REMOVED two ignores and documented doing so -- counted as two
# undeclared cells. The guard fired on the CORRECT behaviour, and the cheapest
# way to green was to delete the explanation.
#
# The probes are fed as text through the same regex and the same filter, so
# this needs no temp files and no tools beyond grep: checks (1) and (2) are
# documented as hermetic and must keep running wherever a plain `sh` does.
scan_probe() {
	printf '%s\n' "$@" | scan_ignores | grep -c . || true
}
# LOOSE bound: every one of these is PROSE or a different attribute, so a
# correct pattern scores ZERO.
ctl_loose=$(scan_probe \
	'src/a.rs:1:/// UN-`#[ignore]`d by the change that satisfies it.' \
	'src/a.rs:2:// #[ignore] commented out while debugging.' \
	'src/a.rs:3://! module doc mentioning #[ignore = "MEASUREMENT: x"].' \
	'src/a.rs:4:	/// indented doc comment mentioning #[ignore].' \
	'src/a.rs:5:#[ignored_by_some_other_tool]')
# TIGHT bound: real attributes, bare and with a reason, at column zero, tab-
# indented and space-indented. Ranking prose out must not rank these out too --
# a pattern that scores 0 here would make the census silently measure nothing.
# The last probe carries a URL on purpose: the comment filter must key on
# comment POSITION, not on the presence of "//" anywhere in the line. Without
# it, a filter of `grep -v '//'` passes this control while silently dropping
# every cell whose reason cites a link.
ctl_tight=$(scan_probe \
	'src/b.rs:1:#[ignore]' \
	'src/b.rs:2:	#[ignore = "MEASUREMENT: indented, carries a reason"]' \
	'src/b.rs:3:    #[ignore = "#7209: reds until the mutex is split"]' \
	'src/b.rs:4:#[ignore = "MEASUREMENT: baseline at https://ci/run/7, not an assertion"]')
scan_ctl_fail=""
[ "$ctl_loose" -eq 0 ] ||
	scan_ctl_fail="$scan_ctl_fail too-loose(counted $ctl_loose of 5 non-cells)"
[ "$ctl_tight" -eq 4 ] ||
	scan_ctl_fail="$scan_ctl_fail too-tight(found $ctl_tight of 4 real cells)"
if [ -n "$scan_ctl_fail" ]; then
	echo "FAIL: scan-pattern control —$scan_ctl_fail" >&2
	echo "  The sweep below would be measuring the wrong lines, so it was not run." >&2
	exit 1
fi
echo "  PASS: scan-pattern control — 0 of 5 non-cells, 4 of 4 real cells"

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
HITS=$(scan_ignores $SCAN_LIST)

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
