#!/usr/bin/env bash
# Self-test for test/incus/cos-apply-lib.sh (#6440).
#
# Hermetic: no incus, no cluster, no VM, no network. `incus` is mocked as a
# shell function that replays a canned CLI transcript, so the marker gate and
# the verified-rollback helper are exercised end-to-end.
#
# The load-bearing pair is "the #6440 failure transcript" vs "the benign
# transcript": BOTH carry the same path-not-found noise from this script's
# idempotent `delete` lines, and they differ ONLY in whether the CLI reported
# its success markers. A gate that keyed on `error:` lines instead of the
# markers would reject both; a gate that keyed on the session exit status
# (the pre-fix behavior) would accept both.
#
# Usage: ./test/incus/cos-apply-lib-selftest.sh   (rc 0 = all pass)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

PASS=0
FAIL=0
ok()  { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

# ── transcript fixtures ───────────────────────────────────────────────
# The exact shape apply-cos-config.sh captures. The `error: ... path not
# found` lines are the NORMAL, benign result of the script's idempotent
# delete list on a fresh post-deploy box where CoS was already wiped
# (config.ConfigTree.DeletePath -> ErrPathNotFound).
BENIGN_NOISE='error: delete: path not found: class-of-service
error: delete: path not found: firewall family inet filter bandwidth-output'

# A healthy phase-1 (commit check) session.
transcript_check_ok() {
	cat <<EOF
$BENIGN_NOISE
load merge complete
configuration check succeeds
Exiting configuration mode
EOF
}

# The #6440 failure: `load merge` failed, so the candidate held ONLY the
# deletes. That IS a valid candidate, so `commit check` still succeeded. The
# REPL printed the error and carried on; the session exited 0.
transcript_check_load_failed() {
	cat <<EOF
$BENIGN_NOISE
error: load merge: line 12: "set class-of-service ..." is not a set/delete/deactivate/activate command
configuration check succeeds
Exiting configuration mode
EOF
}

# A healthy phase-2 (commit) session.
transcript_commit_ok() {
	cat <<EOF
$BENIGN_NOISE
load merge complete
commit complete
Exiting configuration mode
EOF
}

# Phase 2 where the commit itself failed after a good load.
transcript_commit_failed() {
	cat <<EOF
load merge complete
error: commit failed: rpc error: code = Unavailable desc = connection refused
Exiting configuration mode
EOF
}

# require_on <fixture-fn> <label> <marker>...
#
# Materialize <fixture-fn>'s transcript to a temp file and run
# cos_require_markers against it. The transcript path must land in argument
# POSITION 2 (cos_require_markers <label> <transcript> <marker>...) — an
# earlier revision of this harness appended it after the markers instead,
# which made cos_require_markers stat a marker STRING as its transcript,
# fail the [[ -f ]] guard, and report every marker missing. Every "must be
# REJECTED" cell then passed for the wrong reason (a vacuous green) while
# the "must be ACCEPTED" cells failed. Keep the position explicit.
require_on() {
	local fixture="$1" label="$2"; shift 2
	local t; t=$(mktemp)
	"$fixture" > "$t"
	cos_require_markers "$label" "$t" "$@"
	local rc=$?
	rm -f "$t"
	return $rc
}

# ── cos_transcript_has_marker ─────────────────────────────────────────
t=$(mktemp); printf 'commit complete\n' > "$t"
cos_transcript_has_marker "$t" "$COS_MARKER_COMMIT" \
	&& ok "marker found on its own line" \
	|| bad "marker found on its own line"

printf 'commit complete: 3 changes\n' > "$t"
cos_transcript_has_marker "$t" "$COS_MARKER_COMMIT" \
	&& ok "marker matches the 'commit complete: <summary>' form" \
	|| bad "marker matches the 'commit complete: <summary>' form"

# Line-anchoring: the marker text appearing INSIDE an error message must not
# satisfy the assertion. Without the ^ anchor this cell passes wrongly.
printf 'error: commit failed before commit complete could be reported\n' > "$t"
cos_transcript_has_marker "$t" "$COS_MARKER_COMMIT" \
	&& bad "marker must NOT match mid-line inside an error message" \
	|| ok "marker must NOT match mid-line inside an error message"

printf 'nothing here\n' > "$t"
cos_transcript_has_marker "$t" "$COS_MARKER_COMMIT" \
	&& bad "absent marker must not be reported present" \
	|| ok "absent marker must not be reported present"

cos_transcript_has_marker "/nonexistent/transcript" "$COS_MARKER_COMMIT" \
	&& bad "a missing transcript file must not satisfy the gate" \
	|| ok "a missing transcript file must not satisfy the gate"
rm -f "$t"

# ── cos_require_markers: the load-bearing pair ────────────────────────
# Benign noise + both markers -> ACCEPT. Proves the gate does not
# false-positive on the idempotent delete list's path-not-found errors.
if require_on transcript_check_ok "phase1" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT_CHECK" 2>/dev/null; then
	ok "healthy commit-check transcript ACCEPTED despite benign delete errors"
else
	bad "healthy commit-check transcript ACCEPTED despite benign delete errors"
fi

# Same benign noise, `load merge` marker absent -> REJECT. This is the exact
# #6440 case that the old exit-status gate could not see.
if require_on transcript_check_load_failed "phase1" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT_CHECK" 2>/dev/null; then
	bad "#6440: a silently-failed 'load merge' must be REJECTED even though commit-check passed"
else
	ok "#6440: a silently-failed 'load merge' must be REJECTED even though commit-check passed"
fi

if require_on transcript_commit_ok "phase2" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT" 2>/dev/null; then
	ok "healthy commit transcript ACCEPTED"
else
	bad "healthy commit transcript ACCEPTED"
fi

if require_on transcript_commit_failed "phase2" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT" 2>/dev/null; then
	bad "a failed commit must be REJECTED"
else
	ok "a failed commit must be REJECTED"
fi

# The failure report must NAME the missing marker, so the operator learns
# which verb failed instead of chasing the downstream symptom.
report=$(require_on transcript_check_load_failed "phase1" \
	"$COS_MARKER_LOAD_MERGE" "$COS_MARKER_COMMIT_CHECK" 2>&1)
if grep -q "never reported \"load merge complete\"" <<<"$report"; then
	ok "the failure report names the missing marker (load merge)"
else
	bad "the failure report names the missing marker (load merge)"
fi
# ...and must NOT accuse the verb that actually succeeded.
if grep -q "never reported \"configuration check succeeds\"" <<<"$report"; then
	bad "the failure report must not accuse commit-check, which succeeded"
else
	ok "the failure report must not accuse commit-check, which succeeded"
fi

# ── incus mock for the rollback / readiness helpers ───────────────────
# MOCK_ROLLBACK_TRANSCRIPT selects what the mocked CLI prints for the
# rollback session; MOCK_READY_AFTER makes the readiness probe fail N times
# before succeeding. MOCK_READY_CALLS counts probes.
MOCK_ROLLBACK_TRANSCRIPT="ok"
MOCK_READY_AFTER=0
MOCK_READY_CALLS=0

incus() {
	# Only `incus exec <inst> -- /usr/local/sbin/cli ...` is used by the lib.
	if [[ "$*" == *"-c show system uptime"* ]]; then
		MOCK_READY_CALLS=$((MOCK_READY_CALLS + 1))
		[[ "$MOCK_READY_CALLS" -gt "$MOCK_READY_AFTER" ]] && return 0
		return 1
	fi
	# The rollback session: consume the heredoc on stdin, emit a transcript.
	cat >/dev/null
	case "$MOCK_ROLLBACK_TRANSCRIPT" in
	ok)
		echo "configuration rolled back"
		echo "commit complete"
		;;
	rollback_failed)
		echo "error: rollback: no previous configuration"
		;;
	commit_failed)
		echo "configuration rolled back"
		echo "error: commit failed: connection refused"
		;;
	esac
	return 0
}
# `sleep` is mocked away so the readiness timeout cell runs instantly.
sleep() { :; }

# ── cos_rollback_one ──────────────────────────────────────────────────
MOCK_ROLLBACK_TRANSCRIPT="ok"
if cos_rollback_one "fake:vm" 2>/dev/null; then
	ok "a rollback that reported BOTH markers is treated as landed"
else
	bad "a rollback that reported BOTH markers is treated as landed"
fi

# The #6440 reassurance: the pre-fix script announced "live state reverted"
# from the `then` branch of an `if` on the session exit status, which is 0
# even here. The helper must call this a FAILURE.
MOCK_ROLLBACK_TRANSCRIPT="rollback_failed"
if cos_rollback_one "fake:vm" 2>/dev/null; then
	bad "a rollback whose 'rollback' verb failed must NOT report 'live state reverted'"
else
	ok "a rollback whose 'rollback' verb failed must NOT report 'live state reverted'"
fi

MOCK_ROLLBACK_TRANSCRIPT="commit_failed"
if cos_rollback_one "fake:vm" 2>/dev/null; then
	bad "a rollback whose 'commit' verb failed must NOT report 'live state reverted'"
else
	ok "a rollback whose 'commit' verb failed must NOT report 'live state reverted'"
fi

# And the operator-facing text must only claim a revert when it was verified.
MOCK_ROLLBACK_TRANSCRIPT="rollback_failed"
msg=$(cos_rollback_one "fake:vm" 2>&1)
if grep -q "live state reverted" <<<"$msg"; then
	bad "an unverified rollback must not print 'live state reverted'"
else
	ok "an unverified rollback must not print 'live state reverted'"
fi
if grep -q "MANUAL INTERVENTION REQUIRED" <<<"$msg"; then
	ok "an unverified rollback escalates to MANUAL INTERVENTION REQUIRED"
else
	bad "an unverified rollback escalates to MANUAL INTERVENTION REQUIRED"
fi

# ── cos_wait_daemon_ready ─────────────────────────────────────────────
MOCK_READY_CALLS=0; MOCK_READY_AFTER=0
if cos_wait_daemon_ready "fake:vm" 10; then
	ok "readiness returns 0 when xpfd answers immediately"
else
	bad "readiness returns 0 when xpfd answers immediately"
fi

MOCK_READY_CALLS=0; MOCK_READY_AFTER=2
if cos_wait_daemon_ready "fake:vm" 30; then
	ok "readiness retries past a not-yet-listening daemon"
else
	bad "readiness retries past a not-yet-listening daemon"
fi

# A daemon that never comes up must TIME OUT rather than spin forever.
MOCK_READY_CALLS=0; MOCK_READY_AFTER=100000
if cos_wait_daemon_ready "fake:vm" 6; then
	bad "readiness times out when xpfd never answers"
else
	ok "readiness times out when xpfd never answers"
fi

# ── wiring: apply-cos-config.sh must actually USE the gate ────────────
# The helpers above can be perfect and the script still fail open if a phase
# forgets to call them, or calls them with the wrong marker set. These cells
# bind the call sites. They are textual on purpose: the phases run only
# against a live cluster, so this is the only hermetic way to prove the
# wiring did not regress.
APPLY="${SCRIPT_DIR}/apply-cos-config.sh"

if grep -q 'source "${_LOCK_SCRIPT_DIR}/cos-apply-lib.sh"' "$APPLY"; then
	ok "apply-cos-config.sh sources the gate library"
else
	bad "apply-cos-config.sh sources the gate library"
fi

# Phase 1 must require BOTH the load and the commit-check markers. Requiring
# only commit-check is precisely the #6440 hole: a failed load leaves a
# deletes-only candidate that checks clean.
if grep -A2 'cos_require_markers "commit check' "$APPLY" \
	| grep -q 'COS_MARKER_LOAD_MERGE.*COS_MARKER_COMMIT_CHECK'; then
	ok "phase 1 requires the load-merge AND commit-check markers"
else
	bad "phase 1 requires the load-merge AND commit-check markers"
fi

if grep -A2 'cos_require_markers "commit on' "$APPLY" \
	| grep -q 'COS_MARKER_LOAD_MERGE.*COS_MARKER_COMMIT"'; then
	ok "phase 2 requires the load-merge AND commit markers"
else
	bad "phase 2 requires the load-merge AND commit markers"
fi

# No unverified rollback heredoc may survive: every rollback must go through
# cos_rollback_one, which checks the markers before claiming a revert.
if grep -q '^rollback 1$' "$APPLY"; then
	bad "no raw 'rollback 1' heredoc may remain in apply-cos-config.sh"
else
	ok "no raw 'rollback 1' heredoc may remain in apply-cos-config.sh"
fi

if grep -q 'live state reverted' "$APPLY"; then
	bad "apply-cos-config.sh must not claim 'live state reverted' itself (cos_rollback_one owns that, verified)"
else
	ok "apply-cos-config.sh must not claim 'live state reverted' itself (cos_rollback_one owns that, verified)"
fi

# The `cli -c` readback exit status must no longer be discarded.
if grep -q 'show class-of-service interface" \\$' "$APPLY" \
	&& grep -A1 'show class-of-service interface"' "$APPLY" | grep -q '|| true'; then
	bad "the 'show class-of-service interface' readback must not discard its exit status"
else
	ok "the 'show class-of-service interface' readback must not discard its exit status"
fi

if grep -q 'cos_wait_daemon_ready "\$TARGET"' "$APPLY"; then
	ok "apply-cos-config.sh waits for xpfd readiness before the first commit"
else
	bad "apply-cos-config.sh waits for xpfd readiness before the first commit"
fi

echo
echo "cos-apply-lib-selftest: ${PASS} passed, ${FAIL} failed"
[[ "$FAIL" -eq 0 ]]
