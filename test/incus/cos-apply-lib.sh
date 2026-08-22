#!/usr/bin/env bash
# Shared CLI-transcript verification helpers for the xpf CoS apply path
# (#6440).
#
# WHY THIS EXISTS
#
# `apply-cos-config.sh` drives the Junos-style CLI by piping a heredoc into
# `/usr/local/sbin/cli`:
#
#     if ! incus exec "$TARGET" -- /usr/local/sbin/cli <<EOF
#     configure
#     delete class-of-service
#     load merge /tmp/cos-iperf-sets.set
#     commit check
#     ...
#
# and gated each phase on that command's EXIT STATUS. That gate is
# structurally unable to detect a failure, because the stdin form of the CLI
# is a REPL, not a batch runner. Its read loop (cmd/cli/main.go) is:
#
#     err = c.dispatch(line)
#     if err != nil {
#         if err == errExit { break }
#         fmt.Fprintf(os.Stderr, "error: %v\n", err)   // print and CONTINUE
#     }
#
# A failed `load merge` / `commit check` / `commit` prints one `error: ...`
# line to stderr, the loop moves to the NEXT heredoc line, and `main` returns
# normally — process exit status 0. (`cli -c "<one command>"` is the opposite:
# that path DOES `os.Exit(1)` on a dispatch error. Only the piped-stdin form
# swallows.)
#
# The consequence #6440 reported: a `load merge` that failed left a candidate
# holding ONLY the script's `delete class-of-service ...` lines. Deleting is
# perfectly valid, so `commit check` passed and `commit` committed the deletes
# — wiping CoS instead of re-applying it. Neither the phase-1 nor the phase-2
# gate could fire, so the first thing that noticed anything was the phase-3
# output grep, which reported the MISLEADING "no shaper/scheduler binding"
# and exited 6. Every CoS-dependent measurement taken after such a run was
# silently taken against un-applied config.
#
# THE GATE
#
# Instead of trusting the exit status, assert the CLI's own SUCCESS MARKERS
# are present in the captured transcript. Each config verb prints a distinct
# line to stdout only on success (cmd/cli/main.go, cmd/cli/shared.go):
#
#     load merge      -> "load merge complete"
#     commit check    -> "configuration check succeeds"
#     commit          -> "commit complete" (or "commit complete: <summary>")
#     rollback N      -> "configuration rolled back"
#
# On failure the marker is NOT printed and an `error: ...` line appears
# instead. Asserting the positive marker is deliberately preferred over
# scanning for `error:`: the script's own delete list is idempotent by design
# and its `delete <path>` lines legitimately error with a path-not-found on a
# fresh post-deploy box (config.ConfigTree.DeletePath returns ErrPathNotFound;
# see pkg/config/event_options_4423_test.go). Those benign errors must not
# fail the apply, and they do not disturb the success markers.
#
# The Go-side contract these markers form is pinned by
# cmd/cli/cos_apply_markers_6440_test.go, so a reworded CLI cannot silently
# un-arm this gate.
#
# These helpers depend on nothing but bash + grep so the self-test
# (cos-apply-lib-selftest.sh, `make test-cos-apply-lib`) is hermetic.

# The CLI success markers this gate keys on. Each is matched ANCHORED to the
# start of a line, so a marker appearing inside an error/warning message body
# cannot satisfy the assertion. Keep in sync with
# cmd/cli/cos_apply_markers_6440_test.go.
# shellcheck disable=SC2034  # consumed by apply-cos-config.sh, which sources this file
COS_MARKER_LOAD_MERGE="load merge complete"
# shellcheck disable=SC2034  # consumed by apply-cos-config.sh, which sources this file
COS_MARKER_COMMIT_CHECK="configuration check succeeds"
COS_MARKER_COMMIT="commit complete"
COS_MARKER_ROLLBACK="configuration rolled back"

# cos_transcript_has_marker <transcript-file> <marker>
#
# True when <marker> appears at the START of some line of the transcript.
# Line-anchored on purpose: `commit complete` must match both the bare form
# and `commit complete: <summary>`, but must NOT match a line such as
# `error: commit failed: ... commit complete ...`.
cos_transcript_has_marker() {
	local transcript="$1" marker="$2"
	[[ -f "$transcript" ]] || return 1
	grep -q "^${marker}" "$transcript"
}

# cos_require_markers <label> <transcript-file> <marker>...
#
# Assert every supplied marker is present in the transcript. Returns 0 when
# all are found. On the first miss it reports WHICH marker was missing (that
# names the verb that actually failed, rather than blaming a downstream
# symptom) plus the CLI transcript, and returns 1.
#
# Callers turn that 1 into the phase-appropriate exit code + rollback.
cos_require_markers() {
	local label="$1" transcript="$2"
	shift 2
	local marker missing=0
	for marker in "$@"; do
		if ! cos_transcript_has_marker "$transcript" "$marker"; then
			echo "error: ${label}: the CLI never reported \"${marker}\"" >&2
			missing=1
		fi
	done
	if [[ "$missing" -ne 0 ]]; then
		echo "error: ${label}: a command inside the CLI session FAILED." >&2
		echo "  The piped-stdin CLI is a REPL: it prints 'error: ...' for a failed" >&2
		echo "  command, continues to the next line, and still exits 0 — so the" >&2
		echo "  session's exit status cannot be trusted (#6440)." >&2
		echo "---- cli transcript ----" >&2
		cat "$transcript" >&2
		echo "---- end cli transcript ----" >&2
		return 1
	fi
	return 0
}

# cos_wait_daemon_ready <target> [timeout-seconds]
#
# Block until xpfd's gRPC endpoint answers on <target>, or the timeout
# expires. Returns 0 when ready, 1 on timeout.
#
# `apply-cos-config.sh` is normally run right after `make cluster-deploy`,
# which restarts xpfd. #6440 recorded a run whose commit-check failed with
# connection-refused because the daemon's gRPC listener was not up yet —
# there was no readiness wait between deploy and the first CLI call.
#
# The probe uses `cli -c`, NOT the piped-stdin form: the `-c` path exits
# non-zero both when xpfd is unreachable (the GetStatus reachability probe)
# and when the command itself fails, so its exit status is meaningful.
cos_wait_daemon_ready() {
	local target="$1" timeout="${2:-60}"
	local waited=0
	while [[ "$waited" -lt "$timeout" ]]; do
		if incus exec "$target" -- /usr/local/sbin/cli -c "show system uptime" \
			>/dev/null 2>&1; then
			return 0
		fi
		sleep 2
		waited=$((waited + 2))
	done
	return 1
}

# cos_rollback_one <target>
#
# Run `rollback 1 | commit` on <target> and VERIFY it actually landed.
# Returns 0 only when the CLI reported BOTH "configuration rolled back" and
# "commit complete".
#
# Every rollback site in apply-cos-config.sh previously ran this as
# `... <<'EOF' || true` and then announced "live state reverted" from the
# `then` branch of an `if` on the session's exit status — which, being the
# piped-stdin REPL, is 0 whether or not the rollback worked. So the script
# could print a clean "live state reverted" over a rollback that never
# happened, leaving the cluster on the half-applied config the caller
# believed had been undone. #6440 observed exactly that reassurance.
cos_rollback_one() {
	local target="$1"
	local out
	out=$(mktemp)
	incus exec "$target" -- /usr/local/sbin/cli >"$out" 2>&1 <<'CLIEOF' || true
configure
rollback 1
commit
exit
quit
CLIEOF
	if cos_require_markers "rollback 1 | commit on $target" "$out" \
		"$COS_MARKER_ROLLBACK" "$COS_MARKER_COMMIT"; then
		echo "rollback 1 committed — live state reverted (verified)" >&2
		rm -f "$out"
		return 0
	fi
	echo "WARN: rollback commit did NOT land — MANUAL INTERVENTION REQUIRED" >&2
	rm -f "$out"
	return 1
}
