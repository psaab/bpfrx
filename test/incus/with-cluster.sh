#!/usr/bin/env bash
#
# #1875 — run a command as an exclusive "lock cell" on the shared
# loss userspace cluster.
#
#   ./test/incus/with-cluster.sh "<purpose>" -- <cmd> [args...]
#
# Examples:
#   ./test/incus/with-cluster.sh "1736 S2b closure" -- bash -c '
#       make cluster-deploy &&
#       ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0 &&
#       WG_PEER_TYPE=container ./test/incus/wg-interop.sh all'
#
# This is the ONLY process that holds /tmp/xpf-cluster.lock across
# commands (protocol header in cluster-lock.sh). Properties:
#   - Blocks until the lock is free, printing a named-holder report
#     every 30s (who, since when, what for). Set
#     XPF_CLUSTER_LOCK_TIMEOUT=<seconds> to abort loudly instead of
#     waiting forever.
#   - Reentrant: inside a valid cell (XPF_CLUSTER_LOCK_HELD marker
#     from a live ancestor holder) the command just runs — cells nest
#     and self-locking scripts (cluster-setup.sh, apply-cos-config.sh)
#     do not deadlock.
#   - The command runs with the lock fd CLOSED (9>&-): killing the
#     cell's whole process tree releases the lock immediately; no
#     orphaned child can become an invisible holder.
#   - Fail-closed split-mutex assertion: if the owner file names a
#     LIVE holder whose recorded lock dev:ino differs from ours AND
#     that holder still has the old inode open on fd 9, someone
#     deleted/recreated the lock file mid-hold — refuse to run.
#   - Exit status of the command is propagated.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-lock.sh
source "${SCRIPT_DIR}/cluster-lock.sh"

usage() {
	echo "Usage: $0 \"<purpose>\" -- <cmd> [args...]" >&2
	exit 2
}

[[ $# -ge 3 ]] || usage
PURPOSE="$1"
shift
[[ "$1" == "--" ]] || usage
shift

# Reentrant case: a live ancestor cell already holds the lock. Run the
# command directly — no second acquire, no owner write, no trap (the
# outer cell owns cleanup). `env --` pins the command to an EXTERNAL
# binary: a shell builtin like `exec` would otherwise run inside this
# wrapper shell, drop the lock early, and skip the cleanup trap (Codex
# code-r1 F1). Cells are processes by contract.
if xpf_cluster_lock_held; then
	exec env -- "$@"
fi

WAITED=0
# Timeout: digits only, forced base-10 (a leading zero like "08" must
# not become an octal arithmetic error that silently disables the
# timeout — Codex code-r1 F2), length-capped so absurd values cannot
# overflow signed arithmetic. Anything else degrades to 0 = wait
# forever, the safe direction.
TIMEOUT="${XPF_CLUSTER_LOCK_TIMEOUT:-0}"
if [[ "$TIMEOUT" =~ ^[0-9]{1,7}$ ]]; then
	TIMEOUT=$((10#$TIMEOUT))
else
	TIMEOUT=0
fi

while :; do
	# Append-only open: NEVER truncate (a concurrent holder's inode
	# must not be disturbed) and never rm (cluster-lock.sh header).
	exec 9>>"$XPF_CLUSTER_LOCK"
	chmod 0666 "$XPF_CLUSTER_LOCK" 2>/dev/null || true

	# Contend in (up to) 30s flock windows so a holder release is
	# picked up immediately, while still reporting the named holder
	# periodically. The window is capped at the remaining timeout so
	# sub-30s XPF_CLUSTER_LOCK_TIMEOUT values fire on time.
	while :; do
		WINDOW=30
		if [[ "$TIMEOUT" -gt 0 ]]; then
			REMAIN=$((TIMEOUT - WAITED))
			if [[ "$REMAIN" -le 0 ]]; then
				echo "[with-cluster] ABORT: lock not acquired within XPF_CLUSTER_LOCK_TIMEOUT=${TIMEOUT}s" >&2
				xpf_cluster_owner_report >&2
				exit 75  # EX_TEMPFAIL
			fi
			[[ "$REMAIN" -lt "$WINDOW" ]] && WINDOW=$REMAIN
		fi
		if flock -w "$WINDOW" 9; then
			break
		fi
		WAITED=$((WAITED + WINDOW))
		echo "[with-cluster $(date +%H:%M:%S)] waiting for cluster lock (${WAITED}s, purpose: ${PURPOSE})" >&2
		xpf_cluster_owner_report >&2
	done

	# Post-acquire dev:ino revalidation: if the path was unlinked or
	# replaced between our open and our flock, we locked a dead inode.
	# Close and retry on the current path.
	PATH_INO=$(stat -c %d:%i "$XPF_CLUSTER_LOCK" 2>/dev/null || true)
	FD_INO=$(stat -L -c %d:%i "/proc/$$/fd/9" 2>/dev/null || true)
	if [[ -z "$PATH_INO" || "$PATH_INO" != "$FD_INO" ]]; then
		echo "[with-cluster] lock file changed under us (path ${PATH_INO:-gone} vs fd ${FD_INO:-?}) — reacquiring" >&2
		exec 9>&-
		continue
	fi
	break
done

# Split-mutex assertion (fail-closed, the one owner-file check that
# gates execution): a LIVE recorded holder with a DIFFERENT lock
# dev:ino that it provably still holds on its fd 9 means the lock
# path was deleted/recreated while held — two "holders" would both
# believe they own the cluster. Refuse and diagnose. The fd-9 probe
# defeats pid-recycling false positives (a recycled pid won't have
# the old inode open on fd 9).
OWNER_LINE=$(cat "$XPF_CLUSTER_OWNER" 2>/dev/null || true)
if [[ -n "$OWNER_LINE" ]]; then
	read -r OPID _ _ _ OINO _ <<<"$OWNER_LINE" || true
	if [[ "${OPID:-}" =~ ^[0-9]+$ && -n "${OINO:-}" && "$OINO" != "$FD_INO" ]] \
		&& kill -0 "$OPID" 2>/dev/null; then
		HOLDER_FD_INO=$(stat -L -c %d:%i "/proc/${OPID}/fd/9" 2>/dev/null || true)
		if [[ -n "$HOLDER_FD_INO" && "$HOLDER_FD_INO" == "$OINO" ]]; then
			echo "[with-cluster] ABORT: SPLIT MUTEX — pid ${OPID} still holds lock inode ${OINO} but the path now resolves to ${FD_INO}." >&2
			echo "  Someone deleted/recreated ${XPF_CLUSTER_LOCK} while it was held (never rm the lock file)." >&2
			echo "  Wait for pid ${OPID} to finish; both runs proceeding would clobber each other." >&2
			exit 70  # EX_SOFTWARE
		fi
	fi
fi

# Acquired. Publish owner metadata atomically (tmp + mv), clean it up
# on exit. Only THIS process (the successful acquirer) installs the
# trap.
OWNER_TMP=$(mktemp "${XPF_CLUSTER_OWNER}.XXXXXX")
BRANCH=$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "?")
printf '%s %s %s %s %s %s\n' \
	"$$" "$(date -Is)" "${USER:-$(id -un)}" "$BRANCH" "$FD_INO" "$PURPOSE" \
	>"$OWNER_TMP"
chmod 0666 "$OWNER_TMP" 2>/dev/null || true
mv -f "$OWNER_TMP" "$XPF_CLUSTER_OWNER"
trap 'rm -f "$XPF_CLUSTER_OWNER" 2>/dev/null || true' EXIT

export XPF_CLUSTER_LOCK_HELD="${XPF_CLUSTER_LOCK}:$$"

echo "[with-cluster $(date +%H:%M:%S)] lock acquired (pid $$, purpose: ${PURPOSE})" >&2

# Run the cell with the lock fd closed: children never inherit fd 9,
# so killing the cell's tree releases the lock the instant this
# process dies. `env --` pins the cell to an external command — a
# builtin (`exec`, `eval`, ...) would mutate THIS wrapper instead of
# running as a child (Codex code-r1 F1).
rc=0
env -- "$@" 9>&- || rc=$?
exit "$rc"
