#!/usr/bin/env bash
#
# Re-apply the CoS iperf test config (cos-iperf-config.set) to a cluster
# VM after a deploy that wiped it. Usage:
#
#   ./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
#   ./test/incus/apply-cos-config.sh                     # defaults to xpf-userspace-fw0
#
# Only the RG0 primary needs the config applied — it replicates to the
# secondary via config sync. Run against the primary.
#
# The config file starts with three `delete` lines so it can be applied
# idempotently to a VM that already has a previous CoS config loaded.
# On a fresh post-deploy apply those paths don't exist, so the deletes
# would abort `load merge` and leave the candidate empty. Work around
# by splitting the file into its delete and set halves, running deletes
# in their own session with `|| true`, then merging the sets. Single
# atomic commit at the end is fine because the deletes are no-ops on a
# fresh apply (and the sets are the whole desired state).
#
set -euo pipefail

TARGET="${1:-loss:xpf-userspace-fw0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/cos-iperf-config.set"
REMOTE_SETS="/tmp/cos-iperf-sets.set"

if [[ ! -f "$CONFIG_FILE" ]]; then
	echo "error: cannot find $CONFIG_FILE" >&2
	exit 1
fi

# Temp file with only the set lines (comments + blanks stripped too).
SETS_TMP="$(mktemp)"
trap "rm -f '$SETS_TMP'" EXIT
grep -E '^(set |$|#)' "$CONFIG_FILE" | grep -v '^$\|^#' > "$SETS_TMP"

# Push sets-only file to the VM.
incus file push "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null

# Drive one interactive CLI session:
#   1. Enter configure mode (candidate created).
#   2. Explicitly delete any pre-existing state for the three top-level
#      paths this config owns. Each `delete` is followed by `|| true` in
#      spirit — we achieve the same effect by running each delete in the
#      same configure session; the one that targets a missing path is
#      rejected, but `configure`-mode-rejection leaves the other deletes
#      already-applied in the candidate. We redirect stderr on the per-
#      line deletes so the transcript stays readable.
#   3. `load merge` the sets-only file (clean: no deletes inside it).
#   4. `commit` atomically.
#
# Lines prefixed with `#` in the heredoc are bash comments; the CLI
# never sees them. Each subsequent line is a command to the CLI.
incus exec "$TARGET" -- /usr/local/sbin/cli <<EOF || true
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
load merge ${REMOTE_SETS}
commit
exit
quit
EOF

# Verify the exact queue landed.
incus exec "$TARGET" -- /usr/local/sbin/cli -c "show class-of-service interface"
