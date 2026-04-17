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
# The config file starts with `delete` lines so it can be reapplied
# idempotently to a VM that already has a previous CoS config loaded.
# On a fresh post-deploy apply those paths do not exist, so load merge
# would abort on the first `delete`. Running the deletes in a separate
# best-effort session sidesteps that, while the merge/commit session
# stays strict so validation failures are not masked.
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

# Strip `delete` and blank/comment lines out of the merge input so the
# strict session (below) cannot abort on a missing path.
SETS_TMP="$(mktemp)"
trap "rm -f '$SETS_TMP'" EXIT
grep -E '^set ' "$CONFIG_FILE" > "$SETS_TMP"

incus file push --mode 0644 "$SETS_TMP" "${TARGET}/${REMOTE_SETS}" >/dev/null

# ---- Phase 1: best-effort deletes ----
# These target paths that may or may not exist depending on whether this
# is a fresh post-deploy apply or a re-apply. `|| true` is scoped here
# only — we do NOT tolerate a bad merge/commit in phase 2.
incus exec "$TARGET" -- /usr/local/sbin/cli <<EOF || true
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
delete firewall family inet6 filter bandwidth-output
delete interfaces reth0 unit 80 family inet6 filter output
commit
exit
quit
EOF

# ---- Phase 2: strict merge + commit ----
# A bad load merge, a syntax drift in the fixture, or a failed commit
# must fail the script. `set -e` is in effect; no `|| true` here.
incus exec "$TARGET" -- /usr/local/sbin/cli <<EOF
configure
load merge ${REMOTE_SETS}
commit
exit
quit
EOF

# ---- Phase 3: verify ----
incus exec "$TARGET" -- /usr/local/sbin/cli -c "show class-of-service interface"
