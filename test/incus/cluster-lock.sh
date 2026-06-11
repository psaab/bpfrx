# shellcheck shell=bash
#
# #1875 — shared-cluster lock helpers (sourced, never executed).
#
# The loss userspace cluster (loss:xpf-userspace-fw0/fw1) is shared by
# multiple cooperating agents on this dev box. Mutual exclusion is the
# advisory flock on /tmp/xpf-cluster.lock; ownership *visibility* is
# the metadata in /tmp/xpf-cluster.owner. Protocol (converged plan,
# docs/pr/1875-cluster-ownership/plan.md):
#
#   - test/incus/with-cluster.sh is the ONLY long-lived, self-locking,
#     marker-exporting holder. It exports
#         XPF_CLUSTER_LOCK_HELD="<lockpath>:<holderpid>"
#     while a lock cell is active.
#   - Scripts that self-lock (cluster-setup.sh mutating verbs,
#     apply-cos-config.sh) re-exec through with-cluster.sh when the
#     marker is absent and run lock-free when it is valid.
#   - Standalone per-command `flock /tmp/xpf-cluster.lock <cmd>`
#     holders (wg-interop.sh inc(), ad-hoc one-liners around commands
#     that do NOT self-lock) remain valid and never set the marker.
#   - NEVER `rm` the lock or owner files: flock binds the inode, so
#     deleting the path silently splits the mutex. Recovery from a
#     stuck holder is `kill <holder-pid>` (the kernel releases the
#     lock when its fd closes), never `rm`.
#
# Everything here must be safe under `set -euo pipefail` in consumers:
# no unguarded reads, no unguarded kill -0, no traps, no global state
# beyond the two XPF_CLUSTER_* path variables.

XPF_CLUSTER_LOCK="${XPF_CLUSTER_LOCK:-/tmp/xpf-cluster.lock}"
XPF_CLUSTER_OWNER="${XPF_CLUSTER_OWNER:-/tmp/xpf-cluster.owner}"

# True (0) iff XPF_CLUSTER_LOCK_HELD names THIS lock path and a holder
# pid that is alive AND an ancestor of the current process. Any parse
# or validation failure returns 1: the caller then waits for the lock,
# which is always safe — the failure direction is never "skip the
# lock". The ancestry walk defeats the stale-marker leak (a cell's
# backgrounded daemon that outlives the cell inherits the env but is
# no longer a descendant of a live holder).
xpf_cluster_lock_held() {
	local marker="${XPF_CLUSTER_LOCK_HELD:-}"
	[[ -n "$marker" ]] || return 1
	local mpath="${marker%:*}" mpid="${marker##*:}"
	[[ "$mpath" == "$XPF_CLUSTER_LOCK" ]] || return 1
	[[ "$mpid" =~ ^[0-9]+$ ]] || return 1
	kill -0 "$mpid" 2>/dev/null || return 1
	# Ancestry: walk PPid from $$ up to init.
	local cur=$$ ppid
	while [[ "$cur" -gt 1 ]]; do
		if [[ "$cur" -eq "$mpid" ]]; then
			return 0
		fi
		ppid=$(awk '/^PPid:/ {print $2}' "/proc/${cur}/status" 2>/dev/null || true)
		[[ "$ppid" =~ ^[0-9]+$ ]] || return 1
		cur="$ppid"
	done
	return 1
}

# Print a one-line-per-fact ownership report to stdout. Diagnostics
# only — callers must not gate execution on this output (the single
# fail-closed exception lives in with-cluster.sh's split-mutex
# assertion, which re-derives state itself). Tolerates absent, empty,
# corrupt, and stale owner files.
xpf_cluster_owner_report() {
	local lock_ino
	lock_ino=$(stat -c %d:%i "$XPF_CLUSTER_LOCK" 2>/dev/null || echo "?")
	echo "cluster lock: ${XPF_CLUSTER_LOCK} (dev:ino ${lock_ino})"
	local owner
	owner=$(cat "$XPF_CLUSTER_OWNER" 2>/dev/null || true)
	if [[ -z "$owner" ]]; then
		echo "  no owner metadata (raw-flock holder, or holder predates the owner protocol)"
		fuser -v "$XPF_CLUSTER_LOCK" 2>&1 | sed 's/^/  fuser: /' || true
		return 0
	fi
	local opid otime ouser obranch oino opurpose
	read -r opid otime ouser obranch oino opurpose <<<"$owner" || true
	echo "  held by pid ${opid:-?} (${ouser:-?}) since ${otime:-?}"
	echo "  branch: ${obranch:-?}  lock dev:ino at acquire: ${oino:-?}"
	echo "  purpose: ${opurpose:-?}"
	if [[ "${opid:-}" =~ ^[0-9]+$ ]] && kill -0 "$opid" 2>/dev/null; then
		echo "  holder is ALIVE — wait for it or coordinate; NEVER kill another agent's holder, NEVER rm the lock file"
	else
		echo "  holder pid is DEAD — stale metadata (holder was SIGKILLed?); the flock itself is released on fd close."
		echo "  if the lock still appears held, a child inherited the fd; diagnose with:"
		fuser -v "$XPF_CLUSTER_LOCK" 2>&1 | sed 's/^/  fuser: /' || true
	fi
}
