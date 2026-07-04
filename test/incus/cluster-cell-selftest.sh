#!/usr/bin/env bash
#
# #4020 — self-test for the destructive-smoke lock preamble
# (test/incus/cluster-cell.sh, helper xpf_enter_destructive_cluster_cell).
#
# Two halves, both runnable ANYWHERE — no incus, no cluster, no network,
# and NEVER touching the real /tmp/xpf-cluster.lock (a PRIVATE lock path
# under a temp dir is used throughout):
#
#   STATIC   — every DESTRUCTIVE HA smoke script routes through the
#              #1875 lock cell (sources cluster-cell.sh AND calls
#              xpf_enter_destructive_cluster_cell in its preamble). This
#              is the RED-on-revert guard: reverting #4020 drops the
#              wiring and this half fails, naming the unprotected script.
#              Read-only test-connectivity.sh must stay lock-free.
#
#   BEHAVIORAL — the helper actually serializes: a standalone run
#              acquires the lock and runs its body; a second concurrent
#              run QUEUES (blocks) behind the held lock instead of
#              colliding; and a run already inside a with-cluster.sh
#              cell runs lock-free (reentrant, no deadlock).
#
# Usage: ./test/incus/cluster-cell-selftest.sh   (rc 0 = all pass)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WC="${SCRIPT_DIR}/with-cluster.sh"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

waitfor() { # waitfor <seconds> <desc> <cmd...>
	local n=$(( $1 * 10 )) desc="$2"; shift 2
	while (( n-- > 0 )); do
		if "$@" 2>/dev/null; then return 0; fi
		sleep 0.1
	done
	fail "timeout waiting for: $desc"
}

# ── STATIC: every destructive smoke script routes through the lock ────
#
# These are the scripts whose Makefile targets reboot / force-stop /
# fail over / restart a node on the SHARED loss cluster. Each MUST
# source cluster-cell.sh and call the entry helper in its preamble.
DESTRUCTIVE=(
	test-failover.sh
	test-ha-crash.sh
	test-double-failover.sh
	test-stress-failover.sh
	test-chained-crash.sh
	test-active-active.sh
	test-restart-connectivity.sh
	test-private-rg.sh
)

for s in "${DESTRUCTIVE[@]}"; do
	p="${SCRIPT_DIR}/${s}"
	[[ -f "$p" ]] || fail "static: missing destructive smoke script $s"
	# The wiring must sit in the preamble (first 60 lines), BEFORE any
	# incus mutation — assert both the source and the call are present
	# and appear before the first destructive incus/systemctl op.
	head_n="$(head -n 60 "$p")"
	# Literal match of the source line — the ${...} must NOT expand.
	# shellcheck disable=SC2016
	grep -q 'source "\${_CELL_DIR}/cluster-cell.sh"' <<<"$head_n" \
		|| fail "static: $s does not source cluster-cell.sh in its preamble (#4020 lock dropped?)"
	call_line=$(grep -n 'xpf_enter_destructive_cluster_cell' "$p" | head -1 | cut -d: -f1)
	[[ -n "$call_line" ]] \
		|| fail "static: $s never calls xpf_enter_destructive_cluster_cell (#4020 lock dropped?)"
	# First line that reboots / force-stops / fails over / restarts a
	# node. The lock call must precede it so we never mutate the shared
	# cluster before acquiring the lock. Skip comment lines so a "Phase
	# 1: incus stop --force" doc line is not mistaken for a real op.
	mut_line=$(awk '
		/^[[:space:]]*#/ { next }
		/failover reset/ { next }
		/incus (stop|start|restart) |sysrq|systemctl (stop|restart)|request chassis cluster failover redundancy-group/ { print NR; exit }
	' "$p" || true)
	if [[ -n "$mut_line" ]]; then
		(( call_line < mut_line )) \
			|| fail "static: $s mutates the cluster (line $mut_line) before taking the lock (line $call_line)"
	fi
	ok "static: $s takes the #1875 lock (line $call_line) before any node mutation"
done

# Read-only connectivity test must NOT take the cluster lock (the lock
# header forbids read-only verbs from holding it — e.g. interactive ssh).
if grep -q 'cluster-cell.sh' "${SCRIPT_DIR}/test-connectivity.sh"; then
	fail "static: read-only test-connectivity.sh must not take the cluster lock"
fi
ok "static: read-only test-connectivity.sh stays lock-free"

# ── BEHAVIORAL: private lock path + fake incus, no cluster ────────────
T=$(mktemp -d /tmp/xpf-cell-selftest.XXXXXX)
trap 'rm -rf "$T"' EXIT
export XPF_CLUSTER_LOCK="$T/lock"
export XPF_CLUSTER_OWNER="$T/owner"

# Fake `incus` on PATH: succeeds so the helper's incus-admin sg branch
# is never taken (keeps the test hermetic — no group juggling, no real
# incus). The helper then exercises the pure lock-cell logic.
mkdir -p "$T/bin"
cat >"$T/bin/incus" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$T/bin/incus"
export PATH="$T/bin:$PATH"

# Fixture: a stand-in destructive script. Enters the cell, then (with
# the lock held transitively) records that it started and optionally
# lingers so a concurrent run can observe the held lock.
FIX="$T/fixture.sh"
cat >"$FIX" <<STUB
#!/usr/bin/env bash
set -euo pipefail
_CELL_DIR="${SCRIPT_DIR}"
# shellcheck source=/dev/null
source "\${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "fixture \$*" "\$0" "\$@"
echo started >"\${FIX_START}"
sleep "\${FIX_SLEEP:-0}"
STUB
chmod +x "$FIX"

# (a) standalone run acquires the lock and runs its body.
FIX_START="$T/a.start" FIX_SLEEP=0 "$FIX" || fail "(a) standalone fixture failed"
[[ -f "$T/a.start" ]] || fail "(a) fixture body did not run under the lock"
[[ ! -f "$XPF_CLUSTER_OWNER" ]] || fail "(a) owner file leaked after standalone run"
ok "standalone destructive run acquires the lock and runs its body"

# (b) a second run QUEUES behind a held lock instead of colliding.
FIX_START="$T/b.start" FIX_SLEEP=6 "$FIX" &
B_HOLDER=$!
waitfor 5 "holder fixture started" test -f "$T/b.start"
set +e
FIX_START="$T/b2.start" FIX_SLEEP=0 XPF_CLUSTER_LOCK_TIMEOUT=1 "$FIX" >"$T/b2.out" 2>&1
B2_RC=$?
set -e
[[ $B2_RC -eq 75 ]] \
	|| fail "(b) concurrent run expected to queue+timeout (75), got $B2_RC — did it collide?"
[[ ! -f "$T/b2.start" ]] || fail "(b) queued run ran its body despite a held lock (collision!)"
grep -q "fixture" "$T/b2.out" || fail "(b) waiter did not report the holding fixture cell"
wait "$B_HOLDER" || true
ok "concurrent destructive run queues behind a held lock (no collision)"

# (c) reentrant: inside a with-cluster.sh cell the fixture runs
#     lock-free (marker held) — no second acquire, no deadlock.
set +e
FIX_START="$T/c.start" FIX_SLEEP=0 timeout 20 "$WC" "outer cell" -- "$FIX" >"$T/c.out" 2>&1
C_RC=$?
set -e
[[ $C_RC -eq 0 ]] || fail "(c) reentrant fixture inside a cell failed/deadlocked (rc=$C_RC)"
[[ -f "$T/c.start" ]] || fail "(c) reentrant fixture body did not run"
ok "destructive run inside a with-cluster.sh cell runs lock-free (reentrant, no deadlock)"

echo "ALL ${PASS} CASES PASS"
