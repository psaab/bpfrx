#!/usr/bin/env bash
#
# #1875 — dry-run contention matrix for the shared-cluster lock cell
# (plan §9.2). Exercises with-cluster.sh + cluster-lock.sh against a
# PRIVATE lock path under /tmp — never touches the real
# /tmp/xpf-cluster.lock, no cluster access, safe to run anywhere.
#
#   ./test/incus/with-cluster-selftest.sh
#
# Exits 0 with "ALL n CASES PASS" or non-zero naming the failed case.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WC="${SCRIPT_DIR}/with-cluster.sh"

T=$(mktemp -d /tmp/xpf-lock-selftest.XXXXXX)
trap 'rm -rf "$T"' EXIT
export XPF_CLUSTER_LOCK="$T/lock"
export XPF_CLUSTER_OWNER="$T/owner"

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Wait (bounded) for a condition.
waitfor() { # waitfor <seconds> <desc> <cmd...>
	local n=$(( $1 * 10 )) desc="$2"; shift 2
	while (( n-- > 0 )); do
		if "$@" 2>/dev/null; then return 0; fi
		sleep 0.1
	done
	fail "timeout waiting for: $desc"
}

# ── (a) holder blocks a second cell; waiter prints the named-holder report
"$WC" "case-a holder" -- bash -c 'echo started >"'"$T"'/a.start"; sleep 6' &
A_PID=$!
waitfor 5 "cell A started" test -f "$T/a.start"
set +e
XPF_CLUSTER_LOCK_TIMEOUT=1 "$WC" "case-a waiter" -- true >"$T/a.out" 2>&1
A_RC=$?
set -e
[[ $A_RC -eq 75 ]] || fail "(a) waiter expected timeout exit 75, got $A_RC"
grep -q "case-a holder" "$T/a.out" || fail "(a) waiter report missing holder purpose"
grep -q "held by pid" "$T/a.out" || fail "(a) waiter report missing holder pid"
ok "waiter blocks and reports holder pid+purpose, timeout honors XPF_CLUSTER_LOCK_TIMEOUT"
wait "$A_PID" || true

# ── (b) kill -9 of the whole cell tree releases the lock immediately
"$WC" "case-b victim" -- bash -c 'echo started >"'"$T"'/b.start"; sleep 60' &
B_PID=$!
waitfor 5 "cell B started" test -f "$T/b.start"
# Kill the wrapper and every descendant (children run with fd 9 closed,
# the wrapper holds the only lock fd).
pkill -9 -P "$B_PID" 2>/dev/null || true
kill -9 "$B_PID" 2>/dev/null || true
wait "$B_PID" 2>/dev/null || true
XPF_CLUSTER_LOCK_TIMEOUT=35 "$WC" "case-b reclaim" -- true \
	|| fail "(b) lock not reclaimable after kill -9 of holder tree"
ok "kill -9 of cell tree releases the lock (no orphan holder)"

# ── (c) nested cell is reentrant; outer owner metadata survives the
#        inner cell's exit (acquired-only trap rule)
"$WC" "case-c outer" -- bash -c '
	"'"$WC"'" "case-c inner" -- true || exit 40
	[ -f "'"$T"'/owner" ] || exit 41          # inner exit must NOT remove owner
	grep -q "case-c outer" "'"$T"'/owner" || exit 42
' || fail "(c) nested reentrancy / owner-preservation failed (rc=$?)"
[[ ! -f "$T/owner" ]] || fail "(c) outer cell did not clean owner on exit"
ok "nested cell runs lock-free; inner exit preserves outer owner metadata"

# ── (d) forged/stale markers are rejected (acquire proceeds normally)
# d1: live but non-ancestor pid
sleep 30 & NONANC=$!
XPF_CLUSTER_LOCK_HELD="$XPF_CLUSTER_LOCK:$NONANC" "$WC" "case-d1" -- true \
	|| fail "(d1) live non-ancestor marker did not degrade to acquire"
kill "$NONANC" 2>/dev/null || true
# d2: dead pid (spawn+reap a short-lived sleep)
sleep 0.01 & DEAD=$!; wait "$DEAD" || true
XPF_CLUSTER_LOCK_HELD="$XPF_CLUSTER_LOCK:$DEAD" "$WC" "case-d2" -- true \
	|| fail "(d2) dead-pid marker did not degrade to acquire"
# d3: mismatched lock path with a real ancestor pid ($$ IS our ancestor)
XPF_CLUSTER_LOCK_HELD="/tmp/some-other.lock:$$" "$WC" "case-d3" -- true \
	|| fail "(d3) wrong-path marker did not degrade to acquire"
# d4: garbage marker
XPF_CLUSTER_LOCK_HELD="garbage" "$WC" "case-d4" -- true \
	|| fail "(d4) garbage marker did not degrade to acquire"
ok "forged/stale/wrong-path/garbage markers all rejected; acquire proceeds"

# ── (e) stale + corrupt owner files never crash or block an acquire
echo "999999999 2020-01-01T00:00:00 nobody dead-branch 1:1 stale" >"$XPF_CLUSTER_OWNER"
"$WC" "case-e stale" -- true || fail "(e) stale owner file broke acquire"
printf '\0\0garbage\n' >"$XPF_CLUSTER_OWNER"
"$WC" "case-e corrupt" -- true || fail "(e) corrupt owner file broke acquire"
: >"$XPF_CLUSTER_OWNER"
"$WC" "case-e empty" -- true || fail "(e) empty owner file broke acquire"
ok "stale/corrupt/empty owner files tolerated under set -euo pipefail"

# ── (f) exit-status propagation + owner cleanup on failure
set +e
"$WC" "case-f" -- bash -c 'exit 3'
F_RC=$?
set -e
[[ $F_RC -eq 3 ]] || fail "(f) expected exit 3, got $F_RC"
[[ ! -f "$XPF_CLUSTER_OWNER" ]] || fail "(f) owner file leaked after failing cell"
ok "cell exit status propagates (3) and owner file is cleaned"

# ── (g) split-mutex: rm the lock while held → fail-closed abort naming inodes
"$WC" "case-g holder" -- bash -c 'echo started >"'"$T"'/g.start"; sleep 8' &
G_PID=$!
waitfor 5 "cell G started" test -f "$T/g.start"
OLD_INO=$(stat -c %d:%i "$XPF_CLUSTER_LOCK")
rm -f "$XPF_CLUSTER_LOCK"        # the documented NEVER-do — simulate it
set +e
"$WC" "case-g intruder" -- true >"$T/g.out" 2>&1
G_RC=$?
set -e
[[ $G_RC -eq 70 ]] || fail "(g) expected split-mutex abort 70, got $G_RC (out: $(cat "$T/g.out"))"
grep -q "SPLIT MUTEX" "$T/g.out" || fail "(g) abort missing SPLIT MUTEX diagnosis"
grep -q "$OLD_INO" "$T/g.out" || fail "(g) abort does not name the held inode"
wait "$G_PID" || true
# After the real holder exits, acquire on the new inode must succeed
# (dead recorded pid → stale metadata path).
"$WC" "case-g reclaim" -- true || fail "(g) post-holder reclaim failed"
ok "rm-while-held fails closed with SPLIT MUTEX diagnosis; reclaim works after holder exits"

# ── (h) marker survives an env-preserving re-exec boundary (sg-shaped:
#        rebuilt command string, env vars forwarded explicitly)
# shellcheck disable=SC2016  # single quotes deliberate: expansion happens inside the cell
"$WC" "case-h outer" -- bash -c '
	local_env="XPF_CLUSTER_LOCK=$(printf %q "$XPF_CLUSTER_LOCK") XPF_CLUSTER_OWNER=$(printf %q "$XPF_CLUSTER_OWNER") XPF_CLUSTER_LOCK_HELD=$(printf %q "$XPF_CLUSTER_LOCK_HELD")"
	bash -c "${local_env} \"'"$WC"'\" case-h-inner -- true"
' || fail "(h) marker did not survive the rebuilt-command-string boundary"
ok "marker survives an sg-shaped rebuilt-command re-exec boundary"

echo "ALL ${PASS} CASES PASS"
