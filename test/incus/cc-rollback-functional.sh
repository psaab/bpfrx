#!/usr/bin/env bash
# #1922 Item 1a live functional gate: a SERVICE-MODE (gRPC) commit
# confirmed that is NOT confirmed must auto-revert the running config AND
# re-apply it to the dataplane. We prove the dataplane half by making the
# confirmed change BLOCK lan->wan forwarding (delete the allow-all policy;
# default-policy is deny-all), then asserting forwarding is restored AFTER
# the timeout rollback. A store-only revert would leave the dataplane
# blocking, which is exactly the #1922 bug.
#
# Runs against loss:xpf-userspace-fw0. Invoke inside the cluster lock cell.
set -uo pipefail

NODE="${NODE:-loss:xpf-userspace-fw0}"
HOST="${HOST:-loss:cluster-userspace-host}"   # lan-side container, 10.0.61.102
TARGET="${TARGET:-172.16.80.200}"        # wan-side ping target
SG="sg incus-admin -c"

run_cli() { $SG "incus exec $NODE -- bash -lc 'cli'" 2>&1; }
host_ping() { $SG "incus exec $HOST -- ping -c2 -W2 $TARGET" >/dev/null 2>&1; }
policy_present() {
	printf 'show configuration security policies from-zone lan to-zone wan\n' | run_cli | grep -q 'policy allow-all'
}

echo "=== #1922 Item 1a commit-confirmed timeout rollback functional gate ==="
echo "node=$NODE host=$HOST target=$TARGET"

echo "--- baseline ---"
if policy_present; then echo "baseline policy allow-all: PRESENT"; else echo "baseline policy allow-all: MISSING (precondition)"; exit 3; fi
if host_ping; then echo "baseline forwarding lan->wan: OK"; else echo "baseline forwarding lan->wan: FAIL (precondition)"; exit 3; fi

echo "--- service-mode: delete allow-all, commit confirmed 1 (NOT confirming) ---"
printf 'configure\ndelete security policies from-zone lan to-zone wan policy allow-all\nshow | compare\ncommit confirmed 1\nexit\n' | run_cli | tail -12

sleep 5
echo "--- mid-window ---"
if policy_present; then MID_POL=PRESENT; else MID_POL=GONE; fi
echo "mid policy allow-all: $MID_POL"
if host_ping; then MID_FWD=OK; else MID_FWD=BLOCKED; fi
echo "mid forwarding lan->wan: $MID_FWD"

echo "--- waiting for 1-min commit-confirmed timeout (no confirm) ---"
sleep 80

echo "--- post-timeout ---"
if policy_present; then POST_POL=PRESENT; else POST_POL=GONE; fi
echo "post policy allow-all: $POST_POL"
POST_FWD=BLOCKED
for i in 1 2 3 4 5 6 7 8; do
	if host_ping; then POST_FWD=OK; break; fi
	sleep 3
done
echo "post forwarding lan->wan: $POST_FWD"

echo "=== VERDICT ==="
fail=0
[ "$MID_FWD" = "BLOCKED" ] && echo "PASS: change applied mid-window (forwarding blocked)" || { echo "FAIL: change did not apply mid-window"; fail=1; }
[ "$POST_POL" = "PRESENT" ] && echo "PASS: store reverted (allow-all policy back)" || { echo "FAIL: store NOT reverted"; fail=1; }
[ "$POST_FWD" = "OK" ] && echo "PASS: dataplane re-applied (forwarding restored)" || { echo "FAIL: forwarding still blocked (dataplane NOT re-applied = the #1922 bug)"; fail=1; }
exit $fail
