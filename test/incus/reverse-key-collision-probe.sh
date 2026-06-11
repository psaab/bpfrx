#!/usr/bin/env bash
# #1760 W2: live-fire validation of the NAT reverse-key collision watch.
#
# Forces a REAL reverse-key (K) collision through portless interface-mode
# SNAT on the loss userspace cluster and asserts the watch fires:
#   - per-worker counter xpf_userspace_worker_session_nat_reverse_key_
#     collisions_total and/or the W3' shared-map counter
#     xpf_userspace_session_nat_reverse_key_shared_displacements_total
#     go nonzero on the active node,
#   - the W1 journald warn ("xpf-dp: NAT reverse-key collision detected")
#     appears in the xpfd journal.
#
# Construction (plan docs/research/1760-reverse-key-v2/plan.md, W2):
# two source IPs on the LAN host, each binding the SAME local port toward
# the same external dst:port. Interface-mode SNAT preserves the source
# port, so both flows derive the identical reply tuple K — the genuine
# #1758/#1760 1:N collision. A single source IP can never reproduce this
# (kernel 4-tuple ephemeral-port uniqueness).
#
# Variants:
#   warm (default) — flow 1 is established and its reverse path proven
#       before flow 2 starts (counter must fire via the normal install /
#       replica-fanout path).
#   cold — the firewall's egress neighbor entry for the target is flushed
#       first and both flows start back-to-back, exercising the
#       MissingNeighborSeed path where ONLY the W3' shared-map counter can
#       see the collision (per-worker counter is structurally blind:
#       seeds are not replicated).
#
# DELIBERATELY NOT PART OF SMOKE: this test corrupts the two probe flows
# by design (mis-delivered or dropped replies are the expected observable
# of the underlying bug). Rerunnable; probe flows time out naturally.
#
# Usage:
#   ./test/incus/reverse-key-collision-probe.sh [warm|cold]
#
# Run under the shared-cluster flock per project convention:
#   flock /tmp/xpf-cluster.lock sg incus-admin -c \
#     "./test/incus/reverse-key-collision-probe.sh warm"
set -euo pipefail

VARIANT="${1:-warm}"
REMOTE="${INCUS_REMOTE:-loss}"
FW0="${VM0:-xpf-userspace-fw0}"
FW1="${VM1:-xpf-userspace-fw1}"
LAN_HOST="${LAN_HOST:-cluster-userspace-host}"
# Second (probe-only) LAN address added to the LAN host for the duration
# of the run. Outside the cluster's DHCP/static range.
PROBE_IP2="${PROBE_IP2:-10.0.61.177}"
# Target on the WAN VLAN-80 path (the AF_XDP fast path). Any listening
# TCP port works; the iperf3 control port is always listening during
# cluster operation. Override TARGET/TPORT for other listeners.
TARGET="${TARGET:-172.16.80.200}"
TPORT="${TPORT:-5201}"
SRC_PORT="${SRC_PORT:-46161}"

inc() { incus exec "$REMOTE:$1" -- bash -lc "$2"; }

metric_sum() {
    # $1 = node, $2 = metric prefix (summed across labels)
    inc "$1" "curl -s localhost:8080/metrics | awk '/^$2/ {s+=\$NF} END {print s+0}'"
}

active_node() {
    # The node whose RG1 holds the LAN VIP is the data-path active node.
    for n in "$FW0" "$FW1"; do
        if inc "$n" "ip -4 addr show" | grep -q "10\\.0\\.61\\.1/"; then
            echo "$n"
            return
        fi
    done
    echo "ERROR: no node owns the LAN VIP" >&2
    exit 1
}

echo "== #1760 W2 reverse-key collision probe (variant: $VARIANT) =="
ACTIVE="$(active_node)"
echo "active node: $ACTIVE"

echo "-- preflight 1: portless interface-mode SNAT on the traversal path"
if ! inc "$ACTIVE" "cli -c 'show configuration security nat source' 2>/dev/null" \
        | grep -q "interface;"; then
    echo "FAIL: active config does not use interface-mode source NAT —"
    echo "      the collision construction requires the portless mode."
    exit 1
fi

echo "-- preflight 2: probe address + baseline counters"
inc "$LAN_HOST" "ip addr add $PROBE_IP2/24 dev eth1 2>/dev/null || true"
cleanup() {
    inc "$LAN_HOST" "ip addr del $PROBE_IP2/24 dev eth1 2>/dev/null || true"
}
trap cleanup EXIT

BASE_LOCAL="$(metric_sum "$ACTIVE" "xpf_userspace_worker_session_nat_reverse_key_collisions_total")"
BASE_SHARED="$(metric_sum "$ACTIVE" "xpf_userspace_session_nat_reverse_key_shared_displacements_total")"
JOURNAL_T0="$(inc "$ACTIVE" "date '+%Y-%m-%d %H:%M:%S'")"
echo "baseline: local=$BASE_LOCAL shared=$BASE_SHARED"

# Python probe: connect from (src_ip, SRC_PORT) to TARGET:TPORT with
# SO_REUSEADDR, hold the socket open, report success/failure.
PROBE_PY='
import socket, sys, time
src_ip, src_port, dst_ip, dst_port, hold = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(5)
s.bind((src_ip, src_port))
try:
    s.connect((dst_ip, dst_port))
    print(f"CONNECTED {src_ip}:{src_port}")
    time.sleep(hold)
except Exception as e:
    print(f"CONNECT-RESULT {src_ip}:{src_port}: {e}")
finally:
    s.close()
'

PROBE_IP1="$(inc "$LAN_HOST" "ip -4 -o addr show dev eth1 scope global" \
    | awk '{print $4}' | cut -d/ -f1 | grep -v "^${PROBE_IP2}\$" | head -1)"
echo "probe source IPs: $PROBE_IP1 + $PROBE_IP2 (src port $SRC_PORT)"

if [ "$VARIANT" = "cold" ]; then
    echo "-- cold preflight: prove target reachability (ephemeral source port,"
    echo "   does not occupy the colliding K) before disturbing neighbor state"
    if ! inc "$LAN_HOST" "timeout 5 bash -c 'exec 3<>/dev/tcp/$TARGET/$TPORT'"; then
        echo "FAIL(cold preflight): $TARGET:$TPORT unreachable BEFORE the cold"
        echo "  construction — a later non-firing counter would be a path/"
        echo "  listener failure, not a watch defect. Fix the path first."
        exit 1
    fi
    echo "-- cold variant: flushing egress neighbor state on $ACTIVE"
    inc "$ACTIVE" "ip neigh flush dev \$(ip -4 route get $TARGET | awk '/dev/ {for(i=1;i<=NF;i++) if(\$i==\"dev\") print \$(i+1)}' | head -1) 2>/dev/null || true"
    echo "-- starting BOTH flows back-to-back (seed path)"
    inc "$LAN_HOST" "python3 -c '$PROBE_PY' $PROBE_IP1 $SRC_PORT $TARGET $TPORT 8 &
                     python3 -c '$PROBE_PY' $PROBE_IP2 $SRC_PORT $TARGET $TPORT 8 &
                     wait" || true
else
    echo "-- warm variant: establish + prove flow 1 reverse path first"
    inc "$LAN_HOST" "python3 - <<'PYEOF'
import socket, subprocess, sys, time
src1, src2, sp = \"$PROBE_IP1\", \"$PROBE_IP2\", $SRC_PORT
dst, dp = \"$TARGET\", $TPORT
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s1.settimeout(5)
s1.bind((src1, sp))
s1.connect((dst, dp))  # completing the handshake proves the reverse path
print(f\"flow1 CONNECTED {src1}:{sp} -> {dst}:{dp} (reverse path proven)\")
time.sleep(1)
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s2.settimeout(5)
s2.bind((src2, sp))
try:
    s2.connect((dst, dp))
    print(f\"flow2 CONNECTED {src2}:{sp} (collision admitted — observe corruption)\")
    time.sleep(4)
except Exception as e:
    print(f\"flow2 RESULT {src2}:{sp}: {e}\")
s1.close(); s2.close()
PYEOF" || true
fi

echo "-- settling (counter publish cadence is ~1s)"
sleep 5

POST_LOCAL="$(metric_sum "$ACTIVE" "xpf_userspace_worker_session_nat_reverse_key_collisions_total")"
POST_SHARED="$(metric_sum "$ACTIVE" "xpf_userspace_session_nat_reverse_key_shared_displacements_total")"
echo "after: local=$POST_LOCAL shared=$POST_SHARED (baseline local=$BASE_LOCAL shared=$BASE_SHARED)"

FAIL=0
if [ "$POST_LOCAL" -le "$BASE_LOCAL" ] && [ "$POST_SHARED" -le "$BASE_SHARED" ]; then
    echo "FAIL: neither collision counter advanced — the watch did not fire."
    FAIL=1
fi
if [ "$VARIANT" = "cold" ] && [ "$POST_SHARED" -le "$BASE_SHARED" ]; then
    echo "FAIL(cold): the W3' shared-map counter did not advance — the"
    echo "  seed-path coverage claim is not holding."
    FAIL=1
fi

# W1 warn is part of the watch contract: poll up to 90s for it (the warn
# is throttled to 1/min process-wide via a CAS whose pending-retry covers
# the first-60s-of-uptime suppression). Only meaningful if a counter
# advanced; FAIL if it never appears.
WARN_COUNT=0
if [ "$FAIL" -eq 0 ]; then
    for _ in $(seq 1 18); do
        WARN_COUNT="$(inc "$ACTIVE" "journalctl -u xpfd --since '$JOURNAL_T0' 2>/dev/null | grep -c 'NAT reverse-key collision detected' || true")"
        [ "$WARN_COUNT" -gt 0 ] && break
        sleep 5
    done
    echo "journald warn lines since start: $WARN_COUNT"
    if [ "$WARN_COUNT" -eq 0 ]; then
        echo "FAIL: counters advanced but the W1 journald warn never appeared"
        echo "  within 90s — the durable artifact is not firing."
        FAIL=1
    fi
fi
if [ "$FAIL" -eq 0 ]; then
    echo "PASS: collision watch fired (local +$((POST_LOCAL - BASE_LOCAL)), shared +$((POST_SHARED - BASE_SHARED)), warns $WARN_COUNT)"
fi
exit "$FAIL"
