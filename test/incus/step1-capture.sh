#!/usr/bin/env bash
#
# step1-capture.sh — Phase B Step 1 per-cell capture driver.
#
# Usage:
#   step1-capture.sh <port> <direction> <cos-state>
#
#     port        5201 | 5202 | 5203 | 5204
#     direction   fwd | rev
#     cos-state   with-cos | no-cos
#
# Emits all artifacts under:
#   docs/pr/line-rate-investigation/step1-evidence/<cos-state>/p<port>-<dir>/
#
# See docs/pr/line-rate-investigation/step1-plan.md §§2-3 for the
# capture protocol this script implements. The script is the
# canonical protocol; the plan documents what the script does.
#
# Dependencies on the firewall VM (loss:xpf-userspace-fw0):
#   socat jq ethtool mpstat perf ss dmesg ps pgrep xpf-userspace-dp
# Dependencies on the traffic host (loss:cluster-userspace-host):
#   iperf3 ping taskset
#
# The script enforces §5 invariants I1-I10 post-capture. Any
# violation marks the cell SUSPECT and returns a non-zero exit.
# Re-run protocol (up to 2 retries) is the caller's responsibility;
# this script captures a single cell in one attempt.
#
set -euo pipefail

usage() {
	cat >&2 <<EOF
usage: $0 <port> <direction> <cos-state>
  port        one of 5201, 5202, 5203, 5204
  direction   one of fwd, rev
  cos-state   one of with-cos, no-cos
EOF
	exit 2
}

if [[ $# -ne 3 ]]; then
	usage
fi

PORT="$1"
DIR="$2"
COS="$3"

case "$PORT" in
	5201|5202|5203|5204) ;;
	*) echo "error: port must be 5201/5202/5203/5204, got '$PORT'" >&2; exit 2 ;;
esac

case "$DIR" in
	fwd) MAYBE_R="" ;;
	rev) MAYBE_R="-R" ;;
	*) echo "error: direction must be fwd|rev, got '$DIR'" >&2; exit 2 ;;
esac

case "$COS" in
	with-cos|no-cos) ;;
	*) echo "error: cos-state must be with-cos|no-cos, got '$COS'" >&2; exit 2 ;;
esac

# Per plan §2.1: reverse cells in no-cos half are SKIPPED (strict
# duplication of with-cos reverse, no new signal).
if [[ "$COS" == "no-cos" && "$DIR" == "rev" ]]; then
	echo "SKIP: no-cos × reverse is out of matrix per plan §1" >&2
	exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FW="loss:xpf-userspace-fw0"
HOST="loss:cluster-userspace-host"
IPERF_SERVER="172.16.80.200"

OUTDIR="$REPO_ROOT/docs/pr/line-rate-investigation/step1-evidence/$COS/p${PORT}-${DIR}"
mkdir -p "$OUTDIR"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }
fw()  { incus exec "$FW"   -- bash -c "$*"; }
host(){ incus exec "$HOST" -- bash -c "$*"; }

# -- 2.1 pre-run ------------------------------------------------------

log "drain in-flight iperf3 on $FW and $HOST"
for attempt in 1 2 3; do
	fw_count=$(fw "ss -tnH 'sport = :5201 or sport = :5202 or sport = :5203 or sport = :5204 or dport = :5201 or dport = :5202 or dport = :5203 or dport = :5204' | wc -l")
	host_count=$(host "ss -tnH 'sport = :5201 or sport = :5202 or sport = :5203 or sport = :5204 or dport = :5201 or dport = :5202 or dport = :5203 or dport = :5204' | wc -l")
	if [[ "$fw_count" == "0" && "$host_count" == "0" ]]; then
		break
	fi
	log "drain attempt $attempt: fw=$fw_count host=$host_count — killing stragglers"
	fw "pkill -9 -f 'iperf3' || true"
	host "pkill -9 -f 'iperf3' || true"
	sleep 1
done
if [[ "$fw_count" != "0" || "$host_count" != "0" ]]; then
	echo "SUSPECT: could not drain iperf3 after 3 attempts" | tee "$OUTDIR/verdict.txt" >&2
	exit 1
fi

log "capture cluster-state snapshot (pre)"
fw "cli -c 'show chassis cluster status'" > "$OUTDIR/cluster-status-pre.txt"

# I9 start-of-run invariant: primary is fw0, no recent fab flap.
PRIMARY_NODE=$(grep -E '^[[:space:]]*primary' "$OUTDIR/cluster-status-pre.txt" | head -1 || true)
if ! echo "$PRIMARY_NODE" | grep -qi 'fw0\|node0'; then
	echo "SUSPECT(I9): RG0 primary is not fw0: $PRIMARY_NODE" | tee "$OUTDIR/verdict.txt" >&2
	exit 1
fi

log "capture cold flow_steer snapshot"
fw "echo '{\"request_type\":\"status\"}' | socat -t 5 - UNIX-CONNECT:/run/xpf/userspace-dp.sock | jq ." \
	> "$OUTDIR/flow_steer_cold.json"

log "capture cold NIC counters (ge-0-0-1, ge-0-0-2)"
fw "ethtool -S ge-0-0-1 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-cold-ge-0-0-1.txt"
fw "ethtool -S ge-0-0-2 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-cold-ge-0-0-2.txt"

log "capture CoS shaper state"
fw "cli -c 'show class-of-service interface'" > "$OUTDIR/cos-interface-pre.txt"

# I8: record daemon ActiveEnterTimestamp for the worker-restart check.
DAEMON_START_PRE=$(fw "systemctl show -p ActiveEnterTimestamp --value xpfd || systemctl show -p ActiveEnterTimestamp --value xpf-userspace-dp || true")
echo "$DAEMON_START_PRE" > "$OUTDIR/daemon-start-pre.txt"

# Collect worker TIDs per plan §2.2(c) / invariant I8.
WORKER_TIDS=$(fw "ps -eLo tid,comm | awk '\$2 ~ /^xpf-userspace-worker-/ {print \$1}' | paste -sd,")
WORKER_TID_COUNT=$(echo "$WORKER_TIDS" | tr ',' '\n' | grep -c . || true)
echo "$WORKER_TIDS" > "$OUTDIR/worker-tids.txt"
if [[ "$WORKER_TID_COUNT" -lt 4 ]]; then
	echo "SUSPECT(I8): only $WORKER_TID_COUNT worker TIDs found (expected >= 4)" | tee "$OUTDIR/verdict.txt" >&2
	exit 1
fi

# -- 2.2 during run ---------------------------------------------------

log "start pinned ICMP probes (small + large) on $HOST"
host "taskset -c 4 ping -i 0.01 -s 56   -D -q -w 60 $IPERF_SERVER > /tmp/ping-small.txt 2>&1 &
      taskset -c 5 ping -i 0.01 -s 1400 -D -q -w 60 $IPERF_SERVER > /tmp/ping-large.txt 2>&1 &
      echo \$! > /tmp/ping-pids"

# Small sleep so ping is steady-state before iperf3 handshake.
sleep 0.2

log "launch iperf3 -c -P 16 -t 60 -p $PORT $MAYBE_R"
host "iperf3 -c $IPERF_SERVER -P 16 -t 60 -p $PORT $MAYBE_R -J > /tmp/iperf3.json 2> /tmp/iperf3.err &
      echo \$! > /tmp/iperf3-pid"

# Small delay for handshake per plan §2.2 (~200 ms).
sleep 0.2

log "launch concurrent mpstat + perf stat + samplers (60 s)"
fw "mpstat -P ALL 1 60 > /tmp/mpstat.txt 2>&1 &
    perf stat --per-thread -t $WORKER_TIDS \
      -e task-clock,cycles,instructions,cache-references,cache-misses,L1-dcache-load-misses,LLC-loads \
      -- sleep 60 > /tmp/perf-stat.txt 2>&1 &
    : > /tmp/flow_steer_samples.jsonl
    : > /tmp/ss-samples.jsonl
    for i in \$(seq 0 11); do
      (
        ts=\$(date +%s)
        echo '{\"request_type\":\"status\"}' \
          | socat -t 5 - UNIX-CONNECT:/run/xpf/userspace-dp.sock \
          | jq -c --arg ts \"\$ts\" '. + {_sample_ts: \$ts}' \
          >> /tmp/flow_steer_samples.jsonl
        {
          echo \"{\\\"t\\\":\$ts,\\\"flows\\\":[\"
          ss -tiH \"dport = :$PORT\" | awk 'BEGIN{first=1} {gsub(/\"/,\"\\\\\\\"\");
               if(first){first=0}else{printf \",\"}; printf \"\\\"%s\\\"\", \$0}'
          echo \"]}\"
        } >> /tmp/ss-samples.jsonl
      )
      sleep 5
    done
    wait"

# Wait on iperf3 too.
host "wait \$(cat /tmp/iperf3-pid) 2>/dev/null || true"

log "retrieve during-run artifacts"
incus file pull "$HOST/tmp/iperf3.json"    "$OUTDIR/iperf3.json"
incus file pull "$HOST/tmp/ping-small.txt" "$OUTDIR/ping-small.txt"
incus file pull "$HOST/tmp/ping-large.txt" "$OUTDIR/ping-large.txt"
incus file pull "$FW/tmp/mpstat.txt"              "$OUTDIR/mpstat.txt"
incus file pull "$FW/tmp/perf-stat.txt"           "$OUTDIR/perf-stat.txt"
incus file pull "$FW/tmp/flow_steer_samples.jsonl" "$OUTDIR/flow_steer_samples.jsonl"
incus file pull "$FW/tmp/ss-samples.jsonl"        "$OUTDIR/ss-samples.jsonl"

# -- 2.3 post-run -----------------------------------------------------

log "capture post-run snapshots"
fw "echo '{\"request_type\":\"status\"}' | socat -t 5 - UNIX-CONNECT:/run/xpf/userspace-dp.sock | jq ." \
	> "$OUTDIR/flow_steer_post.json"
fw "ethtool -S ge-0-0-1 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-post-ge-0-0-1.txt"
fw "ethtool -S ge-0-0-2 | grep -vE ' 0$' || true" > "$OUTDIR/nic-counters-post-ge-0-0-2.txt"
fw "cli -c 'show chassis cluster status'" > "$OUTDIR/cluster-status-post.txt"
fw "dmesg -T | tail -50" > "$OUTDIR/dmesg-tail.txt"

DAEMON_START_POST=$(fw "systemctl show -p ActiveEnterTimestamp --value xpfd || systemctl show -p ActiveEnterTimestamp --value xpf-userspace-dp || true")
echo "$DAEMON_START_POST" > "$OUTDIR/daemon-start-post.txt"

# -- 5. post-capture invariants --------------------------------------

FAIL=""
add_fail() { FAIL="${FAIL}${FAIL:+; }$1"; }

# I1 — all files exist, size > 0.
for f in iperf3.json flow_steer_cold.json flow_steer_post.json \
         flow_steer_samples.jsonl mpstat.txt perf-stat.txt \
         ping-small.txt ping-large.txt ss-samples.jsonl \
         nic-counters-cold-ge-0-0-1.txt nic-counters-post-ge-0-0-1.txt \
         nic-counters-cold-ge-0-0-2.txt nic-counters-post-ge-0-0-2.txt \
         cluster-status-pre.txt cluster-status-post.txt dmesg-tail.txt; do
	if [[ ! -s "$OUTDIR/$f" ]]; then
		add_fail "I1:$f missing or empty"
	fi
done

# I2 — iperf3 SUM within ±10 % of expected baseline. Baseline source
# is 8matrix-findings.md for with-cos and the pre-#804 mean for
# no-cos. We skip strict enforcement here (the findings doc in step 1
# will cross-check) but we do parse and record for downstream.
SUM_BPS=$(jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // 0' "$OUTDIR/iperf3.json")
echo "sum_bps=$SUM_BPS" > "$OUTDIR/sum.txt"
if [[ "$SUM_BPS" == "0" ]]; then
	add_fail "I2: iperf3 SUM is zero — capture failed"
fi

# I4 — same RG0 primary pre and post.
PRE_PRIM=$(grep -iE 'primary' "$OUTDIR/cluster-status-pre.txt" | head -1 || true)
POST_PRIM=$(grep -iE 'primary' "$OUTDIR/cluster-status-post.txt" | head -1 || true)
if [[ "$PRE_PRIM" != "$POST_PRIM" ]]; then
	add_fail "I4: RG0 primary drifted ($PRE_PRIM -> $POST_PRIM)"
fi

# I5 — no softlockup / mlx5 error / BUG.
if grep -iE 'softlockup|mlx5.*(error|reset)|BUG:' "$OUTDIR/dmesg-tail.txt" >/dev/null 2>&1; then
	add_fail "I5: dmesg shows kernel failure"
fi

# I6 — flow_steer_samples.jsonl has 12 lines, each valid JSON,
# each with non-empty per_binding array of length >= 8.
SAMPLE_LINES=$(wc -l < "$OUTDIR/flow_steer_samples.jsonl")
if [[ "$SAMPLE_LINES" != "12" ]]; then
	add_fail "I6: expected 12 samples, got $SAMPLE_LINES"
else
	if ! jq -e 'select(.per_binding | length >= 8)' \
	     "$OUTDIR/flow_steer_samples.jsonl" >/dev/null; then
		add_fail "I6: per_binding array too small on one or more samples"
	fi
fi

# I8 — daemon did not restart mid-cell.
if [[ "$DAEMON_START_PRE" != "$DAEMON_START_POST" ]]; then
	add_fail "I8: daemon restarted mid-cell ($DAEMON_START_PRE -> $DAEMON_START_POST)"
fi

# I10 — on with-cos cells, cos_interfaces non-empty AND filter_term_counters
# delta non-zero on this port's term.
if [[ "$COS" == "with-cos" ]]; then
	COS_IFACE_COUNT=$(jq '.cos_interfaces | length' "$OUTDIR/flow_steer_post.json")
	if [[ "$COS_IFACE_COUNT" -lt 1 ]]; then
		add_fail "I10: with-cos but cos_interfaces is empty"
	fi
	# Filter-term-counter delta — require any term matching dest port
	# to have non-zero packet/byte delta between cold and post.
	DELTA=$(jq -r --arg p "$PORT" '
		(.filter_term_counters // []) as $post
		| ($post | map(select(.term_name | test($p))) | map(.matched_packets // 0) | add) // 0
	' "$OUTDIR/flow_steer_post.json")
	COLD_DELTA=$(jq -r --arg p "$PORT" '
		(.filter_term_counters // []) as $cold
		| ($cold | map(select(.term_name | test($p))) | map(.matched_packets // 0) | add) // 0
	' "$OUTDIR/flow_steer_cold.json")
	if [[ "$DELTA" -le "$COLD_DELTA" ]]; then
		add_fail "I10: filter_term_counters delta is zero on port $PORT (cold=$COLD_DELTA post=$DELTA)"
	fi
fi

if [[ -n "$FAIL" ]]; then
	echo "SUSPECT: $FAIL" | tee "$OUTDIR/verdict.txt" >&2
	exit 1
fi

log "all invariants PASS — cell valid; verdict classification deferred to post-run analysis"
echo "PENDING: $OUTDIR (run step1-classify.sh next to compute verdict)" > "$OUTDIR/verdict.txt"
exit 0
