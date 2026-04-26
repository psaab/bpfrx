#!/usr/bin/env bash
# Run one rep of the #905 mouse-latency cell.
#
# Usage: test-mouse-latency.sh <N> <M> <duration_s> <out_dir>
#   N: elephant streams against 172.16.80.200:5201 (iperf-a)
#   M: concurrent mouse coroutines against 172.16.80.200:7 (best-effort)
#   duration_s: probe duration in seconds (≥ 60 recommended)
#   out_dir: per-rep output directory (created if missing)
#
# See docs/pr/905-mouse-latency/plan.md for the full spec. Heavy
# parsing logic lives in mouse_latency_orchestrate.py.

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <N> <M> <duration_s> <out_dir>" >&2
    exit 1
fi

N="$1"
M="$2"
DURATION="$3"
OUT_DIR="$4"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Constants from plan §3.1.
INCUS_REMOTE="loss"
PRIMARY="xpf-userspace-fw0"
SECONDARY="xpf-userspace-fw1"
SOURCE="cluster-userspace-host"
TARGET_V4="172.16.80.200"
ELEPHANT_PORT=5201
MOUSE_PORT=7
SHAPER_BPS=$((1 * 1000 * 1000 * 1000))  # 1 Gb/s for iperf-a
SETTLE_BUDGET=20
SLACK=10

mkdir -p "$OUT_DIR"
# Include the cell name in REP_TAG so per-rep temp files on the
# remote source container don't collide across cells (e.g.
# cell_N0_M10/rep_00 vs cell_N128_M10/rep_00 — without the cell
# prefix, both write to /tmp/probe-rep_00.json and a failed pull
# in the second cell silently picks up the first cell's data).
# Codex R6 HIGH.
CELL_DIR="$(basename "$(dirname "$OUT_DIR")")"
REP_TAG="${CELL_DIR}_${OUT_DIR##*/}"

# Local-side stale-artifact guard (Codex R7 HIGH): if OUT_DIR is
# reused (rerun into an existing rep dir) and the new probe run
# fails before overwriting probe.json, the previous run's data
# would silently masquerade as the current rep's result. Wipe
# the artifacts at rep start; INVALID-* markers from a prior run
# are also cleared so the new rep's verdict is clean.
rm -f "${OUT_DIR}"/probe.json \
      "${OUT_DIR}"/probe-stdout.log \
      "${OUT_DIR}"/iperf3.txt \
      "${OUT_DIR}"/iperf3-settle.txt \
      "${OUT_DIR}"/mpstat.txt \
      "${OUT_DIR}"/screen-pre.txt \
      "${OUT_DIR}"/screen-post.txt \
      "${OUT_DIR}"/rg-state-poll.txt \
      "${OUT_DIR}"/rg-state-initial.txt \
      "${OUT_DIR}"/rg-state-final.txt \
      "${OUT_DIR}"/rg-state-flap.log \
      "${OUT_DIR}"/rg-state-final-diff.log \
      "${OUT_DIR}"/ha-transitions.log \
      "${OUT_DIR}"/manifest.json \
      "${OUT_DIR}"/cos-apply.log \
      "${OUT_DIR}"/jc-cursor-* \
      "${OUT_DIR}"/INVALID-*

# `incus_run` wraps incus calls so they work both inside and outside
# the incus-admin group. Only the user's own group needs to differ —
# if the user isn't already in incus-admin, `sg` runs the command
# under that group via a single shell invocation.
#
# R1 MED 1: `sg ... -c "incus $*"` collapses argv across word
# boundaries. We use `printf '%q '` to safely re-quote each arg.
incus_run() {
    if id -nG "$USER" 2>/dev/null | grep -qw incus-admin; then
        incus "$@"
        return
    fi
    if command -v sg >/dev/null && getent group incus-admin >/dev/null 2>&1; then
        local quoted
        quoted=$(printf '%q ' "$@")
        sg incus-admin -c "incus ${quoted}"
        return
    fi
    incus "$@"
}

incus_exec() {
    local target="$1"; shift
    incus_run exec "${INCUS_REMOTE}:${target}" -- "$@"
}

# Discover which node is currently primary (R1 MED 2: post-rep SYN
# snapshot must follow primary if a transition happened in-rep).
current_primary() {
    local out
    out=$(incus_exec "$PRIMARY" cli -c "show chassis cluster status" 2>/dev/null) || out=""
    local node
    node=$(printf '%s' "$out" | python3 -c '
import sys
sys.path.insert(0, "'"${SCRIPT_DIR}"'")
from cluster_status_parse import parse_cluster_status
for rg, n, st in parse_cluster_status(sys.stdin.read()):
    if rg == 0 and st == "primary":
        print(f"xpf-userspace-fw{n}")
        break
') || node=""
    if [[ -z "$node" ]]; then
        node="$PRIMARY"
    fi
    echo "$node"
}

invalidate() {
    local reason="$1"
    : > "${OUT_DIR}/INVALID-${reason}"
    echo "REP INVALID: $reason" >&2
    exit 0
}

cleanup() {
    # Best-effort kill on early exit. The MPSTAT_PID is started AFTER
    # the probe is launched, so on early INVALID exit (e.g. during
    # cwnd-settle gate or step 4 cursor capture) it isn't running yet.
    [[ -n "${IPERF_PID:-}" ]] && kill "$IPERF_PID" 2>/dev/null || true
    [[ -n "${RG_POLL_PID:-}" ]] && kill "$RG_POLL_PID" 2>/dev/null || true
    [[ -n "${MPSTAT_PID:-}" ]] && kill "$MPSTAT_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Defense in depth: remove any stale per-rep temp files on the
# remote source before this rep starts (Codex R6 HIGH: without
# REP_TAG including the cell name, two cells with the same rep
# index would collide; even with that fix, a failed pull
# previously left a stale file behind that the next reuse with the
# same tag would inherit. Belt-and-suspenders.)
incus_exec "$SOURCE" sh -c \
    "rm -f /tmp/probe-${REP_TAG}.json /tmp/mpstat-${REP_TAG}.txt /tmp/iperf3-${REP_TAG}.txt" \
    < /dev/null > /dev/null 2>&1 || true

# Push helper scripts to the source container (probe driver runs there).
incus_run file push "${SCRIPT_DIR}/mouse_latency_probe.py" \
    "${INCUS_REMOTE}:${SOURCE}/tmp/mouse_latency_probe.py"

# ---- step 1: CoS preflight (fixture-apply only, plan §3.3 + R4 MED 4)
"${SCRIPT_DIR}/apply-cos-config.sh" "${INCUS_REMOTE}:${PRIMARY}" \
    > "${OUT_DIR}/cos-apply.log" 2>&1

# ---- step 3: RG state polling at 1 Hz (plan §4.5 step 3)
RG_POLL_FILE="${OUT_DIR}/rg-state-poll.txt"
: > "$RG_POLL_FILE"
(
    end_t=$(($(date +%s) + DURATION + SETTLE_BUDGET + SLACK + 5))
    while [[ $(date +%s) -lt $end_t ]]; do
        ts=$(date +%s%3N)
        incus_exec "$PRIMARY" cli -c "show chassis cluster status" 2>/dev/null \
            | python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
                  parse-cluster-state "$ts" \
            >> "$RG_POLL_FILE" 2>/dev/null || true
        sleep 1
    done
) &
RG_POLL_PID=$!

# Initial RG state snapshot (one-shot).
incus_exec "$PRIMARY" cli -c "show chassis cluster status" \
    > "${OUT_DIR}/rg-state-initial.txt" 2>/dev/null || true

# ---- step 4: journalctl cursor capture on BOTH nodes (plan §4.5 step 4).
# Empty cursors lose HA coverage on that node; fail-fast if capture fails.
for FW in "$PRIMARY" "$SECONDARY"; do
    cursor_out=$(incus_exec "$FW" journalctl --show-cursor -n 0 2>/dev/null \
                 | tail -1) || cursor_out=""
    cursor=$(echo "$cursor_out" | sed -n 's/.*cursor: //p')
    if [[ -z "$cursor" ]]; then
        echo "journalctl cursor capture failed on $FW" >&2
        invalidate "jc-cursor-capture-${FW}"
    fi
    echo "$cursor" > "${OUT_DIR}/jc-cursor-${FW}.txt"
done

# ---- step 4a: SYN-cookie counter snapshot (pre)
incus_exec "$PRIMARY" cli -c "show security screen statistics zone wan" \
    > "${OUT_DIR}/screen-pre.txt" 2>/dev/null || true

# ---- step 5: elephant launch (if N > 0). Background; let it run for
# SETTLE_BUDGET + DURATION + SLACK seconds total.
IPERF_DURATION=$((SETTLE_BUDGET + DURATION + SLACK))

if [[ "$N" -gt 0 ]]; then
    incus_exec "$SOURCE" sh -c \
        "iperf3 -c ${TARGET_V4} -p ${ELEPHANT_PORT} -P ${N} -t ${IPERF_DURATION} -i 1 --forceflush > /tmp/iperf3-${REP_TAG}.txt 2>&1" \
        < /dev/null > /dev/null 2>&1 &
    IPERF_PID=$!

    # Wait the SETTLE_BUDGET, then snapshot iperf3.txt and run the
    # cwnd-settle gate. (Live tailing inside incus exec is hard to
    # plumb reliably; the budget is the gate.)
    sleep "$SETTLE_BUDGET"
    incus_run file pull \
        "${INCUS_REMOTE}:${SOURCE}/tmp/iperf3-${REP_TAG}.txt" \
        "${OUT_DIR}/iperf3-settle.txt" 2>/dev/null || true
    if ! python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
            check-cwnd-settle "${OUT_DIR}/iperf3-settle.txt" "$SHAPER_BPS"; then
        invalidate "cwnd-not-settled"
    fi
fi

# ---- step 2 (deferred to here): start mpstat over the probe window only.
# R2 HIGH 6 fix had the killer-before-Average regression: starting mpstat
# at top-of-rep means we kill it before its `Average:` row prints. Now
# mpstat's count == DURATION, so it exits naturally just as the probe
# does and writes the Average: line.
incus_exec "$SOURCE" sh -c \
    "mpstat 1 ${DURATION} > /tmp/mpstat-${REP_TAG}.txt 2>&1" \
    < /dev/null > /dev/null 2>&1 &
MPSTAT_PID=$!

# ---- step 6: probe driver (M coroutines, closed-loop)
incus_exec "$SOURCE" python3 /tmp/mouse_latency_probe.py \
    --target "$TARGET_V4" --port "$MOUSE_PORT" \
    --concurrency "$M" --duration "$DURATION" \
    --payload-bytes 64 --out "/tmp/probe-${REP_TAG}.json" \
    > "${OUT_DIR}/probe-stdout.log" 2>&1 || true

incus_run file pull \
    "${INCUS_REMOTE}:${SOURCE}/tmp/probe-${REP_TAG}.json" \
    "${OUT_DIR}/probe.json" 2>/dev/null || true

# ---- step 8: elephant stop + collapse check
if [[ -n "${IPERF_PID:-}" ]]; then
    # Wait for iperf3 to finish naturally (it has a -t budget that
    # already includes settle + probe + slack). Capture exit status.
    set +e
    wait "$IPERF_PID"
    iperf_rc=$?
    set -e
    incus_run file pull \
        "${INCUS_REMOTE}:${SOURCE}/tmp/iperf3-${REP_TAG}.txt" \
        "${OUT_DIR}/iperf3.txt" 2>/dev/null || true
    if [[ $iperf_rc -ne 0 ]]; then
        echo "iperf3 exited rc=$iperf_rc" >&2
        invalidate "iperf3-rc${iperf_rc}"
    fi
    if [[ ! -s "${OUT_DIR}/iperf3.txt" ]]; then
        invalidate "iperf3-no-output"
    fi
    # Scope collapse detection to the probe window (R5 HIGH): rows
    # [SETTLE_BUDGET : SETTLE_BUDGET + DURATION] are the probe
    # period. Earlier rows are settle warmup; later rows are slack
    # post-probe. Anchoring on probe-start (--skip-front) avoids
    # the off-by-window error where "last N rows" would lose the
    # first DURATION seconds of probe and include SLACK seconds
    # of post-probe noise.
    set +e
    python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
        check-collapse --skip-front "$SETTLE_BUDGET" --n-rows "$DURATION" \
        "${OUT_DIR}/iperf3.txt" "$SHAPER_BPS"
    collapse_rc=$?
    set -e
    case "$collapse_rc" in
        0) invalidate "elephant-collapsed" ;;
        1) : ;;  # not collapsed, ok
        *) invalidate "collapse-check-error-rc${collapse_rc}" ;;
    esac
fi

# ---- step 7: wait for mpstat to finish on its own count (so it
# writes an `Average:` row), then parse client-busy result.
wait "$MPSTAT_PID" 2>/dev/null || true
incus_run file pull "${INCUS_REMOTE}:${SOURCE}/tmp/mpstat-${REP_TAG}.txt" \
    "${OUT_DIR}/mpstat.txt" 2>/dev/null || true
# Missing or unparseable mpstat output → INVALID rather than silent
# pass (R2 HIGH 6 partial: v1 treated 0% as "fine"; that hid mpstat
# crashes / pull failures).
if [[ ! -s "${OUT_DIR}/mpstat.txt" ]]; then
    invalidate "mpstat-missing"
fi
mpstat_busy=$(awk '/^Average:.*all/ { print 100 - $NF; exit }' \
    "${OUT_DIR}/mpstat.txt")
if [[ -z "$mpstat_busy" ]]; then
    invalidate "mpstat-unparseable"
fi
if python3 -c "import sys; sys.exit(0 if float('${mpstat_busy}') > 80 else 1)"; then
    invalidate "client-saturated"
fi

# ---- step 9: journalctl HA-transition diff (plan §4.5 step 9).
HA_RE='cluster: primary transition|vrrp: transitioning to (MASTER|BACKUP)'
ha_seen=0
for FW in "$PRIMARY" "$SECONDARY"; do
    cursor=$(cat "${OUT_DIR}/jc-cursor-${FW}.txt" 2>/dev/null || true)
    if [[ -z "$cursor" ]]; then
        # Cursor was captured non-empty in step 4 (or we'd have
        # invalidated then). An empty cursor here means the file
        # got clobbered — treat as harness failure.
        invalidate "jc-cursor-missing-${FW}"
    fi
    set +e
    matches=$(incus_exec "$FW" journalctl --after-cursor="$cursor" -u xpfd 2>"/tmp/jc-stderr-${REP_TAG}-${FW}")
    jc_rc=$?
    set -e
    if [[ $jc_rc -ne 0 ]]; then
        echo "journalctl on $FW failed (rc=$jc_rc)" >&2
        invalidate "jc-error"
    fi
    set +e
    hit=$(echo "$matches" | grep -iE "$HA_RE")
    gr_rc=$?
    set -e
    if [[ $gr_rc -gt 1 ]]; then
        invalidate "jc-grep-error"
    fi
    if [[ -n "$hit" ]]; then
        ha_seen=1
        {
            echo "HA transition on $FW:"
            echo "$hit"
        } >> "${OUT_DIR}/ha-transitions.log"
    fi
done
[[ $ha_seen -eq 1 ]] && invalidate "ha-transition"

# ---- step 9a: SYN-cookie counter snapshot (post). Follow whichever
# node is currently primary — if a transition happened in-window we
# already invalidated above, but for the no-transition case we want
# the screen counters from the same node we sampled in step 4a.
post_primary=$(current_primary)
incus_exec "$post_primary" cli -c "show security screen statistics zone wan" \
    > "${OUT_DIR}/screen-post.txt" 2>/dev/null || true
screen_engaged="false"
if ! diff -q "${OUT_DIR}/screen-pre.txt" "${OUT_DIR}/screen-post.txt" \
        > /dev/null 2>&1; then
    screen_engaged="true"
fi

# ---- step 10: RG state poll review.
kill "$RG_POLL_PID" 2>/dev/null || true
wait "$RG_POLL_PID" 2>/dev/null || true

# Final RG state one-shot, compared to the initial snapshot from
# step 3 (Codex R6 MED: catches an in-window state change that
# slipped through gaps in the 1Hz polling — even if individual
# `cli` calls failed during the rep, the initial vs final pair
# is two extra independent samples).
incus_exec "$PRIMARY" cli -c "show chassis cluster status" \
    > "${OUT_DIR}/rg-state-final.txt" 2>/dev/null || true

initial_triples=$(python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
    parse-cluster-state 0 < "${OUT_DIR}/rg-state-initial.txt" 2>/dev/null \
    | sort -u || true)
final_triples=$(python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
    parse-cluster-state 0 < "${OUT_DIR}/rg-state-final.txt" 2>/dev/null \
    | sort -u || true)
if [[ -n "$initial_triples" && "$initial_triples" != "$final_triples" ]]; then
    {
        echo "initial vs final RG state mismatch:"
        diff <(echo "$initial_triples") <(echo "$final_triples") || true
    } > "${OUT_DIR}/rg-state-final-diff.log"
    invalidate "rg-state-initial-vs-final"
fi

# Exit codes: 0 = drift detected (INVALID), 1 = stable, 2 = no data (INVALID).
set +e
python3 "${SCRIPT_DIR}/mouse_latency_orchestrate.py" \
    rg-state-flapped "$RG_POLL_FILE" \
    > "${OUT_DIR}/rg-state-flap.log" 2>&1
rg_rc=$?
set -e
case "$rg_rc" in
    0) invalidate "rg-state-flap" ;;
    1) : ;;  # stable, ok
    2) invalidate "rg-poll-no-data" ;;
    *) invalidate "rg-poll-error-rc${rg_rc}" ;;
esac

# ---- step 11: manifest write
cat > "${OUT_DIR}/manifest.json" <<EOF
{
  "N": $N,
  "M": $M,
  "duration_s": $DURATION,
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "screen_engaged": $screen_engaged,
  "ha_transition_seen": $ha_seen,
  "mpstat_avg_busy": "${mpstat_busy:-0}"
}
EOF

echo "REP OK"
