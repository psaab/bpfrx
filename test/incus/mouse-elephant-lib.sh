#!/usr/bin/env bash
#
# Elephant-generator lifecycle helpers for the #905 mouse-latency harness.
#
# WHY THIS EXISTS
#
# test-mouse-latency.sh launches the elephant load as a BACKGROUND
# `incus exec <source> -- sh -c "iperf3 -c ... -t 90"` and, on an early
# INVALID exit (cwnd-not-settled, cursor-capture failure, ...), stopped
# it from the EXIT trap with `kill "$IPERF_PID"`.
#
# $IPERF_PID is the LOCAL incus-exec client. Killing it does NOT
# terminate the remote process: incus leaves the command running in the
# instance when a non-interactive client disconnects. Measured directly
# (2026-09-02, loss:cluster-userspace-host): a backgrounded
# `incus exec ... -- sh -c "sleep 137"` was still running 8 s after its
# local client was killed.
#
# The consequence is not a leaked process, it is a CORRUPTED CELL. The
# rep script re-enters ~8 s after an early INVALID while the orphaned
# 90 s iperf3 keeps sending, so the next rep's elephants share the
# 1 Gb/s exact class with the previous rep's. One marginal rejection
# therefore guarantees every subsequent rep in the cell fails the
# cwnd-settle floor, and the cell reports 0 valid reps with no hint
# that the harness caused it. That is exactly what happened to the
# #7159 surplus leg on 2026-08-31: reps 00-03 ran at ~1.0-1.23 Gb/s,
# rep 04 at ~0.40 Gb/s, and reps 05-14 sat on a ~0.25 Gb/s plateau —
# 1 Gb/s divided by the ~3.5 concurrent 90 s runs a 28 s rep cadence
# sustains.
#
# So the elephant needs an identity on the REMOTE side that a kill can
# address. `echo $$ > <pidfile>; exec iperf3 ...` makes the remote
# shell's pid become iperf3's own pid, and the kill command reads it
# back. Both halves are load-bearing: without `exec` the pidfile names
# a wrapper shell whose death orphans iperf3 again.

# Remote paths, derived from the rep tag so concurrent cells cannot
# collide (the tag already carries the cell name, Codex R6 HIGH).
mouse_elephant_outfile() { printf '/tmp/iperf3-%s.txt' "$1"; }
mouse_elephant_pidfile() { printf '/tmp/iperf3-%s.pid' "$1"; }

# Remote `sh -c` body that runs one elephant leg and leaves its pid
# behind. `exec` is required: it makes $$ (already written) the pid of
# iperf3 itself rather than of a shell that merely forked it.
mouse_elephant_start_cmd() {
    local tag="$1" target="$2" port="$3" streams="$4" duration="$5"
    printf 'echo $$ > %s; exec iperf3 -c %s -p %s -P %s -t %s -i 1 --forceflush > %s 2>&1' \
        "$(mouse_elephant_pidfile "$tag")" \
        "$target" "$port" "$streams" "$duration" \
        "$(mouse_elephant_outfile "$tag")"
}

# Remote `sh -c` body that stops this rep's elephant. Always exits 0:
# a rep that finished normally has no pid file, and the EXIT trap must
# not turn a clean rep into a failure.
mouse_elephant_kill_cmd() {
    local pidfile
    pidfile="$(mouse_elephant_pidfile "$1")"
    printf 'pid=$(cat %s 2>/dev/null); if [ -n "$pid" ]; then kill "$pid" 2>/dev/null; fi; rm -f %s; exit 0' \
        "$pidfile" "$pidfile"
}

# Remote `sh -c` body that reports whether ANY iperf3 CLIENT is already
# running on the traffic source. Exits 1 when one is (the rep must not
# start: its elephants would share the class with a stranger), 0 when
# the source is idle.
#
# The `[-]c` bracket is not decoration: `pgrep -f "iperf3 -c "` matches
# the cmdline of the very `sh -c` that runs it, so the naive pattern
# reports a stale client on a perfectly idle source, every time.
mouse_elephant_stale_check_cmd() {
    printf 'if pgrep -f "iperf3 [-]c " >/dev/null 2>&1; then exit 1; fi; exit 0'
}
