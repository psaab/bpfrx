#!/usr/bin/env bash
#
# Remote background-job lifecycle helpers for the #905 mouse-latency
# harness (elephant generator and both mpstat samplers).
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

# ---------------------------------------------------------------------
# Generic remote background job.
#
# A job is identified by (name, rep tag). The name is the artifact
# prefix the harness already uses -- "iperf3", "mpstat", "mpstat-settle"
# -- so pidfiles sit beside the outputs they belong to and the existing
# artifact names do not move.

mouse_remote_job_pidfile() { printf '/tmp/%s-%s.pid' "$1" "$2"; }
mouse_remote_job_outfile() { printf '/tmp/%s-%s.txt' "$1" "$2"; }

# Remote `sh -c` body that runs one job and leaves its pid behind.
# `exec` is required: it makes $$ (already written) the pid of the job
# itself rather than of a shell that merely forked it.
#   $1 job name, $2 rep tag, $3.. the command and its arguments
mouse_remote_job_start_cmd() {
    local job="$1" tag="$2"
    shift 2
    printf 'echo $$ > %s; exec %s > %s 2>&1' \
        "$(mouse_remote_job_pidfile "$job" "$tag")" \
        "$*" \
        "$(mouse_remote_job_outfile "$job" "$tag")"
}

# Remote `sh -c` body that stops one job. Safe to run on every path,
# including a rep that finished normally:
#
#   - It confirms the recorded pid still belongs to the expected
#     program before signalling. A finished job's pid can have been
#     reused by an unrelated process on the source container by the time
#     the EXIT trap runs, and killing a stranger is worse than the leak.
#   - It always removes the pidfile, so a completed rep leaves nothing
#     behind, and it always exits 0, so the EXIT trap cannot turn a
#     valid rep into a failure.
#
#   $1 job name, $2 rep tag, $3 program name expected in /proc/<pid>/cmdline
mouse_remote_job_kill_cmd() {
    local pidfile
    pidfile="$(mouse_remote_job_pidfile "$1" "$2")"
    printf 'pid=$(cat %s 2>/dev/null); if [ -n "$pid" ] && grep -qa %s /proc/$pid/cmdline 2>/dev/null; then kill "$pid" 2>/dev/null; fi; rm -f %s; exit 0' \
        "$pidfile" "$3" "$pidfile"
}

# ---------------------------------------------------------------------
# Elephant generator: the load-bearing case, kept as named wrappers so
# call sites read as what they are.

mouse_elephant_outfile() { mouse_remote_job_outfile iperf3 "$1"; }
mouse_elephant_pidfile() { mouse_remote_job_pidfile iperf3 "$1"; }

mouse_elephant_start_cmd() {
    local tag="$1" target="$2" port="$3" streams="$4" duration="$5"
    mouse_remote_job_start_cmd iperf3 "$tag" \
        iperf3 -c "$target" -p "$port" -P "$streams" -t "$duration" \
        -i 1 --forceflush
}

mouse_elephant_kill_cmd() { mouse_remote_job_kill_cmd iperf3 "$1" iperf3; }

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
