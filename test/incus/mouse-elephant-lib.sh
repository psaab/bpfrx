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
    # shellcheck disable=SC2016  # the single quotes are the point: this
    # printf EMITS a shell snippet that runs on the REMOTE host, so $pid must
    # reach it unexpanded. Expanding it here would kill whatever pid this
    # shell happened to have.
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

# ---------------------------------------------------------------------------
# #8244: the canonical default ports, in ONE place.
#
# These were declared independently in test-mouse-latency.sh and
# test-mouse-latency-matrix.sh, and a default that lives in two files drifts.
# `cos_port_grid_test.py` pinned one of the two spellings, so a change to the
# other would have gone unnoticed.
#
# 6200 is queue 0 / best-effort in the canonical grid (cos-iperf-config.set,
# PORT_GRID in cos_port_grid_test.py), which is the right SEMANTIC default for
# a cross-class mouse: it matches no `bandwidth-output` term and so shares no
# class with the elephants.
#
# It is also, on the standing loss cluster, the one echo listener that is
# down — 6201-6211 are all up. That is a PROVISIONING gap, and the fix for it
# is NOT to move the default to 6201.
#
# Auto-selecting an open port would be worse than the bug. The echo port
# DETERMINES THE FORWARDING CLASS (620x -> queue x), so silently substituting
# 6201 would move the mice from best-effort into iperf-100m and change what
# the run measures — two invocations of the same command would produce
# different experiments, with nothing in the output saying so. A wrong number
# that looks right is the failure this harness has already paid for twice.
#
# So the default stays semantic, and the ABORT is what improves: it reports
# the whole grid, so a one-port gap reads as a one-port gap instead of a dead
# lab (#8244).
# shellcheck disable=SC2034  # consumed by test-mouse-latency.sh and
# test-mouse-latency-matrix.sh, which SOURCE this file, and pinned by
# cos_port_grid_test.py. shellcheck cannot see across a source boundary,
# so this is a false positive rather than dead code — the whole point of
# #8244 was to single-source these two values here.
MOUSE_DEFAULT_ECHO_PORT=6200
# shellcheck disable=SC2034  # same: sourced, not dead. A directive covers
# only the following line, so each assignment needs its own.
MOUSE_DEFAULT_IPERF_PORT=5202
