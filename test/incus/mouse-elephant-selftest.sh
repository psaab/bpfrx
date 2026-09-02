#!/usr/bin/env bash
#
# Hermetic self-test for test/incus/mouse-elephant-lib.sh (#7159, #8270).
#
# The defect under guard is INVISIBLE to any assertion on the rep
# script's exit code or artifacts: the old stop path (`kill` on the
# LOCAL incus-exec client) returned success, wrote a correct
# INVALID-cwnd-not-settled marker, and left a 90 s iperf3 running
# inside the source container. The next rep then measured a class it
# was sharing with its own predecessor and failed the same way, so a
# whole cell voided with a plausible reason and no trace of the cause.
#
# The properties, and what each one would let through if absent:
#
#   1. The pidfile names the LEAF process. Dropping `exec` from the
#      start command leaves it naming a wrapper shell whose death
#      orphans iperf3, and the cascade is back with every text-level
#      assertion still green.
#   2. The stop command actually reaps that process, and exits 0 when
#      there is nothing to stop -- it runs from an EXIT trap on every
#      rep including clean ones, so a non-zero exit there would turn a
#      valid rep into a failure.
#   3. The stale-client check answers 0 on an IDLE source. That is the
#      positive control, and it is the one that catches the obvious
#      implementation: `pgrep -f "iperf3 -c "` matches its own `sh -c`
#      cmdline, so the natural pattern reports a stale client on an
#      idle box and would abort every rep of every cell.
#
# Hermetic: a fake `iperf3` on PATH execs a uniquely-named marker
# process, and the stale-client controls run inside an unprivileged PID
# namespace so the verdict cannot be decided by an unrelated process on
# a shared dev host. Nothing here touches a cluster.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/mouse-elephant-lib.sh"
# shellcheck source=test/incus/mouse-elephant-lib.sh
. "$LIB"

TMP="$(mktemp -d)"
BASE="xpf-mouse-elephant-selftest-$$"
# Each fake's argv[0] embeds the program name it stands in for: the
# stop command confirms /proc/<pid>/cmdline still names that program
# before signalling (cell 5), so a stand-in that does not look like the
# program would be spared and cells 1 and 4 would fail for the wrong
# reason.
MARKER="iperf3-${BASE}"
MARKER_MPSTAT="mpstat-${BASE}"
TAG="selftest_$$"
cleanup() {
    pkill -f "$BASE" 2>/dev/null
    rm -rf "$TMP"
    rm -f "$(mouse_elephant_pidfile "$TAG")" "$(mouse_elephant_outfile "$TAG")"
}
trap cleanup EXIT
fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# Fake iperf3: replaces itself with a uniquely-named sleep so the test
# can ask "is the LEAF still alive", not "did some shell exit".
cat > "${TMP}/iperf3" <<FAKE
#!/usr/bin/env bash
exec -a "$MARKER" sleep 4242
FAKE
chmod +x "${TMP}/iperf3"

leaf_alive() { pgrep -f "${1:-$MARKER}" >/dev/null 2>&1; }

# ---- 1. start writes a pidfile naming the LEAF; stop reaps it.
PATH="${TMP}:${PATH}" setsid sh -c \
    "$(mouse_elephant_start_cmd "$TAG" 10.0.0.1 5202 4 90)" \
    < /dev/null > /dev/null 2>&1 &
for _ in $(seq 1 50); do
    leaf_alive && break
    sleep 0.1
done
if ! leaf_alive; then
    fail "fake elephant never started; the stop path was NOT exercised"
else
    pidfile="$(mouse_elephant_pidfile "$TAG")"
    if [[ ! -s "$pidfile" ]]; then
        fail "start command wrote no pidfile at $pidfile"
    fi
    remote_pid="$(cat "$pidfile" 2>/dev/null)"
    leaf_pid="$(pgrep -f "$MARKER" | head -1)"
    if [[ "$remote_pid" != "$leaf_pid" ]]; then
        fail "pidfile names pid $remote_pid but the leaf process is $leaf_pid (missing exec?)"
    else
        pass "pidfile names the leaf process itself"
    fi

    sh -c "$(mouse_elephant_kill_cmd "$TAG")"
    kill_rc=$?
    for _ in $(seq 1 30); do
        leaf_alive || break
        sleep 0.1
    done
    if leaf_alive; then
        fail "stop command left the elephant running"
    else
        pass "stop command reaped the elephant"
    fi
    if [[ $kill_rc -ne 0 ]]; then
        fail "stop command exited $kill_rc on a live elephant"
    fi
    if [[ -e "$(mouse_elephant_pidfile "$TAG")" ]]; then
        fail "stop command left the pidfile behind"
    else
        pass "stop command removed the pidfile"
    fi
fi

# ---- 2. stop is a clean no-op when the rep already finished.
sh -c "$(mouse_elephant_kill_cmd "nonexistent_$$")"
if [[ $? -ne 0 ]]; then
    fail "stop command exits non-zero when there is nothing to stop"
else
    pass "stop command is a clean no-op on a finished rep"
fi

# ---- 3. stale-client check, inside an isolated PID namespace.
#
# The controls must run where the only visible processes are the ones
# this test started. On a shared dev host any command line that merely
# MENTIONS an iperf3 client -- an editor, a shell history line, the
# writer of this very file -- is visible to pgrep, and the idle control
# would fail for a reason that has nothing to do with the subject. For
# the same reason the busy-process command line lives in its own script
# file: putting it in the namespace driver's argv makes the driver
# match its own pattern.
cat > "${TMP}/busy.sh" <<'BUSY'
#!/usr/bin/env bash
exec -a "iperf3 -c 172.16.80.200 -p 5202" sleep 4243
BUSY
chmod +x "${TMP}/busy.sh"
cat > "${TMP}/ns.sh" <<'NS'
#!/usr/bin/env bash
. "$1"
sh -c "$(mouse_elephant_stale_check_cmd)"
idle=$?
"$2" &
for _ in $(seq 1 50); do
    pgrep -f "$3" >/dev/null 2>&1 && break
    sleep 0.1
done
sh -c "$(mouse_elephant_stale_check_cmd)"
busy=$?
printf '%s %s\n' "$idle" "$busy"
NS
chmod +x "${TMP}/ns.sh"

ns_results=""
if unshare -Ufrp --mount-proc true 2>/dev/null; then
    ns_results=$(unshare -Ufrp --mount-proc \
        bash "${TMP}/ns.sh" "$LIB" "${TMP}/busy.sh" 'sleep 4243' 2>/dev/null | tail -1)
fi

if [[ -z "$ns_results" ]]; then
    # Not a pass. An unrunnable control is a third state, not a green
    # one, so say so on stderr rather than counting it either way.
    echo "SKIP: unprivileged PID namespaces unavailable; stale-client controls NOT run" >&2
else
    read -r idle_rc busy_rc <<< "$ns_results"
    if [[ "$idle_rc" != "0" ]]; then
        fail "stale-client check reports a stale client on an IDLE source (rc=$idle_rc; self-matching pattern?)"
    else
        pass "stale-client check passes on an idle source"
    fi
    if [[ "$busy_rc" == "0" ]]; then
        fail "stale-client check passed while an iperf3 client was running"
    else
        pass "stale-client check fails when an iperf3 client is already running"
    fi
fi

# ---- 4. the generic job layer, used by both mpstat samplers (#8270).
#
# Same property as the elephant: the pidfile must name the LEAF, and
# the stop command must reap it. A separate cell rather than trusting
# the elephant wrapper, because the samplers are what regressed --
# #8268 fixed one call site and left two with the old shape.
MPTAG="selftest_mpstat_$$"
cat > "${TMP}/mpstat" <<FAKE
#!/usr/bin/env bash
exec -a "$MARKER_MPSTAT" sleep 4242
FAKE
chmod +x "${TMP}/mpstat"

PATH="${TMP}:${PATH}" setsid sh -c \
    "$(mouse_remote_job_start_cmd mpstat "$MPTAG" mpstat 1 60)" \
    < /dev/null > /dev/null 2>&1 &
for _ in $(seq 1 50); do
    leaf_alive "$MARKER_MPSTAT" && break
    sleep 0.1
done
if ! leaf_alive "$MARKER_MPSTAT"; then
    fail "fake mpstat never started; the sampler stop path was NOT exercised"
else
    mp_pidfile="$(mouse_remote_job_pidfile mpstat "$MPTAG")"
    mp_recorded="$(cat "$mp_pidfile" 2>/dev/null)"
    mp_leaf="$(pgrep -f "$MARKER_MPSTAT" | head -1)"
    if [[ "$mp_recorded" != "$mp_leaf" ]]; then
        fail "sampler pidfile names $mp_recorded but the leaf is $mp_leaf (missing exec?)"
    else
        pass "sampler pidfile names the leaf process itself"
    fi
    sh -c "$(mouse_remote_job_kill_cmd mpstat "$MPTAG" mpstat)"
    for _ in $(seq 1 30); do
        leaf_alive "$MARKER_MPSTAT" || break
        sleep 0.1
    done
    if leaf_alive "$MARKER_MPSTAT"; then
        fail "sampler stop command left the process running"
    else
        pass "sampler stop command reaped the process"
    fi
fi
rm -f "$(mouse_remote_job_pidfile mpstat "$MPTAG")" \
      "$(mouse_remote_job_outfile mpstat "$MPTAG")"

# ---- 5. the stop command refuses a pid that is no longer its job.
#
# This is the control that fails on CORRECT input rather than on a
# mutant: the stop command now runs on every path, including reps that
# finished normally, so by the time it fires the recorded pid may have
# been reused by an unrelated process on the source container. A stop
# command without the /proc/<pid>/cmdline check kills that stranger and
# every other cell here still passes.
REUSE_TAG="selftest_reuse_$$"
INNOCENT="${BASE}-innocent"
setsid bash -c "exec -a '$INNOCENT' sleep 4244" < /dev/null > /dev/null 2>&1 &
for _ in $(seq 1 50); do
    pgrep -f "$INNOCENT" >/dev/null 2>&1 && break
    sleep 0.1
done
innocent_pid="$(pgrep -f "$INNOCENT" | head -1)"
if [[ -z "$innocent_pid" ]]; then
    fail "could not start the pid-reuse stand-in; reuse control NOT run"
else
    echo "$innocent_pid" > "$(mouse_remote_job_pidfile mpstat "$REUSE_TAG")"
    sh -c "$(mouse_remote_job_kill_cmd mpstat "$REUSE_TAG" mpstat)"
    sleep 0.3
    if pgrep -f "$INNOCENT" >/dev/null 2>&1; then
        pass "stop command spares a reused pid that is not its job"
    else
        fail "stop command killed an unrelated process holding a reused pid"
    fi
    if [[ -e "$(mouse_remote_job_pidfile mpstat "$REUSE_TAG")" ]]; then
        fail "stop command left the pidfile behind on the reuse path"
    fi
    pkill -f "$INNOCENT" 2>/dev/null
fi

if [[ $fails -ne 0 ]]; then
    echo "mouse-elephant-selftest: $fails failure(s)" >&2
    exit 1
fi
echo "mouse-elephant-selftest: all checks passed"
