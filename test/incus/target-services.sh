#!/usr/bin/env bash
#
# #8040 — the ONE place that knows the CoS/fairness target-service contract.
#
# Every per-class harness in test/incus (mouse-latency, fairness, the CoS
# best-effort contention sweep) sends traffic from the LAN-side source
# container, through the firewall, to a WAN-side target on VLAN 80. That
# target must be running:
#
#   * per-class iperf3 servers on 5200-5211, and
#   * per-class TCP echo daemons on 6200-6211,
#
# with the port -> forwarding-class mapping in test/incus/cos-iperf-config.set.
# None of those harnesses could create a listener, none of them checked more
# than the ONE port it was about to use, and nothing in the tree said the
# dependency existed. So the first harness to run rediscovered it, having
# already spent a build, a deploy, and the shared /tmp/xpf-cluster.lock.
#
#   ./test/incus/target-services.sh status         # the whole grid, one table
#   ./test/incus/target-services.sh check           # exit 1 if ANY of the 24 is down
#   ./test/incus/target-services.sh check 5202 6200 # exit 1 only if THESE are down
#   ./test/incus/target-services.sh up       # start what is missing
#   ./test/incus/target-services.sh down     # stop what this script started
#
# WHY `up` CAN FAIL WITH A DESCRIPTION RATHER THAN A FIX. The target is
# addressed by IP, and on the standing loss cluster it is external lab
# hardware: it answers ICMP on ge-0-0-2.80 but is not an incus instance in any
# project, and it does not accept ssh. There is no handle to run a command on
# it from here. `up` provisions the case where the target IS reachable as an
# incus instance (which is how a fresh environment should be built) and
# otherwise prints exactly what is missing and where it must be started. That
# is the honest boundary: this script cannot invent a management path that
# does not exist, but it CAN stop every harness from rediscovering the fact.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
[[ -f "${SCRIPT_DIR}/cluster-env.sh" ]] && source "${SCRIPT_DIR}/cluster-env.sh" 2>/dev/null || true

TARGET_V4="${TARGET_V4:-${IPERF_TARGET4:-172.16.80.200}}"
# The probe runs from the container the harnesses actually SEND from, not
# from the workstation and not from a firewall node.
#
# The workstation is excluded for the obvious reason: it has no route onto
# VLAN 80, so a probe from there reports every port closed on a perfectly
# healthy target.
#
# A FIREWALL NODE is excluded for a much less obvious one, and this script
# used to default to `xpf-userspace-fw0` and get it wrong (#8164). The
# firewall FORWARDS VLAN-80 traffic; it does not originate it. Its own host
# stack cannot open a TCP connection to the target even when every service is
# up. Measured on the standing loss cluster, same instrument (bash /dev/tcp),
# same 24 ports, same target, at the same moment:
#
#   from loss:cluster-userspace-host   OPEN: 23 / 24   (only 6200 closed)
#   from loss:xpf-userspace-fw0        OPEN:  0 / 24
#   from loss:xpf-userspace-fw1        (same — closed)
#
# ICMP and ARP succeed from the firewall throughout (`ping` 0% loss, neigh
# REACHABLE), and `ip route get 172.16.80.200` there resolves with
# `src 172.16.80.8` — an address `ge-0-0-2.80` does not carry, it is a
# RETH/VRRP VIP. So the firewall vantage answers a question nobody asked and
# fails to "everything closed", which is indistinguishable from the target
# host having died. #7100 and #7159 were both parked for weeks as "blocked on
# lab hardware, every TCP port closed" on exactly this reading; the services
# were up the whole time and only the single port 6200 was genuinely down.
#
# Defaulting to the cluster env's own LAN host (rather than a literal) also
# makes the probe correct on any env: cluster-env.sh derives
# CLUSTER_LAN_HOST_NAME from each env file's LAN_HOST.
PROBE_FROM="${PROBE_FROM:-${CLUSTER_LAN_HOST_NAME:-${LAN_HOST:-cluster-userspace-host}}}"
INCUS_REMOTE="${INCUS_REMOTE:-loss}"

IPERF_PORTS=(5200 5201 5202 5203 5204 5205 5206 5207 5208 5209 5210 5211)
ECHO_PORTS=(6200 6201 6202 6203 6204 6205 6206 6207 6208 6209 6210 6211)

incus_run() {
    if id -nG "$USER" 2>/dev/null | grep -qw incus-admin; then
        incus "$@"; return
    fi
    if command -v sg >/dev/null && getent group incus-admin >/dev/null 2>&1; then
        local quoted; quoted=$(printf '%q ' "$@")
        sg incus-admin -c "incus ${quoted}"; return
    fi
    incus "$@"
}

# probe_ports <host> <port>... -> prints "<port> open|closed" per line.
#
# One `incus exec` for the WHOLE range, not one per port: twenty-four execs
# cost seconds of container round-trips, and the point of this script is that
# a runner sees the entire grid before deciding anything. bash /dev/tcp rather
# than nc, because the probe container does not ship netcat.
probe_ports() {
    local host="$1"; shift
    local ports="$*"
    incus_run exec "${INCUS_REMOTE}:${PROBE_FROM}" -- bash -c "
        for p in ${ports}; do
            if timeout 2 bash -c \"exec 3<>/dev/tcp/${host}/\$p\" 2>/dev/null; then
                echo \"\$p open\"
            else
                echo \"\$p closed\"
            fi
        done" 2>/dev/null
}

# target_reachable reports whether the target answers ICMP at all. It
# separates "the host is gone" from "the host is up and the services are
# down" — two different problems with two different owners, and a table of
# twenty-four closed ports does not distinguish them.
target_reachable() {
    incus_run exec "${INCUS_REMOTE}:${PROBE_FROM}" -- \
        ping -c1 -W2 "$TARGET_V4" > /dev/null 2>&1
}

# target_instance echoes the incus instance name holding TARGET_V4, or
# nothing. `up` needs a handle, and an IP is not one.
target_instance() {
    incus_run list "${INCUS_REMOTE}:" --all-projects --format csv -c n4 2>/dev/null \
        | awk -v ip="$TARGET_V4" -F, '$0 ~ ip {print $1; exit}'
}

cmd_status() {
    echo "target:     ${TARGET_V4}"
    echo "probed from: ${INCUS_REMOTE}:${PROBE_FROM}"
    if target_reachable; then
        echo "icmp:       UP"
    else
        echo "icmp:       DOWN — the target host itself is unreachable from"
        echo "            ${PROBE_FROM}; the service table below is meaningless"
        echo "            until that is fixed."
    fi
    local inst; inst="$(target_instance)"
    if [[ -n "$inst" ]]; then
        echo "instance:   ${INCUS_REMOTE}:${inst}"
    else
        echo "instance:   (none) — the target is not an incus instance in any"
        echo "            project on ${INCUS_REMOTE}:, so there is no handle to"
        echo "            start services on it from here."
    fi
    echo
    local down=0 line port state
    printf '%-6s %-8s %s\n' "PORT" "STATE" "PURPOSE"
    while read -r port state; do
        [[ -z "$port" ]] && continue
        printf '%-6s %-8s %s\n' "$port" "$state" "iperf3 class $((port - 5200))"
        [[ "$state" == "closed" ]] && down=$((down + 1))
    done < <(probe_ports "$TARGET_V4" "${IPERF_PORTS[@]}")
    while read -r port state; do
        [[ -z "$port" ]] && continue
        printf '%-6s %-8s %s\n' "$port" "$state" "tcp echo class $((port - 6200))"
        [[ "$state" == "closed" ]] && down=$((down + 1))
    done < <(probe_ports "$TARGET_V4" "${ECHO_PORTS[@]}")
    echo
    if (( down == 0 )); then
        echo "all 24 target services are up."
    else
        echo "${down} of 24 target services are DOWN."
        echo
        echo "Every per-class harness needs these — test-mouse-latency*.sh,"
        echo "fairness-harness.sh, fairness-cos-class-sweep.sh and"
        echo "cos-be-contention-harness.sh all send to ${TARGET_V4} on a port"
        echo "whose forwarding class comes from test/incus/cos-iperf-config.set."
        echo "make test-failover does NOT (it uses the default iperf3 port), so"
        echo "the standing smoke stays green while every per-class harness is"
        echo "unrunnable. That asymmetry is why this went unnoticed (#8040)."
        echo
        echo "To bring them up on the target host:"
        echo "  for p in ${IPERF_PORTS[*]}; do iperf3 -s -p \$p -D; done"
        echo "  for p in ${ECHO_PORTS[*]}; do"
        echo "    socat -d TCP-LISTEN:\$p,reuseaddr,fork EXEC:/bin/cat &"
        echo "  done"
    fi
    return "$down"
}

# cmd_check [port...] — the gate a harness calls.
#
# WHY IT TAKES PORTS. A harness that needs class 2 and class 11 must not be
# blocked because class 7's server happens to be down; requiring all 24 would
# be an over-rejection that trains runners to skip the gate. But the REPORT is
# always the whole grid: when something is missing, a runner wants to see
# every hole at once rather than fix one port, re-run, and discover the next.
# So the predicate is narrow and the diagnosis is wide.
#
# With no arguments the predicate is all 24, which is what a full sweep needs.
cmd_check() {
    local want=("$@")
    if (( ${#want[@]} == 0 )); then
        want=("${IPERF_PORTS[@]}" "${ECHO_PORTS[@]}")
    fi
    local missing=() port state
    while read -r port state; do
        [[ -z "$port" ]] && continue
        [[ "$state" == "closed" ]] && missing+=("$port")
    done < <(probe_ports "$TARGET_V4" "${want[@]}")

    if (( ${#missing[@]} == 0 )); then
        echo "target services OK on ${TARGET_V4}: ${want[*]}"
        return 0
    fi
    echo "ABORT: target services missing on ${TARGET_V4}: ${missing[*]}" >&2
    echo >&2
    cmd_status >&2
    return 1
}

cmd_up() {
    local inst; inst="$(target_instance)"
    if [[ -z "$inst" ]]; then
        echo "cannot start services: ${TARGET_V4} is not an incus instance on" >&2
        echo "${INCUS_REMOTE}: in any project, so there is no handle to run a" >&2
        echo "command on it. On the standing loss cluster the VLAN-80 target is" >&2
        echo "external lab hardware — it answers ICMP but accepts no ssh." >&2
        echo >&2
        echo "Run './test/incus/target-services.sh status' for the grid and the" >&2
        echo "commands to run ON that host (#8040)." >&2
        return 2
    fi
    echo "starting target services on ${INCUS_REMOTE}:${inst}..."
    incus_run exec "${INCUS_REMOTE}:${inst}" -- bash -c "
        for p in ${IPERF_PORTS[*]}; do
            pgrep -f \"iperf3 -s -p \$p\" >/dev/null || iperf3 -s -p \$p -D
        done
        for p in ${ECHO_PORTS[*]}; do
            pgrep -f \"TCP-LISTEN:\$p\" >/dev/null || \
                setsid socat -d TCP-LISTEN:\$p,reuseaddr,fork EXEC:/bin/cat \
                    </dev/null >/dev/null 2>&1 &
        done
        sleep 1" || return 1
    cmd_check
}

cmd_down() {
    local inst; inst="$(target_instance)"
    if [[ -z "$inst" ]]; then
        echo "no incus handle for ${TARGET_V4}; nothing to stop from here" >&2
        return 2
    fi
    incus_run exec "${INCUS_REMOTE}:${inst}" -- bash -c "
        pkill -f 'iperf3 -s -p 52' || true
        pkill -f 'TCP-LISTEN:62'   || true"
    echo "stopped target services on ${INCUS_REMOTE}:${inst}"
}

case "${1:-status}" in
    status) cmd_status; exit 0 ;;
    check)  shift || true; cmd_check "$@" ;;
    up)     cmd_up ;;
    down)   cmd_down ;;
    *) echo "usage: $0 {status|check|up|down}" >&2; exit 1 ;;
esac
