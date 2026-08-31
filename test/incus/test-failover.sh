#!/usr/bin/env bash
# xpf cluster failover test
#
# Validates that active TCP connections survive fw0 reboot.
# Requires: cluster nodes from BPFRX_CLUSTER_ENV running (default: loss userspace cluster).
# Requires: iperf3 server reachable at IPERF_TARGET (default from IPERF_TARGET4).
#
# Tests:
#   1. Start iperf3 -P2 through the firewall (LAN host → WAN target)
#   2. Verify sessions sync from primary (fw0) to secondary (fw1)
#   3. Reboot fw0 (unclean — no priority-0 burst)
#   4. Verify iperf3 survives (TCP connections maintained through failover)
#   5. Verify fw0 comes back as secondary (no auto-preempt)
#   6. Manual failover: fw0 becomes primary again, iperf3 survives
#
# Usage:
#   ./test/incus/test-failover.sh
#   IPERF_TARGET=10.1.2.3 ./test/incus/test-failover.sh

set -euo pipefail

# #1875/#4020: this DESTRUCTIVE smoke reboots / force-stops / fails
# over a node on the SHARED loss cluster. Re-exec under the
# incus-admin group if needed, then serialize as a #1875 lock cell
# so a concurrent deploy/smoke can't collide with our reboot (it
# queues behind a held /tmp/xpf-cluster.lock instead of colliding).
_CELL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cluster-cell.sh
source "${_CELL_DIR}/cluster-cell.sh"
xpf_enter_destructive_cluster_cell "test-failover $*" "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/cluster-env.sh
source "${SCRIPT_DIR}/cluster-env.sh"
# #7368: deploy_reassert_node0_primary_ok (the per-RG primacy predicate #6591
# added) and failover_ownership_verdict, both covered by
# `make test-deploy-lib` against a mocked incus.
# shellcheck source=test/incus/deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"
# shellcheck source=test/incus/iperf-throughput-lib.sh
source "${SCRIPT_DIR}/iperf-throughput-lib.sh"

IPERF_TARGET="${IPERF_TARGET:-$IPERF_TARGET4}"
# #6934: the IPv6 transit target. cluster-env.sh has exported IPERF_TARGET6 all
# along and this gate never read it — every assertion here was IPv4-only, which
# is why an IPv6-specific failover regression reached a human as an ad-hoc
# observation instead of reddening this gate.
IPERF_TARGET6="${IPERF_TARGET6:-2001:559:8585:80::200}"
V6_PROBE_COUNT=5        # #6934: see check_v6_transit for why this is not 1
V6_PROBE_MIN=3          # received replies required to call the path up
V6_RECHECK_DELAY=30     # #6934: seconds between the two post-failover samples
# COUPLED TO #7770 — tighten this when that is fixed.
#
# 3-of-5 is not a general-purpose tolerance; it is calibrated to absorb one
# specific KNOWN defect. #7770: a LAN/WAN redundancy-group split drops the first
# packet of every new flow, symmetrically in v4 and v6, and does not self-heal
# (measured 12.5% on 8 packets, still 12.5% on a fresh probe 45s later, against
# 0% for a full failover). A 0%-loss assertion here would red on that rather
# than on anything this gate is scoped to.
#
# So once #7770 lands, this threshold is LOOSER than it needs to be and would
# hide a one-packet regression. Raise V6_PROBE_MIN to V6_PROBE_COUNT then.
#
# Written down because a tolerance whose reason is undocumented is
# indistinguishable from a tolerance nobody thought about — the next reader
# cannot tell "3 of 5 because a known defect costs exactly one packet" from
# "3 of 5 because the author was not sure", and only the first has an expiry.
IPERF_DURATION=120      # seconds — long enough to span retries + reboot + failback
IPERF_STREAMS=8
MIN_SESSIONS=4          # minimum established sessions (control + some data streams)
SYNC_WAIT=5             # seconds to wait for session sync sweep
REBOOT_WAIT=60          # max WALL-CLOCK seconds to wait for fw0 to come back (#1880)
MIN_THROUGHPUT=1.0      # Gbps — iperf3 must report at least this
# #7673: the CoS output filter classifies by DESTINATION PORT, and iperf3
# defaults to 5201 -- which cos-iperf-config.set maps to `iperf-100m`, a
# `transmit-rate 100m exact` class. Measuring a deliberately-100Mbit-shaped
# class against a 1.0 Gbps floor fails by construction, and it fails looking
# exactly like a forwarding regression (~92-94 Mbits/s, every failover
# assertion passing). 5211 is the `iperf-uncapped` term, whose scheduler
# carries no transmit-rate.
#
# This only bites once apply-cos-config.sh has been run, and the CoS config
# survives until the next deploy wipes it -- so the gate passed or failed
# depending on what the PREVIOUS agent left on the cluster. That is why it
# reproduced on master and read as a real regression.
#
# iperf-throughput-selftest.sh asserts this port still maps to an unshaped
# class, so the two files cannot drift apart silently.
IPERF_PORT="${IPERF_PORT:-5211}"

PASS=0
FAIL=0
ERRORS=()

info()  { echo "==> $*"; }
pass()  { echo "  PASS  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }

die() { echo "FATAL: $*" >&2; exit 2; }

# check_v6_transit asserts IPv6 traffic still crosses the firewall (#6934).
#
# It probes the WAN-side target rather than the LAN VIP deliberately. Pinging
# the VIP exercises L2 and local delivery on the same segment and never crosses
# the fabric, so it stays green through exactly the failures this is here to
# catch — measured: during a LAN/WAN redundancy-group split the VIP answers with
# 0% loss while transit is degraded.
#
# The failure message deliberately does NOT blame the neighbour cache. That was
# this issue's first instinct for three rounds and it is measurably wrong here:
# on this LAN host the IPv4 and IPv6 neigh parameters are byte-identical, and
# poisoning the default gateway's entry with a bogus MAC costs 8.51s in IPv6
# against 8.71s in IPv4 — symmetric, and 8.5s rather than the ~30/~60s the old
# message asserted. A stale neighbour entry can produce a blackhole; it cannot
# produce a v4/v6 ASYMMETRY on this host, and it cannot produce a ~60s one.
# Measurements in docs/log/6934.md.
#
# It tolerates losing packets but not all of them, and that threshold is
# measured rather than picked. A cross-node split costs the FIRST packet of a
# new flow, reproducibly and without self-healing, so a `-c 1` probe would be
# flaky on a healthy-enough cluster while a "0% loss" assertion would red on a
# condition this gate is not scoped to. Requiring 3 of 5 separates a blackhole
# (0 received — the #6934 report) from that first-packet loss (4 of 5).
check_v6_transit() {
	local label="$1" out recv
	out=$(incus exec "$CLUSTER_LAN_HOST" -- ping6 -c "$V6_PROBE_COUNT" -W 1 "$IPERF_TARGET6" 2>&1 || true)
	recv=$(printf '%s\n' "$out" | sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' | head -1)
	[ -z "$recv" ] && recv=0
	if [ "$recv" -ge "$V6_PROBE_MIN" ]; then
		pass "IPv6 transit OK ${label} (${recv}/${V6_PROBE_COUNT} to ${IPERF_TARGET6})"
	else
		fail "IPv6 transit BLACKHOLED ${label}: only ${recv}/${V6_PROBE_COUNT} replies from ${IPERF_TARGET6}. Do NOT reach for a neighbour-cache explanation first: on this LAN host every neigh parameter is byte-identical between the families (base_reachable_time_ms 30000/30000, gc_stale_time 60/60, delay_first_probe_time 5/5, retrans_time_ms 1000/1000, ucast_solicit 3/3), and a deliberately poisoned gateway entry repairs in 8.51s for v6 against 8.71s for v4 — symmetric, and 8.5s rather than 30 or 60. A v6-ONLY failure therefore has to be somewhere the families genuinely differ, and the one place they do here is the default route: v4 is proto static, v6 is proto ra with a 180s lifetime refreshed every 10-30s. Capture ip -6 route / ip -6 neigh AND their v4 twins DURING the window (#6934, docs/log/6934.md)"
	fi
}
# #7368: a PRECONDITION failure is not a failover regression, and neither is an
# ownership/forwarding divergence. All three used to exit 2, so `FO_RC=2` was
# read as "failover broke" when it meant "the cluster was not in a state to
# test" — twice, on the shared gate, against changes that were not at fault.
die_precondition() { echo "FATAL[PRECONDITION]: $*" >&2; exit 2; }
die_divergence()   { echo "FATAL[DIVERGENCE]: $*" >&2; exit 3; }

instance_running() {
	local status
	status=$(incus info "$1" 2>/dev/null | grep -o "RUNNING" || true)
	[[ "$status" == "RUNNING" ]]
}

wait_for_instance() {
	local inst="$1" max="$2"
	for i in $(seq 1 "$max"); do
		if incus exec "$inst" -- systemctl is-active --quiet xpfd 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

# ── Preflight ────────────────────────────────────────────────────────

info "Preflight checks"

for inst in "$FW0" "$FW1" "$CLUSTER_LAN_HOST"; do
	instance_running "$inst" || die "$inst is not running"
done

# Reset any stale manual failover flags from previous test runs.
# Without this, fw1 can't take over during the reboot test because
# ManualFailover blocks election even when the peer is lost.
for rg in 0 1 2; do
	incus exec "$FW0" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
	incus exec "$FW1" -- cli -c "request chassis cluster failover reset redundancy-group $rg" 2>/dev/null || true
done
sleep 2

# Verify fw0 is primary for EVERY redundancy group.
#
# #7368: this was `grep -q "node0.*primary"` over the whole status output.
# `secondary` does not contain `primary`, so that part was sound — but the grep
# is not scoped to a redundancy group, so a cluster with node0 SECONDARY for
# RG0 and primary for RG1 satisfied it. The reassert makes node0 primary for
# all RGs, and the post-failover phase below already asserts all three, so the
# precondition should be the same shape. deploy_reassert_node0_primary_ok is
# the predicate #6591 added and `make test-deploy-lib` covers; reusing it keeps
# one definition of "node0 is primary" rather than a second grep that can drift.
fw0_status=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if printf '%s\n' "$fw0_status" | deploy_reassert_node0_primary_ok; then
	pass "fw0 is primary for every redundancy group"
else
	die_precondition "fw0 is not primary for every redundancy group — cannot run the failover test. This is a PRECONDITION failure, NOT a failover regression: the cluster was not in a testable state before the change under test ran. Check the post-deploy reassert (#6591) and re-read the state directly:
$fw0_status"
fi

# Verify iperf target reachable
if incus exec "$CLUSTER_LAN_HOST" -- ping -c 2 -W 2 "$IPERF_TARGET" &>/dev/null; then
	pass "iperf3 target reachable ($IPERF_TARGET)"
else
	die "Cannot reach iperf3 target $IPERF_TARGET from ${CLUSTER_LAN_HOST}"
fi

# #6934: the IPv6 baseline. Asserted BEFORE any failover so a later v6 failure
# is attributable to the transition rather than to a cluster that never had v6
# transit — without this the post-failover cells could red on a broken fixture.
check_v6_transit "at baseline (before any failover)"

# Kill any stale iperf3
incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
sleep 1

# ── Phase 1: Start iperf3 ───────────────────────────────────────────

info "Starting iperf3 -P${IPERF_STREAMS} -t${IPERF_DURATION} -p${IPERF_PORT} → ${IPERF_TARGET}"

# iperf3 server handles one client at a time. After a previous test
# disrupts connections (session clear / failover), the server may hold
# a stale session until TCP keepalive fires (~minutes). Retry startup
# with increasing back-off to wait for the server to become available.
iperf_started=false
for attempt in 1 2 3; do
	incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
	sleep 1
	incus exec "$CLUSTER_LAN_HOST" -- bash -c \
		"iperf3 --forceflush --connect-timeout 5000 -t ${IPERF_DURATION} -c ${IPERF_TARGET} -p ${IPERF_PORT} -P ${IPERF_STREAMS} > /tmp/iperf3-failover.log 2>&1 &"

	sleep 8  # all parallel streams must be fully established

	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		info "iperf3 exited on attempt $attempt — server may be busy, retrying"
		sleep $((attempt * 5))
		continue
	fi

	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	if [[ "$fw0_sessions" -ge "$IPERF_STREAMS" ]]; then
		iperf_started=true
		break
	fi

	# iperf3 is running but not enough sessions — streams may have timed out
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "unable to connect" /tmp/iperf3-failover.log 2>/dev/null; then
		info "iperf3 stream connect failed on attempt $attempt — server busy, retrying"
		incus exec "$CLUSTER_LAN_HOST" -- pkill -9 iperf3 2>/dev/null || true
		sleep $((attempt * 10))
		continue
	fi

	iperf_started=true
	break
done

if ! $iperf_started; then
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
		die "iperf3 failed to start after 3 attempts"
	fi
fi

# Verify iperf3 is running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 running on ${CLUSTER_LAN_HOST}"
else
	incus exec "$CLUSTER_LAN_HOST" -- cat /tmp/iperf3-failover.log 2>/dev/null || true
	die "iperf3 failed to start"
fi

# Verify sessions exist on fw0.
# iperf3 server is single-client — if a stale session from the previous
# test lingers, some data streams may not connect. Accept MIN_SESSIONS
# (control + some data) rather than requiring all IPERF_STREAMS.
#
# #4052: the 8 TCP streams take a sub-second to finish their 3-way
# handshakes, so a single immediate assert here can catch the
# establishment window with only 0-3 Valid sessions and FALSE-FAIL a
# healthy cluster (a settled cluster shows ~25 Valid sessions at
# 23.4 Gbps / 0 retr). Poll up to 10s (20 × 0.5s), breaking as soon as
# the count reaches MIN_SESSIONS; only fail if the streams genuinely
# never establish within the timeout — a real establishment failure.
fw0_sessions=0
for _ in $(seq 1 20); do
	fw0_sessions=$(incus exec "$FW0" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	[[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]] && break
	sleep 0.5
done
# #7368: cross-reference the two independent checks this script already
# performs before deciding WHICH failure this is.
#
# Primacy is read from `show chassis cluster status` — a field the node reports
# about itself, with no oracle. The session count is a real measurement. They
# were never compared, so #6656's divergence (node0 primary with 1 session,
# node1 carrying 33) surfaced here as "streams did not establish" — a shortfall
# attributed to whatever change was under test, when the actual failure was
# that ownership and forwarding disagreed.
#
# The peer count is read ONLY on the shortfall path, so the healthy run pays
# nothing. failover_ownership_verdict is pure and selftested.
if [[ "$fw0_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw0 has $fw0_sessions established sessions"
else
	fw1_probe=$(incus exec "$FW1" -- cli -c \
		"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
	case "$(failover_ownership_verdict "$fw0_sessions" "$fw1_probe" "$MIN_SESSIONS")" in
	diverged)
		die_divergence "OWNERSHIP AND FORWARDING DISAGREE. fw0 reports PRIMARY for every redundancy group but carries only $fw0_sessions session(s), while fw1 — reported secondary — carries $fw1_probe. The cluster-state field and the traffic disagree, so neither 'failover is broken' nor 'the streams did not establish' is the right reading; see #6656. Read both nodes directly before re-running:
  incus exec $FW0 -- cli -c 'show chassis cluster status'
  incus exec $FW1 -- cli -c 'show chassis cluster status'"
		;;
	*)
		fail "fw0 has only $fw0_sessions established sessions (expected >= $MIN_SESSIONS); fw1 carries $fw1_probe, so this is an establishment failure rather than an ownership/forwarding divergence"
		;;
	esac
fi

# ── Phase 2: Wait for session sync ──────────────────────────────────

info "Waiting ${SYNC_WAIT}s for session sync to fw1"
sleep "$SYNC_WAIT"

fw1_sessions=$(incus exec "$FW1" -- cli -c \
	"show security flow session destination-prefix ${IPERF_TARGET}" 2>/dev/null | grep -c "Session State: Valid" || true)
if [[ "$fw1_sessions" -ge "$MIN_SESSIONS" ]]; then
	pass "fw1 has $fw1_sessions synced sessions"
else
	fail "fw1 has only $fw1_sessions synced sessions (expected >= $MIN_SESSIONS)"
fi

# ── Phase 3: Crash fw0 (sysrq reboot) ───────────────────────────────
#
# sysrq-b is the repo's proven unclean primitive (same as
# test-double-failover.sh): the guest resets instantly, with no unit
# stops, no priority-0 VRRP burst, and no shutdown-job queueing. The
# previous `reboot` here was a GRACEFUL systemd reboot despite the
# "unclean" claim — xpfd got a clean stop (emitting the planned-shutdown
# priority-0 burst, i.e. the ~1ms takeover path instead of the ~60ms
# worst-case detection this test exists to exercise) AND the whole
# shutdown queued behind any wedged stop job. The #1880 budget misses
# were exactly that: post-deploy `systemctl reload frr` poisons
# frr.service into a 2-minute stop-sigterm on FRR 10.6, and a graceful
# reboot inside that window waited out the timer.

info "Crashing fw0 (sysrq reboot — unclean shutdown, tests worst-case failover)"

# timeout is load-bearing AND needs -k: sysrq-b resets the guest
# INSTANTLY, killing the incus-agent serving this exec, so the exec
# never observes an exit status (measured: a 47-minute hang on the
# first live run). Worse, `incus exec` FORWARDS SIGTERM to the (dead)
# remote session instead of exiting (measured: `timeout 10` alone left
# the client alive for 38+ minutes), so only the -k SIGKILL follow-up
# reliably reaps the local client. `|| true` alone cannot save a
# command that never returns.
# Braces, not just 2>/dev/null on the command: bash prints its own
# "Killed" job notice for the SIGKILLed child, which would land in the
# test transcript as alarming noise.
{ timeout -k 5 10 incus exec "$FW0" -- bash -c 'echo b > /proc/sysrq-trigger' || true; } 2>/dev/null

# Wait for fw1 to detect failure and become primary
sleep 3

# Verify iperf3 survived the failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 reboot (failover to fw1)"
else
	fail "iperf3 DIED during fw0 reboot — failover broke TCP connections"
fi

# ── Phase 4: Wait for fw0 to come back as secondary (no auto-preempt) ─

info "Waiting for fw0 to reboot and rejoin as secondary (max ${REBOOT_WAIT}s)"

# Wall-clock budget (#1880): the old `seq 1 $REBOOT_WAIT` loop counted
# ITERATIONS as seconds, but each iteration costs ~1.2s (1s sleep +
# ~240ms incus exec), so "60s" silently meant ~74s and the PASS message
# under-reported by ~23%. Measured comebacks on the loss userspace
# cluster: ~22s clean (sysrq), so 60s wall keeps ~2.7x headroom.
fw0_back=false
wait_start=$SECONDS
while (( SECONDS - wait_start < REBOOT_WAIT )); do
	if wait_for_instance "$FW0" 1; then
		fw0_back=true
		info "fw0 xpfd active after $((SECONDS - wait_start))s"
		break
	fi
done

if $fw0_back; then
	pass "fw0 xpfd restarted after reboot"
else
	fail "fw0 xpfd did not come back within ${REBOOT_WAIT}s"
fi

# Wait for cluster to stabilize (gRPC takes ~15s after systemctl active)
sleep 20

# Verify fw0 is secondary (NOT primary — no auto-preempt)
fw0_status_after=$(incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null)
if echo "$fw0_status_after" | grep -q "node0.*secondary"; then
	pass "fw0 rejoined as secondary (no auto-preempt)"
elif echo "$fw0_status_after" | grep -q "node0.*primary"; then
	fail "fw0 auto-preempted to primary (should stay secondary)"
else
	fail "fw0 cluster status unclear: $fw0_status_after"
fi

# Verify fw1 is still primary
if incus exec "$FW1" -- cli -c 'show chassis cluster status' 2>/dev/null | grep -q "node1.*primary"; then
	pass "fw1 remains primary after fw0 rejoin"
else
	fail "fw1 is not primary after fw0 rejoin"
fi

# Verify iperf3 still running
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived fw0 rejoin"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before rejoin check)"
	else
		fail "iperf3 DIED during fw0 rejoin"
	fi
fi

# ── Phase 4b: Manual failover — fw0 becomes primary again ───────────

info "Manual failover: requesting fw1 to failover all RGs to fw0"

# Execute manual failover on fw1 for all RGs (current primary).
# Each RG must be explicitly failed over — RG0 alone doesn't move RG1/RG2
# because per-RG election is independent with non-preempt.
for rg in 0 1 2; do
	incus exec "$FW1" -- cli -c "request chassis cluster failover redundancy-group $rg" 2>/dev/null || true
done

# Wait for failover to complete
sleep 5

# Verify fw0 is now primary for ALL RGs
all_primary=true
for rg in 0 1 2; do
	if ! incus exec "$FW0" -- cli -c 'show chassis cluster status' 2>/dev/null | grep -A1 "Redundancy group: $rg" | grep -q "node0.*primary"; then
		all_primary=false
		fail "fw0 is not primary for RG$rg after manual failover"
	fi
done
if $all_primary; then
	pass "fw0 became primary for all RGs after manual failover"
fi

# Verify iperf3 survived manual failover
if incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
	pass "iperf3 survived manual failover"
else
	if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
		pass "iperf3 completed successfully (finished before manual failover check)"
	else
		fail "iperf3 DIED during manual failover"
	fi
fi

# #6934: the reported scenario. A manual RG failover moves the RETH virtual MAC,
# so every peer holding a neighbour entry for a VIP or for the stable RETH
# link-local must be corrected by the unsolicited-NA burst. The iperf3 check
# above cannot see a failure here: it is one long-lived IPv4 flow, so it
# survives on established state while a NEW IPv6 flow blackholes.
check_v6_transit "after manual failover"

# #6934: sample the window TWICE, not once. The reported symptom self-heals
# after ~60s with no intervention, and a single probe fired immediately after
# the failover reports a clean pass whether it landed before such a window
# opened or after it closed — a check that cannot distinguish "healthy" from
# "I sampled the wrong instant".
#
# Cost, counted rather than asserted: the 120s iperf3 starts at line ~207 and by
# the time control reaches here the script has already spent 8 + SYNC_WAIT + 3 +
# (reboot wait) + 20 + 5 seconds plus a 5-packet probe. With a typical reboot
# that leaves ~35-55s of iperf3 still to run, so the wait below overlaps it and
# Phase 5 just waits out the remainder — free. Only when the reboot consumes the
# full REBOOT_WAIT budget does any of it become extra wall clock, and then at
# most V6_RECHECK_DELAY of it.
sleep "$V6_RECHECK_DELAY"
check_v6_transit "${V6_RECHECK_DELAY}s after manual failover"

# ── Phase 5: Wait for iperf3 to complete and validate results ───────

info "Waiting for iperf3 to complete"

for i in $(seq 1 "$IPERF_DURATION"); do
	if ! incus exec "$CLUSTER_LAN_HOST" -- pgrep iperf3 &>/dev/null; then
		break
	fi
	sleep 1
done

# Check iperf3 completed successfully.
# iperf3's control socket may close during failover even though all data
# streams survived — this produces "control socket has closed unexpectedly"
# instead of "iperf Done". Accept either outcome as long as the sender
# [SUM] line shows adequate throughput.
# #6897: capture the whole [SUM] sender line and let the lib parse it. The
# previous inline parse matched only "Gbits", so a sub-Gbit run yielded the
# literal "0" and then matched NEITHER the pass branch nor the fail branch —
# there was no else, and the run emitted no throughput cell at all while still
# summarising as "0 failed". Sub-Gbit is exactly what a throughput regression
# or a CoS-shaped class looks like, so the gate went silent in the case it
# exists to catch.
sum_line=$(incus exec "$CLUSTER_LAN_HOST" -- grep '\[SUM\].*sender' /tmp/iperf3-failover.log 2>/dev/null \
	| tail -1 || true)
throughput=$(iperf_sum_rate_gbps "$sum_line")

if incus exec "$CLUSTER_LAN_HOST" -- grep -q "iperf Done" /tmp/iperf3-failover.log 2>/dev/null; then
	pass "iperf3 completed successfully"
elif [[ -n "$throughput" ]] && awk "BEGIN{exit !($throughput >= $MIN_THROUGHPUT)}"; then
	pass "iperf3 data transfer completed (${throughput} Gbps) — control socket disrupted during failover"
else
	iperf_log=$(incus exec "$CLUSTER_LAN_HOST" -- tail -5 /tmp/iperf3-failover.log 2>/dev/null || echo "(no log)")
	fail "iperf3 did not complete: $iperf_log"
fi

# The verdict is total: absent, unparseable, too-low and healthy each yield
# exactly one cell. The catch-all default keeps that true even if the lib ever
# grows a status this caller does not know about — a missing cell is the
# defect, so no path may end without emitting one.
throughput_verdict=$(iperf_throughput_verdict "$MIN_THROUGHPUT" "$sum_line")
case "$throughput_verdict" in
PASS\ *) pass "${throughput_verdict#PASS }" ;;
FAIL\ *) fail "${throughput_verdict#FAIL }" ;;
*)       fail "iperf3 throughput: unrecognised verdict from iperf_throughput_verdict: ${throughput_verdict}" ;;
esac

# ── Results ──────────────────────────────────────────────────────────

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Failover test: $PASS passed, $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ $FAIL -gt 0 ]]; then
	echo
	echo "Failures:"
	for err in "${ERRORS[@]}"; do
		echo "  - $err"
	done
	exit 1
fi
