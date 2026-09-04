#!/usr/bin/env bash
#
# #8336 — a reusable crafted-frame screen probe for the shared cluster.
#
# WHY THIS EXISTS. #8298 was a live security bypass whose cluster reproduction
# was not achievable with the obvious tooling. Two attempts came back VOID, for
# reasons that had nothing to do with the fix and everything to do with the
# instrument. This script is those two attempts turned into a procedure so the
# next screen finding is demonstrable rather than argued.
#
# THE PROCEDURE, and every step is one of the traps:
#
#   1. ARM a screen profile. `stage_screen_check` is gated on
#      `has_screen_state()` and the loss userspace cluster carries no
#      `security screen` config, so without this the whole stage
#      short-circuits and the run is green for reasons unrelated to the change.
#   2. SAMPLE the AGGREGATE `xpf_screen_drops_total`, not the per-reason
#      series. A parse-failure drop is reason `ip-malformed`, which -- with
#      `syn-cookie` and `icmp-fragment` -- appears ONLY in the aggregate. There
#      is no label to sample in the per-reason metric, so a fail-closed drop is
#      invisible there by construction.
#   3. Send a WITNESS frame alongside the subject: something crafted to trip a
#      per-reason screen, whose counter moving proves the path is live. Without
#      it a flat aggregate cannot distinguish "arrived and was permitted" from
#      "never arrived", and that ambiguity is what made both earlier attempts
#      unreadable.
#   4. DISARM, and verify on BOTH nodes. The cluster is shared and config syncs
#      to the peer, so a profile left bound changes the environment for every
#      other lane.
#
# The verdict layer is `screen-probe-lib.sh`, hermetically tested by
# `screen-probe-selftest.sh` (`make test-screen-probe-lib`). The decision --
# in particular that a flat witness is VOID rather than a pass -- lives there
# precisely so it can be tested without a cluster.
#
# USAGE
#   ./test/incus/screen-probe.sh <subject-send-cmd> <witness-send-cmd>
#
# Both commands are run on the LAN host and are expected to emit their frames.
# They are supplied by the caller because the crafted frame IS the experiment;
# this script owns the arming, sampling, witnessing and cleanup around it.
#
# This script takes the shared-cluster lock via cluster-cell.sh, like every
# other destructive or config-mutating target. NEVER run it outside the lock:
# it commits config to both nodes.

set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=screen-probe-lib.sh
source ./screen-probe-lib.sh
# shellcheck source=cluster-env.sh
source ./cluster-env.sh

SUBJECT_CMD="${1:?usage: screen-probe.sh <subject-send-cmd> <witness-send-cmd>}"
WITNESS_CMD="${2:?usage: screen-probe.sh <subject-send-cmd> <witness-send-cmd>}"
PROFILE="${SCREEN_PROBE_PROFILE:-probe8336}"

metrics() {
	# The aggregate, per trap 2. Prints the raw sample or nothing.
	incus exec "$FW0" -- curl -sf --max-time 5 \
		http://127.0.0.1:8080/metrics 2>/dev/null \
		| awk -v m="$1" '$1 == m { print $2 }' | head -1
}

arm() {
	printf 'arming screen profile %s on %s\n' "$PROFILE" "$FW0" >&2
	incus exec "$FW0" -- /usr/local/bin/cli <<-EOF
	configure
	set security screen ids-option $PROFILE ip tear-drop
	set security zones security-zone lan screen $PROFILE
	commit
	exit
	EOF
}

disarm() {
	printf 'disarming screen profile %s\n' "$PROFILE" >&2
	incus exec "$FW0" -- /usr/local/bin/cli <<-EOF || true
	configure
	delete security zones security-zone lan screen
	delete security screen ids-option $PROFILE
	commit
	exit
	EOF
}

count_profile_on() {
	incus exec "$1" -- /usr/local/bin/cli -c \
		"show configuration | display set | grep -c $PROFILE" 2>/dev/null \
		| tr -dc '0-9' | head -c 8
}

# Disarm on ANY exit, including a failure mid-probe. A shared cluster left
# armed is the worst outcome here -- worse than a failed measurement, because
# it silently changes what every other lane measures.
trap disarm EXIT

armed_state="not-armed"
if arm; then
	armed_state="armed"
fi

witness_before="$(metrics xpf_screen_drops_by_reason_total || true)"
subject_before="$(metrics xpf_screen_drops_total || true)"

printf 'sending witness frame\n' >&2
eval "$WITNESS_CMD" || true
printf 'sending subject frame\n' >&2
eval "$SUBJECT_CMD" || true
sleep 2

witness_after="$(metrics xpf_screen_drops_by_reason_total || true)"
subject_after="$(metrics xpf_screen_drops_total || true)"

verdict="$(screen_probe_verdict "$armed_state" \
	"$witness_before" "$witness_after" "$subject_before" "$subject_after")"
printf '\nSCREEN PROBE: %s\n' "$verdict"

disarm
trap - EXIT
cleanup="$(screen_probe_disarm_verdict \
	"$(count_profile_on "$FW0")" "$(count_profile_on "$FW1")")"
printf 'SCREEN PROBE CLEANUP: %s\n' "$cleanup"

# A VOID measurement is not a pass. Exit non-zero so a caller that only checks
# the status does not read "we did not measure" as "nothing was wrong" -- which
# is the reading this whole file exists to make impossible.
case "$verdict" in
	VOID\ *) exit 2 ;;
esac
case "$cleanup" in
	FAIL\ *) exit 3 ;;
esac
