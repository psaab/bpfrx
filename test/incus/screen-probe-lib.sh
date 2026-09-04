#!/usr/bin/env bash
#
# #8336 — the crafted-frame screen probe's ANALYSIS layer.
#
# Extracted from the probe script so the decision is HERMETICALLY TESTABLE,
# exactly as iperf-throughput-lib.sh was extracted for the same reason.
#
# This exists because TWO measurement attempts against #8298 came back VOID,
# both for reusable reasons. Anyone crafting frames at the cluster to exercise
# a screen will hit the same traps and reach for the same wrong counter.
#
# THE THREE TRAPS, and what this layer does about each:
#
#  1. THE STANDARD SMOKE EXERCISES NO SCREEN CODE. `stage_screen_check` is
#     gated on `has_screen_state()` and the loss userspace cluster carries no
#     `security screen` configuration, so `extract_screen_info` is never
#     reached and the whole stage short-circuits. A cluster-deploy plus
#     test-failover against a screen change is green for reasons that have
#     nothing to do with the change. The probe script arms a profile first and
#     disarms after; this layer refuses to render a verdict from a run that
#     did not record the profile as armed.
#
#  2. THE PER-REASON COUNTER CANNOT SEE A PARSE-ERROR DROP. The obvious
#     instrument is `xpf_screen_drops_by_reason_total{reason="teardrop"}`, and
#     it is the wrong one for any drop originating in a parse failure:
#     `extract_screen_info` failing closed yields reason `ip-malformed`, and
#     `ip-malformed`, `syn-cookie` and `icmp-fragment` are surfaced ONLY
#     through the aggregate `xpf_screen_drops_total`. There is no
#     `ip-malformed` label in the per-reason series to sample, so a fail-closed
#     drop is invisible there BY CONSTRUCTION and the zero reads exactly like
#     "nothing happened". This layer takes the AGGREGATE as the subject.
#
#  3. WITHOUT AN ARRIVAL WITNESS A ZERO IS UNREADABLE. A flat aggregate has two
#     indistinguishable causes: the crafted frame never reached the firewall
#     (routing, L2, the host stack, or the NIC discarding a malformed header
#     before AF_XDP), or it arrived and was not dropped -- which is the actual
#     finding. Those are different results and collapsing them is how both
#     earlier attempts produced an unreadable zero.
#
# THE VERDICT IS THEREFORE THREE-VALUED, NOT TWO. The witness is a companion
# frame crafted to trip a per-reason screen, sent alongside the subject, so its
# counter moving proves the path is live. A flat witness means THE MEASUREMENT
# DID NOT HAPPEN, and that is VOID -- never a pass and never a failure. The
# same shape as the counter-witness technique in docs/engineering-style.md:
# pair the measurement with something whose movement proves the instrument is
# connected.
#
# And the verdict is TOTAL: every input class yields exactly one line. The
# defect that produced #6897's sibling lib was not a wrong number, it was NO
# CELL AT ALL for an input class nobody had enumerated.

# screen_probe_delta <before> <after>
#   Print the counter delta, or nothing when either sample is not an integer.
#   An unparseable sample is NOT zero: a scrape that returned an error page, a
#   metric that was absent, and a counter that genuinely did not move all
#   render as "no number here", and treating them alike is how a broken scrape
#   becomes a clean result.
screen_probe_delta() {
	local before="${1-}" after="${2-}"
	[[ "$before" =~ ^[0-9]+$ ]] || return 0
	[[ "$after" =~ ^[0-9]+$ ]] || return 0
	# A counter that went BACKWARDS means the helper restarted mid-probe (the
	# series is process-scoped). That is not a negative drop count; it is a
	# run whose two samples describe different processes.
	if (( after < before )); then
		return 0
	fi
	printf '%s\n' "$(( after - before ))"
}

# screen_probe_verdict <armed> <witness_before> <witness_after> <subject_before> <subject_after>
#   Print exactly one verdict line:
#     "VOID <message>"    the measurement did not happen; nothing was learned
#     "DROPPED <message>" the subject frame was dropped by a screen
#     "PASSED <message>"  the subject frame arrived and was NOT dropped
#
#   VOID is checked FIRST and in dependency order: an unarmed profile makes the
#   witness meaningless, and a flat witness makes the subject meaningless. A
#   layer that checked the subject first would report "not dropped" for a frame
#   that never arrived -- which is precisely the reading that made both earlier
#   attempts look like findings.
screen_probe_verdict() {
	# Defaulted, not required. An unquoted empty variable at a call site
	# word-splits away and the call arrives with FEWER arguments than the
	# signature -- under `set -u` that aborts the function and it emits NOTHING.
	# A verdict layer that can emit nothing is the missing-cell defect this file
	# exists to prevent, wearing the file's own clothes. Found by this lib's own
	# totality check rather than by review.
	local armed="${1-}" wb="${2-}" wa="${3-}" sb="${4-}" sa="${5-}"

	if [[ "$armed" != "armed" ]]; then
		printf 'VOID %s\n' "no screen profile was armed (got '${armed}') — stage_screen_check is gated on has_screen_state(), so the screen stage short-circuits and NOTHING under test ran (#8336 trap 1)"
		return 0
	fi

	local wdelta
	wdelta="$(screen_probe_delta "$wb" "$wa")"
	if [[ -z "$wdelta" ]]; then
		printf 'VOID %s\n' "the witness counter is unreadable (before='${wb}' after='${wa}') — a missing metric, a failed scrape or a helper restart mid-probe. The subject sample cannot be interpreted without it (#8336 trap 3)"
		return 0
	fi
	if (( wdelta == 0 )); then
		printf 'VOID %s\n' "the witness frame did not move its counter — the crafted frames did not reach the screen stage at all (routing, L2, the host stack, or the NIC discarding the header before AF_XDP). A flat subject here means THE MEASUREMENT DID NOT HAPPEN, not that the frame was permitted (#8336 trap 3)"
		return 0
	fi

	local sdelta
	sdelta="$(screen_probe_delta "$sb" "$sa")"
	if [[ -z "$sdelta" ]]; then
		printf 'VOID %s\n' "the witness moved (+${wdelta}) but the subject counter is unreadable (before='${sb}' after='${sa}') — the path is live and the instrument is not"
		return 0
	fi

	if (( sdelta > 0 )); then
		printf 'DROPPED %s\n' "xpf_screen_drops_total +${sdelta} with the witness live (+${wdelta}) — the subject frame reached the screen stage and was dropped"
		return 0
	fi
	printf 'PASSED %s\n' "xpf_screen_drops_total did not move while the witness did (+${wdelta}) — the subject frame REACHED the screen stage and was NOT dropped. This is a result, not an absence of one"
}

# screen_probe_disarm_verdict <node0_count> <node1_count>
#   Print "PASS"/"FAIL" for the post-run cleanup check.
#
#   The cluster is SHARED. A screen profile left bound to a zone changes the
#   environment for every other lane, and config syncs to the peer -- so the
#   check is per-node and BOTH must be clean. A single aggregate count would
#   pass with 0 on one node and a leftover on the other.
screen_probe_disarm_verdict() {
	local n0="${1-}" n1="${2-}"
	for v in "$n0" "$n1"; do
		if [[ ! "$v" =~ ^[0-9]+$ ]]; then
			printf 'FAIL %s\n' "disarm check unreadable (node0='${n0}' node1='${n1}') — cannot confirm the shared cluster was left clean"
			return 0
		fi
	done
	if (( n0 == 0 && n1 == 0 )); then
		printf 'PASS %s\n' "screen profile removed on both nodes"
		return 0
	fi
	printf 'FAIL %s\n' "screen profile still present (node0=${n0} node1=${n1}) — the shared cluster was left armed; remove it before another lane deploys"
}
