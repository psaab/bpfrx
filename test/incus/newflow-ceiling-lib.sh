#!/usr/bin/env bash
# Node-selection verdict for the #4800 new-flow ceiling harness (#6962).
#
# WHY THIS EXISTS
#
# `newflow-ceiling-harness.sh` must read NAT-pool and Prometheus counters off
# the node that actually installs the sessions. It picked that node with:
#
#     for fw in "$FW0" "$FW1"; do
#         if incus_cmd exec "$fw" -- cli -c "show chassis cluster status" \
#             | grep -qi "primary"; then ACTIVE_FW="$fw"; break; fi
#     done
#
# `show chassis cluster status` prints BOTH nodes' rows on whichever node you
# ask (pkg/cluster/status.go FormatStatus emits the local node row and then the
# peer's). So node0's own output contains node1's row:
#
#     Node name: node0
#     Redundancy group: 0 , Failover count: 1
#     node0   100      secondary      yes      no       None
#     node1   200      primary        yes      no       None
#
# The unanchored grep matches the PEER's row, `ACTIVE_FW=$FW0`, `break`. $FW0
# therefore always wins regardless of who is primary. This is not a
# `secondary`-contains-`primary` substring artifact — there is no node token in
# the pattern at all, so the pattern cannot tell whose row it matched.
#
# It FAILS TO A PLAUSIBLE VALUE, not to an error: the harness prints
# "active node = xpf-userspace-fw0" and proceeds. Downstream the analyzer's
# zero-allocations gate refuses the cell as INVALID, so the cost is a wasted run
# under the shared cluster lock that looks like a dataplane problem. A fix
# verified by "the harness now reports a node" proves nothing — it reported one
# before. The selftest fixture therefore has node0 and node1 carrying DIFFERENT
# states, which is the only shape in which the anchor is load-bearing.
#
# WHAT "PRIMARY" HAS TO MEAN HERE
#
# Not "primary for some redundancy group". On the loss userspace cluster the
# measured path spans TWO RGs — reth0 (WAN, `redundancy-group 1`) and reth1
# (LAN, `redundancy-group 2`), per docs/ha-cluster-userspace.conf — so a node
# that owns only one of them installs only part of the flows and its pool
# counters describe half a measurement. That is the same wrong-node error one
# level in, and it would be invisible for the same reason: the run completes and
# prints numbers.
#
# So the verdict is: the LOCAL node's row reads `primary` in EVERY redundancy
# group the status reports. A split (active/active) cluster yields NOT-PRIMARY
# from both nodes and the harness refuses the run, naming the split — rather
# than measuring a node that owns half the path. There is deliberately no
# `--rg` selector: the harness reads one node's counters for the whole path, so
# "measure the node that owns RG N only" is not a question its output can
# answer.
#
# Depends on nothing but bash + awk, so newflow-ceiling-selftest.sh
# (`make test-newflow-ceiling-lib`) is hermetic — no cluster, no incus.

# newflow_cluster_primary_verdict <show-chassis-cluster-status-output>
#
#   Print exactly one line:
#
#     PRIMARY     <msg>   the local node owns EVERY redundancy group
#     NOT-PRIMARY <msg>   the status was readable and the answer is no
#     UNKNOWN     <msg>   the status could not be read as a status at all
#
#   TOTAL BY CONSTRUCTION — every path prints exactly one verdict line, so this
#   can never be the silent hole the bare grep was. UNKNOWN and NOT-PRIMARY are
#   kept apart on purpose: they are the same decision for the harness (do not
#   select this node) and different diagnoses for the operator ("I could not
#   read the instrument" vs "I read it and this node is the standby").
newflow_cluster_primary_verdict() {
	local status="${1-}"
	if [[ -z "${status//[[:space:]]/}" ]]; then
		printf 'UNKNOWN %s\n' "cluster status was EMPTY — the node did not answer 'show chassis cluster status' (down, cli missing, or incus exec failed), so nothing about its role is known"
		return 0
	fi
	awk '
	{
		line = $0
		sub(/^[ \t]+/, "", line)
		low = tolower(line)

		# "Node name: nodeN" — the LOCAL node, the whole point of the anchor.
		# Mirrors parseLocalNodeID in pkg/upgrade/cluster_cli.go.
		if (low ~ /^node name:/) {
			n = split(line, f, /[ \t]+/)
			tok = tolower(f[n])
			if (tok ~ /^node[0-9]+$/) local = tok
			next
		}

		# "Redundancy group: N , Failover count: M".
		#
		# A header whose id does not parse is FAIL-CLOSED: the verdict this lib
		# exists to give is "the local node owns EVERY redundancy group", and a
		# group we could not read is a group whose ownership is unknown, so the
		# END block returns UNKNOWN rather than answering about the groups that
		# happened to parse. The `cur = ""` alongside it is DEFENSIVE, not
		# load-bearing under that policy: it stops the rows after a malformed
		# header being attributed to the PREVIOUS group (the same reset the Go
		# parser does, pkg/upgrade/cluster_cli.go), which would matter again the
		# moment anyone relaxes the UNKNOWN. No selftest cell can isolate it
		# while the fail-closed verdict dominates, and it is kept for that
		# reason rather than because a test proves it.
		if (low ~ /^redundancy group:/) {
			n = split(line, f, /[ \t]+/)
			if (n >= 3 && f[3] ~ /^[0-9]+$/) {
				cur = f[3]
				if (!(cur in seen)) { seen[cur] = 1; order[++nrg] = cur }
			} else {
				cur = ""
				malformed++
			}
			next
		}

		# A node row: "nodeN  <prio>  <state>  <preempt> <manual> <mon>".
		# Anchored on field 1, so the PEER row can never answer for the local
		# node — and the "  Takeover ready: ..." / "Held secondary: ..." lines,
		# whose free-text reasons could contain any word, are not node rows.
		n = split(line, f, /[ \t]+/)
		if (n >= 3 && cur != "" && tolower(f[1]) ~ /^node[0-9]+$/) {
			if (local != "" && tolower(f[1]) == local) {
				state[cur] = tolower(f[3])
				sawlocal[cur] = 1
			}
		}
	}
	END {
		if (local == "") {
			printf "UNKNOWN %s\n", "no \"Node name: nodeN\" line in the status — the local node cannot be identified, so no row can be attributed to it (this is the header FormatStatus always emits; its absence means the output is not a cluster status)"
			exit 0
		}
		if (malformed > 0) {
			printf "UNKNOWN %s\n", "status contains " malformed " unparseable \"Redundancy group:\" header(s) — a group whose id cannot be read is a group whose ownership is unknown, and this verdict is about owning EVERY group"
			exit 0
		}
		if (nrg == 0) {
			printf "UNKNOWN %s\n", "status names the local node " local " but contains no \"Redundancy group:\" block — there is no row to read a role from"
			exit 0
		}
		seen_local = 0
		for (i = 1; i <= nrg; i++) if (sawlocal[order[i]]) seen_local++
		if (seen_local == 0) {
			printf "UNKNOWN %s\n", "status has " nrg " redundancy group(s) but no row for " local " in any of them — the node cannot report on itself"
			exit 0
		}
		summary = ""
		notprimary = ""
		missing = ""
		for (i = 1; i <= nrg; i++) {
			rg = order[i]
			if (!sawlocal[rg]) {
				summary = summary sprintf("%srg%s=<no row>", (summary == "" ? "" : " "), rg)
				missing = missing sprintf("%srg%s", (missing == "" ? "" : ","), rg)
				continue
			}
			summary = summary sprintf("%srg%s=%s", (summary == "" ? "" : " "), rg, state[rg])
			if (state[rg] != "primary") {
				notprimary = notprimary sprintf("%srg%s", (notprimary == "" ? "" : ","), rg)
			}
		}
		if (missing != "") {
			printf "NOT-PRIMARY %s\n", local " has no row in redundancy group(s) " missing " (" summary ") — ownership of the whole measured path cannot be confirmed, so this node is not selectable"
			exit 0
		}
		if (notprimary != "") {
			printf "NOT-PRIMARY %s\n", local " is not primary for redundancy group(s) " notprimary " (" summary ")"
			exit 0
		}
		printf "PRIMARY %s\n", local " is primary for every redundancy group (" summary ")"
	}
	' <<<"$status"
}

# newflow_select_active_node <name0> <verdict0> <name1> <verdict1>
#
#   Decide which node the harness measures, from the two verdict lines above.
#   Print exactly one line: "SELECT <name>" or "REFUSE <msg>".
#
#   Both nodes are evaluated before deciding. The loop this replaces broke on
#   the first match, which meant $FW0 was answered for and $FW1 was never asked
#   — so the two states that most need naming, "neither node owns the path"
#   (a split cluster) and "both claim to" (split-brain), were unreachable: the
#   first was reported as "no node reports primary for the tested RG" with no
#   evidence, and the second silently measured $FW0.
#
#   TOTAL BY CONSTRUCTION, and every REFUSE carries both nodes' verdict text,
#   because the cost of this decision is a wasted run under the shared cluster
#   lock and the operator has to be able to tell WHY from the log alone.
newflow_select_active_node() {
	local n0="$1" v0="$2" n1="$3" v1="$4"
	local w0="${v0%% *}" w1="${v1%% *}"
	if [[ "$w0" == "PRIMARY" && "$w1" == "PRIMARY" ]]; then
		printf 'REFUSE %s\n' "BOTH nodes report primary for every redundancy group — the cluster is split-brain, and whichever node were measured the other would be installing flows too. ${n0}: ${v0} | ${n1}: ${v1}"
		return 0
	fi
	if [[ "$w0" == "PRIMARY" ]]; then
		printf 'SELECT %s\n' "$n0"
		return 0
	fi
	if [[ "$w1" == "PRIMARY" ]]; then
		printf 'SELECT %s\n' "$n1"
		return 0
	fi
	printf 'REFUSE %s\n' "no node is primary for EVERY redundancy group, so no single node installs the whole measured path. ${n0}: ${v0} | ${n1}: ${v1}"
}
