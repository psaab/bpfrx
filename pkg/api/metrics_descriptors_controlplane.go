package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initControlPlaneDescriptors() {
	c.neighborPeriodicAge = prometheus.NewDesc(
		"xpf_daemon_neighbor_periodic_last_success_age_seconds",
		"Seconds since each Go periodic neighbor-maintenance phase "+
			"last completed. A monotonically climbing value means that "+
			"phase's guarded goroutine is wedged on a stuck netlink/probe "+
			"syscall (#1780).",
		[]string{"phase"}, nil,
	)
	c.frrReloadDegraded = prometheus.NewDesc(
		"xpf_frr_reload_degraded",
		"1 while the last applied FRR reload fell back to the additive "+
			"vtysh -f path (full frr-reload.py diff failed) and the "+
			"in-manager retry has not yet converged; stale-config "+
			"removal is deferred while set (#1880).",
		nil, nil,
	)
	c.frrPolicyChainsNarrowed = prometheus.NewDesc(
		"xpf_frr_policy_chains_narrowed",
		"Number of BGP policy-chain attachments in the last rendered FRR "+
			"managed section whose applied chain is a strict, non-empty subset "+
			"of what the operator authored, because some member names an "+
			"undefined policy-statement (#8363). Non-zero means those neighbors "+
			"are still filtered but by LESS than was configured — routes are "+
			"NOT withdrawn, which is why this is separate from "+
			"xpf_frr_route_maps_quarantined. Alert on > 0.",
		nil, nil,
	)
	c.frrPolicyChainsNarrowedDenySafe = prometheus.NewDesc(
		"xpf_frr_policy_chains_narrowed_deny_safe",
		"Subset of xpf_frr_policy_chains_narrowed whose undefined members form "+
			"a SUFFIX of the authored chain. For those a synthesized deny would "+
			"be safe; for the complement it would DELETE the surviving members, "+
			"because FRR's composed route-map stops at the first member with a "+
			"terminating default action (#8363). Published to size that decision "+
			"on how often the safe shape occurs. Not an alert on its own.",
		nil, nil,
	)
	c.frrRouteMapsQuarantined = prometheus.NewDesc(
		"xpf_frr_route_maps_quarantined",
		"Number of route-maps in the last rendered FRR managed section that "+
			"were replaced with a bounded explicit DENY because the policy's "+
			"expansion would overflow FRR's sequence ceiling (#5701/#5732/"+
			"#6807). Non-zero means every route on the BGP neighbors carrying "+
			"those attachments is being WITHDRAWN — FRR denies a route-map "+
			"name it cannot otherwise resolve — until the policy is reduced "+
			"or detached. Alert on > 0.",
		nil, nil,
	)
	c.natRulesLenientTerminalAction = prometheus.NewDesc(
		"xpf_nat_rules_lenient_terminal_action",
		"Number of NAT rules in the ACTIVE config that the tolerant load / "+
			"peer-sync / rollback path admitted despite the strict "+
			"terminal-action cardinality gate rejecting them (#5628/#7640). "+
			"Non-zero means this node is running a rule a commit would refuse: "+
			"an ACTIONLESS rule installs no translation and (source NAT) does "+
			"not stop rule evaluation, so matching traffic falls through to any "+
			"later broader rule; a CONTRADICTORY rule has all but one action "+
			"discarded by a fixed precedence the operator did not write. The "+
			"warning that reports this at compile time reaches an operator only "+
			"through a commit response, which a tolerant LOAD does not have — "+
			"so before this gauge the surviving rules were invisible for the "+
			"life of the node. Alert on > 0; `show security nat source rule "+
			"detail` names them.",
		nil, nil,
	)
	c.ipsecRebindPending = prometheus.NewDesc(
		"xpf_ipsec_rebind_pending",
		"1 while the last DHCP-lease-change IPsec rebind failed and has "+
			"not yet reconverged (#4899): a DHCP renewal moved the kernel "+
			"address an IPsec gateway is dynamically bound to "+
			"(external-interface, no explicit local-address), but the "+
			"swanctl re-render/reload failed, so strongSwan keeps binding "+
			"the STALE lease address and the tunnel cannot re-establish. "+
			"The daemon retries the rebind autonomously; 0 once swanctl "+
			"local_addrs reconverge on the current lease.",
		nil, nil,
	)
	// #6802: a failed host-inbound conntrack revocation is deliberately NOT a
	// commit failure — the nft table is already applied, so enforcement for NEW
	// connections holds, and rolling the commit back over a transient conntrack
	// error would discard correct enforcement. But before #6802 it was not
	// anything ELSE either: no return value, no dirty flag, no counter, no
	// metric and no retry owner. These two series are that missing signal.
	c.hostInboundConntrackRevocationPending = prometheus.NewDesc(
		"xpf_host_inbound_conntrack_revocation_pending",
		"1 while a host-inbound kernel-conntrack revocation has failed and "+
			"has not yet been re-driven (#6802). The failure is fail-OPEN: an "+
			"established direct-kernel connection to a service the operator "+
			"has REMOVED keeps riding the host-inbound chain's leading "+
			"`ct state established,related accept`, so a now-denied host "+
			"service stays reachable on that connection. The daemon re-drives "+
			"the owed revocation autonomously every 30s; 0 once it succeeds.",
		nil, nil,
	)
	c.hostInboundConntrackRevocationFailures = prometheus.NewDesc(
		"xpf_host_inbound_conntrack_revocation_failures_total",
		"Total host-inbound kernel-conntrack revocation failures (#6802). "+
			"Counts every failed attempt including retries, so a value that "+
			"climbs while xpf_host_inbound_conntrack_revocation_pending stays "+
			"1 means the retry owner is running but not converging.",
		nil, nil,
	)
	// #6800: an xpf-managed service configuration file converges on disk and the
	// applier then gates its RUNTIME reload on "did the on-disk set change".
	// That gate erased the debt of a FAILED reload — the file was already
	// converged, so every later apply saw no change and skipped the reload — and
	// the node kept serving the previous ruleset with no signal anywhere. These
	// two series are that missing signal; the retry owner is the other half.
	c.managedServiceReloadPending = prometheus.NewDesc(
		"xpf_managed_service_reload_pending",
		"1 while an xpf-managed service configuration file has converged on "+
			"disk but the RUNTIME reload that would load it has not succeeded "+
			"(#6800). Labelled by service: `rsyslog` means the managed "+
			"/etc/rsyslog.d drop-ins are on disk but rsyslog has not re-read "+
			"them, so records may still be flowing to a destination the "+
			"operator REMOVED; `chrony-sources` and `chrony-threshold` mean "+
			"chrony is still running the previous server set or "+
			"logchange/maxchange. The daemon re-drives the owed reload "+
			"autonomously every 30s; 0 once it succeeds.",
		[]string{"service"}, nil,
	)
	c.managedServiceReloadFailures = prometheus.NewDesc(
		"xpf_managed_service_reload_failures_total",
		"Total failed runtime-reload attempts per xpf-managed service (#6800). "+
			"Counts retries too, so a value that climbs while "+
			"xpf_managed_service_reload_pending stays 1 means the retry owner "+
			"is running but not converging — a masked or failed unit, say — "+
			"rather than a single transient failure already paid.",
		[]string{"service"}, nil,
	)
	// #7615: the remaining debt-driven retry owners. Two siblings already
	// publish (#6800, #6802); these complete the family. Proxy-ARP joined in
	// #7685 — not by a drift predicate, which reports a routine self-corrected
	// event, but by the debt its reconcile already held.
	c.raDeadSenderPending = prometheus.NewDesc(
		"xpf_ra_dead_sender_pending",
		"1 while a router-advertisement sender's asynchronous conn open has "+
			"failed and has not yet been rebuilt (#6793). While set, that "+
			"interface is advertising NOTHING and hosts on the segment get no "+
			"default route from this firewall — on a node whose commit reported "+
			"success. The daemon rebuilds it autonomously every 30s; 0 once it "+
			"succeeds.",
		nil, nil,
	)
	c.proxyARPUnresolved = prometheus.NewDesc(
		"xpf_proxy_arp_unresolved_pending",
		"1 while a CONFIGURED proxy-arp interface failed to resolve to a Linux "+
			"netdev on the most recent reconcile (#7685). While set, proxy-arp "+
			"is configured on that interface and the responder is NOT answering "+
			"— the reconcile could not enable it and retains its prior state as "+
			"debt rather than tearing it down (#6536) — on a node whose commit "+
			"reported success. Unlike a drifted sysctl, which the always-on loop "+
			"re-asserts on its next tick, this does not clear until the "+
			"interface exists. 0 once it resolves or proxy-arp is unconfigured.",
		nil, nil,
	)
	c.fabricOverlayMissing = prometheus.NewDesc(
		"xpf_fabric_overlay_missing",
		"1 while a configured fabric IPVLAN (fab0/fab1) is absent or down "+
			"(#6791). While set the node has NO cluster heartbeat and no "+
			"session-sync transport, so a peer cannot distinguish it from a dead "+
			"node. The daemon re-creates it autonomously every 30s; 0 once the "+
			"overlay is present and admin-up.",
		nil, nil,
	)
	c.managementListenerDown = prometheus.NewDesc(
		"xpf_management_listener_down",
		"1 while a management listener the configuration asks for is not "+
			"serving (#6803). This is the failure an operator is least able to "+
			"observe by other means, because the channel they would use to look "+
			"is the channel that is down. The daemon rebinds it autonomously "+
			"every 30s; 0 once it is serving.",
		nil, nil,
	)
	c.schedulerRepublishFailed = prometheus.NewDesc(
		"xpf_scheduler_republish_failed",
		"1 while the most recent scheduler-driven policy republish "+
			"failed and has not yet converged (#3780): stale "+
			"enforcement is live past a schedule window — a scheduled "+
			"permit may still be forwarding after its window closed, or "+
			"a scheduled block never engaged. The daemon retries the "+
			"transition autonomously on each scheduler tick; 0 when the "+
			"enforcement snapshot is in sync with the schedule state.",
		nil, nil,
	)
	c.schedulerRepublishStale = prometheus.NewDesc(
		"xpf_scheduler_republish_stale_seconds",
		"Seconds since the current scheduler-republish failure streak "+
			"began (#3780); 0 when healthy. A climbing value means "+
			"enforcement has been out of sync with the schedule window "+
			"for that long while the daemon retries.",
		nil, nil,
	)
	c.schedulerRepublishFailClosed = prometheus.NewDesc(
		"xpf_scheduler_republish_fail_closed",
		"1 while the scheduler-republish failure streak has persisted past "+
			"the bounded age and the scheduler has escalated to FAIL-CLOSED "+
			"(#5669): scheduled policies are forced inactive (deny) so a "+
			"scheduled permit stops forwarding past its window close instead "+
			"of relying on an eventual republish recovery. 0 when healthy or "+
			"still inside the bounded retry window (xpf_scheduler_republish_"+
			"failed=1, xpf_scheduler_republish_stale_seconds climbing).",
		nil, nil,
	)
	c.configPersistDegraded = prometheus.NewDesc(
		"xpf_daemon_config_persist_degraded",
		"1 while the running active configuration failed to persist "+
			"to disk and the background retry has not yet succeeded "+
			"(a daemon restart would load a stale config, #1799); 0 "+
			"when config persistence is healthy.",
		nil, nil,
	)
	c.rollbackHistoryDegraded = prometheus.NewDesc(
		"xpf_config_rollback_persist_degraded",
		"1 while the most recent commit failed to durably persist its "+
			"text rollback-history files (the canonical rollback "+
			"history, #3441); 0 when healthy. The commit still "+
			"succeeded and the active config is durable (#1799) — this "+
			"flags a degraded recovery aid, not a forwarding outage.",
		nil, nil,
	)
	c.userspacePolicyContentRejected = prometheus.NewDesc(
		"xpf_userspace_policy_content_rejected",
		"1 while the most recently built userspace snapshot carries "+
			"unrepresentable policy content (a policy names an "+
			"application protocol/port or address the matcher cannot "+
			"represent) that the helper integrity preflight rejects "+
			"(#3261). The helper stays armed and retains the "+
			"previous-good policy state (a fresh boot lands on "+
			"default-deny) — it never fails open to the kernel. Nonzero "+
			"means the running dataplane policy is NOT the committed "+
			"config; edit out the offending application/address and "+
			"re-commit. 0 when the last build was fully representable.",
		nil, nil,
	)
	c.userspaceZoneIDCollision = prometheus.NewDesc(
		"xpf_userspace_zone_id_collision",
		"1 while the most recently built userspace snapshot QUARANTINED "+
			"one or more security zones because two zone names fold to the "+
			"same StableZoneID (#3719). The strict commit path rejects a "+
			"collision; this fires only on the lenient / HA-sync / "+
			"pre-#3075-persisted path, where the later-sorting zone is "+
			"dropped from the dataplane (its interfaces unzoned, its "+
			"traffic denied) so two zones never share an id. The dataplane "+
			"is fail-closed, but zone isolation is DEGRADED (the "+
			"quarantined zone forwards nothing) until an operator renames "+
			"one zone and re-commits. 0 when every zone has a distinct id.",
		nil, nil,
	)
	c.rpmPinInstallFailures = prometheus.NewDesc(
		"xpf_rpm_probe_pin_install_failures",
		"Number of RPM next-hop probe pins whose kernel fwmark rule / "+
			"pinned route failed to install. Affected tests hold their "+
			"prior state (ErrProbeSetup) instead of probing the default "+
			"path, so a nonzero value means those uplinks are NOT being "+
			"health-checked (#1895).",
		nil, nil,
	)
}
