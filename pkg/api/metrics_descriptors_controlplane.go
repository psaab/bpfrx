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
