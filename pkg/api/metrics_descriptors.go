package api

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func newCollector(srv *Server) *xpfCollector {
	return &xpfCollector{
		srv: srv,

		packetsTotal: prometheus.NewDesc(
			"xpf_packets_total",
			"Total packets processed.",
			[]string{"direction"}, nil,
		),
		dropsTotal: prometheus.NewDesc(
			"xpf_drops_total",
			// #4508: enforcement drops only — policy deny + screen/IDS +
			// host-inbound deny + source-NAT alloc fail (the GlobalCtrDrops
			// bridge, #4477). This does NOT include no-route/missing-neighbor,
			// fabric-forwarding (idx 32), VLAN-push (idx 40), or NAT64
			// fail-closed drops, so it undercounts total discards. No-route
			// drops surface separately in the userspace helper status
			// ("Route misses"). Kept the mirror of the vSRX "Packets dropped"
			// field name/scope; see docs/junos-cli-reference.md.
			"Packets dropped by enforcement (policy deny, screen/IDS, "+
				"host-inbound deny, source-NAT alloc fail). Does NOT include "+
				"no-route, fabric-forwarding, VLAN-push, or NAT64 fail-closed "+
				"drops, so it undercounts total discards.",
			nil, nil,
		),
		// #3345/#3408: scrape-error signal for counter reads across the global,
		// per-zone, per-policy, and per-filter dataplane collectors AND the
		// kernel-nftables host-inbound collector (#3361, pre-gate). A failed read
		// omits the affected counter sample instead of emitting a misleading 0,
		// and bumps this monotonic counter so a degraded counter bridge is
		// alertable rather than silently reported as zero. #3463: the descriptor
		// text names every read surface that increments this counter — including
		// the host-inbound kernel-nftables read — so an operator runbook built on
		// it does not misdiagnose a zone/policy/filter or host-inbound counter
		// failure as global-only.
		counterReadErrorsTotal: prometheus.NewDesc(
			"xpf_counter_read_errors_total",
			"Total counter read failures during metric scrapes (global, zone, "+
				"policy, and filter dataplane reads, plus kernel-nftables "+
				"host-inbound reads).",
			nil, nil,
		),
		sessionsCreatedTotal: prometheus.NewDesc(
			"xpf_sessions_created_total",
			"Total sessions created.",
			nil, nil,
		),
		sessionsClosedTotal: prometheus.NewDesc(
			"xpf_sessions_closed_total",
			"Total sessions closed.",
			nil, nil,
		),
		screenDropsTotal: prometheus.NewDesc(
			"xpf_screen_drops_total",
			"Total packets dropped by screen/IDS checks.",
			nil, nil,
		),
		// #3343: per-reason breakdown of screen/IDS drops. The aggregate
		// xpf_screen_drops_total cannot attribute a drop to a specific screen
		// check; this labeled series can (reason = syn-flood, port-scan,
		// session-limit, ...). Each reason maps to a dataplane.GlobalCtrScreen*
		// counter now populated by the userspace counter bridge (#3343).
		screenDropsByReasonTotal: prometheus.NewDesc(
			"xpf_screen_drops_by_reason_total",
			"Total packets dropped by screen/IDS checks, by reason.",
			[]string{"reason"}, nil,
		),
		policyDeniesTotal: prometheus.NewDesc(
			"xpf_policy_denies_total",
			"Total packets denied by policy.",
			nil, nil,
		),
		natAllocFailsTotal: prometheus.NewDesc(
			"xpf_nat_alloc_failures_total",
			"Total NAT port allocation failures.",
			nil, nil,
		),
		nat64XlateTotal: prometheus.NewDesc(
			"xpf_nat64_translations_total",
			"Total NAT64 (IPv6<->IPv4) packet translations.",
			nil, nil,
		),
		hostInboundDeny: prometheus.NewDesc(
			"xpf_host_inbound_denies_total",
			"Total host-inbound traffic denials on the userspace-dp (AF_XDP) path.",
			nil, nil,
		),
		// #3361: host-bound traffic to a firewall interface IP / VRRP VIP is
		// shunted to the kernel by the XDP shim before userspace-dp sees it, so
		// the PRIMARY host-inbound enforcement is the kernel nftables
		// `inet xpf_hostinbound` chain. Its catch-all DROP rules now carry a
		// named per-zone/family nft counter (pkg/daemon/daemon_nft.go), scraped
		// here. This is a DISTINCT enforcement path from
		// xpf_host_inbound_denies_total (the userspace-dp #3326 path) — they are
		// not double counts. The counter resets when the daemon rebuilds the
		// table (every commit / DHCP address change); Prometheus rate() handles
		// the reset.
		hostInboundKernelDenies: prometheus.NewDesc(
			"xpf_host_inbound_kernel_denies_total",
			"Total host-inbound traffic denials by the kernel nftables host-inbound "+
				"chain, per zone/family (distinct from the userspace-dp "+
				"xpf_host_inbound_denies_total path).",
			[]string{"zone", "family"}, nil,
		),
		// #4146: per-scope/family drop counters for the kernel `to-zone
		// junos-host` DENY rules on the same `inet xpf_hostinbound` chain. These
		// are the fine per-source/per-application host-inbound denies enforced on
		// the DIRECT host-bound path — DISTINCT from xpf_host_inbound_kernel_denies
		// _total (coarse "no service opened this") and from the userspace-dp
		// xpf_host_inbound_denies_total path, so the three do not double-count.
		// This does NOT populate per-Junos-policy hit counters / `then count` /
		// RT_FLOW deny attribution (nft cannot attribute a drop to a policy object,
		// #4146 §6.7). The counter resets on table rebuild; rate() handles it. On a
		// read failure the series is skipped and xpf_counter_read_errors_total is
		// bumped.
		hostInboundJunosHostDenies: prometheus.NewDesc(
			"xpf_host_inbound_junos_host_denies_total",
			"Total direct host-bound traffic denials by the kernel nftables "+
				"`to-zone junos-host` DENY rules, per ingress-zone scope and family "+
				"(distinct from the coarse xpf_host_inbound_kernel_denies_total and "+
				"the userspace-dp xpf_host_inbound_denies_total paths).",
			[]string{"scope", "family"}, nil,
		),
		// #4759: per-type-class hit counters for the GLOBAL ICMP-error / ND accept
		// rules on the same kernel `inet xpf_hostinbound` chain. Those rules admit
		// ICMPv6 Neighbor Discovery (types 133-137), ICMPv6 error/PMTUD (types
		// 1-4), and ICMPv4 error/PMTUD (destination-unreachable, time-exceeded,
		// parameter-problem) regardless of any per-zone host-inbound service set,
		// so core L3 operation is never black-holed; before #4759 those accepts
		// were UNCOUNTED. The counts are AGGREGATE — the accept rules are GLOBAL,
		// not per-zone, so there is no per-zone `type` breakdown (a per-zone split
		// would need per-zone rule duplication, the #4759 Low-severity caveat).
		// The counter resets when the daemon rebuilds the table (every commit /
		// DHCP address change); Prometheus rate() handles the reset. On a read
		// failure the series is skipped (no misleading 0) and
		// xpf_counter_read_errors_total is bumped.
		hostInboundICMPNDAccept: prometheus.NewDesc(
			"xpf_host_inbound_icmp_nd_accept_total",
			"Total ICMP-error / ND control-message accepts by the kernel nftables "+
				"host-inbound chain, per type-class (icmp6_nd, icmp6_error, "+
				"icmp4_error). Aggregate across all zones (the accept rules are "+
				"global, not per-zone).",
			[]string{"type"}, nil,
		),
		// #3698: 1 while a configured host-inbound-enforcing zone is in the
		// transient fail-open admit window — it has a non-lifeline interface but
		// no resolvable address yet (DHCP WAN before first lease, backup node
		// before VIP install), so the kernel host-inbound chain emits no deny for
		// it. A control-plane signal (config-derived, independent of dataplane
		// load), emitted BEFORE the dataplane gate in Collect. The series is
		// present only for zones currently in the window (absent = enforced), so
		// `max_over_time(...)` alerts on any zone that ever fails open.
		hostInboundAddresslessZones: prometheus.NewDesc(
			"xpf_host_inbound_addressless_zones",
			"1 while a configured host-inbound-enforcing zone has no resolvable "+
				"address yet and is therefore omitted from host-inbound deny "+
				"scoping (transient fail-open admit window), labeled by zone.",
			[]string{"zone"}, nil,
		),
		// #3710: the per-interface/per-family refinement of the addressless-zone
		// signal above. 1 while a non-lifeline logical unit in a configured
		// host-inbound-enforcing zone has a DHCP/DHCPv6 client configured for a
		// family but has not yet resolved an address in that family — a transient
		// fail-open window that the zone-level series hides whenever an addressed
		// sibling interface (or the other family) already scopes the zone.
		// Config-derived, independent of dataplane load, emitted BEFORE the
		// dataplane gate. Present only while the window is open (absent =
		// enforced), labeled by zone, interface (logical unit), family and reason.
		hostInboundAddresslessIface: prometheus.NewDesc(
			"xpf_host_inbound_addressless_interfaces",
			"1 while a non-lifeline interface unit in a configured host-inbound-"+
				"enforcing zone has a DHCP/DHCPv6 client for a family but no "+
				"resolved address in that family yet (per-interface/per-family "+
				"transient fail-open admit window, #3710), labeled by zone, "+
				"interface, family and reason.",
			[]string{"zone", "interface", "family", "reason"}, nil,
		),
		// #3718 (Option B): 1 per firewall-local address that is
		// host-inbound-reachable from more than one security zone with DIFFERING
		// host-inbound service/protocol sets. The kernel host-inbound nftables
		// chain matches on destination address only (no ingress predicate) over a
		// single global input chain, so such an address's admission verdict is
		// decided order-dependently by whichever zone sorts first, and can
		// disagree with the ingress-scoped userspace-dp path (split-brain). The
		// strict commit gate hard-rejects this; a tolerant / peer-synced load
		// (#1960) can slip one through, and unlike the addressless window it is
		// NOT self-healing — so this control-plane signal (config-derived,
		// emitted BEFORE the dataplane gate) stays 1 until the ambiguity is
		// resolved. Absent = no ambiguous address.
		hostInboundAmbiguousAddrs: prometheus.NewDesc(
			"xpf_host_inbound_ambiguous_addresses",
			"1 per firewall-local address that is host-inbound-reachable from "+
				"multiple security zones with differing host-inbound service/"+
				"protocol sets, making the kernel destination-address-only "+
				"host-inbound verdict order-dependent (#3718), labeled by "+
				"address and family.",
			[]string{"address", "family"}, nil,
		),
		// #4422: per-`then count` hit counters for the kernel lo0 loopback input
		// filter (`inet xpf_lo0` table). lo0 host-inbound traffic is enforced by
		// the KERNEL nftables chain (not the userspace fast path), so its
		// firewall-filter `then count <name>` counts live in nft named-counter
		// objects, DISTINCT from xpf_filter_hits_total (which merges the
		// userspace-dp fast-path per-term hits for data-interface filters,
		// including FBF steering). Before #4422 nothing scraped the lo0 counters.
		// The table is installed independent of dataplane load, so this is a
		// control-plane signal emitted BEFORE the dataplane gate. The counter
		// object is shared by name across terms/families (Junos named-counter
		// semantics), so the series is labeled by the count name only. Counters
		// reset on every table rebuild (commit / DHCP re-render); rate() handles
		// the reset. On a read failure the series is skipped (no misleading 0) and
		// xpf_counter_read_errors_total is bumped.
		lo0CounterHits: prometheus.NewDesc(
			"xpf_lo0_counter_hits_total",
			"Total lo0 loopback input-filter hits by firewall-filter `then count` "+
				"name, read from the kernel nftables lo0 chain (distinct from the "+
				"userspace-dp xpf_filter_hits_total fast-path counters).",
			[]string{"counter"}, nil,
		),
		// #4422: policy-based-routing (filter-based-forwarding) build health.
		// xpf_pbr_rules_installed is the number of kernel `ip rule` FBF entries
		// the active config's routing-instance filter terms yield (the
		// desired-install set). Config-derived (routing.PBRBuildStats, a pure
		// function of config), emitted BEFORE the dataplane gate.
		pbrRulesInstalled: prometheus.NewDesc(
			"xpf_pbr_rules_installed",
			"Number of kernel ip-rule filter-based-forwarding entries the active "+
				"config's routing-instance filter terms yield (#4422).",
			nil, nil,
		),
		// #4422: number of routing-instance filter terms DROPPED from the kernel
		// FBF mirror (fail-closed under-steer to the main table) — an
		// unrepresentable except set, a DSCP-0 match, a contradictory
		// routing-instance+discard/reject term (#4534), an ip-rule-unrepresentable
		// L4/per-packet predicate (#3730), or the priority-window overflow (#3430
		// M3). Non-zero means the kernel slow path under-steers vs the userspace
		// fast path (which still enforces every term exactly). There is no
		// "widened" state — the builder refuses to widen an unrepresentable match.
		pbrDegradedTerms: prometheus.NewDesc(
			"xpf_pbr_degraded_terms",
			"Number of routing-instance filter terms dropped from the kernel "+
				"filter-based-forwarding mirror (fail-closed under-steer), because "+
				"the term carries a predicate an ip rule cannot express (#4422).",
			nil, nil,
		),
		tcEgressPacketsTotal: prometheus.NewDesc(
			"xpf_tc_egress_packets_total",
			"Total TC egress packets processed.",
			nil, nil,
		),
		syncookieTotal: prometheus.NewDesc(
			"xpf_screen_syncookie_total",
			"SYN cookie counters by type.",
			[]string{"type"}, nil,
		),
		flowCacheTotal: prometheus.NewDesc(
			"xpf_flow_cache_total",
			"Flow cache counters by type (IPv4 + IPv6).",
			[]string{"type"}, nil,
		),
		ifacePacketsTotal: prometheus.NewDesc(
			"xpf_interface_packets_total",
			"Total packets per interface.",
			[]string{"iface", "direction"}, nil,
		),
		ifaceBytesTotal: prometheus.NewDesc(
			"xpf_interface_bytes_total",
			"Total bytes per interface.",
			[]string{"iface", "direction"}, nil,
		),
		// #3464: per-interface counter-read scrape-error signal. A failed
		// ReadInterfaceCounters OMITS that interface's xpf_interface_* samples
		// (rather than emitting a misleading 0) and bumps this monotonic
		// counter, so a degraded interface-counter bridge is alertable instead
		// of silently reported as zero. Distinct from
		// xpf_counter_read_errors_total: interface counters are intentionally
		// out of the #3345 security-counter contract, so they get their own
		// error metric (always emitted, 0 when healthy).
		interfaceCounterReadErrorsTotal: prometheus.NewDesc(
			"xpf_interface_counter_read_errors_total",
			"Total per-interface dataplane counter read failures during metric "+
				"scrapes. A failed read omits that interface's xpf_interface_* "+
				"samples instead of emitting a misleading 0. Distinct from "+
				"xpf_counter_read_errors_total (interface counters are not "+
				"security counters; #3464).",
			nil, nil,
		),
		policyHitsTotal: prometheus.NewDesc(
			"xpf_policy_hits_total",
			"Total policy rule hits.",
			[]string{"from_zone", "to_zone", "rule"}, nil,
		),
		filterHitsTotal: prometheus.NewDesc(
			"xpf_filter_hits_total",
			"Total firewall filter term hits.",
			[]string{"filter", "family", "term"}, nil,
		),
		threeColorPolicerPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_packets_total",
			"Userspace three-color policer packets by resulting color.",
			[]string{"policer", "color"}, nil,
		),
		threeColorPolicerBytesTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_bytes_total",
			"Userspace three-color policer bytes by resulting color.",
			[]string{"policer", "color"}, nil,
		),
		threeColorPolicerDropsTotal: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drops_total",
			"Userspace three-color policer packets dropped by policer treatment.",
			[]string{"policer"}, nil,
		),
		threeColorPolicerDropBytes: prometheus.NewDesc(
			"xpf_userspace_three_color_policer_drop_bytes_total",
			"Userspace three-color policer bytes dropped by policer treatment.",
			[]string{"policer"}, nil,
		),
		sessionsActive: prometheus.NewDesc(
			"xpf_sessions_active",
			"Current number of active session entries.",
			nil, nil,
		),
		sessionsEstablished: prometheus.NewDesc(
			"xpf_sessions_established",
			"Current number of established sessions.",
			nil, nil,
		),
		sessionsIPv4: prometheus.NewDesc(
			"xpf_sessions_ipv4",
			"Current number of IPv4 sessions.",
			nil, nil,
		),
		sessionsIPv6: prometheus.NewDesc(
			"xpf_sessions_ipv6",
			"Current number of IPv6 sessions.",
			nil, nil,
		),
		sessionsSNAT: prometheus.NewDesc(
			"xpf_sessions_snat",
			"Current number of SNAT sessions.",
			nil, nil,
		),
		sessionsDNAT: prometheus.NewDesc(
			"xpf_sessions_dnat",
			"Current number of DNAT sessions.",
			nil, nil,
		),
		sessionScrapeOK: prometheus.NewDesc(
			"xpf_sessions_breakdown_scrape_ok",
			"1 if the last session-breakdown scrape (ipv4/ipv6/snat/dnat gauges) "+
				"enumerated the full session table; 0 if a backend iterator "+
				"error truncated the scan (the breakdown gauges are then omitted).",
			nil, nil,
		),
		gcSweepDuration: prometheus.NewDesc(
			"xpf_gc_sweep_duration_seconds",
			"Duration of the last GC sweep in seconds.",
			nil, nil,
		),
		natPoolUsedPorts: prometheus.NewDesc(
			"xpf_nat_pool_used_ports",
			"Number of used ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolTotalPorts: prometheus.NewDesc(
			"xpf_nat_pool_total_ports",
			"Total available ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolDeterministicInfo: prometheus.NewDesc(
			"xpf_nat_pool_deterministic_info",
			"Deterministic NAT pool configuration (1 = enabled).",
			[]string{"pool", "block_size", "host_count"}, nil,
		),
		natPoolDetBlocksTotal: prometheus.NewDesc(
			"xpf_nat_deterministic_pool_blocks_total",
			"Total per-subscriber port-block capacity of a deterministic NAT "+
				"pool (pool addresses x floor(port-range / block-size)). The "+
				"denominator for deterministic-pool block utilization; the "+
				"pool-wide xpf_nat_pool_used_ports metric is meaningless for a "+
				"deterministic pool (#4752).",
			[]string{"pool"}, nil,
		),
		natPoolDetBlocksAllocated: prometheus.NewDesc(
			"xpf_nat_deterministic_pool_blocks_allocated",
			"Port blocks statically allocated to the provisioned subscriber "+
				"range of a deterministic NAT pool (one block per subscriber). "+
				"The numerator for block utilization: divide by "+
				"xpf_nat_deterministic_pool_blocks_total and alarm as it "+
				"approaches 1.0 (#4752).",
			[]string{"pool"}, nil,
		),
		userspaceSNATPoolLiveFlows: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_live_flows",
			"Live source NAT pool flow allocations tracked by the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolUsedPorts: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_used_ports",
			"Source NAT pool translated ports currently owned by the userspace dataplane allocator.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolPersistentLeases: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_persistent_leases",
			"Persistent source NAT leases retained by the userspace dataplane allocator.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolAllocationsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_allocations_total",
			"Total new source NAT pool translated tuple allocations by the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolReusesTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_reuses_total",
			"Total source NAT pool live or persistent lease reuses by the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		userspaceSNATPoolExhaustionsTotal: prometheus.NewDesc(
			"xpf_userspace_source_nat_pool_exhaustions_total",
			"Total source NAT pool allocator exhaustion events in the userspace dataplane.",
			[]string{"pool", "rule"}, nil,
		),
		dhcpLeasesActive: prometheus.NewDesc(
			"xpf_dhcp_leases_active",
			"Number of active DHCP leases.",
			[]string{"family"}, nil,
		),

		// #1387 inc-2: DHCP dynamic-DNS counters. Label cardinality is
		// CLOSED (plan §4.4 m4): result in {ok,fail}; reason in
		// {no-name,no-backend,conflict,ptr-notauth,ptr-deferred,coowned} —
		// never a raw rcode. "coowned" (#5709) counts wire deletes suppressed
		// because the RR is still co-owned by another DDNS scope.
		dhcpDDNSUpsertsTotal: prometheus.NewDesc(
			"xpf_dhcp_ddns_upserts_total",
			"Total DHCP dynamic-DNS forward/reverse record upserts by result.",
			[]string{"result"}, nil,
		),
		dhcpDDNSDeletesTotal: prometheus.NewDesc(
			"xpf_dhcp_ddns_deletes_total",
			"Total DHCP dynamic-DNS record deletes by result.",
			[]string{"result"}, nil,
		),
		dhcpDDNSReconcileRunsTotal: prometheus.NewDesc(
			"xpf_dhcp_ddns_reconcile_runs_total",
			"Total DHCP dynamic-DNS reconcile passes by result.",
			[]string{"result"}, nil,
		),
		dhcpDDNSSkippedTotal: prometheus.NewDesc(
			"xpf_dhcp_ddns_skipped_total",
			"Total DHCP dynamic-DNS records skipped by reason.",
			[]string{"reason"}, nil,
		),
		dhcpDDNSOwnedRecords: prometheus.NewDesc(
			"xpf_dhcp_ddns_owned_records",
			"Current number of DHCP dynamic-DNS records this node owns in DNS.",
			nil, nil,
		),
		dhcpDDNSPTRPending: prometheus.NewDesc(
			"xpf_dhcp_ddns_ptr_pending",
			"Current number of owned DHCP dynamic-DNS records whose forward "+
				"A/AAAA is published but whose reverse PTR is still owed "+
				"(distinct from the cumulative ptr-deferred counter; #2708).",
			nil, nil,
		),
		dhcpDDNSDegraded: prometheus.NewDesc(
			"xpf_dhcp_ddns_degraded",
			"1 when the DHCP dynamic-DNS ownership state failed to load "+
				"(corrupt / unsupported-version / unreadable) and the manager is "+
				"FAILING CLOSED: publishing and withdrawals are suspended until the "+
				"operator resolves the quarantined state file (#2650).",
			nil, nil,
		),
		dhcpDDNSLastReconcileTs: prometheus.NewDesc(
			"xpf_dhcp_ddns_last_reconcile_timestamp_seconds",
			"Unix timestamp of the last DHCP dynamic-DNS reconcile pass.",
			nil, nil,
		),
		dhcpDDNSLastReconcileN: prometheus.NewDesc(
			"xpf_dhcp_ddns_last_reconcile_leases",
			"Active leases seen on the last DHCP dynamic-DNS reconcile pass.",
			nil, nil,
		),

		surfaceADDNSUpsertsTotal: prometheus.NewDesc(
			"xpf_ddns_surface_a_upserts_total",
			"Total Surface A (router/interface-address) DDNS publishes by result.",
			[]string{"result"}, nil,
		),
		surfaceADDNSDeletesTotal: prometheus.NewDesc(
			"xpf_ddns_surface_a_deletes_total",
			"Total Surface A DDNS record withdrawals by result.",
			[]string{"result"}, nil,
		),
		surfaceADDNSSkippedTotal: prometheus.NewDesc(
			"xpf_ddns_surface_a_skipped_total",
			"Total Surface A DDNS reconcile skips by reason.",
			[]string{"reason"}, nil,
		),
		surfaceADDNSScopes: prometheus.NewDesc(
			"xpf_ddns_surface_a_scopes",
			"Current number of Surface A DDNS records this node owns in DNS.",
			nil, nil,
		),
		surfaceADDNSOrphaned: prometheus.NewDesc(
			"xpf_ddns_surface_a_orphaned",
			"Current number of Surface A DDNS records stale at a PREVIOUS provider "+
				"endpoint that a provider identity change (rename to a different "+
				"endpoint / in-place server-zone edit / removed binding after an edit) "+
				"left un-withdrawable through the current catalog (#3735). Non-zero "+
				"means an old record needs MANUAL operator cleanup — auto-withdrawal is "+
				"deferred (old creds are redacted and the old endpoint is usually gone).",
			nil, nil,
		),
		surfaceADDNSDegraded: prometheus.NewDesc(
			"xpf_ddns_surface_a_degraded",
			"1 when the Surface A DDNS ownership state is unloadable and the "+
				"manager is fail-closed (publishing/withdrawals suspended), else 0.",
			nil, nil,
		),

		sysCPUUser: prometheus.NewDesc(
			"xpf_system_cpu_user_percent",
			// #4707: inter-scrape delta (busyΔ/totalΔ), scaled by CPU count,
			// NOT the since-boot cumulative average. Not emitted on the first
			// scrape (no predecessor sample yet).
			"User+nice CPU utilization percentage over the last scrape interval "+
				"(summed across CPUs).",
			nil, nil,
		),
		sysCPUSystem: prometheus.NewDesc(
			"xpf_system_cpu_system_percent",
			// #4707: inter-scrape delta (busyΔ/totalΔ), scaled by CPU count.
			"System CPU utilization percentage over the last scrape interval "+
				"(summed across CPUs).",
			nil, nil,
		),
		sysMemTotal: prometheus.NewDesc(
			"xpf_system_memory_total_bytes",
			"Total system memory in bytes.",
			nil, nil,
		),
		sysMemAvail: prometheus.NewDesc(
			"xpf_system_memory_available_bytes",
			"Available system memory in bytes.",
			nil, nil,
		),
		daemonUptime: prometheus.NewDesc(
			"xpf_daemon_uptime_seconds",
			"Daemon uptime in seconds.",
			nil, nil,
		),
		daemonMemRSS: prometheus.NewDesc(
			"xpf_daemon_memory_rss_bytes",
			"Daemon resident set size in bytes.",
			nil, nil,
		),
		neighborPeriodicAge: prometheus.NewDesc(
			"xpf_daemon_neighbor_periodic_last_success_age_seconds",
			"Seconds since each Go periodic neighbor-maintenance phase "+
				"last completed. A monotonically climbing value means that "+
				"phase's guarded goroutine is wedged on a stuck netlink/probe "+
				"syscall (#1780).",
			[]string{"phase"}, nil,
		),
		frrReloadDegraded: prometheus.NewDesc(
			"xpf_frr_reload_degraded",
			"1 while the last applied FRR reload fell back to the additive "+
				"vtysh -f path (full frr-reload.py diff failed) and the "+
				"in-manager retry has not yet converged; stale-config "+
				"removal is deferred while set (#1880).",
			nil, nil,
		),
		ipsecRebindPending: prometheus.NewDesc(
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
		),
		schedulerRepublishFailed: prometheus.NewDesc(
			"xpf_scheduler_republish_failed",
			"1 while the most recent scheduler-driven policy republish "+
				"failed and has not yet converged (#3780): stale "+
				"enforcement is live past a schedule window — a scheduled "+
				"permit may still be forwarding after its window closed, or "+
				"a scheduled block never engaged. The daemon retries the "+
				"transition autonomously on each scheduler tick; 0 when the "+
				"enforcement snapshot is in sync with the schedule state.",
			nil, nil,
		),
		schedulerRepublishStale: prometheus.NewDesc(
			"xpf_scheduler_republish_stale_seconds",
			"Seconds since the current scheduler-republish failure streak "+
				"began (#3780); 0 when healthy. A climbing value means "+
				"enforcement has been out of sync with the schedule window "+
				"for that long while the daemon retries.",
			nil, nil,
		),
		schedulerRepublishFailClosed: prometheus.NewDesc(
			"xpf_scheduler_republish_fail_closed",
			"1 while the scheduler-republish failure streak has persisted past "+
				"the bounded age and the scheduler has escalated to FAIL-CLOSED "+
				"(#5669): scheduled policies are forced inactive (deny) so a "+
				"scheduled permit stops forwarding past its window close instead "+
				"of relying on an eventual republish recovery. 0 when healthy or "+
				"still inside the bounded retry window (xpf_scheduler_republish_"+
				"failed=1, xpf_scheduler_republish_stale_seconds climbing).",
			nil, nil,
		),
		configPersistDegraded: prometheus.NewDesc(
			"xpf_daemon_config_persist_degraded",
			"1 while the running active configuration failed to persist "+
				"to disk and the background retry has not yet succeeded "+
				"(a daemon restart would load a stale config, #1799); 0 "+
				"when config persistence is healthy.",
			nil, nil,
		),
		rollbackHistoryDegraded: prometheus.NewDesc(
			"xpf_config_rollback_persist_degraded",
			"1 while the most recent commit failed to durably persist its "+
				"text rollback-history files (the canonical rollback "+
				"history, #3441); 0 when healthy. The commit still "+
				"succeeded and the active config is durable (#1799) — this "+
				"flags a degraded recovery aid, not a forwarding outage.",
			nil, nil,
		),
		userspacePolicyContentRejected: prometheus.NewDesc(
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
		),
		userspaceZoneIDCollision: prometheus.NewDesc(
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
		),
		rpmPinInstallFailures: prometheus.NewDesc(
			"xpf_rpm_probe_pin_install_failures",
			"Number of RPM next-hop probe pins whose kernel fwmark rule / "+
				"pinned route failed to install. Affected tests hold their "+
				"prior state (ErrProbeSetup) instead of probing the default "+
				"path, so a nonzero value means those uplinks are NOT being "+
				"health-checked (#1895).",
			nil, nil,
		),
		eventActionsCommitted: prometheus.NewDesc(
			"xpf_event_actions_committed_total",
			"Total event-options change-configuration remediation actions "+
				"that committed successfully (#2157). INCLUDES the "+
				"committed-with-apply-debt subset (#5063): the generation was "+
				"promoted, is active, and the dataplane armed even when a "+
				"best-effort subsystem stayed in debt.",
			nil, nil,
		),
		eventActionsCommittedWithDebt: prometheus.NewDesc(
			"xpf_event_actions_committed_with_debt_total",
			"Subset of xpf_event_actions_committed_total whose commit "+
				"promoted+armed the generation but left a BEST-EFFORT subsystem "+
				"(networkd write / Kea restart / host-inbound nft) in debt "+
				"(#5063). The change is LIVE — this is not a rejection — but a "+
				"nonzero value means a committed remediation applied with a "+
				"recoverable subsystem hiccup worth investigating.",
			nil, nil,
		),
		eventActionsRejected: prometheus.NewDesc(
			"xpf_event_actions_rejected_total",
			"Total event-options remediation actions rejected as a "+
				"permanent failure — a malformed/unknown command, a "+
				"candidate apply error, or a commit-check failure. The "+
				"batch is transactional (#2139): a rejected action applies "+
				"NOTHING (the candidate is discarded).",
			nil, nil,
		),
		eventActionsRetried: prometheus.NewDesc(
			"xpf_event_actions_retried_total",
			"Total retry attempts for event-options remediation actions "+
				"deferred because the config lock was held by another "+
				"session (#2157). The action is retried with bounded "+
				"backoff rather than dropped.",
			nil, nil,
		),
		eventActionsDropped: prometheus.NewDesc(
			"xpf_event_actions_dropped_total",
			"Total event-options remediation actions dropped (NOT applied). "+
				"reason=lock_held: the config lock stayed held past the "+
				"retry deadline. reason=queue_full: the bounded action queue "+
				"was full of OTHER policies' actions and this one could not fit "+
				"(#2157; a same-policy dedup is counted separately as "+
				"xpf_event_actions_superseded_total, #5853). reason=stale: at "+
				"commit time the policy had been removed or redefined, or its 30s "+
				"cooldown was now active — the action was revalidated and dropped "+
				"rather than committing a batch no active policy authorizes "+
				"(#3750). A nonzero lock_held/queue_full value means automated "+
				"remediation was lost — investigate the lock holder; stale is "+
				"expected under operator config churn or duplicate events.",
			[]string{"reason"}, nil,
		),
		eventActionsSuperseded: prometheus.NewDesc(
			"xpf_event_actions_superseded_total",
			"Total event-options remediation actions SUPERSEDED by a newer "+
				"same-policy trigger while queued (#5853). The dedup keeps at "+
				"most one pending action per policy, so a burst from one policy "+
				"cannot fill the bounded queue and starve other policies. This is "+
				"benign — nothing is lost, the newer equivalent action still "+
				"runs — and is expected under duplicate events; it is NOT a "+
				"capacity drop (see reason=queue_full on "+
				"xpf_event_actions_dropped_total).",
			nil, nil,
		),
		eventAttributesInvalid: prometheus.NewDesc(
			"xpf_event_attributes_match_invalid_total",
			"Total times a malformed or unknown-field attributes-match line "+
				"was hit at runtime, causing the policy to fail CLOSED (not "+
				"fire). Strict commit rejects these (#2141); a nonzero value "+
				"means a config persisted by an older binary booted through a "+
				"lenient load with a bad line — fix it on the next commit.",
			nil, nil,
		),
		eventActionQueueDepth: prometheus.NewDesc(
			"xpf_event_action_queue_depth",
			"Current number of event-options remediation actions queued "+
				"but not yet applied by the single action worker (#2157). "+
				"A persistently nonzero depth means actions are backing up "+
				"behind a held config lock.",
			nil, nil,
		),
		eventStreamSubscriberDropped: prometheus.NewDesc(
			"xpf_event_stream_subscriber_dropped_total",
			"Total security/audit event records dropped by the EventBuffer "+
				"fan-out because a subscriber's channel was full (#5064). A "+
				"slow REST-SSE / gRPC event-stream / CLI-monitor consumer sheds "+
				"records non-blocking; a nonzero, climbing value means a live "+
				"forensic stream is gapped. Subscribers also see the gap in-band "+
				"via the record's monotonic BufSeq and an Overrun flag.",
			nil, nil,
		),
		feedSecondsSinceSuccess: prometheus.NewDesc(
			"xpf_feed_seconds_since_last_success",
			"Seconds since a dynamic-address feed last fetched successfully. "+
				"Climbs while the feed cannot be refreshed; the last-good "+
				"snapshot is retained indefinitely by default (#2050). -1 "+
				"means the feed has never had a successful fetch (no snapshot "+
				"installed; fail-closed).",
			[]string{"feed"}, nil,
		),
		feedStale: prometheus.NewDesc(
			"xpf_feed_stale",
			"1 while a dynamic-address feed's last-good snapshot is being "+
				"retained as stale (a fetch has failed since the last good "+
				"one and the snapshot is still enforced); 0 while fresh "+
				"(#2050).",
			[]string{"feed"}, nil,
		),
		ipmonPolicyFailed: prometheus.NewDesc(
			"xpf_ipmon_policy_failed",
			"1 while the services ip-monitoring policy is in FAIL state "+
				"(preferred routes injected); 0 while passing (#1827).",
			[]string{"policy"}, nil,
		),
		ipmonPolicyTransitions: prometheus.NewDesc(
			"xpf_ipmon_policy_transitions_total",
			"Total FAIL/recover state transitions of the services "+
				"ip-monitoring policy (#1827). A steadily climbing value "+
				"indicates a flapping uplink; consider a non-zero hold-down.",
			[]string{"policy"}, nil,
		),
		ipmonRoutesApplied: prometheus.NewDesc(
			"xpf_ipmon_routes_applied",
			"Number of ip-monitoring preferred routes ACTUALLY applied — "+
				"the size of the last CONVERGED actuation's overlay that is "+
				"live in both the kernel and userspace FIBs (#1827, #3761). "+
				"Diverges below xpf_ipmon_routes_desired while an actuation "+
				"is pending or the FRR/snapshot/FIB actuation keeps failing "+
				"(#3757): a persistent gap flags a failover that is desired "+
				"but not converged.",
			nil, nil,
		),
		ipmonRoutesDesired: prometheus.NewDesc(
			"xpf_ipmon_routes_desired",
			"Number of ip-monitoring preferred routes the engine WANTS "+
				"injected right now (winner-resolved overlay across FAILED "+
				"policies, #3761). Compare with xpf_ipmon_routes_applied: a "+
				"sustained desired>applied gap means the actuator has not "+
				"converged the failover routes.",
			nil, nil,
		),
		ipmonUnresolvedNextHops: prometheus.NewDesc(
			"xpf_ipmon_unresolved_next_hops",
			"Number of ip-monitoring interface-typed preferred routes of "+
				"FAILED policies currently skipped from the overlay "+
				"because the tracked interface unit has no DHCP-learned "+
				"gateway (#1844). Non-zero during a failover means the "+
				"backup uplink's lease is missing and the failover route "+
				"is NOT injected.",
			nil, nil,
		),
		ipmonActuationFailures: prometheus.NewDesc(
			"xpf_ipmon_actuation_failures_total",
			"Cumulative ip-monitoring route-overlay actuations that did "+
				"NOT converge — a hard FRR reload error, a snapshot-publish "+
				"failure, an unconfirmed FIB-generation bump (#3757), or a "+
				"bounded-timeout/shutdown abort (#3758, #4423). The engine "+
				"retries autonomously (throttle-paced), so a steadily "+
				"climbing value means ip-monitoring cannot commit its "+
				"overlay and failover protection is degraded — pair it with "+
				"a sustained xpf_ipmon_routes_desired > xpf_ipmon_routes_applied "+
				"gap.",
			nil, nil,
		),

		// #709: owner-profile telemetry. Labels:
		//   ifindex:      interface ifindex as string
		//   queue_id:     CoS queue id 0-255
		//   bucket_hi_ns: upper bound of the histogram bucket (ns),
		//                 formatted as the power-of-two.
		// The histogram metrics are counters (monotonic bucket counts
		// in the Rust dataplane); owner/peer pps are gauges since the
		// Rust side re-uses them across the window.
		cosDrainLatencyBucket: prometheus.NewDesc(
			"xpf_cos_drain_latency_ns_bucket",
			"CoS owner-drain latency histogram — power-of-two ns buckets (#709).",
			[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
		),
		cosDrainInvocationsTotal: prometheus.NewDesc(
			"xpf_cos_drain_invocations_total",
			"Total CoS owner-drain invocations per (ifindex, queue_id) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosRedirectAcquireBucket: prometheus.NewDesc(
			"xpf_cos_redirect_acquire_ns_bucket",
			"CoS redirect-acquire latency histogram — power-of-two ns buckets, sampled 1-in-256 (#709).",
			[]string{"ifindex", "queue_id", "bucket_hi_ns"}, nil,
		),
		cosOwnerPPS: prometheus.NewDesc(
			"xpf_cos_owner_pps",
			"CoS owner-local pps (window accumulator, cleared by operator) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosPeerPPS: prometheus.NewDesc(
			"xpf_cos_peer_pps",
			"CoS peer-redirected pps (window accumulator, cleared by operator) (#709).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainGuaranteeSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_guarantee_sent_bytes_total",
			"Bytes sent by this CoS queue during guarantee-phase service (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainSurplusSentBytes: prometheus.NewDesc(
			"xpf_userspace_cos_drain_surplus_sent_bytes_total",
			"Bytes sent by this CoS queue during surplus-phase service (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainNonExactSentBytesWhileExactBacklogged: prometheus.NewDesc(
			"xpf_userspace_cos_drain_nonexact_sent_bytes_while_exact_backlogged_total",
			"Non-exact CoS queue bytes sent while at least one exact queue on the same shaped interface still had backlog; non-zero deltas indicate best-effort/uncapped service competing with exact demand (#1369).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosRootTokenStarvationParks: prometheus.NewDesc(
			"xpf_userspace_cos_root_token_starvation_parks_total",
			"Times this CoS queue was parked at the shaper because the shared ROOT token bucket was empty. A rising delta on a best-effort/mouse queue while a surplus-sharing borrower drains means the borrower is holding the shared root rate — root-surplus arbitration is the surplus-sharing mouse-latency tail cause, not this queue's own bucket (#1642/#1359).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosQueueTokenStarvationParks: prometheus.NewDesc(
			"xpf_userspace_cos_queue_token_starvation_parks_total",
			"Times this CoS queue was parked at the shaper because its OWN per-queue token bucket was empty (this queue is rate-capped, distinct from shared-root starvation above) (#1642/#1359).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainParkRootTokens: prometheus.NewDesc(
			"xpf_userspace_cos_drain_park_root_tokens_total",
			"Drain-loop parks of this CoS queue attributed to insufficient shared ROOT tokens during a batch. Distinct from the shaper-side root_token_starvation_parks: this counts the per-batch drain-loop decision (#760/#1359).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosDrainParkQueueTokens: prometheus.NewDesc(
			"xpf_userspace_cos_drain_park_queue_tokens_total",
			"Drain-loop parks of this CoS queue attributed to insufficient per-queue tokens during a batch (#760/#1359).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosLeaseV8RequestedBytes: prometheus.NewDesc(
			"xpf_userspace_cos_lease_v8_requested_bytes_total",
			"Cumulative bytes this worker REQUESTED from this CoS queue's shared v8 lease (every acquire_v8 ask, granted or not). Compare with ..._granted_bytes_total: requested >> granted on a worker = share-bounded asks (mismatch); a worker with near-zero requested while the class undergrants = claim-sampling loss. Step-0 attribution instrument for the honored-realization gap (#1863).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		cosLeaseV8GrantedBytes: prometheus.NewDesc(
			"xpf_userspace_cos_lease_v8_granted_bytes_total",
			"Cumulative bytes this worker was GRANTED by this CoS queue's shared v8 lease. Per-class sum approximates the class's realized guarantee-phase throughput; see ..._requested_bytes_total for the attribution contract (#1863).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		cosAdmissionFlowShareDrops: prometheus.NewDesc(
			"xpf_userspace_cos_admission_flow_share_drops_total",
			"Packets dropped at CoS admission because the flow exceeded its per-flow buffer share (summed across worker instances by the Rust coordinator). Previously wire-only (#710/#718); exported for the #1863 supply-path drop-site attribution.",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosAdmissionBufferDrops: prometheus.NewDesc(
			"xpf_userspace_cos_admission_buffer_drops_total",
			"Packets dropped at CoS admission because the queue's buffer limit was exceeded (summed across worker instances). Previously wire-only (#710/#718); exported for the #1863 supply-path drop-site attribution.",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosAdmissionEcnMarked: prometheus.NewDesc(
			"xpf_userspace_cos_admission_ecn_marked_total",
			"Packets ECN-CE-marked at CoS admission instead of dropped (summed across worker instances). Previously wire-only; exported alongside the admission drop counters (#1863).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillPhase1Admissions: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_admissions_total",
			"Times this CoS queue was admitted by the guarantee-rate waterfill Phase-1 (small-first honored) walk. Combine with phase2_admissions + queued_bytes + *_starvation_parks to diagnose Phase-2 lock-in (#1628).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillPhase2Admissions: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase2_admissions_total",
			"Times this CoS queue was admitted by the guarantee-rate waterfill Phase-2 (descending residual) walk. Climbing while phase1_admissions stays flat is evidence (not proof) of Phase-2 lock-in for a small class within the Phase-1 budget (#1628).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillEligibleVisits: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_eligible_visits_total",
			"Times the guarantee-rate waterfill selector reached this CoS queue eligible (nonempty/runnable/guarantee/exact) and evaluated it (both phases, before the token gate). Low value + high *_starvation_parks = backlogged-but-parked; low + low parks + zero queued = idle on this owner (#1628).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillPhase1SelectedNoProgress: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_selected_no_progress_total",
			"Times this CoS queue was honored by the guarantee-rate waterfill Phase-1 walk but made ZERO TX progress, so its budget debit and honored bit were refunded (hb166 T-2). Climbing here while waterfill_phase1_admissions stays flat = TX-ring pressure eating a small class's guarantee pass (the #1630/#4256 mid-rate-residual signal).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosWaterfillEpochs: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_epochs_total",
			"Completed guarantee-rate waterfill epochs (Phase-1 budget refills) on this CoS interface, summed across workers (#1628).",
			[]string{"ifindex"}, nil,
		),
		cosWaterfillPhase1BudgetBreaks: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_phase1_budget_breaks_total",
			"Times the guarantee-rate waterfill Phase-1 walk broke into Phase 2 because the next ascending queue's cost exceeded the remaining Phase-1 budget, summed across workers. High breaks-per-epoch means Phase 1 routinely exhausts its budget mid-walk (#1628).",
			[]string{"ifindex"}, nil,
		),
		cosWaterfillMinEpochsPerWorker: prometheus.NewDesc(
			"xpf_userspace_cos_waterfill_min_epochs_per_worker",
			"Minimum waterfill_epochs across workers/bindings WITH active exact-guarantee backlog on this CoS interface. A worker/binding locked in Phase-2 keeps its epochs frozen, dropping this MIN even while the summed epochs climb; a value of 0 is a hard lock-in (a backlogged binding that completed zero epochs). The gauge is SUPPRESSED (no series) for an idle interface with no active-backlog candidate, so any emitted value — including 0 — is a real lock-in signal and alertable with `< N` (#1628).",
			[]string{"ifindex"}, nil,
		),
		cosEqualFlowEnforcementEnabled: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforcement_enabled",
			"1 when this exact CoS queue's shared v8 lease is configured for opt-in equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowTargetPolicy: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_target_policy",
			"Info metric (always 1): the equal-flow target policy active on this exact CoS queue's shared v8 lease — policy label is one of slowest | mean | ideal-share (#1746). Sibling of the existing equal-flow gauges; series identity of those gauges is unchanged.",
			[]string{"ifindex", "queue_id", "policy"}, nil,
		),
		cosEqualFlowEnforced: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_enforced",
			"1 when this exact CoS queue's current shared v8 lease epoch is actively applying equal-flow suppression; 0 when configured but failed open (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_target_per_flow_bps",
			"Current Rust-enforced equal-flow per-flow target in bits per second, derived from shared v8 lease grants rather than the measurement-only Go estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowMaxWorkerCapBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_max_worker_cap_bytes",
			"Maximum per-worker bytes-per-epoch cap currently published by the shared v8 equal-flow suppressor (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowCapHitEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_cap_hit_events_total",
			"Acquire calls denied by the opt-in shared v8 equal-flow cap while class capacity remained (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowSuppressedGrantBytes: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_suppressed_grant_bytes_total",
			"Requested queue-lease bytes withheld by the opt-in shared v8 equal-flow suppressor while class capacity remained (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowStaleOrTagMismatchEvents: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_stale_or_tag_mismatch_events_total",
			"Acquire-side stale/tag-mismatch equal-flow cap reads that failed open without overwriting the rotation-published epoch reason (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosEqualFlowFailOpen: prometheus.NewDesc(
			"xpf_userspace_cos_equal_flow_fail_open",
			"1 for the current bounded fail-open reason on an opt-in shared v8 equal-flow queue; absent for queues without equal-flow enforcement (#1304).",
			[]string{"ifindex", "queue_id", "reason"}, nil,
		),
		// #1829 Phase 1: dequeue-time sojourn gauges, MAX-merged
		// across worker instances and across workers (worst
		// instance). The windowed-min gauge is the #1829 Phase-2
		// gate metric.
		cosSojournEwmaNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_ewma_ns",
			"Shift-add EWMA (alpha=1/8) of per-packet queue sojourn measured at dequeue on this CoS queue, ns, MAX-merged across workers. Supporting context only — biased high by scheduler service gaps; gate standing-queue decisions on xpf_userspace_cos_sojourn_windowed_min_ns instead (#1829).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosSojournPeakNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_peak_ns",
			"Lifetime maximum per-packet queue sojourn measured at dequeue on this CoS queue, ns, MAX-merged across workers (#1829).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosSojournWindowedMinNS: prometheus.NewDesc(
			"xpf_userspace_cos_sojourn_windowed_min_ns",
			"Minimum per-packet queue sojourn over the last 1-2 100 ms windows on this CoS queue, ns, MAX-merged across workers (worst instance). CoDel's standing-queue estimator and the #1829 Phase-2 gate metric: a value persistently above codel-target is standing-queue evidence; 0 means no pops in the last ~2 windows (no standing queue).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		// #1830 (g): bucket-vs-flow occupancy gauges. The ratio
		// flows_active / buckets_occupied is meaningful only while the
		// queue is continuously backlogged; see the wire-field docs.
		cosFlowFairBucketsOccupied: prometheus.NewDesc(
			"xpf_userspace_cos_flow_fair_buckets_occupied",
			"Currently occupied (backlogged) SFQ flow-fair buckets on this CoS queue, summed across workers; 0 on idle or non-flow-fair queues. Compare against xpf_userspace_cos_flow_fair_flows_active under sustained backlog: fewer occupied buckets than known concurrent flows indicates SFQ hash collisions shrinking per-flow shares (#1830).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		cosFlowFairFlowsActive: prometheus.NewDesc(
			"xpf_userspace_cos_flow_fair_flows_active",
			"Flow-cache active-window (~650 ms) distinct flows mapped to this CoS queue, summed across workers. Numerator of the collision ratio against xpf_userspace_cos_flow_fair_buckets_occupied; on idle/bursty queues it naturally exceeds occupied buckets (demand variance, not collision evidence) (#1830).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		// #869: per-worker busy/idle runtime counters.
		workerWallSecs: prometheus.NewDesc(
			"xpf_userspace_worker_wall_seconds_total",
			"Monotonic wall seconds observed by the userspace-dp worker loop (#869).",
			[]string{"worker_id"}, nil,
		),
		workerActiveSecs: prometheus.NewDesc(
			"xpf_userspace_worker_active_seconds_total",
			"Seconds the userspace-dp worker spent processing packets (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleSpinSecs: prometheus.NewDesc(
			"xpf_userspace_worker_idle_spin_seconds_total",
			"Seconds the userspace-dp worker spent idle-spinning on empty rings (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleBlockSecs: prometheus.NewDesc(
			"xpf_userspace_worker_idle_block_seconds_total",
			"Seconds the userspace-dp worker spent blocked in poll()/sleep (#869).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUSecs: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_seconds_total",
			"CLOCK_THREAD_CPUTIME_ID sample for the userspace-dp worker thread (#869).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUSecsLast60s: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_seconds_last_60s",
			"CLOCK_THREAD_CPUTIME_ID consumed by the worker thread over the most recent rolling ~60s window (gauge, not counter; 0 until ~60s after worker start).",
			[]string{"worker_id"}, nil,
		),
		workerThreadCPUWindowSecs: prometheus.NewDesc(
			"xpf_userspace_worker_thread_cpu_window_seconds",
			"Wall-clock width of the rolling thread-CPU window matching xpf_userspace_worker_thread_cpu_seconds_last_60s; 0 until ~60s after worker start. Operators compute live CPU% as last_60s / this gauge.",
			[]string{"worker_id"}, nil,
		),
		workerWorkLoops: prometheus.NewDesc(
			"xpf_userspace_worker_work_loops_total",
			"Worker-loop iterations that did useful packet/ring work (#869).",
			[]string{"worker_id"}, nil,
		),
		workerIdleLoops: prometheus.NewDesc(
			"xpf_userspace_worker_idle_loops_total",
			"Worker-loop iterations with no useful work (#869).",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseAcquireV8Calls: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total",
			"V8 CoS queue-lease acquire calls made by this worker (#1240).",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseAcquireV8GrantedBytes: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total",
			"Bytes granted by v8 CoS queue-lease acquire calls for this worker (#1240).",
			[]string{"worker_id"}, nil,
		),
		// #1782 Step-1 cold-start CoS instruments.
		workerCoSWheelTicksAdvancedTotal: prometheus.NewDesc(
			"xpf_userspace_worker_cos_wheel_ticks_advanced_total",
			"Cumulative CoS timer-wheel ticks (50us each) advanced by advance_cos_timer_wheel across this worker's bindings — the O(lag) cold-start catch-up cost, mechanism (i) of the #1782 Step-1 disambiguation.",
			[]string{"worker_id"}, nil,
		),
		workerCoSWheelTicksAdvancedMax: prometheus.NewDesc(
			"xpf_userspace_worker_cos_wheel_ticks_advanced_max",
			"Largest single-call CoS timer-wheel tick advance ever observed on this worker (monotonic high-water mark, never resets). A multi-million-tick value after a cold reproduction pins the #1782 §4(i) wheel catch-up mechanism.",
			[]string{"worker_id"}, nil,
		),
		workerCoSQueueLeaseUndergrant: prometheus.NewDesc(
			"xpf_userspace_worker_cos_queue_lease_undergrant_total",
			"CoS exact-guarantee selector visits where the post-top-up queue tokens still could not cover the head frame, attributed to the v8 acquire shortfall cause (#1782 Step-1 mechanism (ii)); a v8-attributed subset of drain_park_queue_tokens.",
			[]string{"worker_id", "cause"}, nil,
		),
		workerSessionTableEntries: prometheus.NewDesc(
			"xpf_userspace_worker_session_table_entries",
			"Live session-table entries published by this userspace worker.",
			[]string{"worker_id"}, nil,
		),
		workerSessionTableCapacity: prometheus.NewDesc(
			"xpf_userspace_worker_session_table_capacity",
			"Maximum session-table entries supported by this userspace worker.",
			[]string{"worker_id"}, nil,
		),
		workerNatReverseKeyCollisions: prometheus.NewDesc(
			"xpf_userspace_worker_session_nat_reverse_key_collisions_total",
			"Cumulative NAT reverse-key (nat_reverse_index) 1:N collision "+
				"displacement events on this userspace worker's session table "+
				"(#1758/#1760 latent corruption made observable). Event count, "+
				"not a census: standing collisions after a winner's expiry and "+
				"never-replicated MissingNeighborSeed collisions are not "+
				"counted here — see the shared displacements counter.",
			[]string{"worker_id"}, nil,
		),
		workerSessionCreateDrops: prometheus.NewDesc(
			"xpf_userspace_worker_session_create_drops_total",
			"Cumulative session installs refused at the max_sessions cap on "+
				"this userspace worker's session table (#1861 — previously "+
				"counted internally but never exported). Covers every "+
				"capped install site (new-flow, reply repair, seed, "+
				"fabric-return, LocalMiss helper). UpsertLocal replicas "+
				"moved to the uncapped sync-family install in #1870 and "+
				"no longer contribute.",
			[]string{"worker_id"}, nil,
		),
		workerSessionInstallAdmissionRefused: prometheus.NewDesc(
			"xpf_userspace_worker_session_install_admission_refused_total",
			"Cumulative new flows refused (trigger packet dropped, Junos "+
				"parity) by the #1861 forward+reverse pair-admission "+
				"preflight at/near max_sessions on this userspace worker. "+
				"One increment per refused flow, not per missing slot.",
			[]string{"worker_id"}, nil,
		),
		workerSessionInstallPartial: prometheus.NewDesc(
			"xpf_userspace_worker_session_install_partial_total",
			"Post-preflight partial session installs on this userspace "+
				"worker (#1861 release residual arms). Expected to stay 0 "+
				"forever; nonzero means the preflight/install pairing has a "+
				"bug and the dataplane degraded a flow instead of "+
				"half-committing it.",
			[]string{"worker_id"}, nil,
		),
		userspaceSessionTableEntries: prometheus.NewDesc(
			"xpf_userspace_session_table_entries",
			"Aggregate live userspace session-table entries across workers.",
			nil, nil,
		),
		userspaceSessionTableCapacity: prometheus.NewDesc(
			"xpf_userspace_session_table_capacity",
			"Aggregate userspace session-table capacity across workers.",
			nil, nil,
		),
		userspaceNatReverseKeyCollisions: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_collisions_total",
			"Aggregate NAT reverse-key (nat_reverse_index) 1:N collision "+
				"displacement events across userspace workers (#1758/#1760 "+
				"latent corruption made observable). Event count, not a "+
				"census (replica fanout over-counts; standing and seed-path "+
				"collisions under-count — pair with the shared displacements "+
				"counter). >=1 means at least one real collision occurred "+
				"and is the structural-fix revisit trigger.",
			nil, nil,
		),
		userspaceNatReverseKeySharedDisplacements: prometheus.NewDesc(
			"xpf_userspace_session_nat_reverse_key_shared_displacements_total",
			"Shared-map NAT reverse-key displacement events: a "+
				"publish_shared_session insert displaced a DIFFERENT forward "+
				"session's entry at the same reverse key (#1760 latent 1:N "+
				"reverse-path corruption). The shared map is the choke point "+
				"all transit forward NAT sessions pass through (including "+
				"MissingNeighborSeed installs invisible to the per-worker "+
				"counter). Event count, not a pair census: >=1 means at "+
				"least one real collision occurred; standing collisions "+
				"against an already-unindexed session are not counted.",
			nil, nil,
		),
		userspaceSessionCreateDrops: prometheus.NewDesc(
			"xpf_userspace_session_create_drops_total",
			"Aggregate session installs refused at the max_sessions cap "+
				"across userspace workers (#1861).",
			nil, nil,
		),
		userspaceSessionInstallAdmissionRefused: prometheus.NewDesc(
			"xpf_userspace_session_install_admission_refused_total",
			"Aggregate new flows refused (trigger packet dropped, Junos "+
				"parity) by the #1861 forward+reverse pair-admission "+
				"preflight at/near max_sessions, across userspace workers.",
			nil, nil,
		),
		userspaceSessionInstallPartial: prometheus.NewDesc(
			"xpf_userspace_session_install_partial_total",
			"Aggregate post-preflight partial session installs across "+
				"userspace workers (#1861 release residual arms; expected 0 "+
				"forever — nonzero means a preflight/install pairing bug).",
			nil, nil,
		),
		userspaceSessionPublishErrors: prometheus.NewDesc(
			"xpf_userspace_session_publish_errors_total",
			"Failed USERSPACE_SESSIONS BPF-map publishes across all helper "+
				"paths (worker poll, HA upsert, session-glue, post-reconcile "+
				"replay, activation/reverse prewarm). A failed publish means "+
				"the XDP shim never learns the session key and takes the "+
				"NO_SESSION degraded path (drop in STRICT mode); a rising "+
				"value attributes shim no-session fallbacks to publish "+
				"failures (session map at capacity, stale fd after "+
				"reconcile) (#1789).",
			nil, nil,
		),
		userspaceDnatPublishErrors: prometheus.NewDesc(
			"xpf_userspace_dnat_publish_errors_total",
			"Failed dnat_table reverse-SNAT BPF-map publishes across "+
				"userspace workers. The dnat_table backs embedded-ICMP NAT "+
				"reversal — the reverse lookup that maps an inbound ICMP "+
				"error (PMTUD Packet Too Big / Time Exceeded / traceroute) "+
				"back to the original pre-NAT source. A failed publish (map "+
				"at capacity, EINVAL, kernel resource exhaustion) silently "+
				"omits the reverse record, so the error is dropped or "+
				"mis-delivered; a rising value attributes that loss to "+
				"dnat_table map-capacity pressure (#2244).",
			nil, nil,
		),
		userspaceSyncedImportCapDrops: prometheus.NewDesc(
			"xpf_userspace_synced_import_cap_drops_total",
			"Peer-synced session imports rejected by the coordinator's "+
				"aggregate admission bound. Locally-created sessions are "+
				"capped per worker at max_sessions; peer-synced imports were "+
				"uncapped and fanned out to every worker command queue+table, "+
				"so a peer under session-table pressure (or a compromised "+
				"peer) could drive this node past its own aggregate session "+
				"ceiling and multiply that state across all workers. The "+
				"import path now bounds the shared synced map at this "+
				"appliance's own ceiling (worker_count * max_sessions) and "+
				"drop-newest-rejects an over-ceiling import; a rising value "+
				"means a peer exceeded that ceiling. A legitimate "+
				"symmetric-pair failover never trips it (#5674).",
			nil, nil,
		),
		userspaceWorkerCommandQueuePoisonRecoveries: prometheus.NewDesc(
			"xpf_userspace_worker_command_queue_poison_recoveries_total",
			"Worker command-queue mutex poison recoveries across all "+
				"helper producer/consumer sites (worker poll, HA enqueues, "+
				"session replication, activation prewarm, tunnel install, "+
				"cross-binding shaped-TX redirect). A poisoned mutex means "+
				"a worker thread panicked while holding the lock; recovery "+
				"keeps the committed queue and clears the poison so the "+
				"queues keep flowing instead of going permanently deaf. "+
				"A nonzero value indicates a contained worker panic "+
				"occurred (#1807, extends #1790).",
			nil, nil,
		),
		userspaceGreDecapEcnIllegalDrops: prometheus.NewDesc(
			"xpf_userspace_gre_decap_ecn_illegal_drops_total",
			"GRE-decap frames dropped by the RFC 6040 4.2 decap-side ECN "+
				"combine because the outer header carried a CE (congestion "+
				"experienced) mark over an inner packet that was Not-ECT "+
				"(the illegal combination: a congested router CE-marked a "+
				"packet whose endpoints never negotiated ECN). RFC 6040 "+
				"mandates dropping this rather than silently clearing the "+
				"bogus CE. A nonzero value flags a misbehaving tunnel "+
				"ingress that ECT-marked the outer for un-ECN inner "+
				"traffic on a congested path (#2315).",
			nil, nil,
		),
		userspaceWgDecapEcnIllegalDrops: prometheus.NewDesc(
			"xpf_userspace_wg_decap_ecn_illegal_drops_total",
			"WireGuard-decap inner packets dropped by the RFC 6040 4.2 "+
				"decap-side ECN combine because the (recvmsg-captured) "+
				"outer header carried a CE (congestion experienced) mark "+
				"over an inner packet that was Not-ECT (the illegal "+
				"combination: a congested router CE-marked a packet whose "+
				"endpoints never negotiated ECN). The WG decap path reads "+
				"the outer ECN out-of-band via IP_RECVTOS/IPV6_RECVTCLASS "+
				"(the kernel UDP socket strips the outer IP header before "+
				"userspace) and applies the same combine. RFC 6040 mandates "+
				"dropping this rather than silently clearing the bogus CE. "+
				"A nonzero value flags a misbehaving WG ingress that "+
				"ECT-marked the outer for un-ECN inner traffic on a "+
				"congested path (#2317).",
			nil, nil,
		),
		userspaceGreEncapDfOversizeDrops: prometheus.NewDesc(
			"xpf_userspace_gre_encap_df_oversize_drops_total",
			"Native-GRE encap frames dropped because the fully built "+
				"outer datagram (outer IP + GRE header, including the "+
				"optional 4-byte key, + inner packet) exceeded the "+
				"resolved transport/egress MTU while the IPv4 outer "+
				"carries DF=1 (the only outer the native encap builder "+
				"emits; the IPv6 outer cannot be fragmented in-path "+
				"either). A DF-set oversized outer cannot be fragmented "+
				"downstream and would silently blackhole every inner flow "+
				"over the tunnel with no PMTUD signal back to the inner "+
				"source, so the builder refuses to emit it. A nonzero "+
				"value flags inner flows whose encapped size exceeds the "+
				"tunnel path MTU (typically a missing or too-high inner "+
				"MSS clamp, or a non-TCP inner with no segmentation "+
				"lever). PMTUD/PTB signalling is deferred to #2330 "+
				"(#2331).",
			nil, nil,
		),
		userspaceGreDecapChecksumInvalidDrops: prometheus.NewDesc(
			"xpf_userspace_gre_decap_checksum_invalid_drops_total",
			"Native-GRE decap frames dropped because the GRE "+
				"Checksum-Present (C) bit was set but the GRE checksum "+
				"failed to verify (or the header was truncated past the "+
				"4-byte Checksum+Reserved1 field). Per RFC 2784 2.1 and "+
				"RFC 2890 the checksum is the IP-style one's-complement "+
				"checksum of the GRE header and payload; a checksummed "+
				"peer (for example a vSRX with GRE checksum enabled) is "+
				"now decapped after skipping and validating the checksum "+
				"field instead of being silently blackholed, and only a "+
				"frame the path corrupted is dropped here. A nonzero "+
				"value flags a checksummed GRE peer delivering corrupt "+
				"frames or a truncated GRE header (#2782).",
			nil, nil,
		),
		userspaceTimeExceededRateLimited: prometheus.NewDesc(
			"xpf_userspace_time_exceeded_rate_limited_total",
			"Locally-generated ICMP/ICMPv6 Time Exceeded (TTL/hop-limit) "+
				"error replies dropped because the per-reason token bucket "+
				"was empty. The generator is rate-limited (global-per-reason, "+
				"Linux icmp_msgs_per_sec model, default 1000/s + 1000 burst) "+
				"so a low-TTL flood or a routing loop cannot drive unbounded "+
				"generated-error emission (CPU/TX amplification + reflection). "+
				"A nonzero value flags an error-amplification attempt (or a "+
				"real routing loop) being clamped (#2472).",
			nil, nil,
		),
		userspacePacketTooBigRateLimited: prometheus.NewDesc(
			"xpf_userspace_packet_too_big_rate_limited_total",
			"Locally-generated ICMPv4 Frag-Needed / ICMPv6 Packet Too Big "+
				"PMTUD replies dropped because the per-reason token bucket "+
				"was empty (same limiter as Time Exceeded, independent "+
				"bucket). A nonzero value flags an oversized-DF / IPv6 flood "+
				"being clamped before it amplifies into unbounded PTB "+
				"emission (#2472).",
			nil, nil,
		),
		userspaceRejectRateLimited: prometheus.NewDesc(
			"xpf_userspace_reject_rate_limited_total",
			"Locally-generated policy/filter `reject` replies (TCP RST or "+
				"ICMP/ICMPv6 administratively-prohibited unreachable) dropped "+
				"because the per-reason token bucket was empty. This is in "+
				"ADDITION to the SYN-cookie TX-frame budget gate "+
				"(which is queue protection, not a rate cap). A nonzero value "+
				"flags a rejected-flow flood being clamped before it amplifies "+
				"into unbounded RST/ICMP backscatter (#2472). Source-neutral "+
				"aggregate: the rate-limit bucket is a single global-per-reason "+
				"bucket. The per-source breakdown is "+
				"xpf_userspace_reject_rate_limited_by_source_total (#3661).",
			nil, nil,
		),
		// #3657 (H13/H15/M02): source-split reject reply telemetry. #3615
		// wired the per-source sent / TX-frame reply-budget / egress
		// output-filter legs onto BindingStatus; these expose them so
		// alerting can tell policy-reject from filter-reject and success from
		// suppression. Summed across bindings, labeled source=policy|filter,
		// emitted unconditionally (a 0 is a real "no reject activity" signal).
		userspaceRejectSent: prometheus.NewDesc(
			"xpf_userspace_reject_sent_total",
			"Locally-generated `reject` replies (TCP RST or ICMP/ICMPv6 "+
				"administratively-prohibited unreachable) actually enqueued, "+
				"split by source: a security-policy `then reject` "+
				"(source=policy, includes a zone `tcp-rst`) vs a "+
				"firewall-filter `then reject` (source=filter). This is the "+
				"active reject SUCCESS volume — as important as the suppression "+
				"counters for validating vSRX-style reject under load "+
				"(#3615/#3657 H13).",
			[]string{"source"}, nil,
		),
		userspaceRejectReplyBudgetDrops: prometheus.NewDesc(
			"xpf_userspace_reject_reply_budget_drops_total",
			"Locally-generated `reject` replies suppressed because the "+
				"per-tick TX-frame budget was exhausted, split by source "+
				"(policy vs firewall-filter). Budget pressure during a flood is "+
				"exactly when a `reject` is silently downgraded to a truthful "+
				"`deny`; the source split tells policy-reject starvation from "+
				"filter-reject starvation and is distinct from the global "+
				"rate-limit bucket (xpf_userspace_reject_rate_limited_total) "+
				"and an egress output-filter drop (#3615 L04/#3657 H14/M02).",
			[]string{"source"}, nil,
		),
		userspaceRejectOutputFilterDrops: prometheus.NewDesc(
			"xpf_userspace_reject_output_filter_drops_total",
			"Locally-generated `reject` replies dropped by an egress output "+
				"firewall filter (terminal discard/reject or three-color "+
				"policer) applied to the reflected reply's own egress tuple, "+
				"split by source (policy vs firewall-filter). Distinguishes an "+
				"operator-installed output filter suppressing a reject from a "+
				"TX-frame budget or rate-limit drop (#3615 L05/#3657 H15/M02).",
			[]string{"source"}, nil,
		),
		// #3661 (M02 Rust follow-up): per-source breakdown of the reject
		// rate-limit drop leg. The aggregate
		// xpf_userspace_reject_rate_limited_total stays source-neutral for
		// back-compat; this attributes each drop (at the consume site, where
		// the reply source is known) to a security-policy `then reject`
		// (source=policy) or a firewall-filter `then reject` (source=filter),
		// so a rejected-flow flood's bucket starvation is attributable. Both
		// sources share the one global-per-reason bucket, so policy+filter sum
		// to the aggregate. Summed across bindings, labeled source=policy|
		// filter, emitted unconditionally (a 0 is a real "no rate-limit drop"
		// signal).
		userspaceRejectRateLimitedBySource: prometheus.NewDesc(
			"xpf_userspace_reject_rate_limited_by_source_total",
			"Locally-generated `reject` replies (TCP RST or ICMP/ICMPv6 "+
				"administratively-prohibited unreachable) dropped because the "+
				"shared per-reason rate-limit token bucket was empty, split by "+
				"source (policy vs firewall-filter). Distinguishes "+
				"policy-reject starvation from filter-reject starvation under a "+
				"rejected-flow flood. The source-neutral aggregate is "+
				"xpf_userspace_reject_rate_limited_total; policy+filter sum to "+
				"it (#3661).",
			[]string{"source"}, nil,
		),
		userspaceMartianDropped: prometheus.NewDesc(
			"xpf_userspace_martian_dropped_total",
			"Packets dropped with a NoRoute disposition whose destination is a "+
				"martian address (IPv4 multicast/broadcast/unspecified/loopback, "+
				"IPv6 multicast/unspecified/loopback) — a firewall never forwards "+
				"these and they have no legitimate route, so they miss the FIB and "+
				"drop as NoRoute. A strict sub-breakout of the route-miss total "+
				"(every martian drop also bumps route_miss_packets), summed across "+
				"bindings, so an operator can tell a martian-dst drop apart from an "+
				"ordinary route miss and correlate it with a firewall-filter accept "+
				"log (#4743/#4768). Emitted unconditionally so 0 is a real "+
				"\"no martian drops\" signal.",
			nil, nil,
		),
		userspaceIPv6ExtHeaderDropped: prometheus.NewDesc(
			"xpf_userspace_ipv6_ext_header_dropped_total",
			"Packets fail-closed-dropped because their IPv6 extension-header "+
				"chain is unparseable or exceeds the MAX_IPV6_EXT_HEADERS walk "+
				"bound (an over-limit chain the helper cannot inspect), summed "+
				"across bindings. Distinct from a truncated chain; makes the "+
				"otherwise-silent fail-closed drop observable (#4743/#4768, "+
				"relates to #4555). Emitted unconditionally so 0 is a real "+
				"\"no ext-header drops\" signal.",
			nil, nil,
		),
		userspaceFlowCacheActiveFlows: prometheus.NewDesc(
			"xpf_userspace_flow_cache_active_flows",
			"Aggregate active userspace flow-cache entries across bindings.",
			nil, nil,
		),
		userspaceFlowCacheCapacity: prometheus.NewDesc(
			"xpf_userspace_flow_cache_capacity",
			"Aggregate userspace flow-cache capacity across bindings.",
			nil, nil,
		),
		userspaceEventStreamFramesTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_frames_total",
			"Daemon-side userspace event-stream frames by direction.",
			[]string{"direction"}, nil,
		),
		userspaceEventStreamProducerFramesTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_producer_frames_total",
			"Userspace helper event-stream producer counters by outcome.",
			[]string{"outcome"}, nil,
		),
		userspaceEventStreamDecodeErrorsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_decode_errors_total",
			"Daemon-side userspace event-stream decode errors.",
			nil, nil,
		),
		userspaceEventStreamSequenceGapsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_sequence_gaps_total",
			"Daemon-side userspace event-stream sequence gaps.",
			nil, nil,
		),
		userspaceEventStreamDataplaneEventsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_dataplane_events_total",
			"Decoded RT_FLOW dataplane events received over the userspace event stream.",
			[]string{"type"}, nil,
		),
		userspaceEventStreamDataplaneDropsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_dataplane_event_drops_total",
			"RT_FLOW dataplane events dropped by the userspace event-stream decoder.",
			[]string{"type"}, nil,
		),
		userspaceEventStreamUnknownDropsTotal: prometheus.NewDesc(
			"xpf_userspace_event_stream_unknown_frame_drops_total",
			"Userspace event-stream frames dropped because their frame type is unknown.",
			nil, nil,
		),
		workerDead: prometheus.NewDesc(
			"xpf_userspace_worker_dead",
			"1 if the userspace-dp worker thread has panicked and been "+
				"caught by the supervisor; 0 otherwise. Cleared only by "+
				"daemon restart in Phase 1 (#925).",
			[]string{"worker_id"}, nil,
		),
		// === #1621 cold-path histogram surface ===
		workerColdPathBucket: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_ns_bucket",
			"Cumulative cold-path policy-eval latency observations per "+
				"worker / zone-pair-slot, bucketed into the #1619 24-bucket "+
				"power-of-two ns histogram. Compatible with PromQL "+
				"histogram_quantile() via the `le` label (#1612 step-3).",
			[]string{"worker_id", "zone_pair_slot", "le"}, nil,
		),
		workerColdPathSamples: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_samples_total",
			"Per-worker / zone-pair-slot count of cold-path latency "+
				"samples actually recorded (post sample-mask gate + post "+
				"q32-skip). Use as the denominator for actual sampling rate.",
			[]string{"worker_id", "zone_pair_slot"}, nil,
		),
		workerColdPathSumNS: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_sum_ns_total",
			"Per-worker / zone-pair-slot cumulative sum of recorded "+
				"delta_ns values (post baseline subtraction).",
			[]string{"worker_id", "zone_pair_slot"}, nil,
		),
		workerColdPathAliasSeen: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_alias_seen",
			"1 if this zone-pair-slot saw two different packed "+
				"(from_zone, to_zone) keys during the current publish "+
				"window — the harness excludes aliased slots from Scale "+
				"Target tables. 0 otherwise.",
			[]string{"worker_id", "zone_pair_slot"}, nil,
		),
		workerColdPathSamplePhase: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_sample_phase_total",
			"Per-worker monotonic count of eligible cold-path sampling "+
				"attempts. Increment on every session-miss pass through "+
				"the policy-eval pre-eval gate. Denominator for "+
				"actual_sampling_rate = sum(samples[]) / sample_phase.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathWrapperUnderflow: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_wrapper_underflow_count_total",
			"Per-worker monotonic count of samples where raw_ns < "+
				"wrapper_ns_baseline. Indicates baseline drift "+
				"(frequency scaling, OoO jitter, ultra-fast policy_eval).",
			[]string{"worker_id"}, nil,
		),
		workerColdPathWrapperNSBaseline: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_wrapper_ns_baseline",
			"Calibrated cost of the sample_tsc_start + sample_tsc_end "+
				"fence pair, measured once per worker post pthread "+
				"affinity at startup. Subtracted from every recorded "+
				"delta_ns on the hot path.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathNSPerTSCQ32: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_ns_per_tsc_q32",
			"Q32 fixed-point ns_per_tsc multiplier from worker startup "+
				"calibration. 0 when TSC unavailable. Operators compare "+
				"across workers to detect calibration anomalies.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathClockSource: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_clock_source",
			"1 when this worker's clock source has the value of the "+
				"`source` label. Operators gate Scale Target table "+
				"publication on every worker reporting source='tsc'. "+
				"Always emitted (uncalibrated workers report "+
				"source='unset').",
			[]string{"worker_id", "source"}, nil,
		),
		workerColdPathSnapshotFailedTotal: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_snapshot_failed_total",
			"Per-worker monotonic count of snapshot() calls at the "+
				"coordinator status path that exhausted their retry "+
				"budget (publish contention / scheduler preemption). "+
				"Distinguishes 'no data this scrape' from 'transient "+
				"starvation'.",
			[]string{"worker_id"}, nil,
		),
		// === #1635 sparse v3 per-zone-pair cold-path families ===
		workerColdPathBucketV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_ns_bucket_v3",
			"Cumulative cold-path policy-eval latency observations per "+
				"worker / (from_zone, to_zone), bucketed into the #1635 "+
				"48-bucket log-linear ns histogram (32 linear 16-ns "+
				"buckets over [0,512) ns + 15 pow-2 buckets + saturate). "+
				"Compatible with PromQL histogram_quantile() via `le`.",
			[]string{"worker_id", "from_zone", "to_zone", "le"}, nil,
		),
		workerColdPathSamplesV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_samples_v3_total",
			"Per-worker / (from_zone, to_zone) count of cold-path latency "+
				"samples recorded (#1635 direct slot map).",
			[]string{"worker_id", "from_zone", "to_zone"}, nil,
		),
		workerColdPathSumNSV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_sum_ns_v3_total",
			"Per-worker / (from_zone, to_zone) cumulative sum of recorded "+
				"delta_ns (post baseline subtraction).",
			[]string{"worker_id", "from_zone", "to_zone"}, nil,
		),
		workerColdPathBuilderCollisionV3: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_builder_collision_v3",
			"1 if this (from_zone, to_zone) slot saw two distinct packed "+
				"keys — a snapshot-builder bug with the #1635 direct slot "+
				"map; should always be 0. 0 otherwise.",
			[]string{"worker_id", "from_zone", "to_zone"}, nil,
		),
		workerColdPathOverflowActive: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_overflow_active",
			"1 if a configured zone-pair could not be assigned a cold-path "+
				"histogram slot — either the 255-slot capacity was "+
				"exhausted OR the pair references a zone-id outside the "+
				"0..=64 direct-table range. 0 otherwise.",
			[]string{"worker_id"}, nil,
		),
		workerColdPathLayoutVersion: prometheus.NewDesc(
			"xpf_userspace_worker_cold_path_layout_version",
			"1 when this worker's cold-path wire layout has the value of "+
				"the `version` label (#1635: 3 = sparse log-linear).",
			[]string{"worker_id", "version"}, nil,
		),
		workerColdPathLayoutUnknownTotal: prometheus.NewDesc(
			// Gauge-style state indicator (NOT a counter): emitted as a
			// GaugeValue=1 when the version is unknown, so the name must
			// NOT end in `_total` (Copilot code-r4: a `_total` suffix
			// would mislead operators into rate()-ing a state flag).
			"xpf_userspace_worker_cold_path_layout_version_unknown",
			"1 when this worker reported a cold-path wire layout version "+
				"the collector does not understand (forward-compat guard).",
			[]string{"worker_id", "version"}, nil,
		),
		bindingActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_binding_active_flow_count",
			"Distinct active flows observed in this binding's flow_cache "+
				"in the last ~650ms (10 epoch ticks × ~65ms debug-state tick; "+
				"snapshot refreshed on each tick). Read by the fairness harness to "+
				"compute the structural CoV ceiling per docs/fairness-regimes.md (#1219).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingFlowCacheCapacity: prometheus.NewDesc(
			"xpf_userspace_binding_flow_cache_capacity",
			"Flow-cache capacity published by the userspace helper for this binding.",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletions: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completions_total",
			"Cumulative AF_XDP TX completions reaped by this binding's owner worker (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletionRingAvailable: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available",
			"Last sampled AF_XDP TX completion-ring descriptors available before the owner worker drained completions (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingTXCompletionRingAvailableMax: prometheus.NewDesc(
			"xpf_userspace_binding_tx_completion_ring_available_max",
			"Maximum sampled AF_XDP TX completion-ring descriptors available in the last debug window (#1241).",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		// #1831 (follow-up to #1766): per-binding V_min fairness-throttle
		// counters (#941 work item D / #943), already carried in
		// BindingStatus on the wire but previously unexported.
		bindingVMinThrottles: prometheus.NewDesc(
			"xpf_userspace_binding_v_min_throttles_total",
			"V_min fairness-brake throttle decisions on this binding's "+
				"shared-exact CoS queues: a drain batch early-broke because the "+
				"queue's virtual time ran more than LAG_THRESHOLD ahead of the "+
				"slowest participating peer worker's V_min (#917/#943). Non-zero "+
				"under load confirms the cross-worker brake is engaged; the "+
				"hard-cap-overrides / throttles ratio is the diagnostic for "+
				"LAG_THRESHOLD tuned too tight.",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		bindingVMinThrottleHardCapOverrides: prometheus.NewDesc(
			"xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total",
			"V_MIN_CONSECUTIVE_SKIP_HARD_CAP escape-hatch activations on this "+
				"binding: after that many back-to-back V_min throttle decisions "+
				"the drain force-continues and arms suspension — 'brake too "+
				"tight, escape hatch rescued throughput' (#941 work item D). "+
				"Counted distinctly from (not a subset of) "+
				"xpf_userspace_binding_v_min_throttles_total.",
			[]string{"binding_slot", "queue_id", "worker_id", "iface"}, nil,
		),
		cosActiveFlowCount: prometheus.NewDesc(
			"xpf_userspace_cos_active_flow_count",
			"Distinct active flows observed for this egress CoS queue on this worker "+
				"in the last ~650ms. This class-specific distribution is the preferred "+
				"fairness harness input for mixed workloads (#1248).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessCstruct: prometheus.NewDesc(
			"xpf_fairness_cstruct",
			"Structural per-flow CoV ceiling for this egress CoS queue, derived from "+
				"xpf_userspace_cos_active_flow_count and the fairness-regimes contract (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_active_workers",
			"Number of workers with at least one active flow for this egress CoS queue (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessActiveFlows: prometheus.NewDesc(
			"xpf_fairness_active_flows",
			"Total active flows observed for this egress CoS queue in the current userspace snapshot (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessMaxWorkerFlowShare: prometheus.NewDesc(
			"xpf_fairness_max_worker_flow_share",
			"Largest fraction of this egress CoS queue's active flows owned by one worker (#1247).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessCoSCountsTruncated: prometheus.NewDesc(
			"xpf_fairness_cos_active_flow_counts_truncated",
			"1 when the userspace CoS active-flow snapshot was truncated before fairness RSS gauges were derived; 0 otherwise (#1247).",
			nil, nil,
		),
		fairnessRSSExpectation: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_configured",
			"1 for each configured opt-in RSS/workload expectation evaluated against this egress CoS queue (#1247).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessRSSExpectationValue: prometheus.NewDesc(
			"xpf_fairness_rss_expectation_value",
			"Configured numeric value for RSS/workload expectation kinds that take one, such as active-worker count or threshold (#1265).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessRSSSkewViolation: prometheus.NewDesc(
			"xpf_fairness_rss_skew_violation",
			"1 when the configured RSS/workload expectation fails for this egress CoS queue; 0 when it passes (#1247).",
			[]string{"ifindex", "queue_id", "kind"}, nil,
		),
		fairnessSaturated: prometheus.NewDesc(
			"xpf_fairness_saturated",
			"1 when the rolling per-flow byte window is at or above 95% of the configured egress CoS queue transmit rate (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessObservedCoV: prometheus.NewDesc(
			"xpf_fairness_observed_cov",
			"Rolling observed coefficient of variation across per-flow byte totals for this egress CoS queue (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessStarvedFlows: prometheus.NewDesc(
			"xpf_fairness_starved_flows",
			"Monotonic count of flows that enter below 1% of the rolling mean per-flow bytes for this egress CoS queue, de-duplicated while the flow remains in the rolling window (#1264).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowEstimateValid: prometheus.NewDesc(
			"xpf_fairness_equal_flow_estimate_valid",
			"1 when the measurement-only equal-flow suppression estimator has at least two currently-active-flow workers with rolling byte samples for this egress CoS queue (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowSampledActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_equal_flow_sampled_active_workers",
			"Currently-active-flow workers with non-zero rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowUnsampledActiveWorkers: prometheus.NewDesc(
			"xpf_fairness_equal_flow_unsampled_active_workers",
			"Currently-active-flow workers with no rolling byte samples in the measurement-only equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowTargetPerFlowBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_target_per_flow_bps",
			"Slowest sampled currently-active worker's observed per-flow bit rate used as the measurement-only equal-flow suppression target for this egress CoS queue; low values may reflect source artifacts such as idle or receiver-limited flows, not only dataplane unfairness (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowObservedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_observed_bps",
			"Observed aggregate bits per second across currently-active-flow workers in the rolling estimator window before hypothetical equal-flow suppression (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowCappedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_capped_bps",
			"Estimated aggregate bits per second across currently-active-flow workers after applying the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowSuppressedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_suppressed_bps",
			"Estimated currently-active-flow worker bits per second that would be withheld by the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowThroughputLossRatio: prometheus.NewDesc(
			"xpf_fairness_equal_flow_throughput_loss_ratio",
			"Estimated suppressed_bps / observed_bps ratio for the measurement-only equal-flow suppression cap; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id"}, nil,
		),
		fairnessEqualFlowWorkerObservedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_observed_bps",
			"Observed bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerObservedPerFlowBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_observed_per_flow_bps",
			"Observed per-flow bits per second for one currently-active-flow worker in the rolling equal-flow suppression estimator (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerCapBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_cap_bps",
			"Estimated bits-per-second cap for one currently-active-flow worker under measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessEqualFlowWorkerSuppressedBPS: prometheus.NewDesc(
			"xpf_fairness_equal_flow_worker_suppressed_bps",
			"Estimated bits per second withheld from one currently-active-flow worker by measurement-only equal-flow suppression; artifact-sensitive because the cap follows the slowest sampled per-flow rate (#1304).",
			[]string{"ifindex", "queue_id", "worker_id"}, nil,
		),
		fairnessThroughputWindow: dpuserspace.NewFairnessThroughputWindow(30 * time.Second),
		// #1636 option C: proactive-neighbor-warm telemetry.
		neighborWarmDropsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_warm_drops_total",
			"Proactive neighbor-warm requests dropped because the bounded warmer queue was full (transient saturation under route churn) (#1636).",
			nil, nil,
		),
		neighborWarmDisconnectedTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_warm_disconnected_total",
			"Proactive neighbor-warm requests dropped because the warmer worker thread died; warming is disabled until daemon restart (#1636).",
			nil, nil,
		),
		// #1782 cold-start capture instrumentation.
		negNeighFastFailTotal: prometheus.NewDesc(
			"xpf_userspace_neg_neigh_fast_fail_total",
			"Packets fast-failed by the per-worker neighbor negative cache after a pending_neigh timeout armed the 3s lockout (cold-start H1 amplifier signal) (#1782).",
			nil, nil,
		),
		pendingNeighDuplicateDropsTotal: prometheus.NewDesc(
			"xpf_userspace_pending_neigh_duplicate_drops_total",
			"MissingNeighbor sibling packets recycled because the (egress_ifindex, next_hop) key was already pending in pending_neigh (cold-start H5 sibling-drop signal; excludes the MAX_PENDING_NEIGH capacity-drop case) (#1782).",
			nil, nil,
		),
		pendingNeighDecapDropsTotal: prometheus.NewDesc(
			"xpf_userspace_pending_neigh_decap_drops_total",
			"GRE-decapped MissingNeighbor packets refused pending_neigh admission: the buffered descriptor would pair the un-decapped OUTER UMEM frame with the post-decap INNER meta, and the neighbor-resolution retry would TX a mis-rewritten outer packet (#1902).",
			nil, nil,
		),
		pendingNeighCapacityDropsTotal: prometheus.NewDesc(
			"xpf_userspace_pending_neigh_capacity_drops_total",
			"MissingNeighbor packets for a NEW distinct (egress_ifindex, next_hop) dropped because the per-binding pending_neigh map is at MAX_PENDING_NEIGH distinct unresolved hops — distinct-hop neighbor exhaustion (a scan or upstream outage hitting many cold next hops). Counted separately from xpf_userspace_pending_neigh_duplicate_drops_total, which is normal cold-start coalescing of siblings for an already-pending hop (#2375).",
			nil, nil,
		),
		dynamicNeighborPresent: prometheus.NewDesc(
			"xpf_userspace_dynamic_neighbor_present",
			"Per-key presence gauge (always 1) dumped from the helper userspace dynamic_neighbors mirror so the cold-start capture harness can grep the pre-connect t0' next-hop membership (the H2 absence fingerprint) (#1782). DEBUG-ONLY: gated behind the helper's XPF_DEBUG_NEIGHBOR_KEYS env var and absent by default — an absent metric family means the dump is disabled, NOT that dynamic_neighbors is empty.",
			[]string{"ifindex", "ip"}, nil,
		),
		// #1769: on-demand neighbor-resolver telemetry — operator-visible
		// signal for the MissingNeighbor negative-cache stuck-state.
		neighborResolverQueueDepth: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_queue_depth",
			"On-demand neighbor-resolver queue depth: dsts queued for a single-key RTM_GETNEIGH after a MissingNeighbor negative-cache fast-fail but not yet processed (gauge) (#1769).",
			nil, nil,
		),
		neighborResolverEnqueueDropsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_enqueue_drops_total",
			"On-demand neighbor-resolver enqueue attempts dropped because the bounded queue was full (transient; the dst still fast-fails this round) (#1769).",
			nil, nil,
		),
		neighborResolverDisconnectedTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_disconnected_total",
			"On-demand neighbor-resolver enqueue attempts dropped because the resolver worker thread died; on-demand resolution is disabled until daemon restart (#1769).",
			nil, nil,
		),
		neighborResolverGetAttemptsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_attempts_total",
			"Single-key RTM_GETNEIGH requests issued by the on-demand resolver (after the per-key rate-limit coalesces a SYN storm) (#1769).",
			nil, nil,
		),
		neighborResolverGetResolvedTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_resolved_total",
			"On-demand RTM_GETNEIGH replies confirmed REACHABLE/PERMANENT and cached into the dynamic neighbor map (epoch guard passed) (#1769).",
			nil, nil,
		),
		neighborResolverProbeOnStaleTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_probe_on_stale_total",
			"On-demand RTM_GETNEIGH replies in STALE/DELAY/PROBE that triggered a revalidation probe instead of caching the unconfirmed MAC (the live #1769 wedge state) (#1769).",
			nil, nil,
		),
		neighborResolverGetFailuresTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_failures_total",
			"On-demand RTM_GETNEIGH attempts with no usable reply (timeout, FAILED, INCOMPLETE, no entry, or recv/parse error) (#1769).",
			nil, nil,
		),
		neighborResolverEpochRejectsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_epoch_rejects_total",
			"Confirmed on-demand inserts skipped because the global neighbor epoch advanced between enqueue and the GET reply (epoch guard rejected a potentially-raced stale insert) (#1769).",
			nil, nil,
		),
		// #1772: neighbor/ARP resolution LATENCY metrics. The two
		// histograms localize where an intermittent slow new connection
		// spends its time: pending-buffer dwell vs resolver GETNEIGH RTT.
		neighborPendingDwellSeconds: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_dwell_seconds",
			"Histogram of how long a packet sat in the pending-neighbor buffer before its neighbor resolved and it was dispatched (now-queued at the retry-sweep success path). The 3 s blackout class from #1769 lands in the +Inf tail (#1772).",
			nil, nil,
		),
		neighborResolverGetRttSeconds: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_rtt_seconds",
			"Histogram of the on-demand resolver single-key RTM_GETNEIGH round-trip time (request sent to reply read) on the resolver thread (#1772).",
			nil, nil,
		),
		neighborPendingTimeoutDropsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_timeout_drops_total",
			"Pending-neighbor packets dropped after exceeding PENDING_NEIGH_TIMEOUT without resolving (never reached a usable neighbor within the window) (#1772).",
			nil, nil,
		),
		neighborPendingMaxDepth: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_max_depth",
			"High-water mark of the per-binding pending-neighbor queue depth observed at any retry-sweep entry (gauge) (#1772).",
			nil, nil,
		),
		// #1771 §2.6: resolver backoff + §2.5 ENOBUFS/re-dump telemetry.
		neighborResolverGetBackoffAttemptsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_resolver_get_backoff_attempts_total",
			"On-demand resolver GET attempts that were backoff RETRIES: the key had already been attempted within the resolver's per-key memory and was re-admitted after the per-key rate-limit window. Subset of get_attempts; a rising rate means the same next-hops keep failing to resolve. Per invariant N1 (#1771 §2.4) these retries keep firing even while the key is negatively cached.",
			nil, nil,
		),
		neighborNetlinkEnobufsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_netlink_enobufs_total",
			"ENOBUFS receives on the neighbor-monitor netlink socket: the kernel dropped RTM_NEWNEIGH/DELNEIGH multicast notifications on rcvbuf overflow (the lost-notification desync class the throttled upsert-only re-dump self-heals) (#1771 §2.5).",
			nil, nil,
		),
		neighborNetlinkRedumpsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_netlink_redumps_total",
			"Throttled (5s) upsert-only neighbor-table re-dumps issued after an ENOBUFS (at least one of the v4/v6 dump requests was sent) (#1771 §2.5).",
			nil, nil,
		),
		neighborNetlinkRedumpUpsertsTotal: prometheus.NewDesc(
			"xpf_userspace_neighbor_netlink_redump_upserts_total",
			"Dynamic-neighbor entries (re)added by an upsert-only re-dump reply — RTM_NEWNEIGH dump replies whose insert changed the map. Nonzero proves a re-dump repopulated keys that lost multicast events had desynced (#1771 §2.5).",
			nil, nil,
		),
		neighborPendingKeys: prometheus.NewDesc(
			"xpf_userspace_neighbor_pending_keys",
			"Distinct unresolved (egress_ifindex, next_hop) keys currently holding a buffered packet in the per-binding pending_neigh maps, summed across bindings (gauge; refreshed at the ~65ms per-binding debug tick) (#1771 §2.6).",
			nil, nil,
		),
		negNeighKeys: prometheus.NewDesc(
			"xpf_userspace_neg_neigh_keys",
			"Keys currently held in the per-binding negative neighbor caches, summed across bindings (gauge; lazy-TTL upper bound — an expired entry stays counted until its next access) (#1771 §2.6).",
			nil, nil,
		),
		// #3773 (M13): fabric-link skip diagnostics.
		fabricLinkSkippedMalformedTotal: prometheus.NewDesc(
			"xpf_userspace_fabric_link_skipped_malformed_total",
			"HA cross-chassis fabric links skipped during a forwarding build/refresh because a value was MALFORMED: an invalid parent ifindex, an unparseable peer address, or a non-empty local/peer MAC string that failed to parse. Non-zero (especially climbing) is a fabric config/environment fault an operator must fix; the helper journal names which fabric and why. Before #3773 these were silent (no counter, log, or status) (#3773 M13).",
			nil, nil,
		),
		fabricLinkUnresolvedPeerTotal: prometheus.NewDesc(
			"xpf_userspace_fabric_link_unresolved_peer_total",
			"HA cross-chassis fabric links skipped during a forwarding build/refresh because a peer or local MAC was UNRESOLVED: an EMPTY MAC field still awaiting neighbor/interface resolution (the expected late-resolution SyncFabricState transient). Briefly non-zero at startup is normal; a persistently climbing value means a fabric peer is not resolving. A distinct, non-malformed state vs xpf_userspace_fabric_link_skipped_malformed_total (#3773 M13).",
			nil, nil,
		),
		// #1865: per-tunnel WireGuard telemetry. The tunnel label is
		// the tunnel interface NAME (stable across commits — #1873
		// positional ids renumber and are never a label). Counters
		// reset when a commit changes the tunnel's crypto identity
		// (engine rebuild); rate() handles the monotonic reset.
		wgHandshakesCompletedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshakes_completed_total",
			"WireGuard handshake completions by role: initiator = a consumed response promoted our initiation; responder = we accepted an initiation and created (and installed the session for) the response (#1865).",
			[]string{"tunnel", "role"}, nil,
		),
		wgHandshakeInitiationsCreatedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_initiations_created_total",
			"WireGuard handshake initiations BUILT (not necessarily sent — a failing socket send counts in xpf_userspace_wg_send_errors_total{kind=\"handshake\"}; created rising with completions flat and send errors rising is the silent-send fingerprint from #1736) (#1865).",
			[]string{"tunnel"}, nil,
		),
		wgHandshakeInitiationBuildFailuresTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_initiation_build_failures_total",
			"WireGuard initiation build failures (engine could not construct msg1 — unknown peer, index exhaustion, crypto/internal error; all folded) (#1865).",
			[]string{"tunnel"}, nil,
		),
		wgHandshakeRxDropsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_rx_drops_total",
			"Inbound WireGuard handshake-path datagrams dropped, by reason (mac1_mismatch | malformed | crypto | unknown_peer | stale_response | index_exhausted | cookie_unsupported | under_load_no_mac2 | cookie_reply_budget | unknown_type). mac1_mismatch is the wrong-key-peer signature; under_load_no_mac2 is the #4094 responder under-load DoS mitigation refusing a forged/unprimed initiation and issuing a cookie challenge; cookie_reply_budget is that same path when the per-window cookie-reply budget clamps (#1865, #4094).",
			[]string{"tunnel", "reason"}, nil,
		),
		wgCookieRepliesTotal: prometheus.NewDesc(
			"xpf_userspace_wg_cookie_replies_total",
			"WireGuard cookie mechanism (#4094) by event: sent = type-3 CookieReply challenges the RESPONDER emitted under load to valid-MAC1 initiations lacking a valid MAC2; mac2_ok = under-load initiations that carried a valid MAC2 (a primed peer) and were allowed through to the Noise handshake; consumed = cookie-replies the INITIATOR decrypted and stored (PR-B) to arm a valid MAC2 on its next initiation.",
			[]string{"tunnel", "event"}, nil,
		),
		wgHandshakeRequestsArmedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_requests_armed_total",
			"Accepted NoSession worker→control handshake-request edges (rate-limited to 1/s) — ties an encap-drop burst to the re-initiation it triggered (#1865).",
			[]string{"tunnel"}, nil,
		),
		wgTransportPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_packets_total",
			"WireGuard transport packets successfully processed, by direction (encap = egress encrypt, decap = ingress decrypt+deliver) (#1865).",
			[]string{"tunnel", "direction"}, nil,
		),
		wgTransportBytesTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_bytes_total",
			"WireGuard transport INNER-IP bytes by direction (logical tunnel payload bytes, excluding WG+outer overhead — will not match a kernel peer's `wg show` transfer numbers) (#1865).",
			[]string{"tunnel", "direction"}, nil,
		),
		wgKeepalivesReceivedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_keepalives_received_total",
			"Authenticated zero-length WireGuard transport records (peer persistent keepalives). Classified separately so keepalive traffic never inflates the malformed_inner drop reason (#1865).",
			[]string{"tunnel"}, nil,
		),
		wgTransportDropsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_drops_total",
			"WireGuard transport drops by direction and reason. decap: malformed_header | unknown_session | counter_ceiling | crypto | replay | allowed_ips | malformed_inner | buffer | expired. encap: no_session | unconfirmed | rekey_required | mtu | other | expired. `expired` is the #1888 per-use REJECT_AFTER_TIME refusal (drop-only on decap; arms the rekey edge on encap). `unconfirmed` is the responder key-confirmation window (transient at rekey — distinct from no_session so operators do not tcpdump a blip); `mtu` is the exact pad-aware guard at BOTH egress sites (the #1736 v4-mapped blackhole class) (#1865).",
			[]string{"tunnel", "direction", "reason"}, nil,
		),
		wgSendErrorsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_send_errors_total",
			"WireGuard I/O errors by kind: handshake = msg1/msg2 socket send failed (the #1736 EINVAL class); transport = encap'd datagram send failed; tun_write = decap'd inner delivery to the wgN TUN failed; tun_rx_no_endpoint = inner packets drained+dropped while a responder-only peer has no learned endpoint (#1865).",
			[]string{"tunnel", "kind"}, nil,
		),
		wgSessionConfirmed: prometheus.NewDesc(
			"xpf_userspace_wg_session_confirmed",
			"Whether a tunnel peer currently holds a CONFIRMED (egress-usable) transport session (1/0 gauge). Labeled by tunnel AND peer public key (#1434 multi-peer). The liveness signal — a responder-side handshake completion alone does not imply the peer ever received our response (#1865).",
			[]string{"tunnel", "peer"}, nil,
		),
		wgLastHandshakeTimeSeconds: prometheus.NewDesc(
			"xpf_userspace_wg_last_handshake_time_seconds",
			"Wall-clock epoch seconds of the most recent WireGuard handshake completion (either role). Absent until the first handshake completes; compute age as time() - this (#1865).",
			[]string{"tunnel"}, nil,
		),
		wgRekeysInitiatedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_rekeys_initiated_total",
			"Timer-driven WireGuard handshake initiations by reason: age = REKEY_AFTER_TIME/receive-horizon/expiry on the live session; dead_peer = 15s no-reply reinit (sent data, heard nothing); keepalive_no_session = persistent keepalive due with no usable session (#1888 S5).",
			[]string{"tunnel", "reason"}, nil,
		),
		wgKeepalivesSentTotal: prometheus.NewDesc(
			"xpf_userspace_wg_keepalives_sent_total",
			"WireGuard keepalives SENT by kind: passive = 10s KEEPALIVE_TIMEOUT replies to inbound data (incl. the post-handshake key-confirmation keepalive); persistent = operator-configured persistent-keepalive interval (#1888 S5).",
			[]string{"tunnel", "kind"}, nil,
		),
		wgSessionsExpiredTotal: prometheus.NewDesc(
			"xpf_userspace_wg_sessions_expired_total",
			"WireGuard transport sessions torn down at REJECT_AFTER_TIME (180s) by the control thread's expiry pass. Per-use refusals are the expired reason under xpf_userspace_wg_transport_drops_total (#1888 S5).",
			[]string{"tunnel"}, nil,
		),
		wgHandshakeAttemptsAbortedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_attempts_aborted_total",
			"Pending WireGuard handshake reservations released by the REKEY_ATTEMPT_TIME (90s) give-up — a stale msg2 after this cannot complete the abandoned handshake (#1888 S5).",
			[]string{"tunnel"}, nil,
		),

		// #2464: per-collector flow-export write-health.
		flowExportCollectorWriteAttemptsTotal: prometheus.NewDesc(
			"xpf_flow_export_collector_write_attempts_total",
			"Total NetFlow v9 / IPFIX UDP write attempts per collector. Labeled by instance and template as well as collector and source, so two template groups / family-disjoint instances that share one collector address stay distinct series (#3741).",
			[]string{"protocol", "instance", "template", "collector", "source"}, nil,
		),
		flowExportCollectorWriteFailuresTotal: prometheus.NewDesc(
			"xpf_flow_export_collector_write_failures_total",
			"Total NetFlow v9 / IPFIX UDP write failures per collector (a climbing value while attempts climb means the collector is unreachable and flow records are being silently dropped). Labeled by instance and template as well as collector and source, so a failing template group sharing a collector address is attributable, not hidden (#3741).",
			[]string{"protocol", "instance", "template", "collector", "source"}, nil,
		),
		flowExportCollectorWriteSkippedTotal: prometheus.NewDesc(
			"xpf_flow_export_collector_write_skipped_total",
			"Total NetFlow v9 / IPFIX writes SKIPPED per collector because it was unhealthy and still inside its probe-backoff window (#4423). A climbing value (while attempts/failures hold) means a persistently-dead collector is being skipped between probes rather than re-attempted every flush — the deliberate steady-state cost cap for a dead collector. Same label set as attempts/failures.",
			[]string{"protocol", "instance", "template", "collector", "source"}, nil,
		),
		flowExportCollectorHealthy: prometheus.NewDesc(
			"xpf_flow_export_collector_healthy",
			"1 when the last write to this flow-export collector succeeded, 0 when the last write failed. Labeled by instance and template as well as collector and source (#3741).",
			[]string{"protocol", "instance", "template", "collector", "source"}, nil,
		),
		flowExportCollectorLastSuccessSeconds: prometheus.NewDesc(
			"xpf_flow_export_collector_last_success_timestamp_seconds",
			"Unix timestamp of the last successful write to this flow-export collector (0 if none yet). Labeled by instance and template as well as collector and source (#3741).",
			[]string{"protocol", "instance", "template", "collector", "source"}, nil,
		),
		flowExportCollectorLastFailureSeconds: prometheus.NewDesc(
			"xpf_flow_export_collector_last_failure_timestamp_seconds",
			"Unix timestamp of the last failed write to this flow-export collector (0 if none yet). Labeled by instance and template as well as collector and source (#3741).",
			[]string{"protocol", "instance", "template", "collector", "source"}, nil,
		),

		// #3747: per-exporter pending-batch queue observability.
		flowExportBatchDepth: prometheus.NewDesc(
			"xpf_flow_export_batch_depth",
			"Current number of flow records pending in the export batch for this group (both families combined). Normally near 0 — the exporter drains every 100ms; a sustained nonzero value means the drain cannot keep up (stalled export goroutine, slow/unreachable collector, or a SESSION_CLOSE storm) (#3747).",
			[]string{"protocol", "instance", "template"}, nil,
		),
		flowExportBatchMaxDepth: prometheus.NewDesc(
			"xpf_flow_export_batch_max_depth",
			"High-water mark of the pending export batch depth for this group since the exporter started. Captures a transient backlog even after a later drain empties the queue (#3747).",
			[]string{"protocol", "instance", "template"}, nil,
		),
		flowExportBatchDroppedTotal: prometheus.NewDesc(
			"xpf_flow_export_batch_dropped_total",
			"Total flow records dropped because the pending export batch was at its per-family capacity (#3747). Before #3747 the batch was unbounded and a stalled/overrun drain grew memory without bound; it now drops (drop-newest) and counts. A climbing value means export records are being lost to a drain that cannot keep up.",
			[]string{"protocol", "instance", "template"}, nil,
		),
	}
}
