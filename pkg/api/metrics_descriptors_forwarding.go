package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initForwardingDescriptors() {
	// #4422: policy-based-routing (filter-based-forwarding) build health.
	// xpf_pbr_rules_installed is the number of kernel `ip rule` FBF entries
	// the active config's routing-instance filter terms yield (the
	// desired-install set). Config-derived (routing.PBRBuildStats, a pure
	// function of config), emitted BEFORE the dataplane gate.
	c.pbrRulesInstalled = prometheus.NewDesc(
		"xpf_pbr_rules_installed",
		"Number of kernel ip-rule filter-based-forwarding entries the active "+
			"config's routing-instance filter terms yield (#4422).",
		nil, nil,
	)
	// #4422: number of routing-instance filter terms DROPPED from the kernel
	// FBF mirror (fail-closed under-steer to the main table) — an
	// unrepresentable except set, a DSCP-0 match, a contradictory
	// routing-instance+discard/reject term (#4534), an ip-rule-unrepresentable
	// L4/per-packet predicate (#3730), or the priority-window overflow (#3430
	// M3). Non-zero means the kernel slow path under-steers vs the userspace
	// fast path (which still enforces every term exactly). There is no
	// "widened" state — the builder refuses to widen an unrepresentable match.
	c.pbrDegradedTerms = prometheus.NewDesc(
		"xpf_pbr_degraded_terms",
		"Number of routing-instance filter terms dropped from the kernel "+
			"filter-based-forwarding mirror (fail-closed under-steer), because "+
			"the term carries a predicate an ip rule cannot express (#4422).",
		nil, nil,
	)
	c.tcEgressPacketsTotal = prometheus.NewDesc(
		"xpf_tc_egress_packets_total",
		"Total TC egress packets processed.",
		nil, nil,
	)
	c.syncookieTotal = prometheus.NewDesc(
		"xpf_screen_syncookie_total",
		"SYN cookie counters by type.",
		[]string{"type"}, nil,
	)
	c.flowCacheTotal = prometheus.NewDesc(
		"xpf_flow_cache_total",
		"Flow cache counters by type (IPv4 + IPv6).",
		[]string{"type"}, nil,
	)
}
