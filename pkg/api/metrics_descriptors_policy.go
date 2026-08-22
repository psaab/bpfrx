package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initPolicyDescriptors() {
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total",
		"Total policy rule hits.",
		[]string{"from_zone", "to_zone", "rule"}, nil,
	)
	// #7016: the policy sibling of xpf_zone_counters_unpopulated_zones. The
	// #3965 bulk reader signals a rule the helper has not published with
	// ErrPolicyCounterUnpublished, and collectPolicyCounters used to route that
	// to counterReadErrors -- the same FALSE alert #3643 removed the per-zone
	// family to stop, here firing once per counter-eligible rule per scrape for
	// the whole warm-up window. The sample is still omitted (never an
	// authoritative 0 for an unknown, the #3345 contract); this gauge is what
	// makes the omission visible instead of silent.
	c.policyCountersUnpublishedRules = prometheus.NewDesc(
		"xpf_policy_counters_unpublished_rules",
		"Number of counter-eligible policy rules whose per-rule hit counter the "+
			"dataplane has not published this scrape, so no xpf_policy_hits_total "+
			"sample was emitted for them. Counts configured zone-pair rules, "+
			"global rules, and the implicit default-policy row. Not an error: a "+
			"rule is counted here when the helper has published nothing for its "+
			"stable rule id -- the window before the first status poll lands "+
			"(the shim is loaded, so the dataplane already reads as loaded), or "+
			"config skew after a non-abort-class apply failure (#5679), where "+
			"the control plane has promoted a config the helper is not yet "+
			"enforcing. Matches the rules the REST inventory reports "+
			"hit_counters_unavailable true for. Genuine read failures bump "+
			"xpf_counter_read_errors_total instead (#3408, #7016). Emitted on "+
			"every path through the policy collector, which -- unlike the "+
			"per-zone gauge -- runs only on the dataplane-LOADED path: on a "+
			"degraded / config-only boot no policy counter family is emitted at "+
			"all (pre-existing), and the REST inventory's "+
			"hit_counters_unavailable is the signal for that state.",
		nil, nil,
	)
	c.filterHitsTotal = prometheus.NewDesc(
		"xpf_filter_hits_total",
		"Total firewall filter term hits.",
		[]string{"filter", "family", "term"}, nil,
	)
	c.threeColorPolicerPacketsTotal = prometheus.NewDesc(
		"xpf_userspace_three_color_policer_packets_total",
		"Userspace three-color policer packets by resulting color.",
		[]string{"policer", "color"}, nil,
	)
	c.threeColorPolicerBytesTotal = prometheus.NewDesc(
		"xpf_userspace_three_color_policer_bytes_total",
		"Userspace three-color policer bytes by resulting color.",
		[]string{"policer", "color"}, nil,
	)
	c.threeColorPolicerDropsTotal = prometheus.NewDesc(
		"xpf_userspace_three_color_policer_drops_total",
		"Userspace three-color policer packets dropped by policer treatment.",
		[]string{"policer"}, nil,
	)
	c.threeColorPolicerDropBytes = prometheus.NewDesc(
		"xpf_userspace_three_color_policer_drop_bytes_total",
		"Userspace three-color policer bytes dropped by policer treatment.",
		[]string{"policer"}, nil,
	)
}
