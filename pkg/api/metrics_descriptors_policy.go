package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initPolicyDescriptors() {
	c.policyHitsTotal = prometheus.NewDesc(
		"xpf_policy_hits_total",
		"Total policy rule hits.",
		[]string{"from_zone", "to_zone", "rule"}, nil,
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
