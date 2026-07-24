package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initInterfaceDescriptors() {
	c.ifacePacketsTotal = prometheus.NewDesc(
		"xpf_interface_packets_total",
		"Total packets per interface.",
		[]string{"iface", "direction"}, nil,
	)
	c.ifaceBytesTotal = prometheus.NewDesc(
		"xpf_interface_bytes_total",
		"Total bytes per interface.",
		[]string{"iface", "direction"}, nil,
	)
	// #3464: per-interface counter-read scrape-error signal. A failed
	// ReadInterfaceCounters OMITS that interface's xpf_interface_* samples
	// (rather than emitting a misleading 0) and bumps this monotonic
	// counter, so a degraded interface-counter bridge is alertable instead
	// of silently reported as zero. Distinct from
	// xpf_counter_read_errors_total: interface counters are intentionally
	// out of the #3345 security-counter contract, so they get their own
	// error metric (always emitted, 0 when healthy).
	c.interfaceCounterReadErrorsTotal = prometheus.NewDesc(
		"xpf_interface_counter_read_errors_total",
		"Total per-interface dataplane counter read failures during metric "+
			"scrapes. A failed read omits that interface's xpf_interface_* "+
			"samples instead of emitting a misleading 0. Distinct from "+
			"xpf_counter_read_errors_total (interface counters are not "+
			"security counters; #3464).",
		nil, nil,
	)
}
