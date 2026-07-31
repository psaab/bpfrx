package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initSystemDescriptors() {
	c.sysCPUUser = prometheus.NewDesc(
		"xpf_system_cpu_user_percent",
		// #4707: inter-scrape delta (busyΔ/totalΔ), scaled by CPU count,
		// NOT the since-boot cumulative average. Not emitted on the first
		// scrape (no predecessor sample yet).
		"User+nice CPU utilization percentage over the last scrape interval "+
			"(summed across CPUs).",
		nil, nil,
	)
	c.sysCPUSystem = prometheus.NewDesc(
		"xpf_system_cpu_system_percent",
		// #4707: inter-scrape delta (busyΔ/totalΔ), scaled by CPU count.
		"System CPU utilization percentage over the last scrape interval "+
			"(summed across CPUs).",
		nil, nil,
	)
	c.sysMemTotal = prometheus.NewDesc(
		"xpf_system_memory_total_bytes",
		"Total system memory in bytes.",
		nil, nil,
	)
	c.sysMemAvail = prometheus.NewDesc(
		"xpf_system_memory_available_bytes",
		"Available system memory in bytes.",
		nil, nil,
	)
	c.daemonUptime = prometheus.NewDesc(
		"xpf_daemon_uptime_seconds",
		"Daemon uptime in seconds.",
		nil, nil,
	)
	c.daemonMemRSS = prometheus.NewDesc(
		"xpf_daemon_memory_rss_bytes",
		"Daemon resident set size in bytes.",
		nil, nil,
	)
}
