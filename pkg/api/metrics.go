package api

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
)

// bpfrxCollector implements prometheus.Collector, reading BPF maps on each scrape.
type bpfrxCollector struct {
	srv *Server

	// Global counters
	packetsTotal         *prometheus.Desc
	dropsTotal           *prometheus.Desc
	sessionsCreatedTotal *prometheus.Desc
	sessionsClosedTotal  *prometheus.Desc
	screenDropsTotal     *prometheus.Desc
	policyDeniesTotal    *prometheus.Desc
	natAllocFailsTotal   *prometheus.Desc
	hostInboundDeny      *prometheus.Desc
	tcEgressPacketsTotal *prometheus.Desc

	// Interface counters
	ifacePacketsTotal *prometheus.Desc
	ifaceBytesTotal   *prometheus.Desc

	// Zone counters
	zonePacketsTotal *prometheus.Desc
	zoneBytesTotal   *prometheus.Desc

	// Policy counters
	policyHitsTotal *prometheus.Desc

	// Filter counters
	filterHitsTotal *prometheus.Desc

	// Session gauges (from GC)
	sessionsActive      *prometheus.Desc
	sessionsEstablished *prometheus.Desc
	sessionsIPv4        *prometheus.Desc
	sessionsIPv6        *prometheus.Desc
	sessionsSNAT        *prometheus.Desc
	sessionsDNAT        *prometheus.Desc
	gcSweepDuration     *prometheus.Desc

	// NAT pool utilization
	natPoolUsedPorts  *prometheus.Desc
	natPoolTotalPorts *prometheus.Desc

	// DHCP lease gauge
	dhcpLeasesActive *prometheus.Desc

	// System metrics
	sysCPUUser    *prometheus.Desc
	sysCPUSystem  *prometheus.Desc
	sysMemTotal   *prometheus.Desc
	sysMemAvail   *prometheus.Desc
	daemonUptime  *prometheus.Desc
	daemonMemRSS  *prometheus.Desc
}

func newCollector(srv *Server) *bpfrxCollector {
	return &bpfrxCollector{
		srv: srv,

		packetsTotal: prometheus.NewDesc(
			"bpfrx_packets_total",
			"Total packets processed.",
			[]string{"direction"}, nil,
		),
		dropsTotal: prometheus.NewDesc(
			"bpfrx_drops_total",
			"Total packets dropped.",
			nil, nil,
		),
		sessionsCreatedTotal: prometheus.NewDesc(
			"bpfrx_sessions_created_total",
			"Total sessions created.",
			nil, nil,
		),
		sessionsClosedTotal: prometheus.NewDesc(
			"bpfrx_sessions_closed_total",
			"Total sessions closed.",
			nil, nil,
		),
		screenDropsTotal: prometheus.NewDesc(
			"bpfrx_screen_drops_total",
			"Total packets dropped by screen/IDS checks.",
			nil, nil,
		),
		policyDeniesTotal: prometheus.NewDesc(
			"bpfrx_policy_denies_total",
			"Total packets denied by policy.",
			nil, nil,
		),
		natAllocFailsTotal: prometheus.NewDesc(
			"bpfrx_nat_alloc_failures_total",
			"Total NAT port allocation failures.",
			nil, nil,
		),
		hostInboundDeny: prometheus.NewDesc(
			"bpfrx_host_inbound_denies_total",
			"Total host-inbound traffic denials.",
			nil, nil,
		),
		tcEgressPacketsTotal: prometheus.NewDesc(
			"bpfrx_tc_egress_packets_total",
			"Total TC egress packets processed.",
			nil, nil,
		),
		ifacePacketsTotal: prometheus.NewDesc(
			"bpfrx_interface_packets_total",
			"Total packets per interface.",
			[]string{"iface", "direction"}, nil,
		),
		ifaceBytesTotal: prometheus.NewDesc(
			"bpfrx_interface_bytes_total",
			"Total bytes per interface.",
			[]string{"iface", "direction"}, nil,
		),
		zonePacketsTotal: prometheus.NewDesc(
			"bpfrx_zone_packets_total",
			"Total packets per zone.",
			[]string{"zone", "direction"}, nil,
		),
		zoneBytesTotal: prometheus.NewDesc(
			"bpfrx_zone_bytes_total",
			"Total bytes per zone.",
			[]string{"zone", "direction"}, nil,
		),
		policyHitsTotal: prometheus.NewDesc(
			"bpfrx_policy_hits_total",
			"Total policy rule hits.",
			[]string{"from_zone", "to_zone", "rule"}, nil,
		),
		filterHitsTotal: prometheus.NewDesc(
			"bpfrx_filter_hits_total",
			"Total firewall filter term hits.",
			[]string{"filter", "family", "term"}, nil,
		),
		sessionsActive: prometheus.NewDesc(
			"bpfrx_sessions_active",
			"Current number of active session entries.",
			nil, nil,
		),
		sessionsEstablished: prometheus.NewDesc(
			"bpfrx_sessions_established",
			"Current number of established sessions.",
			nil, nil,
		),
		sessionsIPv4: prometheus.NewDesc(
			"bpfrx_sessions_ipv4",
			"Current number of IPv4 sessions.",
			nil, nil,
		),
		sessionsIPv6: prometheus.NewDesc(
			"bpfrx_sessions_ipv6",
			"Current number of IPv6 sessions.",
			nil, nil,
		),
		sessionsSNAT: prometheus.NewDesc(
			"bpfrx_sessions_snat",
			"Current number of SNAT sessions.",
			nil, nil,
		),
		sessionsDNAT: prometheus.NewDesc(
			"bpfrx_sessions_dnat",
			"Current number of DNAT sessions.",
			nil, nil,
		),
		gcSweepDuration: prometheus.NewDesc(
			"bpfrx_gc_sweep_duration_seconds",
			"Duration of the last GC sweep in seconds.",
			nil, nil,
		),
		natPoolUsedPorts: prometheus.NewDesc(
			"bpfrx_nat_pool_used_ports",
			"Number of used ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		natPoolTotalPorts: prometheus.NewDesc(
			"bpfrx_nat_pool_total_ports",
			"Total available ports in a NAT pool.",
			[]string{"pool"}, nil,
		),
		dhcpLeasesActive: prometheus.NewDesc(
			"bpfrx_dhcp_leases_active",
			"Number of active DHCP leases.",
			[]string{"family"}, nil,
		),

		sysCPUUser: prometheus.NewDesc(
			"bpfrx_system_cpu_user_percent",
			"User CPU utilization percentage.",
			nil, nil,
		),
		sysCPUSystem: prometheus.NewDesc(
			"bpfrx_system_cpu_system_percent",
			"System CPU utilization percentage.",
			nil, nil,
		),
		sysMemTotal: prometheus.NewDesc(
			"bpfrx_system_memory_total_bytes",
			"Total system memory in bytes.",
			nil, nil,
		),
		sysMemAvail: prometheus.NewDesc(
			"bpfrx_system_memory_available_bytes",
			"Available system memory in bytes.",
			nil, nil,
		),
		daemonUptime: prometheus.NewDesc(
			"bpfrx_daemon_uptime_seconds",
			"Daemon uptime in seconds.",
			nil, nil,
		),
		daemonMemRSS: prometheus.NewDesc(
			"bpfrx_daemon_memory_rss_bytes",
			"Daemon resident set size in bytes.",
			nil, nil,
		),
	}
}

func (c *bpfrxCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsTotal
	ch <- c.dropsTotal
	ch <- c.sessionsCreatedTotal
	ch <- c.sessionsClosedTotal
	ch <- c.screenDropsTotal
	ch <- c.policyDeniesTotal
	ch <- c.natAllocFailsTotal
	ch <- c.hostInboundDeny
	ch <- c.tcEgressPacketsTotal
	ch <- c.ifacePacketsTotal
	ch <- c.ifaceBytesTotal
	ch <- c.zonePacketsTotal
	ch <- c.zoneBytesTotal
	ch <- c.policyHitsTotal
	ch <- c.filterHitsTotal
	ch <- c.sessionsActive
	ch <- c.sessionsEstablished
	ch <- c.sessionsIPv4
	ch <- c.sessionsIPv6
	ch <- c.sessionsSNAT
	ch <- c.sessionsDNAT
	ch <- c.gcSweepDuration
	ch <- c.natPoolUsedPorts
	ch <- c.natPoolTotalPorts
	ch <- c.dhcpLeasesActive
	ch <- c.sysCPUUser
	ch <- c.sysCPUSystem
	ch <- c.sysMemTotal
	ch <- c.sysMemAvail
	ch <- c.daemonUptime
	ch <- c.daemonMemRSS
}

func (c *bpfrxCollector) Collect(ch chan<- prometheus.Metric) {
	dp := c.srv.dp
	if dp == nil || !dp.IsLoaded() {
		return
	}

	c.collectGlobalCounters(ch, dp)
	c.collectInterfaceCounters(ch, dp)
	c.collectZoneCounters(ch, dp)
	c.collectPolicyCounters(ch, dp)
	c.collectFilterCounters(ch, dp)
	c.collectSessionGauges(ch, dp)
	c.collectNATPoolMetrics(ch, dp)
	c.collectDHCPMetrics(ch)
	c.collectSystemMetrics(ch)
}

func (c *bpfrxCollector) collectGlobalCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	readCounter := func(idx uint32) float64 {
		v, _ := dp.ReadGlobalCounter(idx)
		return float64(v)
	}

	ch <- prometheus.MustNewConstMetric(c.packetsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrRxPackets), "rx")
	ch <- prometheus.MustNewConstMetric(c.packetsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrTxPackets), "tx")
	ch <- prometheus.MustNewConstMetric(c.dropsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrDrops))
	ch <- prometheus.MustNewConstMetric(c.sessionsCreatedTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSessionsNew))
	ch <- prometheus.MustNewConstMetric(c.sessionsClosedTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSessionsClosed))
	ch <- prometheus.MustNewConstMetric(c.screenDropsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrScreenDrops))
	ch <- prometheus.MustNewConstMetric(c.policyDeniesTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrPolicyDeny))
	ch <- prometheus.MustNewConstMetric(c.natAllocFailsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrNATAllocFail))
	ch <- prometheus.MustNewConstMetric(c.hostInboundDeny, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrHostInboundDeny))
	ch <- prometheus.MustNewConstMetric(c.tcEgressPacketsTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrTCEgressPackets))
}

func (c *bpfrxCollector) collectInterfaceCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			continue
		}
		ctrs, err := dp.ReadInterfaceCounters(iface.Index)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.ifacePacketsTotal, prometheus.CounterValue,
			float64(ctrs.RxPackets), ifName, "rx")
		ch <- prometheus.MustNewConstMetric(c.ifacePacketsTotal, prometheus.CounterValue,
			float64(ctrs.TxPackets), ifName, "tx")
		ch <- prometheus.MustNewConstMetric(c.ifaceBytesTotal, prometheus.CounterValue,
			float64(ctrs.RxBytes), ifName, "rx")
		ch <- prometheus.MustNewConstMetric(c.ifaceBytesTotal, prometheus.CounterValue,
			float64(ctrs.TxBytes), ifName, "tx")
	}
}

func (c *bpfrxCollector) collectZoneCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil {
		return
	}

	for zoneName, zoneID := range cr.ZoneIDs {
		ingress, err := dp.ReadZoneCounters(zoneID, 0)
		if err != nil {
			continue
		}
		egress, err := dp.ReadZoneCounters(zoneID, 1)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.zonePacketsTotal, prometheus.CounterValue,
			float64(ingress.Packets), zoneName, "ingress")
		ch <- prometheus.MustNewConstMetric(c.zonePacketsTotal, prometheus.CounterValue,
			float64(egress.Packets), zoneName, "egress")
		ch <- prometheus.MustNewConstMetric(c.zoneBytesTotal, prometheus.CounterValue,
			float64(ingress.Bytes), zoneName, "ingress")
		ch <- prometheus.MustNewConstMetric(c.zoneBytesTotal, prometheus.CounterValue,
			float64(egress.Bytes), zoneName, "egress")
	}
}

func (c *bpfrxCollector) collectPolicyCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil {
		return
	}

	// Build reverse zone ID map
	zoneNames := make(map[uint16]string)
	for name, id := range cr.ZoneIDs {
		zoneNames[id] = name
	}

	var policyID uint32
	for _, zpp := range cfg.Security.Policies {
		fromZone := zpp.FromZone
		toZone := zpp.ToZone
		for _, rule := range zpp.Policies {
			ctrs, err := dp.ReadPolicyCounters(policyID)
			if err != nil {
				policyID++
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
				float64(ctrs.Packets), fromZone, toZone, rule.Name)
			policyID++
		}
	}
}

func (c *bpfrxCollector) collectFilterCounters(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil || cr.FilterIDs == nil {
		return
	}

	emitFilters := func(family string, filters map[string]*config.FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			fid, ok := cr.FilterIDs[family+":"+name]
			if !ok {
				continue
			}
			fcfg, err := dp.ReadFilterConfig(fid)
			if err != nil {
				continue
			}
			ruleOffset := fcfg.RuleStart
			for _, term := range filter.Terms {
				nSrc := len(term.SourceAddresses)
				if nSrc == 0 {
					nSrc = 1
				}
				nDst := len(term.DestAddresses)
				if nDst == 0 {
					nDst = 1
				}
				numRules := uint32(nSrc * nDst)
				var totalPkts uint64
				for i := uint32(0); i < numRules; i++ {
					if ctrs, err := dp.ReadFilterCounters(ruleOffset + i); err == nil {
						totalPkts += ctrs.Packets
					}
				}
				ch <- prometheus.MustNewConstMetric(c.filterHitsTotal, prometheus.CounterValue,
					float64(totalPkts), name, family, term.Name)
				ruleOffset += numRules
			}
		}
	}

	emitFilters("inet", cfg.Firewall.FiltersInet)
	emitFilters("inet6", cfg.Firewall.FiltersInet6)
}

func (c *bpfrxCollector) collectSessionGauges(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	if c.srv.gc == nil {
		return
	}
	stats := c.srv.gc.Stats()
	ch <- prometheus.MustNewConstMetric(c.sessionsActive, prometheus.GaugeValue,
		float64(stats.TotalEntries))
	ch <- prometheus.MustNewConstMetric(c.sessionsEstablished, prometheus.GaugeValue,
		float64(stats.EstablishedSessions))
	ch <- prometheus.MustNewConstMetric(c.gcSweepDuration, prometheus.GaugeValue,
		stats.LastSweepDuration.Seconds())

	// Session breakdowns by type
	var ipv4, ipv6, snat, dnat int
	_ = dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			ipv4++
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				snat++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnat++
			}
		}
		return true
	})
	_ = dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			ipv6++
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				snat++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				dnat++
			}
		}
		return true
	})
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv4, prometheus.GaugeValue, float64(ipv4))
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv6, prometheus.GaugeValue, float64(ipv6))
	ch <- prometheus.MustNewConstMetric(c.sessionsSNAT, prometheus.GaugeValue, float64(snat))
	ch <- prometheus.MustNewConstMetric(c.sessionsDNAT, prometheus.GaugeValue, float64(dnat))
}

func (c *bpfrxCollector) collectNATPoolMetrics(ch chan<- prometheus.Metric, dp dataplane.DataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dp.LastCompileResult()
	if cr == nil {
		return
	}

	for name, pool := range cfg.Security.NAT.SourcePools {
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		totalPorts := (portHigh - portLow + 1) * len(pool.Addresses)
		ch <- prometheus.MustNewConstMetric(c.natPoolTotalPorts, prometheus.GaugeValue,
			float64(totalPorts), name)

		if id, ok := cr.PoolIDs[name]; ok {
			cnt, err := dp.ReadNATPortCounter(uint32(id))
			if err == nil {
				ch <- prometheus.MustNewConstMetric(c.natPoolUsedPorts, prometheus.GaugeValue,
					float64(cnt), name)
			}
		}
	}
}

func (c *bpfrxCollector) collectDHCPMetrics(ch chan<- prometheus.Metric) {
	if c.srv.dhcp == nil {
		return
	}
	leases := c.srv.dhcp.Leases()
	var inet, inet6 int
	for _, l := range leases {
		if l.Family == 6 {
			inet6++
		} else {
			inet++
		}
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpLeasesActive, prometheus.GaugeValue,
		float64(inet), "inet")
	ch <- prometheus.MustNewConstMetric(c.dhcpLeasesActive, prometheus.GaugeValue,
		float64(inet6), "inet6")
}

func (c *bpfrxCollector) collectSystemMetrics(ch chan<- prometheus.Metric) {
	// Daemon uptime
	ch <- prometheus.MustNewConstMetric(c.daemonUptime, prometheus.GaugeValue,
		time.Since(c.srv.startTime).Seconds())

	// Daemon RSS from /proc/self/statm (field 1 = RSS in pages)
	if data, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			if rssPages, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				ch <- prometheus.MustNewConstMetric(c.daemonMemRSS, prometheus.GaugeValue,
					float64(rssPages)*float64(os.Getpagesize()))
			}
		}
	}

	// System memory from /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				if v := parseMemInfoKB(line); v > 0 {
					ch <- prometheus.MustNewConstMetric(c.sysMemTotal, prometheus.GaugeValue, float64(v)*1024)
				}
			} else if strings.HasPrefix(line, "MemAvailable:") {
				if v := parseMemInfoKB(line); v > 0 {
					ch <- prometheus.MustNewConstMetric(c.sysMemAvail, prometheus.GaugeValue, float64(v)*1024)
				}
			}
		}
	}

	// CPU usage from /proc/stat (instantaneous snapshot)
	if f, err := os.Open("/proc/stat"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "cpu ") {
				fields := strings.Fields(line)
				// fields: cpu user nice system idle iowait irq softirq steal
				if len(fields) >= 5 {
					user, _ := strconv.ParseFloat(fields[1], 64)
					nice, _ := strconv.ParseFloat(fields[2], 64)
					system, _ := strconv.ParseFloat(fields[3], 64)
					idle, _ := strconv.ParseFloat(fields[4], 64)
					iowait := 0.0
					if len(fields) >= 6 {
						iowait, _ = strconv.ParseFloat(fields[5], 64)
					}
					total := user + nice + system + idle + iowait
					if len(fields) >= 9 {
						irq, _ := strconv.ParseFloat(fields[6], 64)
						softirq, _ := strconv.ParseFloat(fields[7], 64)
						steal, _ := strconv.ParseFloat(fields[8], 64)
						total += irq + softirq + steal
					}
					cpus := float64(runtime.NumCPU())
					if total > 0 && cpus > 0 {
						ch <- prometheus.MustNewConstMetric(c.sysCPUUser, prometheus.GaugeValue,
							(user+nice)/total*100*cpus)
						ch <- prometheus.MustNewConstMetric(c.sysCPUSystem, prometheus.GaugeValue,
							system/total*100*cpus)
					}
				}
			}
		}
	}
}

// parseMemInfoKB extracts the numeric kB value from a /proc/meminfo line.
func parseMemInfoKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

