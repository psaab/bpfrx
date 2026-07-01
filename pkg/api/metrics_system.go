package api

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *xpfCollector) collectDHCPMetrics(ch chan<- prometheus.Metric) {
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

// collectDDNSMetrics emits the xpf_dhcp_ddns_* family from the DDNS
// manager's counter snapshot (#1387 inc-2). The family is omitted entirely
// when no DDNSStatsFn is wired or it returns nil (NoDataplane). Label
// cardinality is CLOSED: result in {ok,fail}; reason in
// {no-name,no-backend,conflict,ptr-notauth}.
func (c *xpfCollector) collectDDNSMetrics(ch chan<- prometheus.Metric) {
	if c.srv.ddnsStatsFn == nil {
		return
	}
	st := c.srv.ddnsStatsFn()
	if st == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSReconcileRunsTotal, prometheus.CounterValue,
		float64(st.ReconcileOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSReconcileRunsTotal, prometheus.CounterValue,
		float64(st.ReconcileFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedNoName), "no-name")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedNoBackend), "no-backend")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedConflict), "conflict")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedPTRNotAuth), "ptr-notauth")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSSkippedTotal, prometheus.CounterValue,
		float64(st.PTRDeferred), "ptr-deferred")
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSOwnedRecords, prometheus.GaugeValue,
		float64(st.OwnedRecords))
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSPTRPending, prometheus.GaugeValue,
		float64(st.PTRPendingNow))
	var degraded float64
	if st.Degraded {
		degraded = 1
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSDegraded, prometheus.GaugeValue, degraded)
	var lastTs float64
	if !st.LastReconcile.IsZero() {
		lastTs = float64(st.LastReconcile.Unix())
	}
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSLastReconcileTs, prometheus.GaugeValue, lastTs)
	ch <- prometheus.MustNewConstMetric(c.dhcpDDNSLastReconcileN, prometheus.GaugeValue,
		float64(st.LastReconcileN))
}

// collectSurfaceADDNSMetrics emits the xpf_ddns_surface_a_* family from the
// Surface A (router/interface-address) DDNS manager snapshot (#2691 P2). The
// family is omitted entirely when no SurfaceAStatsFn is wired or it returns nil
// (NoDataplane). Label cardinality is CLOSED: result in {ok,fail}; reason in
// {unchanged,backoff,no-backend}.
func (c *xpfCollector) collectSurfaceADDNSMetrics(ch chan<- prometheus.Metric) {
	if c.srv.surfaceAStatsFn == nil {
		return
	}
	st := c.srv.surfaceAStatsFn()
	if st == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSUpsertsTotal, prometheus.CounterValue,
		float64(st.UpsertFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteOK), "ok")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSDeletesTotal, prometheus.CounterValue,
		float64(st.DeleteFail), "fail")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSSkippedTotal, prometheus.CounterValue,
		float64(st.Skipped), "unchanged")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSSkippedTotal, prometheus.CounterValue,
		float64(st.BackedOff), "backoff")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSSkippedTotal, prometheus.CounterValue,
		float64(st.SkippedNoBackend), "no-backend")
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSScopes, prometheus.GaugeValue,
		float64(st.Scopes))
	var degraded float64
	if st.Degraded {
		degraded = 1
	}
	ch <- prometheus.MustNewConstMetric(c.surfaceADDNSDegraded, prometheus.GaugeValue, degraded)
}

// collectFlowExportMetrics emits the xpf_flow_export_collector_* family
// from the per-collector NetFlow v9 / IPFIX write-health snapshot
// (#2464). The family is omitted entirely when no FlowCollectorHealthFn
// is wired or when no flow export is configured (empty slice). Labels:
// protocol {netflow-v9,ipfix} and the collector address — both bounded
// (one series per configured flow-server). These counters make a
// silently-unreachable collector observable: write_failures climbs while
// write_attempts climbs, healthy drops to 0, and last_success ages. The
// source label carries the per-collector local bind address (#3745), so
// two same-family collectors that bind distinct sources are distinct
// series and a source-bound failure is attributable; it is "" when the OS
// selected the source.
func (c *xpfCollector) collectFlowExportMetrics(ch chan<- prometheus.Metric) {
	if c.srv.flowCollectorHealthFn == nil {
		return
	}
	for _, h := range c.srv.flowCollectorHealthFn() {
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorWriteAttemptsTotal,
			prometheus.CounterValue, float64(h.WriteAttempts), h.Protocol, h.Address, h.SourceAddress)
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorWriteFailuresTotal,
			prometheus.CounterValue, float64(h.WriteFailures), h.Protocol, h.Address, h.SourceAddress)
		healthy := 0.0
		if h.Healthy {
			healthy = 1
		}
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorHealthy,
			prometheus.GaugeValue, healthy, h.Protocol, h.Address, h.SourceAddress)
		var lastSuccess float64
		if !h.LastSuccessTime.IsZero() {
			lastSuccess = float64(h.LastSuccessTime.Unix())
		}
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorLastSuccessSeconds,
			prometheus.GaugeValue, lastSuccess, h.Protocol, h.Address, h.SourceAddress)
		var lastFailure float64
		if !h.LastFailureTime.IsZero() {
			lastFailure = float64(h.LastFailureTime.Unix())
		}
		ch <- prometheus.MustNewConstMetric(c.flowExportCollectorLastFailureSeconds,
			prometheus.GaugeValue, lastFailure, h.Protocol, h.Address, h.SourceAddress)
	}
}

func (c *xpfCollector) collectSystemMetrics(ch chan<- prometheus.Metric) {
	// Daemon uptime
	ch <- prometheus.MustNewConstMetric(c.daemonUptime, prometheus.GaugeValue,
		time.Since(c.srv.startTime).Seconds())

	// #1780: per-phase age of the Go periodic neighbor-maintenance loop.
	// A monotonically climbing age for any phase is the watchdog signal
	// that the phase's guarded goroutine is wedged on a stuck
	// netlink/probe syscall (the idle/overnight cold-connect hang).
	if c.srv.neighborPhaseAgeFn != nil {
		for phase, age := range c.srv.neighborPhaseAgeFn() {
			ch <- prometheus.MustNewConstMetric(c.neighborPeriodicAge,
				prometheus.GaugeValue, age, phase)
		}
	}

	// #1827: services ip-monitoring policy state.
	if c.srv.ipmonStatusFn != nil {
		routesApplied := 0
		unresolved := 0
		for _, ps := range c.srv.ipmonStatusFn() {
			failed := 0.0
			if ps.Failed {
				failed = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.ipmonPolicyFailed,
				prometheus.GaugeValue, failed, ps.Name)
			ch <- prometheus.MustNewConstMetric(c.ipmonPolicyTransitions,
				prometheus.CounterValue, float64(ps.Transitions), ps.Name)
			routesApplied += len(ps.Routes)
			// #1844: Status() recomputes the overlay (including the
			// resolver skips), so the gauge is current on every scrape
			// without requiring an actuation.
			unresolved += len(ps.UnresolvedRoutes)
		}
		ch <- prometheus.MustNewConstMetric(c.ipmonRoutesApplied,
			prometheus.GaugeValue, float64(routesApplied))
		ch <- prometheus.MustNewConstMetric(c.ipmonUnresolvedNextHops,
			prometheus.GaugeValue, float64(unresolved))
	}

	// #2157: event-options remediation action observability. Makes the
	// previously-silent loss (drop on held config lock) visible.
	if c.srv.eventActionStatsFn != nil {
		st := c.srv.eventActionStatsFn()
		ch <- prometheus.MustNewConstMetric(c.eventActionsCommitted,
			prometheus.CounterValue, float64(st.Committed))
		ch <- prometheus.MustNewConstMetric(c.eventActionsRejected,
			prometheus.CounterValue, float64(st.Rejected))
		ch <- prometheus.MustNewConstMetric(c.eventActionsRetried,
			prometheus.CounterValue, float64(st.Retried))
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedLockHeld), "lock_held")
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedQueueFull), "queue_full")
		ch <- prometheus.MustNewConstMetric(c.eventActionsDropped,
			prometheus.CounterValue, float64(st.DroppedStale), "stale")
		ch <- prometheus.MustNewConstMetric(c.eventAttributesInvalid,
			prometheus.CounterValue, float64(st.AttributesInvalid))
		ch <- prometheus.MustNewConstMetric(c.eventActionQueueDepth,
			prometheus.GaugeValue, float64(st.QueueDepth))
	}

	// #1895: currently-failed RPM probe-pin installs. Nonzero means
	// next-hop-pinned tests are holding state (their uplinks are not
	// being health-checked) until a pin retry succeeds.
	if c.srv.rpmPinFailedFn != nil {
		ch <- prometheus.MustNewConstMetric(c.rpmPinInstallFailures,
			prometheus.GaugeValue, c.srv.rpmPinFailedFn())
	}

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
