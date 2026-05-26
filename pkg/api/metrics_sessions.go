package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (c *xpfCollector) collectSessionGauges(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
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
