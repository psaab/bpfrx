package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (c *xpfCollector) collectSessionGauges(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	// xpf_gc_sweep_duration_seconds reflects the last BPF GC sweep timing.
	// On the userspace dataplane (the only live forwarding path) the BPF GC
	// sweep is skipped (#333), so this is 0 — expected, and orthogonal to the
	// session counts derived below.
	if c.srv.gc != nil {
		ch <- prometheus.MustNewConstMetric(c.gcSweepDuration, prometheus.GaugeValue,
			c.srv.gc.Stats().LastSweepDuration.Seconds())
	}

	// #3929: derive the active/established/breakdown session gauges from the
	// LIVE dataplane session table — the same source `show security flow
	// session` reads. Previously xpf_sessions_active/xpf_sessions_established
	// were sourced from GC sweep stats (gc.Stats().TotalEntries /
	// EstablishedSessions), which are permanently 0 on the userspace dataplane
	// because the BPF GC sweep is skipped (#333). Counting inside the single
	// iteration that already backs the type breakdown keeps the scrape cost
	// unchanged (no new periodic scan; the #333 optimization stands).
	//
	// active   = forward session entries (IsReverse == 0) — the live count.
	// established = forward entries whose State is ESTABLISHED (a distinct
	//              session state). Half-open / opening sessions are counted in
	//              active but not established.
	//
	// A backend iterator error (e.g. a helper restart mid-scrape) truncates the
	// scan; publishing the partial counts would report a wrong-but-confident
	// picture (#2469), so on error we EXPOSE xpf_sessions_breakdown_scrape_ok=0
	// and OMIT every session gauge, letting an alert on scrape_ok fire rather
	// than a graph silently dropping toward zero.
	var active, established, ipv4, ipv6, snat, dnat int
	countForward := func(state uint8, flags uint8, ipCounter *int) {
		active++
		*ipCounter++
		if state == dataplane.SessStateEstablished {
			established++
		}
		if flags&dataplane.SessFlagSNAT != 0 {
			snat++
		}
		if flags&dataplane.SessFlagDNAT != 0 {
			dnat++
		}
	}
	errV4 := dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			countForward(val.State, val.Flags, &ipv4)
		}
		return true
	})
	errV6 := dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			countForward(val.State, val.Flags, &ipv6)
		}
		return true
	})
	if errV4 != nil || errV6 != nil {
		ch <- prometheus.MustNewConstMetric(c.sessionScrapeOK, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.sessionScrapeOK, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.sessionsActive, prometheus.GaugeValue, float64(active))
	ch <- prometheus.MustNewConstMetric(c.sessionsEstablished, prometheus.GaugeValue, float64(established))
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv4, prometheus.GaugeValue, float64(ipv4))
	ch <- prometheus.MustNewConstMetric(c.sessionsIPv6, prometheus.GaugeValue, float64(ipv6))
	ch <- prometheus.MustNewConstMetric(c.sessionsSNAT, prometheus.GaugeValue, float64(snat))
	ch <- prometheus.MustNewConstMetric(c.sessionsDNAT, prometheus.GaugeValue, float64(dnat))
}
