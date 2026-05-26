package api

import (
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func (c *xpfCollector) collectGlobalCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
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

	// SYN cookie counters
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieSent), "sent")
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieValid), "valid")
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieInvalid), "invalid")
	ch <- prometheus.MustNewConstMetric(c.syncookieTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrSyncookieBypass), "bypass")

	// Flow cache counters (IPv4 + IPv6)
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheHit), "hit")
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheMiss), "miss")
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheFlush), "flush")
	ch <- prometheus.MustNewConstMetric(c.flowCacheTotal, prometheus.CounterValue,
		readCounter(dataplane.GlobalCtrFlowCacheInvalidate), "invalidate")
}

func (c *xpfCollector) collectInterfaceCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
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

func (c *xpfCollector) collectZoneCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dataplane.LastApplyResultOf(dp)
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

func (c *xpfCollector) collectPolicyCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		fromZone := zpp.FromZone
		toZone := zpp.ToZone
		// Zone-pair compile output normalizes nil entries out of zpp.Policies.
		for i, rule := range zpp.Policies {
			policyID := policyCounterID(policySetID, i)
			ctrs, err := dp.ReadPolicyCounters(policyID)
			if err != nil {
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
				float64(ctrs.Packets), fromZone, toZone, rule.Name)
		}
		policySetID++
	}

	for i, rule := range cfg.Security.GlobalPolicies {
		if rule == nil {
			continue
		}
		policyID := policyCounterID(policySetID, i)
		ctrs, err := dp.ReadPolicyCounters(policyID)
		if err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
			float64(ctrs.Packets), "*", "*", rule.Name)
	}
}

func (c *xpfCollector) collectFilterCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	cr := dataplane.LastApplyResultOf(dp)
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
