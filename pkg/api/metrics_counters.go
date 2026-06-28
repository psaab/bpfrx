package api

import (
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func (c *xpfCollector) collectGlobalCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	// #3345: on a counter-read failure, SKIP emitting the sample instead of
	// reporting a misleading 0, and bump xpf_counter_read_errors_total. A
	// missing sample is distinguishable from a 0 sample; a clean zero would
	// make a degraded counter bridge indistinguishable from "no events".
	emit := func(desc *prometheus.Desc, idx uint32, labels ...string) {
		v, err := dp.ReadGlobalCounter(idx)
		if err != nil {
			c.counterReadErrors.Add(1)
			return
		}
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(v), labels...)
	}

	emit(c.packetsTotal, dataplane.GlobalCtrRxPackets, "rx")
	emit(c.packetsTotal, dataplane.GlobalCtrTxPackets, "tx")
	emit(c.dropsTotal, dataplane.GlobalCtrDrops)
	emit(c.sessionsCreatedTotal, dataplane.GlobalCtrSessionsNew)
	emit(c.sessionsClosedTotal, dataplane.GlobalCtrSessionsClosed)
	emit(c.screenDropsTotal, dataplane.GlobalCtrScreenDrops)
	emit(c.policyDeniesTotal, dataplane.GlobalCtrPolicyDeny)
	emit(c.natAllocFailsTotal, dataplane.GlobalCtrNATAllocFail)
	emit(c.nat64XlateTotal, dataplane.GlobalCtrNAT64Xlate)
	emit(c.hostInboundDeny, dataplane.GlobalCtrHostInboundDeny)
	emit(c.tcEgressPacketsTotal, dataplane.GlobalCtrTCEgressPackets)

	// SYN cookie counters
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieSent, "sent")
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieValid, "valid")
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieInvalid, "invalid")
	emit(c.syncookieTotal, dataplane.GlobalCtrSyncookieBypass, "bypass")

	// Flow cache counters (IPv4 + IPv6)
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheHit, "hit")
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheMiss, "miss")
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheFlush, "flush")
	emit(c.flowCacheTotal, dataplane.GlobalCtrFlowCacheInvalidate, "invalidate")

	// #3345: always emit the scrape-error counter (0 when healthy) so the
	// signal is present for alerting whether or not any read failed.
	ch <- prometheus.MustNewConstMetric(c.counterReadErrorsTotal, prometheus.CounterValue,
		float64(c.counterReadErrors.Load()))
}

func (c *xpfCollector) collectInterfaceCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	for ifName := range allInterfaceNames(cfg) {
		// Translate Junos config name to Linux kernel ifname (#1565).
		iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
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

	// Honor `set security policy-stats system-wide enable` (#2008
	// M4). Junos collects per-policy hit counters only when policy-stats is
	// enabled system-wide; without the knob the firewall does not maintain
	// them. Mirror that: when PolicyStatsEnabled is false (the default), skip
	// per-policy counter collection so the stored-but-unenforced divergence
	// is closed. #3074: a policy with an explicit `then count` modifier
	// (`rule.Count`) opts into per-policy counting independent of the
	// system-wide knob (Junos per-policy `count`), so emit its counter even
	// when the global knob is off. The aggregate `policy_denies_total`
	// counter is emitted separately (collectGlobalCounters) and is
	// unaffected.
	statsEnabled := cfg.Security.PolicyStatsEnabled

	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		fromZone := zpp.FromZone
		toZone := zpp.ToZone
		// Zone-pair compile output normalizes nil entries out of zpp.Policies.
		for i, rule := range zpp.Policies {
			if !statsEnabled && !rule.Count {
				continue
			}
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
		if !statsEnabled && !rule.Count {
			continue
		}
		policyID := policyCounterID(policySetID, i)
		ctrs, err := dp.ReadPolicyCounters(policyID)
		if err != nil {
			continue
		}
		// #3286: a scoped global policy (#3148 `match from-zone`/`to-zone`)
		// narrows itself to a zone pair. Prometheus is the canonical
		// counter-validation surface, so the per-policy hit metric must
		// carry the real scope on its from_zone/to_zone labels instead of
		// the all-zones "*"/"*" — otherwise scoped-global counters are
		// indistinguishable from an all-zones global. An unscoped global
		// keeps from_zone="*"/to_zone="*" (no regression). The rule label
		// is unchanged.
		fromZone, toZone := "*", "*"
		if rule.Match.FromZone != "" {
			fromZone = rule.Match.FromZone
		}
		if rule.Match.ToZone != "" {
			toZone = rule.Match.ToZone
		}
		ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
			float64(ctrs.Packets), fromZone, toZone, rule.Name)
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
