package api

import (
	"net"
	"sort"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// readHostInboundDenyCounters is the kernel nft host-inbound deny-counter source,
// a package var so the collector's degraded-boot behavior is unit-testable
// without a live kernel/netlink (#3361).
var readHostInboundDenyCounters = xnft.ReadHostInboundDenyCounters

// collectHostInboundKernelDenies scrapes the per-zone/family named DROP counters
// from the kernel nftables host-inbound chain (#3361) and emits them as
// xpf_host_inbound_kernel_denies_total. This is the PRIMARY host-inbound
// enforcement path (host-bound traffic is shunted to the kernel before
// userspace-dp sees it), and is distinct from the userspace-dp
// xpf_host_inbound_denies_total path (#3326) — they are not double counts.
//
// The nft `inet xpf_hostinbound` chain is installed by the daemon INDEPENDENT of
// dataplane load state and keeps dropping control-plane traffic in a config-only
// / degraded boot, so Collect calls this BEFORE the dataplane gate — otherwise
// the series would vanish in exactly the degraded boot this metric exists to
// observe. ReadHostInboundDenyCounters reads nft via netlink and has no
// dataplane dependency.
//
// On a read failure the series is SKIPPED (no misleading 0) and
// xpf_counter_read_errors_total is bumped, matching the #3345 contract: a missing
// sample is distinguishable from a real zero. (The error-counter SAMPLE is
// emitted last in Collect by emitCounterReadErrors (#3462); the bump here
// accumulates on the collector and is reflected in the same scrape's emitted
// value when the dataplane is loaded.)
func (c *xpfCollector) collectHostInboundKernelDenies(ch chan<- prometheus.Metric) {
	counts, err := readHostInboundDenyCounters()
	if err != nil {
		c.counterReadErrors.Add(1)
		return
	}
	for _, ctr := range counts {
		ch <- prometheus.MustNewConstMetric(c.hostInboundKernelDenies,
			prometheus.CounterValue, float64(ctr.Packets), ctr.Zone, ctr.Family)
	}
}

// collectHostInboundAddresslessZones emits xpf_host_inbound_addressless_zones
// (#3698): a 1 per configured host-inbound-enforcing zone currently in the
// transient fail-open admit window — it has a non-lifeline interface but no
// resolvable address yet, so BuildZoneHostInboundViews yields an empty address
// set and applyHostInboundFilter emits no deny for it. The series is present
// only for zones IN the window (absent = enforced), matching the deny-counter
// contract where a missing sample is meaningful. Config-derived (no dataplane
// dependency), so Collect calls this BEFORE the dataplane gate. The SSOT for the
// window is dpuserspace.AddresslessEnforcingZones, the same builder that drives
// the daemon's state-transition warning log, so the metric and the log agree.
func (c *xpfCollector) collectHostInboundAddresslessZones(ch chan<- prometheus.Metric) {
	if c.srv == nil || c.srv.store == nil {
		return
	}
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}
	for _, z := range dpuserspace.AddresslessEnforcingZones(cfg) {
		ch <- prometheus.MustNewConstMetric(c.hostInboundAddresslessZones,
			prometheus.GaugeValue, 1, z.Zone)
	}
}

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
	// #3343: per-reason screen-drop breakdown. Emit one labeled series per
	// reason in the shared table; a per-reason read failure SKIPS that series
	// (and bumps counterReadErrors) under the same #3345 contract as `emit`.
	for i := range dataplane.ScreenReasonCounters {
		rc := &dataplane.ScreenReasonCounters[i]
		emit(c.screenDropsByReasonTotal, rc.Index, rc.Reason)
	}
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
}

// emitCounterReadErrors emits the xpf_counter_read_errors_total scrape-error
// sample. #3345: always emitted (0 when healthy) so the signal is present for
// alerting whether or not any read failed. #3462: this MUST run AFTER every
// sub-collector that can bump counterReadErrors (collectHostInboundKernelDenies,
// collectGlobalCounters, collectPolicyCounters,
// collectFilterCounters; #3643 dropped the per-zone bumper) — Collect calls it
// last — so a policy/filter read
// that fails in THIS scrape is reflected in THIS scrape's value, not lagged by
// one scrape (which it was when the sample was emitted from collectGlobalCounters
// before those collectors ran).
func (c *xpfCollector) emitCounterReadErrors(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.counterReadErrorsTotal, prometheus.CounterValue,
		float64(c.counterReadErrors.Load()))
}

// emitInterfaceCounterReadErrors emits the xpf_interface_counter_read_errors_total
// scrape-error sample. #3464: always emitted (0 when healthy) so the signal is
// present for alerting whether or not any interface read failed. Collect calls
// it AFTER collectInterfaceCounters (the only bumper), so a failure this scrape
// is reflected in this scrape's value rather than lagging one scrape behind.
// Kept separate from emitCounterReadErrors because interface counters are out
// of the #3345 security-counter contract.
func (c *xpfCollector) emitInterfaceCounterReadErrors(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.interfaceCounterReadErrorsTotal, prometheus.CounterValue,
		float64(c.interfaceCounterReadErrors.Load()))
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
			// #3464: a per-interface counter-read failure SKIPS this
			// interface's samples (no misleading 0) and bumps
			// xpf_interface_counter_read_errors_total — the interface-counter
			// analogue of the #3345/#3408 security-counter contract (skip, do
			// not emit a 0). The interface error metric is intentionally
			// SEPARATE from xpf_counter_read_errors_total (interface counters
			// are out of the security-counter contract; #3464).
			c.interfaceCounterReadErrors.Add(1)
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

// #3643: collectZoneCounters was removed. Per-zone traffic counters
// (xpf_zone_packets_total / xpf_zone_bytes_total) were never populated in the
// userspace era (the eBPF writers were deleted in #1476) and, worse, every
// read of a stable-hash zone id >= MaxZones (#3075) OOB'd the dense BPF array
// and bumped xpf_counter_read_errors_total once per zone per scrape -- a
// permanent FALSE read-error alert (#3345 signal). The metrics are dropped
// until the per-zone POPULATE path ships (deferred, see
// docs/research/3643-dead-counters/plan.md §5A). Global, per-interface,
// per-policy, and per-screen-reason counters remain live.

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
		// #3476: the compile path normalizes nil entries out, but the
		// tolerant / HA-sync config path (#3474) can leave a nil zone-pair
		// set or rule that the runtime walker skips. Mirror that here so a
		// Prometheus scrape does not crash on zpp.FromZone / rule.Count.
		if zpp == nil {
			policySetID++
			continue
		}
		fromZone := zpp.FromZone
		toZone := zpp.ToZone
		for i, rule := range zpp.Policies {
			if rule == nil {
				continue
			}
			if !statsEnabled && !rule.Count {
				continue
			}
			policyID := policyCounterID(policySetID, i)
			ctrs, err := dp.ReadPolicyCounters(policyID)
			if err != nil {
				c.counterReadErrors.Add(1)
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
			c.counterReadErrors.Add(1)
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

	// #3363: emit the IMPLICIT default-policy hit counter (read via the
	// reserved DefaultPolicySentinelID handle) as its own time series, labeled
	// from_zone="-"/to_zone="-"/policy=dataplane.DefaultPolicyName so an
	// operator can alert on default-deny rate — the security-critical catch-all
	// that was previously uncounted. Gated on policy-stats like the per-rule
	// metrics above so all surfaces agree.
	if statsEnabled {
		if ctrs, err := dp.ReadPolicyCounters(dataplane.DefaultPolicySentinelID); err != nil {
			c.counterReadErrors.Add(1)
		} else {
			ch <- prometheus.MustNewConstMetric(c.policyHitsTotal, prometheus.CounterValue,
				float64(ctrs.Packets), "-", "-", dataplane.DefaultPolicyName)
		}
	}
}

func (c *xpfCollector) collectFilterCounters(ch chan<- prometheus.Metric, dp apiRuntimeDataPlane) {
	cfg := c.srv.store.ActiveConfig()
	if cfg == nil {
		return
	}

	// #3461: merge the userspace helper-published per-term hit counters
	// (filter_term_counters) into xpf_filter_hits_total, exactly as the CLI
	// (`show firewall filter`) and gRPC text paths do via
	// BuildFirewallFilterTermCounterIndex. The userspace-dp runtime publishes
	// filter hits HERE, not in the retired eBPF map, so without this merge the
	// canonical metrics path reports 0/stale while the text commands show real
	// hits. The userspace merge is independent of the eBPF apply result, so it
	// must NOT be gated on cr/FilterIDs below.
	var userspaceStatus *dpuserspace.ProcessStatus
	if provider, ok := dp.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		if status, err := provider.Status(); err == nil {
			userspaceStatus = &status
		}
	}
	userspaceCounters := dpuserspace.BuildFirewallFilterTermCounterIndex(userspaceStatus)

	// The retired-eBPF/map counter path is gated on a compile result carrying
	// filter IDs; it may be absent (a pure userspace dataplane) without
	// suppressing the userspace merge above.
	cr := dataplane.LastApplyResultOf(dp)

	emitFilters := func(family string, filters map[string]*config.FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]

			// Resolve the map-counter span for this filter, if the compile
			// result carries it.
			var ruleOffset uint32
			var hasMap bool
			if cr != nil && cr.FilterIDs != nil {
				if fid, ok := cr.FilterIDs[family+":"+name]; ok {
					if fcfg, err := dp.ReadFilterConfig(fid); err == nil {
						ruleOffset = fcfg.RuleStart
						hasMap = true
					} else {
						// Skip the map path for this filter, but still surface
						// any userspace-published term counters below.
						c.counterReadErrors.Add(1)
					}
				}
			}

			for _, term := range filter.Terms {
				// #3459: the per-term counter-slot stride is the shared SSOT
				// config.FilterTermExpansionCount (full src×dst×dstPort×
				// srcPort cross-product, with prefix-list prefixes folded into
				// src/dst) — NOT the old nSrc*nDst that ignored ports and
				// prefix-lists and drifted later terms onto a neighbouring
				// term's slots, mis-attributing the hit.
				numRules := config.FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists)
				var totalPkts uint64
				mapFailed := false
				if hasMap {
					for i := uint32(0); i < numRules; i++ {
						if ctrs, err := dp.ReadFilterCounters(ruleOffset + i); err == nil {
							totalPkts += ctrs.Packets
						} else {
							c.counterReadErrors.Add(1)
							mapFailed = true
						}
					}
					// Advance the offset regardless so later terms stay aligned.
					ruleOffset += numRules
				}

				userspaceCounter, userspaceOk := userspaceCounters[dpuserspace.FirewallFilterTermCounterKey{
					Family: family, FilterName: name, TermName: term.Name,
				}]
				if userspaceOk {
					totalPkts += userspaceCounter.Packets
				}

				// #3408: on a map read failure with NO userspace signal, SKIP
				// this term's sample (a missing sample, not a stale/partial 0)
				// — matching the zone/policy collectors — and rely on the
				// bumped counterReadErrors. A userspace-published counter is a
				// real signal, so still emit when one is present (#3461).
				if mapFailed && !userspaceOk {
					continue
				}
				if hasMap || userspaceOk {
					ch <- prometheus.MustNewConstMetric(c.filterHitsTotal, prometheus.CounterValue,
						float64(totalPkts), name, family, term.Name)
				}
			}
		}
	}

	emitFilters("inet", cfg.Firewall.FiltersInet)
	emitFilters("inet6", cfg.Firewall.FiltersInet6)
}
