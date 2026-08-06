package api

import "github.com/prometheus/client_golang/prometheus"

// #3651: per-security-zone traffic-volume descriptors, restored after the
// #3643 HIDE.
//
// History, because it is the constraint on this collector. #3643 DROPPED
// xpf_zone_packets_total / xpf_zone_bytes_total for two reasons: nothing
// populated per-zone counters in the userspace era (the eBPF writers went away
// in #1476), and — the load-bearing one — the read indexed a DENSE MaxZones*2
// per-CPU BPF array by a stable-hash zone id. Stable ids are in [1,65533]
// (config.StableZoneID, #3075) while MaxZones is 64, so essentially every real
// zone OOB'd the bounded Lookup, and the collector's err != nil branch bumped
// xpf_counter_read_errors_total once per zone per scrape: a permanent FALSE
// read-error alert on the #3345 signal.
//
// Both halves are now fixed. #3643 re-keyed Manager.ReadZoneCounters onto a
// Go-side SPARSE offset map (map[uint16][2]CounterValue) that is never indexed
// by position, so a large id cannot OOB anything; #3651 shipped the populate
// path (Rust per-zone accounting -> ProcessStatus.ZoneTrafficCounters ->
// ReplaceZoneCounterOffsets). The metrics come back sourced from that map — see
// collectZoneCounters in metrics_counters.go for the read contract.
func (c *xpfCollector) initZoneDescriptors() {
	// Label set is unchanged from the pre-#3643 metric ({zone, direction},
	// direction in {ingress, egress}) so dashboards and recording rules
	// written against the original family keep working across the gap.
	c.zonePacketsTotal = prometheus.NewDesc(
		"xpf_zone_packets_total",
		"Total packets per zone. Omitted for a zone whose per-zone counters "+
			"are not populated -- see xpf_zone_counters_unpopulated_zones; an "+
			"absent sample means \"not known\", never \"zero traffic\".",
		[]string{"zone", "direction"}, nil,
	)
	c.zoneBytesTotal = prometheus.NewDesc(
		"xpf_zone_bytes_total",
		"Total bytes per zone. Omitted for a zone whose per-zone counters "+
			"are not populated -- see xpf_zone_counters_unpopulated_zones; an "+
			"absent sample means \"not known\", never \"zero traffic\".",
		[]string{"zone", "direction"}, nil,
	)
	// #3651: the explicit "not yet known" signal, and the reason the collector
	// can omit samples without the omission being ambiguous.
	//
	// dataplane.ErrCounterNotPopulated conflates THREE states that are
	// indistinguishable from the Go side, because the helper's snapshot is
	// sparse and drops all-zero rows (ZoneCounterStore::snapshot,
	// userspace-dp/src/afxdp/zone_counters.rs): (a) a pre-#3651 helper that
	// publishes no per-zone block at all, (b) a zone past the helper's 63
	// assignable hot-path slots, whose traffic genuinely goes uncounted
	// (the helper stops publishing its row -- see below), and (c) a zone that
	// is simply idle.
	//
	// #6843: the earlier wording here said build "never registers the zone with
	// the store". That holds only for a zone that was ALWAYS overflowed. The
	// store is carried forward across applies and retains still-configured
	// zones, so a zone that accumulated traffic and LATER lost its slot keeps
	// its totals -- which is why the helper filters published rows by live slot
	// assignment and the Go side replaces (not merges) the offset map.
	//
	// Publishing 0 would be correct only for (c) and would silently understate
	// (a) and (b) as "no traffic" — an authoritative zero over an unknown,
	// which is worse than no sample at all. So the sample is OMITTED and this
	// gauge carries the count instead. It is ALWAYS emitted (0 when every
	// configured zone is reporting), so `> 0` is directly alertable and the
	// signal cannot be confused with a scrape that failed to run.
	//
	// This is deliberately NOT an error: unpopulated is a legitimate steady
	// state, so it must never touch xpf_counter_read_errors_total. Routing it
	// there is precisely the per-zone false alert #3643 removed the family to
	// stop. A genuine read failure still bumps that counter — see
	// collectZoneCounters.
	//
	// The counted set is exactly the set of zones REST reports
	// per_zone_counters_available:false for (pkg/api/security.go zonesHandler),
	// so the two surfaces cannot drift apart silently; the coherence is pinned
	// by TestZoneUnpopulatedGaugeMatchesRESTAvailability.
	c.zoneCountersUnpopulatedZones = prometheus.NewDesc(
		"xpf_zone_counters_unpopulated_zones",
		"Number of configured security zones whose per-zone traffic counters "+
			"are not populated this scrape, so no xpf_zone_packets_total / "+
			"xpf_zone_bytes_total samples were emitted for them. Not an error: "+
			"a zone is counted here when the dataplane has published no volume "+
			"for it (helper predates the per-zone populate path, the zone "+
			"exceeded the helper's hot-path slot capacity, or the zone is "+
			"idle). Matches the zones REST reports per_zone_counters_available "+
			"false for. Genuine read failures bump "+
			"xpf_counter_read_errors_total instead (#3651).",
		nil, nil,
	)
}
