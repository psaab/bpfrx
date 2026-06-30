package api

import (
	"net"
	"net/http"
	"sort"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/nftables"
)

func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	// #3345: surface a global-counter read failure instead of silently
	// reporting 0. A degraded userspace shim / counter bridge must not be
	// indistinguishable from "no events" — for a security appliance,
	// "counter unavailable" and "zero attacks" cannot look identical.
	var readErr error
	readCounter := func(idx uint32) uint64 {
		v, err := s.dp.ReadGlobalCounter(idx)
		if err != nil && readErr == nil {
			readErr = err
		}
		return v
	}

	stats := GlobalStats{
		RxPackets:            readCounter(dataplane.GlobalCtrRxPackets),
		TxPackets:            readCounter(dataplane.GlobalCtrTxPackets),
		Drops:                readCounter(dataplane.GlobalCtrDrops),
		SessionsCreated:      readCounter(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:       readCounter(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:          readCounter(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:         readCounter(dataplane.GlobalCtrPolicyDeny),
		NATAllocFails:        readCounter(dataplane.GlobalCtrNATAllocFail),
		HostInboundDeny:      readCounter(dataplane.GlobalCtrHostInboundDeny),
		HostInboundAllowed:   readCounter(dataplane.GlobalCtrHostInbound),
		NAT64Translations:    readCounter(dataplane.GlobalCtrNAT64Xlate),
		TCEgressPackets:      readCounter(dataplane.GlobalCtrTCEgressPackets),
		FabricRedirects:      readCounter(dataplane.GlobalCtrFabricRedirect),
		FabricFwdDrops:       readCounter(dataplane.GlobalCtrFabricFwdDrop),
		FlowCacheHits:        readCounter(dataplane.GlobalCtrFlowCacheHit),
		FlowCacheMisses:      readCounter(dataplane.GlobalCtrFlowCacheMiss),
		FlowCacheFlushes:     readCounter(dataplane.GlobalCtrFlowCacheFlush),
		FlowCacheInvalidates: readCounter(dataplane.GlobalCtrFlowCacheInvalidate),
	}
	if readErr != nil {
		writeError(w, http.StatusInternalServerError,
			"global counter read failed: "+readErr.Error())
		return
	}

	// #3361: aggregate the kernel nftables host-inbound DROP counters (the
	// PRIMARY host-inbound enforcement path, distinct from the userspace-dp
	// HostInboundDeny above). Best-effort: a netlink read failure leaves the
	// field 0 — the per-zone/family Prometheus metric is the canonical surface
	// and omits the series on error rather than reporting a misleading 0.
	if kc, err := nftables.ReadHostInboundDenyCounters(); err == nil {
		for _, ctr := range kc {
			stats.HostInboundKernelDenies += ctr.Packets
		}
	}
	writeOK(w, stats)
}

func (s *Server) ifaceStatsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []InterfaceStats{})
		return
	}

	// Build interface->zone map
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		// Translate Junos config name to Linux kernel ifname (#1565).
		iface, err := net.InterfaceByName(cfg.ResolveKernelIfName(ifName))
		if err != nil {
			continue
		}
		is := InterfaceStats{
			Name:    ifName,
			Ifindex: iface.Index,
			Zone:    ifZone[ifName],
		}
		// #3464: a per-interface counter read failure used to `continue`,
		// dropping the whole interface row — so a degraded counter bridge made
		// the interface VANISH (indistinguishable from "not configured"). Keep
		// the row with an explicit Unavailable marker (counters left 0 but not
		// authoritative) so a read failure is distinguishable from a real idle
		// 0. Uniform with REST /interfaces, gRPC GetInterfaces, and the
		// Prometheus xpf_interface_counter_read_errors_total contract.
		if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err != nil {
			is.Unavailable = true
		} else {
			is.RxPackets = ctrs.RxPackets
			is.RxBytes = ctrs.RxBytes
			is.TxPackets = ctrs.TxPackets
			is.TxBytes = ctrs.TxBytes
		}
		result = append(result, is)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) zoneStatsHandler(w http.ResponseWriter, _ *http.Request) {
	s.zonesHandler(w, nil)
}

func (s *Server) clearCountersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}
	if err := s.dp.ClearAllCounters(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{"status": "ok"})
}
