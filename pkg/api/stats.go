package api

import (
	"net"
	"net/http"
	"sort"

	"github.com/psaab/xpf/pkg/dataplane"
)

func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	readCounter := func(idx uint32) uint64 {
		v, _ := s.dp.ReadGlobalCounter(idx)
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
		TCEgressPackets:      readCounter(dataplane.GlobalCtrTCEgressPackets),
		FabricRedirects:      readCounter(dataplane.GlobalCtrFabricRedirect),
		FabricFwdDrops:       readCounter(dataplane.GlobalCtrFabricFwdDrop),
		FlowCacheHits:        readCounter(dataplane.GlobalCtrFlowCacheHit),
		FlowCacheMisses:      readCounter(dataplane.GlobalCtrFlowCacheMiss),
		FlowCacheFlushes:     readCounter(dataplane.GlobalCtrFlowCacheFlush),
		FlowCacheInvalidates: readCounter(dataplane.GlobalCtrFlowCacheInvalidate),
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
		for _, ifName := range zone.Interfaces {
			ifZone[ifName] = zoneName
		}
	}

	var result []InterfaceStats
	for ifName := range allInterfaceNames(cfg) {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			continue
		}
		ctrs, err := s.dp.ReadInterfaceCounters(iface.Index)
		if err != nil {
			continue
		}
		result = append(result, InterfaceStats{
			Name:      ifName,
			Ifindex:   iface.Index,
			Zone:      ifZone[ifName],
			RxPackets: ctrs.RxPackets,
			RxBytes:   ctrs.RxBytes,
			TxPackets: ctrs.TxPackets,
			TxBytes:   ctrs.TxBytes,
		})
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
