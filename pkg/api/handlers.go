package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/psaab/bpfrx/pkg/dataplane"
	"github.com/psaab/bpfrx/pkg/logging"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, Response{Success: true, Data: data})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Response{Success: false, Error: msg})
}

func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, map[string]string{"status": "ok"})
}

func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = len(cfg.Security.Zones)
	}
	if s.gc != nil {
		stats := s.gc.Stats()
		resp.SessionCount = stats.TotalEntries
	}
	writeOK(w, resp)
}

func (s *Server) globalStatsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	ctrMap := s.dp.Map("global_counters")
	if ctrMap == nil {
		writeError(w, http.StatusInternalServerError, "global_counters map not found")
		return
	}

	readCounter := func(idx uint32) uint64 {
		var perCPU []uint64
		if err := ctrMap.Lookup(idx, &perCPU); err != nil {
			return 0
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total
	}

	stats := GlobalStats{
		RxPackets:       readCounter(dataplane.GlobalCtrRxPackets),
		TxPackets:       readCounter(dataplane.GlobalCtrTxPackets),
		Drops:           readCounter(dataplane.GlobalCtrDrops),
		SessionsCreated: readCounter(dataplane.GlobalCtrSessionsNew),
		SessionsClosed:  readCounter(dataplane.GlobalCtrSessionsClosed),
		ScreenDrops:     readCounter(dataplane.GlobalCtrScreenDrops),
		PolicyDenies:    readCounter(dataplane.GlobalCtrPolicyDeny),
		NATAllocFails:   readCounter(dataplane.GlobalCtrNATAllocFail),
		HostInboundDeny: readCounter(dataplane.GlobalCtrHostInboundDeny),
		TCEgressPackets: readCounter(dataplane.GlobalCtrTCEgressPackets),
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

func (s *Server) zonesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ZoneInfo{})
		return
	}

	cr := s.compileResult()
	var zones []ZoneInfo
	for zoneName, zone := range cfg.Security.Zones {
		zi := ZoneInfo{
			Name:       zoneName,
			Interfaces: zone.Interfaces,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}

		// Host-inbound services
		if zone.HostInboundTraffic != nil {
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.SystemServices...)
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.Protocols...)
		}
		if zi.HostInbound == nil {
			zi.HostInbound = []string{}
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}

		// Zone ID + counters
		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.ID = id
				if s.dp != nil && s.dp.IsLoaded() {
					if ing, err := s.dp.ReadZoneCounters(id, 0); err == nil {
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
					}
					if eg, err := s.dp.ReadZoneCounters(id, 1); err == nil {
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		zones = append(zones, zi)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	writeOK(w, zones)
}

func (s *Server) policiesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []PolicyInfo{})
		return
	}

	var policyID uint32
	var result []PolicyInfo
	for _, zpp := range cfg.Security.Policies {
		pi := PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for _, rule := range zpp.Policies {
			pr := PolicyRule{
				Name:         rule.Name,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}

			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				}
			}
			policyID++
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
	}
	writeOK(w, result)
}

func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	limit := queryInt(r, "limit", 100)
	if limit > 10000 {
		limit = 10000
	}
	offset := queryInt(r, "offset", 0)
	zoneFilter := queryUint16(r, "zone", 0)
	protoFilter := r.URL.Query().Get("protocol")

	now := monotonicSeconds()
	all := make([]SessionEntry, 0)
	idx := 0

	// IPv4 sessions
	_ = s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse != 0 {
			return true
		}
		if zoneFilter != 0 && val.IngressZone != zoneFilter && val.EgressZone != zoneFilter {
			return true
		}
		proto := protoName(key.Protocol)
		if protoFilter != "" && proto != protoFilter {
			return true
		}

		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV4(key, val, now))
		}
		idx++
		return true
	})

	// IPv6 sessions
	_ = s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse != 0 {
			return true
		}
		if zoneFilter != 0 && val.IngressZone != zoneFilter && val.EgressZone != zoneFilter {
			return true
		}
		proto := protoName(key.Protocol)
		if protoFilter != "" && proto != protoFilter {
			return true
		}

		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV6(key, val, now))
		}
		idx++
		return true
	})

	writeOK(w, SessionListResponse{
		Total:    idx,
		Limit:    limit,
		Offset:   offset,
		Sessions: all,
	})
}

func (s *Server) sessionSummaryHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	var summary SessionSummary

	_ = s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
		summary.TotalEntries++
		if val.IsReverse == 0 {
			summary.ForwardOnly++
			summary.IPv4Sessions++
			if val.State == dataplane.SessStateEstablished {
				summary.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				summary.SNATSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				summary.DNATSessions++
			}
		}
		return true
	})

	_ = s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		summary.TotalEntries++
		if val.IsReverse == 0 {
			summary.ForwardOnly++
			summary.IPv6Sessions++
			if val.State == dataplane.SessStateEstablished {
				summary.Established++
			}
			if val.Flags&dataplane.SessFlagSNAT != 0 {
				summary.SNATSessions++
			}
			if val.Flags&dataplane.SessFlagDNAT != 0 {
				summary.DNATSessions++
			}
		}
		return true
	})

	writeOK(w, summary)
}

func (s *Server) natSourceHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATSourceInfo{})
		return
	}

	var result []NATSourceInfo
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			info := NATSourceInfo{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
			}
			if rule.Then.Interface {
				info.Type = "interface"
			} else if rule.Then.PoolName != "" {
				info.Type = "pool"
				info.Pool = rule.Then.PoolName
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) natDestHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		writeOK(w, []NATDestInfo{})
		return
	}

	var result []NATDestInfo
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			info := NATDestInfo{
				Name:    rule.Name,
				DstAddr: rule.Match.DestinationAddress,
			}
			if rule.Match.DestinationPort > 0 {
				info.DstPort = uint16(rule.Match.DestinationPort)
			}
			if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
				info.TranslateIP = pool.Address
				if pool.Port > 0 {
					info.TranslatePort = uint16(pool.Port)
				}
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) screenHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ScreenInfo{})
		return
	}

	var result []ScreenInfo
	for name, profile := range cfg.Security.Screen {
		si := ScreenInfo{Name: name}
		si.Checks = screenChecks(profile)
		if si.Checks == nil {
			si.Checks = []string{}
		}
		result = append(result, si)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeOK(w, []EventEntry{})
		return
	}

	limit := queryInt(r, "limit", 50)
	if limit > 10000 {
		limit = 10000
	}

	filter := logging.EventFilter{
		Zone:     queryUint16(r, "zone", 0),
		Action:   r.URL.Query().Get("action"),
		Protocol: r.URL.Query().Get("protocol"),
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	result := make([]EventEntry, len(events))
	for i, ev := range events {
		result[i] = EventEntry{
			Time:         ev.Time.Format(time.RFC3339),
			Type:         ev.Type,
			SrcAddr:      ev.SrcAddr,
			DstAddr:      ev.DstAddr,
			Protocol:     ev.Protocol,
			Action:       ev.Action,
			PolicyID:     ev.PolicyID,
			InZone:       ev.InZone,
			OutZone:      ev.OutZone,
			ScreenCheck:  ev.ScreenCheck,
			SessionPkts:  ev.SessionPkts,
			SessionBytes: ev.SessionBytes,
		}
	}
	writeOK(w, result)
}

func (s *Server) interfacesHandler(w http.ResponseWriter, _ *http.Request) {
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
		is := InterfaceStats{
			Name: ifName,
			Zone: ifZone[ifName],
		}
		if err == nil {
			is.Ifindex = iface.Index
			if s.dp != nil && s.dp.IsLoaded() {
				if ctrs, err := s.dp.ReadInterfaceCounters(iface.Index); err == nil {
					is.RxPackets = ctrs.RxPackets
					is.RxBytes = ctrs.RxBytes
					is.TxPackets = ctrs.TxPackets
					is.TxBytes = ctrs.TxBytes
				}
			}
		}
		result = append(result, is)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) dhcpLeasesHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dhcp == nil {
		writeOK(w, []DHCPLeaseInfo{})
		return
	}

	leases := s.dhcp.Leases()
	result := make([]DHCPLeaseInfo, len(leases))
	for i, l := range leases {
		family := "inet"
		if l.Family == 6 {
			family = "inet6"
		}
		info := DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    family,
			Address:   l.Address.String(),
			LeaseTime: l.LeaseTime.String(),
			Obtained:  l.Obtained.Format(time.RFC3339),
		}
		if l.Gateway.IsValid() {
			info.Gateway = l.Gateway.String()
		}
		for _, dns := range l.DNS {
			info.DNS = append(info.DNS, dns.String())
		}
		if info.DNS == nil {
			info.DNS = []string{}
		}
		result[i] = info
	}
	writeOK(w, result)
}

func (s *Server) routesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []RouteInfo{})
		return
	}

	var result []RouteInfo
	for _, r := range cfg.RoutingOptions.StaticRoutes {
		ri := RouteInfo{
			Destination: r.Destination,
			NextHop:     r.NextHop,
			Interface:   r.Interface,
			Preference:  r.Preference,
		}
		result = append(result, ri)
	}
	if result == nil {
		result = []RouteInfo{}
	}
	writeOK(w, result)
}

func (s *Server) configHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, nil)
		return
	}
	writeOK(w, cfg)
}

// --- helpers ---

func (s *Server) compileResult() *dataplane.CompileResult {
	if s.dp == nil {
		return nil
	}
	return s.dp.LastCompileResult()
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func queryUint16(r *http.Request, key string, def uint16) uint16 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return def
	}
	return uint16(n)
}

// allInterfaceNames returns a deduplicated set of interface names from
// both the interfaces config and zone declarations.
func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[ifName] = true
	}
	for _, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			names[ifName] = true
		}
	}
	return names
}

func policyActionStr(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case dataplane.ProtoICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", p)
	}
}

func sessionStateName(state uint8) string {
	switch state {
	case dataplane.SessStateNone:
		return "None"
	case dataplane.SessStateNew:
		return "New"
	case dataplane.SessStateSynSent:
		return "SYN_SENT"
	case dataplane.SessStateSynRecv:
		return "SYN_RECV"
	case dataplane.SessStateEstablished:
		return "Established"
	case dataplane.SessStateFINWait:
		return "FIN_WAIT"
	case dataplane.SessStateCloseWait:
		return "CLOSE_WAIT"
	case dataplane.SessStateTimeWait:
		return "TIME_WAIT"
	case dataplane.SessStateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func ntohs(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64) SessionEntry {
	se := SessionEntry{
		SrcAddr:    net.IP(key.SrcIP[:]).String(),
		DstAddr:    net.IP(key.DstIP[:]).String(),
		SrcPort:    ntohs(key.SrcPort),
		DstPort:    ntohs(key.DstPort),
		Protocol:   protoName(key.Protocol),
		State:      sessionStateName(val.State),
		PolicyID:   val.PolicyID,
		InZone:     val.IngressZone,
		OutZone:    val.EgressZone,
		FwdPackets: val.FwdPackets,
		FwdBytes:   val.FwdBytes,
		RevPackets: val.RevPackets,
		RevBytes:   val.RevBytes,
		Timeout:    val.Timeout,
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Age = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.NAT = fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.NAT = fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort))
	}
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64) SessionEntry {
	se := SessionEntry{
		SrcAddr:    net.IP(key.SrcIP[:]).String(),
		DstAddr:    net.IP(key.DstIP[:]).String(),
		SrcPort:    ntohs(key.SrcPort),
		DstPort:    ntohs(key.DstPort),
		Protocol:   protoName(key.Protocol),
		State:      sessionStateName(val.State),
		PolicyID:   val.PolicyID,
		InZone:     val.IngressZone,
		OutZone:    val.EgressZone,
		FwdPackets: val.FwdPackets,
		FwdBytes:   val.FwdBytes,
		RevPackets: val.RevPackets,
		RevBytes:   val.RevBytes,
		Timeout:    val.Timeout,
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Age = int64(now - val.LastSeen)
	}
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		se.NAT = fmt.Sprintf("SNAT [%s]:%d", net.IP(val.NATSrcIP[:]).String(), ntohs(val.NATSrcPort))
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		se.NAT = fmt.Sprintf("DNAT [%s]:%d", net.IP(val.NATDstIP[:]).String(), ntohs(val.NATDstPort))
	}
	return se
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

func screenChecks(p *config.ScreenProfile) []string {
	var checks []string
	if p.TCP.SynFlood != nil {
		checks = append(checks, "syn-flood")
	}
	if p.TCP.Land {
		checks = append(checks, "land")
	}
	if p.TCP.WinNuke {
		checks = append(checks, "winnuke")
	}
	if p.TCP.SynFrag {
		checks = append(checks, "syn-frag")
	}
	if p.TCP.SynFin {
		checks = append(checks, "syn-fin")
	}
	if p.TCP.NoFlag {
		checks = append(checks, "tcp-no-flag")
	}
	if p.TCP.FinNoAck {
		checks = append(checks, "fin-no-ack")
	}
	if p.ICMP.PingDeath {
		checks = append(checks, "ping-death")
	}
	if p.ICMP.FloodThreshold > 0 {
		checks = append(checks, "icmp-flood")
	}
	if p.UDP.FloodThreshold > 0 {
		checks = append(checks, "udp-flood")
	}
	if p.IP.SourceRouteOption {
		checks = append(checks, "source-route-option")
	}
	if p.IP.TearDrop {
		checks = append(checks, "tear-drop")
	}
	return checks
}
