package api

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

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

	view := s.buildSessionView()
	q, errMsg := buildSessionQuery(r, view)
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}

	now := monotonicSeconds()
	all := make([]SessionEntry, 0)
	idx := 0

	// IPv4 sessions. A backend iterator failure (e.g. helper restart
	// mid-scan) must fail the request rather than returning HTTP 200 with
	// a partial/zero session list as a healthy result (#2469).
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if !q.matchV4(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			// Merge the companion reverse entry's counters into the
			// forward entry so REST top-talkers/accounting report the
			// full bidirectional volume, matching gRPC (#3419 H3).
			if rev, err := s.dp.GetSessionV4(val.ReverseKey); err == nil {
				val.RevPackets += rev.RevPackets
				val.RevBytes += rev.RevBytes
				val.FwdPackets += rev.FwdPackets
				val.FwdBytes += rev.FwdBytes
			}
			all = append(all, sessionEntryV4(key, val, now, view))
		}
		idx++
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}

	// IPv6 sessions
	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if !q.matchV6(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			if rev, err := s.dp.GetSessionV6(val.ReverseKey); err == nil {
				val.RevPackets += rev.RevPackets
				val.RevBytes += rev.RevBytes
				val.FwdPackets += rev.FwdPackets
				val.FwdBytes += rev.FwdBytes
			}
			all = append(all, sessionEntryV6(key, val, now, view))
		}
		idx++
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
		return
	}

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

	// A partial scan yields an under-count that looks like a healthy
	// summary — fail the request instead of publishing it (#2469).
	if err := s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
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
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}

	if err := s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
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
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
		return
	}

	writeOK(w, summary)
}

func (s *Server) clearSessionsHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}
	v4, v6, err := s.dp.ClearAllSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, ClearSessionsResult{IPv4Cleared: v4, IPv6Cleared: v6})
}

func (s *Server) sessionZonePairHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, []ZonePairSessionSummary{})
		return
	}

	// Build zone ID -> name reverse map
	zoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			zoneNames[id] = name
		}
	}

	type zpKey struct{ from, to uint16 }
	counts := make(map[zpKey]*ZonePairSessionSummary)

	countSession := func(inZone, outZone uint16, proto uint8) {
		k := zpKey{inZone, outZone}
		zp, ok := counts[k]
		if !ok {
			zp = &ZonePairSessionSummary{
				FromZone: zoneNames[inZone],
				ToZone:   zoneNames[outZone],
			}
			if zp.FromZone == "" {
				zp.FromZone = fmt.Sprintf("zone-%d", inZone)
			}
			if zp.ToZone == "" {
				zp.ToZone = fmt.Sprintf("zone-%d", outZone)
			}
			counts[k] = zp
		}
		switch proto {
		case 6:
			zp.TCP++
		case 17:
			zp.UDP++
		case 1, dataplane.ProtoICMPv6:
			zp.ICMP++
		default:
			zp.Other++
		}
		zp.Total++
	}

	// A partial scan produces a misleading zone-pair breakdown — fail
	// the request rather than serving an incomplete table as OK (#2469).
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}
	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if val.IsReverse == 0 {
			countSession(val.IngressZone, val.EgressZone, key.Protocol)
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
		return
	}

	result := make([]ZonePairSessionSummary, 0, len(counts))
	for _, zp := range counts {
		result = append(result, *zp)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FromZone != result[j].FromZone {
			return result[i].FromZone < result[j].FromZone
		}
		return result[i].ToZone < result[j].ToZone
	})
	writeOK(w, result)
}

// --- Session helper functions ---

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

// uint32ToIP converts a dataplane IPv4 field to net.IP. Session-map
// values hold IP bytes in network order read as a NATIVE-endian u32
// (the Rust helper publishes u32::from_ne_bytes(octets)); BigEndian
// here reversed NAT addresses in the REST session view on
// little-endian hosts (#1827 PR-3 r1, AGY finding).
func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, v)
	return ip
}

// sessionEgressKey identifies a FIB-resolved egress interface (ifindex +
// VLAN), mirroring the gRPC sessionEgressKey used to resolve a session's
// egress interface name (#3419 M4).
type sessionEgressKey struct {
	ifindex uint32
	vlanID  uint16
}

// sessionView holds the enrichment context shared across a single session
// list/iteration: zone/policy/app name maps, the zone->first-interface and
// FIB->interface resolution tables, the active config, and the local HA
// active state. It mirrors the maps the gRPC sessionFilter precomputes
// (#3419 M1/M4/M6) so the REST session view exposes the same fields.
type sessionView struct {
	zoneNames    map[uint16]string
	policyNames  map[uint32]string
	appNames     map[uint16]string
	zoneIfaces   map[uint16]string
	egressIfaces map[sessionEgressKey]string
	cfg          *config.Config
	haActive     bool
}

// buildSessionView precomputes the enrichment maps from the last apply
// result and the active config, mirroring grpcapi buildSessionFilter
// (#3419). It is safe to call when the store/apply result is absent (the
// maps stay empty and the view degrades to numeric ids).
func (s *Server) buildSessionView() sessionView {
	v := sessionView{
		zoneNames:    make(map[uint16]string),
		zoneIfaces:   make(map[uint16]string),
		egressIfaces: make(map[sessionEgressKey]string),
		haActive:     true, // standalone default
	}
	if s.store != nil {
		v.cfg = s.store.ActiveConfig()
	}
	if s.haActiveFn != nil {
		v.haActive = s.haActiveFn()
	}
	cr := s.applyResult()
	if cr != nil {
		for name, id := range cr.ZoneIDs {
			v.zoneNames[id] = name
		}
		v.policyNames = cr.PolicyNames
		v.appNames = cr.AppNames
	}
	if v.cfg != nil && cr != nil {
		for zoneName, zone := range v.cfg.Security.Zones {
			if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
				continue
			}
			if zid, ok := cr.ZoneIDs[zoneName]; ok && len(zone.Interfaces) > 0 {
				v.zoneIfaces[zid] = zone.Interfaces[0]
			}
		}
		// FIB ifindex+VLAN -> display name, so a session's egress interface
		// resolves to the configured unit name (mirrors grpcapi).
		for ifName, ifc := range v.cfg.Interfaces.Interfaces {
			resolvedParent := config.LinuxIfName(strings.SplitN(v.cfg.ResolveReth(ifName), ".", 2)[0])
			parentLink, err := net.InterfaceByName(resolvedParent)
			if err != nil {
				continue
			}
			for _, unit := range ifc.Units {
				displayName := ifName
				if unit.Number != 0 || unit.VlanID != 0 {
					displayName = fmt.Sprintf("%s.%d", ifName, unit.Number)
				}
				vlanID := uint16(unit.VlanID)
				if vlanID == 0 && unit.Number > 0 {
					vlanID = uint16(unit.Number)
				}
				key := sessionEgressKey{ifindex: uint32(parentLink.Index), vlanID: vlanID}
				if _, exists := v.egressIfaces[key]; !exists {
					v.egressIfaces[key] = displayName
				}
			}
		}
	}
	return v
}

// sessionQuery holds the parsed REST session filter predicates. It mirrors
// the gRPC sessionFilter subset that applies to the REST surface: zone,
// protocol, application, interface, nat-only and source-nat-pool (#3419
// M1/M3/M4). Pagination (limit/offset) is handled by the caller and is out
// of scope here (separate from #3421/#3423).
type sessionQuery struct {
	zone         uint16
	proto        string
	natOnly      bool
	app          string
	iface        string
	snatPool     string
	snatPoolNets []*net.IPNet
	view         sessionView
}

// buildSessionQuery parses and validates the session filter query
// parameters. A non-empty but malformed/unresolved filter FAILS CLOSED
// with an error message (the caller emits HTTP 400) rather than silently
// matching every session — mirroring the gRPC sessionFilter.validate
// contract (#2934/#3439, and source-nat-pool not-found per #3419 M3).
func buildSessionQuery(r *http.Request, view sessionView) (sessionQuery, string) {
	q := sessionQuery{view: view}
	zoneFilter, ok := queryUint16Strict(r, "zone", 0)
	if !ok {
		return q, "invalid zone filter: " + r.URL.Query().Get("zone")
	}
	q.zone = zoneFilter
	q.proto = r.URL.Query().Get("protocol")
	q.app = r.URL.Query().Get("application")
	q.iface = r.URL.Query().Get("interface")
	q.snatPool = r.URL.Query().Get("source_nat_pool")
	if v := r.URL.Query().Get("nat_only"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return q, "invalid nat_only filter: " + v
		}
		q.natOnly = b
	}
	if q.snatPool != "" {
		if view.cfg == nil {
			return q, "source NAT pool " + q.snatPool + " not found"
		}
		nets, ok := config.SourceNATPoolNets(&view.cfg.Security.NAT, q.snatPool)
		if !ok {
			return q, "source NAT pool " + q.snatPool + " not found"
		}
		q.snatPoolNets = nets
	}
	return q, ""
}

func (q *sessionQuery) matchV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if val.IsReverse != 0 {
		return false
	}
	if q.zone != 0 && val.IngressZone != q.zone && val.EgressZone != q.zone {
		return false
	}
	if q.proto != "" && !protoFilterMatches(key.Protocol, q.proto) {
		return false
	}
	if q.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if q.app != "" && !appid.SessionMatches(q.app, q.view.appNames, q.view.cfg,
		key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
		return false
	}
	if q.iface != "" {
		inIf := q.view.zoneIfaces[val.IngressZone]
		outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, q.view.zoneIfaces, q.view.egressIfaces)
		if !sessionIfaceMatches(q.iface, inIf) && !sessionIfaceMatches(q.iface, outIf) {
			return false
		}
	}
	if q.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 || !config.IPInNets(uint32ToIP(val.NATSrcIP), q.snatPoolNets) {
			return false
		}
	}
	return true
}

func (q *sessionQuery) matchV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if val.IsReverse != 0 {
		return false
	}
	if q.zone != 0 && val.IngressZone != q.zone && val.EgressZone != q.zone {
		return false
	}
	if q.proto != "" && !protoFilterMatches(key.Protocol, q.proto) {
		return false
	}
	if q.natOnly && val.Flags&(dataplane.SessFlagSNAT|dataplane.SessFlagDNAT) == 0 {
		return false
	}
	if q.app != "" && !appid.SessionMatches(q.app, q.view.appNames, q.view.cfg,
		key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID) {
		return false
	}
	if q.iface != "" {
		inIf := q.view.zoneIfaces[val.IngressZone]
		outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, q.view.zoneIfaces, q.view.egressIfaces)
		if !sessionIfaceMatches(q.iface, inIf) && !sessionIfaceMatches(q.iface, outIf) {
			return false
		}
	}
	if q.snatPool != "" {
		if val.Flags&dataplane.SessFlagSNAT == 0 || !config.IPInNets(net.IP(val.NATSrcIP[:]), q.snatPoolNets) {
			return false
		}
	}
	return true
}

// sessionIfaceMatches matches a session interface against an operator
// filter, accepting either the exact unit name or a base-interface prefix
// (mirrors grpcapi).
func sessionIfaceMatches(filter, ifName string) bool {
	if ifName == "" {
		return false
	}
	return ifName == filter || strings.HasPrefix(ifName, filter+".")
}

// resolveSessionEgressIface resolves a session's egress interface from its
// FIB result, falling back to the egress zone's first interface (mirrors
// grpcapi).
func resolveSessionEgressIface(fibIfindex uint32, fibVlanID uint16, egressZone uint16, zoneIfaces map[uint16]string, egressIfaces map[sessionEgressKey]string) string {
	if fibIfindex != 0 {
		if ifName, ok := egressIfaces[sessionEgressKey{ifindex: fibIfindex, vlanID: fibVlanID}]; ok && ifName != "" {
			return ifName
		}
	}
	return zoneIfaces[egressZone]
}

func sessionEntryV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64, view sessionView) SessionEntry {
	inIf := view.zoneIfaces[val.IngressZone]
	if inIf == "" {
		inIf = view.zoneNames[val.IngressZone]
	}
	outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, view.zoneIfaces, view.egressIfaces)
	if outIf == "" {
		outIf = view.zoneNames[val.EgressZone]
	}
	se := SessionEntry{
		SrcAddr:          net.IP(key.SrcIP[:]).String(),
		DstAddr:          net.IP(key.DstIP[:]).String(),
		SrcPort:          ntohs(key.SrcPort),
		DstPort:          ntohs(key.DstPort),
		Protocol:         protoName(key.Protocol),
		State:            sessionStateName(val.State),
		PolicyID:         val.PolicyID,
		PolicyName:       view.policyNames[val.PolicyID],
		IngressZoneName:  view.zoneNames[val.IngressZone],
		EgressZoneName:   view.zoneNames[val.EgressZone],
		InZone:           val.IngressZone,
		OutZone:          val.EgressZone,
		IngressInterface: inIf,
		EgressInterface:  outIf,
		Application:      appid.ResolveSessionName(view.appNames, view.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
		FwdPackets:       val.FwdPackets,
		FwdBytes:         val.FwdBytes,
		RevPackets:       val.RevPackets,
		RevBytes:         val.RevBytes,
		Timeout:          val.Timeout,
		SessionID:        val.SessionID,
		HAActive:         view.haActive,
	}
	if val.Created > 0 && now > val.Created {
		se.Age = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Idle = int64(now - val.LastSeen)
	}
	var natParts []string
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("SNAT %s:%d", uint32ToIP(val.NATSrcIP), ntohs(val.NATSrcPort)))
		se.NATSrcAddr = uint32ToIP(val.NATSrcIP).String()
		se.NATSrcPort = ntohs(val.NATSrcPort)
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("DNAT %s:%d", uint32ToIP(val.NATDstIP), ntohs(val.NATDstPort)))
		se.NATDstAddr = uint32ToIP(val.NATDstIP).String()
		se.NATDstPort = ntohs(val.NATDstPort)
	}
	se.NAT = strings.Join(natParts, "; ")
	return se
}

func sessionEntryV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64, view sessionView) SessionEntry {
	inIf := view.zoneIfaces[val.IngressZone]
	if inIf == "" {
		inIf = view.zoneNames[val.IngressZone]
	}
	outIf := resolveSessionEgressIface(val.FibIfindex, val.FibVlanID, val.EgressZone, view.zoneIfaces, view.egressIfaces)
	if outIf == "" {
		outIf = view.zoneNames[val.EgressZone]
	}
	se := SessionEntry{
		SrcAddr:          net.IP(key.SrcIP[:]).String(),
		DstAddr:          net.IP(key.DstIP[:]).String(),
		SrcPort:          ntohs(key.SrcPort),
		DstPort:          ntohs(key.DstPort),
		Protocol:         protoName(key.Protocol),
		State:            sessionStateName(val.State),
		PolicyID:         val.PolicyID,
		PolicyName:       view.policyNames[val.PolicyID],
		IngressZoneName:  view.zoneNames[val.IngressZone],
		EgressZoneName:   view.zoneNames[val.EgressZone],
		InZone:           val.IngressZone,
		OutZone:          val.EgressZone,
		IngressInterface: inIf,
		EgressInterface:  outIf,
		Application:      appid.ResolveSessionName(view.appNames, view.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
		FwdPackets:       val.FwdPackets,
		FwdBytes:         val.FwdBytes,
		RevPackets:       val.RevPackets,
		RevBytes:         val.RevBytes,
		Timeout:          val.Timeout,
		SessionID:        val.SessionID,
		HAActive:         view.haActive,
	}
	if val.Created > 0 && now > val.Created {
		se.Age = int64(now - val.Created)
	}
	if val.LastSeen > 0 && now > val.LastSeen {
		se.Idle = int64(now - val.LastSeen)
	}
	var natParts []string
	if val.Flags&dataplane.SessFlagSNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("SNAT [%s]:%d", net.IP(val.NATSrcIP[:]).String(), ntohs(val.NATSrcPort)))
		se.NATSrcAddr = net.IP(val.NATSrcIP[:]).String()
		se.NATSrcPort = ntohs(val.NATSrcPort)
	}
	if val.Flags&dataplane.SessFlagDNAT != 0 {
		natParts = append(natParts, fmt.Sprintf("DNAT [%s]:%d", net.IP(val.NATDstIP[:]).String(), ntohs(val.NATDstPort)))
		se.NATDstAddr = net.IP(val.NATDstIP[:]).String()
		se.NATDstPort = ntohs(val.NATDstPort)
	}
	se.NAT = strings.Join(natParts, "; ")
	return se
}

// monotonicSeconds returns the current monotonic clock in seconds,
// matching BPF's bpf_ktime_get_ns() / 1e9.
func monotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

// protoFilterMatches matches a session protocol against an operator filter
// string: a case-insensitive protocol name (tcp/udp/icmp/icmpv6/...) OR a
// numeric IP protocol number ("6" matches TCP, "47" matches GRE). This
// mirrors the gRPC (pkg/grpcapi server_sessions.go protoFilterMatches) and
// CLI (pkg/cli monitor) contract; REST previously did a case-SENSITIVE
// string compare with no numeric form, so protocol=tcp and protocol=6
// silently returned an empty result (#2935).
func protoFilterMatches(p uint8, filter string) bool {
	if strings.EqualFold(protoName(p), filter) {
		return true
	}
	if n, err := strconv.Atoi(filter); err == nil {
		return n == int(p)
	}
	return false
}

// protoName renders an IP protocol number for the REST surface. The named
// protocol SET is owned by appid.ProtocolName (the #2949 SSOT shared with gRPC
// and the catalog) so a NAMED `protocol=gre` REST filter matches and GRE/ESP/
// IPIP/IPv6 sessions display named instead of numeric. Casing is a REST-local
// concern: REST has always rendered upper-case (TCP/UDP/ICMP/ICMPv6), so the
// canonical lowercase name is upper-cased here. ICMPv6 keeps its mixed-case
// spelling to match the historical REST rendering.
func protoName(p uint8) string {
	name := appid.ProtocolName(p)
	if name == "" {
		return fmt.Sprintf("%d", p)
	}
	if p == dataplane.ProtoICMPv6 {
		return "ICMPv6"
	}
	return strings.ToUpper(name)
}
