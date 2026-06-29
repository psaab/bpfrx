package api

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/dataplane"
)

// sessionCursorIterator is the optional cursor-based session iteration
// surface. The production runtime dataplane (the userspace
// LegacyDataPlaneAdapter wrapping *dataplane.Manager) implements it; REST
// type-asserts s.dp to it for stable page_token pagination and falls back
// to the offset/limit path when it is not available. This mirrors the
// gRPC sessionCursorIterator (pkg/grpcapi/runtime.go) (#3421 H4).
type sessionCursorIterator interface {
	IterateSessionsFrom(*dataplane.SessionKey, func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6From(*dataplane.SessionKeyV6, func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
}

// restSessionFilter holds parsed REST session-list filters. It mirrors the
// gRPC sessionFilter predicate subset REST exposes — zone, protocol,
// source/destination prefix, and source/destination port. Construction
// (parseRESTSessionFilter) FAILS CLOSED: a malformed zone/prefix/port is
// reported so the handler emits HTTP 400 rather than silently zeroing the
// predicate and widening the query to every session (#3421 M2/M8, matching
// pkg/grpcapi sessionFilter.validate → InvalidArgument).
type restSessionFilter struct {
	zone    uint16
	proto   string
	srcNet  *net.IPNet
	dstNet  *net.IPNet
	srcPort uint16
	dstPort uint16
}

// parseRESTSessionFilter parses the session filter query parameters. On a
// malformed value it returns the offending parameter name and ok=false so
// the caller can emit HTTP 400 (fail-closed, #3421 M2/M8). An empty/absent
// value for any parameter means "no filter" on that dimension.
func parseRESTSessionFilter(r *http.Request) (f *restSessionFilter, badParam string, ok bool) {
	f = &restSessionFilter{}

	zone, zok := queryUint16Strict(r, "zone", 0)
	if !zok {
		return nil, "zone", false
	}
	f.zone = zone
	f.proto = r.URL.Query().Get("protocol")

	if sp := r.URL.Query().Get("source_prefix"); sp != "" {
		n, err := parseSessionPrefix(sp)
		if err != nil {
			return nil, "source_prefix", false
		}
		f.srcNet = n
	}
	if dp := r.URL.Query().Get("destination_prefix"); dp != "" {
		n, err := parseSessionPrefix(dp)
		if err != nil {
			return nil, "destination_prefix", false
		}
		f.dstNet = n
	}

	srcPort, spok := queryUint16Strict(r, "source_port", 0)
	if !spok {
		return nil, "source_port", false
	}
	f.srcPort = srcPort
	dstPort, dpok := queryUint16Strict(r, "destination_port", 0)
	if !dpok {
		return nil, "destination_port", false
	}
	f.dstPort = dstPort

	return f, "", true
}

func (f *restSessionFilter) matchV4(key dataplane.SessionKey, val dataplane.SessionValue) bool {
	if val.IsReverse != 0 {
		return false
	}
	if f.zone != 0 && val.IngressZone != f.zone && val.EgressZone != f.zone {
		return false
	}
	if f.proto != "" && !protoFilterMatches(key.Protocol, f.proto) {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if f.srcPort != 0 && ntohs(key.SrcPort) != f.srcPort {
		return false
	}
	if f.dstPort != 0 && ntohs(key.DstPort) != f.dstPort {
		return false
	}
	return true
}

func (f *restSessionFilter) matchV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
	if val.IsReverse != 0 {
		return false
	}
	if f.zone != 0 && val.IngressZone != f.zone && val.EgressZone != f.zone {
		return false
	}
	if f.proto != "" && !protoFilterMatches(key.Protocol, f.proto) {
		return false
	}
	if f.srcNet != nil && !f.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if f.dstNet != nil && !f.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if f.srcPort != 0 && ntohs(key.SrcPort) != f.srcPort {
		return false
	}
	if f.dstPort != 0 && ntohs(key.DstPort) != f.dstPort {
		return false
	}
	return true
}

// parseSessionPrefix parses an operator prefix filter — a CIDR or a bare IP
// (bare IPs become host networks). Mirrors pkg/grpcapi parseSessionPrefix.
func parseSessionPrefix(prefix string) (*net.IPNet, error) {
	cidr := prefix
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128"
		} else {
			cidr += "/32"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	return n, err
}

func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	filter, badParam, ok := parseRESTSessionFilter(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid "+badParam+" filter: "+r.URL.Query().Get(badParam))
		return
	}

	// page_size>0 selects cursor-based pagination over a stable page_token,
	// matching the gRPC contract (page_size triggers getSessionsCursor).
	// The offset path remains for backward compatibility but is best-effort:
	// the backend iterates helper map order, so an offset against a fresh
	// traversal can skip/duplicate rows when sessions expire or insert
	// between pages (#3421 H4). queryIntStrict fails closed on a malformed
	// or negative value (#3421 M8).
	pageSize, ok := queryIntStrict(r, "page_size", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page_size: "+r.URL.Query().Get("page_size"))
		return
	}
	if pageSize > 10000 {
		pageSize = 10000
	}
	if pageSize > 0 {
		if iterDP, cursorOK := s.dp.(sessionCursorIterator); cursorOK {
			s.sessionsCursor(w, r, iterDP, filter, pageSize)
			return
		}
		// Cursor iteration unsupported by this dataplane (test/edge
		// configurations); fall through to the offset/limit path so the
		// request still succeeds, mirroring the gRPC fallback.
	}

	s.sessionsOffset(w, r, filter)
}

// sessionsOffset serves the backward-compatible limit/offset pagination
// path. limit/offset parse fail-closed on malformed/negative input (#3421
// M8); an iterator error fails the request rather than returning a partial
// list as success (#2469).
func (s *Server) sessionsOffset(w http.ResponseWriter, r *http.Request, filter *restSessionFilter) {
	limit, ok := queryIntStrict(r, "limit", 100)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid limit: "+r.URL.Query().Get("limit"))
		return
	}
	if limit > 10000 {
		limit = 10000
	}
	offset, ok := queryIntStrict(r, "offset", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid offset: "+r.URL.Query().Get("offset"))
		return
	}

	now := monotonicSeconds()
	all := make([]SessionEntry, 0)
	idx := 0

	// IPv4 sessions. A backend iterator failure (e.g. helper restart
	// mid-scan) must fail the request rather than returning HTTP 200 with
	// a partial/zero session list as a healthy result (#2469).
	if err := s.dp.IterateSessions(func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
		if !filter.matchV4(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV4(key, val, now))
		}
		idx++
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
		return
	}

	// IPv6 sessions
	if err := s.dp.IterateSessionsV6(func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
		if !filter.matchV6(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			all = append(all, sessionEntryV6(key, val, now))
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

// sessionsCursor serves cursor-based pagination using the same stable
// page_token machinery as gRPC: it iterates v4 then v6 from the cursor,
// emitting up to page_size matching rows and a next_page_token that resumes
// exactly after the last row. Because IterateSessionsFrom resumes AFTER the
// cursor key, pages never skip or duplicate rows across map mutation the way
// the offset path can (#3421 H4). An iterator error fails the request (#2469).
func (s *Server) sessionsCursor(w http.ResponseWriter, r *http.Request, iterDP sessionCursorIterator, filter *restSessionFilter, pageSize int) {
	startV4 := true
	startV6 := false
	var cursorV4 *dataplane.SessionKey
	var cursorV6 *dataplane.SessionKeyV6

	if token := r.URL.Query().Get("page_token"); token != "" {
		kind, keyBytes, err := parseSessionPageToken(token)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid page_token: "+err.Error())
			return
		}
		switch kind {
		case "v4":
			k, err := decodeSessionKeyV4(keyBytes)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid v4 page_token: "+err.Error())
				return
			}
			cursorV4 = &k
		case "v6start":
			startV4 = false
			startV6 = true
		case "v6":
			startV4 = false
			startV6 = true
			k, err := decodeSessionKeyV6(keyBytes)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid v6 page_token: "+err.Error())
				return
			}
			cursorV6 = &k
		}
	}

	now := monotonicSeconds()
	all := make([]SessionEntry, 0, pageSize)
	var lastV4 dataplane.SessionKey
	var lastV6 dataplane.SessionKeyV6

	// Phase 1: v4 from cursor.
	if startV4 {
		if err := iterDP.IterateSessionsFrom(cursorV4, func(key dataplane.SessionKey, val dataplane.SessionValue) bool {
			if len(all) >= pageSize {
				return false
			}
			if !filter.matchV4(key, val) {
				return true
			}
			all = append(all, sessionEntryV4(key, val, now))
			lastV4 = key
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
			return
		}
		if len(all) >= pageSize {
			writeOK(w, SessionListResponse{
				PageSize:      pageSize,
				NextPageToken: encodePageTokenV4(lastV4),
				Sessions:      all,
			})
			return
		}
		startV6 = true
	}

	// Phase 2: v6.
	if startV6 {
		if err := iterDP.IterateSessionsV6From(cursorV6, func(key dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if len(all) >= pageSize {
				return false
			}
			if !filter.matchV6(key, val) {
				return true
			}
			all = append(all, sessionEntryV6(key, val, now))
			lastV6 = key
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
			return
		}
		if len(all) >= pageSize {
			writeOK(w, SessionListResponse{
				PageSize:      pageSize,
				NextPageToken: encodePageTokenV6(lastV6),
				Sessions:      all,
			})
			return
		}
	}

	// Both families exhausted — last page, empty next_page_token.
	writeOK(w, SessionListResponse{
		PageSize: pageSize,
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

func (s *Server) clearSessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	// REST clear is an unconditional clear-ALL of the local table. gRPC
	// supports a FILTERED clear (source/destination prefix, protocol, zone,
	// ports, application, interface, nat-only, source-nat-pool); this
	// handler does not. Silently ignoring filter parameters would degrade a
	// client's intended-narrow clear into a full-table wipe — so reject any
	// query string or request body with HTTP 400 rather than performing an
	// unexpected clear-all (#3421 H6). A parameterless clear (the documented
	// contract) proceeds. Filtered REST clear plus HA peer propagation is
	// tracked separately in #3423; a non-zero ContentLength (including the
	// chunked-transfer -1 sentinel) also rejects so a body-carrying request
	// cannot be silently misread as clear-all.
	if len(r.URL.Query()) > 0 || r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest,
			"filtered clear not supported on this endpoint; it clears all local sessions and accepts no parameters")
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

// --- Cursor page-token codec (#3421 H4) ---
//
// Token format mirrors the gRPC surface (pkg/grpcapi/server_sessions.go):
//
//	"v4:<hex-key>"  — resume v4 iteration after this key, then v6
//	"v6:<hex-key>"  — v4 done, resume v6 iteration after this key
//	"v6start"       — v4 done, start v6 from the beginning
//
// The blob is base64url(rawkind+":"+hex(key-bytes)). Tokens encode local
// session-map keys and are only meaningful on the node that issued them;
// they are opaque to clients.

func encodePageTokenV4(key dataplane.SessionKey) string {
	b := make([]byte, 13)
	copy(b[0:4], key.SrcIP[:])
	copy(b[4:8], key.DstIP[:])
	binary.NativeEndian.PutUint16(b[8:10], key.SrcPort)
	binary.NativeEndian.PutUint16(b[10:12], key.DstPort)
	b[12] = key.Protocol
	return base64.RawURLEncoding.EncodeToString([]byte("v4:" + hex.EncodeToString(b)))
}

func encodePageTokenV6(key dataplane.SessionKeyV6) string {
	b := make([]byte, 37)
	copy(b[0:16], key.SrcIP[:])
	copy(b[16:32], key.DstIP[:])
	binary.NativeEndian.PutUint16(b[32:34], key.SrcPort)
	binary.NativeEndian.PutUint16(b[34:36], key.DstPort)
	b[36] = key.Protocol
	return base64.RawURLEncoding.EncodeToString([]byte("v6:" + hex.EncodeToString(b)))
}

// parseSessionPageToken returns the token kind ("v4", "v6", "v6start") and
// the raw key bytes (nil for "v6start").
func parseSessionPageToken(token string) (kind string, keyBytes []byte, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", nil, fmt.Errorf("invalid page_token encoding: %w", err)
	}
	str := string(raw)
	if str == "v6start" {
		return "v6start", nil, nil
	}
	switch {
	case strings.HasPrefix(str, "v4:"):
		b, err := hex.DecodeString(str[3:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v4 page_token hex: %w", err)
		}
		return "v4", b, nil
	case strings.HasPrefix(str, "v6:"):
		b, err := hex.DecodeString(str[3:])
		if err != nil {
			return "", nil, fmt.Errorf("invalid v6 page_token hex: %w", err)
		}
		return "v6", b, nil
	}
	return "", nil, fmt.Errorf("invalid page_token prefix")
}

func decodeSessionKeyV4(b []byte) (dataplane.SessionKey, error) {
	var key dataplane.SessionKey
	if len(b) < 13 {
		return key, fmt.Errorf("v4 key too short: %d", len(b))
	}
	copy(key.SrcIP[:], b[0:4])
	copy(key.DstIP[:], b[4:8])
	key.SrcPort = binary.NativeEndian.Uint16(b[8:10])
	key.DstPort = binary.NativeEndian.Uint16(b[10:12])
	key.Protocol = b[12]
	return key, nil
}

func decodeSessionKeyV6(b []byte) (dataplane.SessionKeyV6, error) {
	var key dataplane.SessionKeyV6
	if len(b) < 37 {
		return key, fmt.Errorf("v6 key too short: %d", len(b))
	}
	copy(key.SrcIP[:], b[0:16])
	copy(key.DstIP[:], b[16:32])
	key.SrcPort = binary.NativeEndian.Uint16(b[32:34])
	key.DstPort = binary.NativeEndian.Uint16(b[34:36])
	key.Protocol = b[36]
	return key, nil
}
