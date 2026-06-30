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
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
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

func (s *Server) sessionsHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	view := s.buildSessionView()
	q, errMsg := buildSessionQuery(r, view)
	if errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}

	// include_peer is an opt-in HA flag (#3423 M5): when set the local list
	// is augmented with the cluster peer's sessions. Validate it here so a
	// malformed value fails closed (HTTP 400) rather than being silently
	// ignored — mirroring the other boolean filters.
	if _, ok := sessionIncludePeer(r); !ok {
		writeError(w, http.StatusBadRequest, "invalid include_peer: "+r.URL.Query().Get("include_peer"))
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
			s.sessionsCursor(w, r, iterDP, &q, view, pageSize)
			return
		}
		// Cursor iteration unsupported by this dataplane (test/edge
		// configurations); fall through to the offset/limit path so the
		// request still succeeds, mirroring the gRPC fallback.
	}

	s.sessionsOffset(w, r, &q, view)
}

// sessionsOffset serves the backward-compatible limit/offset pagination
// path. limit/offset parse fail-closed on malformed/negative input (#3421
// M8); an iterator error fails the request rather than returning a partial
// list as success (#2469). Rows are enriched and reverse-counter-merged
// identically to the cursor path (#3419).
func (s *Server) sessionsOffset(w http.ResponseWriter, r *http.Request, q *sessionQuery, view sessionView) {
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
		if !q.matchV4(key, val) {
			return true
		}
		if idx >= offset && len(all) < limit {
			all = append(all, s.enrichSessionV4(key, val, now, view))
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
			all = append(all, s.enrichSessionV6(key, val, now, view))
		}
		idx++
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
		return
	}

	s.writeSessionList(w, r, SessionListResponse{
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
// the offset path can (#3421 H4). Rows use the SAME #3419 enrichment +
// reverse-counter merge as the offset path, so cursor and offset modes
// report identical rows and counters. An iterator error fails the request
// (#2469).
func (s *Server) sessionsCursor(w http.ResponseWriter, r *http.Request, iterDP sessionCursorIterator, q *sessionQuery, view sessionView, pageSize int) {
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
			if !q.matchV4(key, val) {
				return true
			}
			all = append(all, s.enrichSessionV4(key, val, now, view))
			lastV4 = key
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
			return
		}
		if len(all) >= pageSize {
			s.writeSessionList(w, r, SessionListResponse{
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
			if !q.matchV6(key, val) {
				return true
			}
			all = append(all, s.enrichSessionV6(key, val, now, view))
			lastV6 = key
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions_v6: "+err.Error())
			return
		}
		if len(all) >= pageSize {
			s.writeSessionList(w, r, SessionListResponse{
				PageSize:      pageSize,
				NextPageToken: encodePageTokenV6(lastV6),
				Sessions:      all,
			})
			return
		}
	}

	// Both families exhausted — last page, empty next_page_token.
	s.writeSessionList(w, r, SessionListResponse{
		PageSize: pageSize,
		Sessions: all,
	})
}

// enrichSessionV4 merges the companion reverse entry's counters into the
// forward entry (full bidirectional volume, #3419 H3) and renders the
// enriched REST row (#3419). Shared by the offset and cursor paths so they
// report identical rows and counters.
func (s *Server) enrichSessionV4(key dataplane.SessionKey, val dataplane.SessionValue, now uint64, view sessionView) SessionEntry {
	if rev, err := s.dp.GetSessionV4(val.ReverseKey); err == nil {
		val.RevPackets += rev.RevPackets
		val.RevBytes += rev.RevBytes
		val.FwdPackets += rev.FwdPackets
		val.FwdBytes += rev.FwdBytes
	}
	return sessionEntryV4(key, val, now, view)
}

// enrichSessionV6 is the IPv6 companion to enrichSessionV4.
func (s *Server) enrichSessionV6(key dataplane.SessionKeyV6, val dataplane.SessionValueV6, now uint64, view sessionView) SessionEntry {
	if rev, err := s.dp.GetSessionV6(val.ReverseKey); err == nil {
		val.RevPackets += rev.RevPackets
		val.RevBytes += rev.RevBytes
		val.FwdPackets += rev.FwdPackets
		val.FwdBytes += rev.FwdBytes
	}
	return sessionEntryV6(key, val, now, view)
}

// sessionIncludePeer parses the include_peer query flag, returning the value
// and whether it was well-formed (an absent flag is valid and defaults to
// false). The handlers fail closed (HTTP 400) on a malformed value rather
// than silently ignoring an opt-in HA request (#3423 M5).
func sessionIncludePeer(r *http.Request) (value bool, ok bool) {
	v := r.URL.Query().Get("include_peer")
	if v == "" {
		return false, true
	}
	b, err := strconv.ParseBool(v)
	return b, err == nil
}

// writeSessionList stamps the local node identity on a REST session list and,
// when include_peer=true and an HA-aware session service is wired, augments it
// with the cluster peer's sessions (#3423 M5). The local list reports the
// LOCAL table only; node_id tells a dashboard which node it observes, and the
// optional peer set keeps it from understating total HA state.
//
// The peer's FULL table is attached only on the FIRST page — cursor mode's
// first page (no page_token) AND offset mode's first window (offset==0). A
// client paginating either way and summing peer.sessions across pages would
// OVER-COUNT the peer if the whole peer table were re-attached on every page
// (the offset path never sets a page_token, so a page_token-only guard let it
// through). page_token additionally encodes node-local map keys meaningless to
// the peer.
func (s *Server) writeSessionList(w http.ResponseWriter, r *http.Request, resp SessionListResponse) {
	resp.NodeID = s.nodeID()
	if includePeer, _ := sessionIncludePeer(r); includePeer && sessionFirstPage(r) {
		if svc := s.clusterSession(); svc != nil {
			if pr, err := svc.GetSessions(r.Context(), peerSessionsRequest(r)); err == nil {
				if peer := pr.GetPeer(); peer != nil {
					resp.Peer = sessionListFromPB(peer)
				}
			}
		}
	}
	writeOK(w, resp)
}

// sessionFirstPage reports whether this list request is the first page, on
// BOTH pagination modes: cursor mode's first page carries no page_token, and
// offset mode's first window has offset==0. A non-first page must NOT re-attach
// the peer table (#3423 — avoids over-counting the peer across pages). The
// offset/page_token query values are already validated by the caller
// (sessionsOffset / sessionsCursor) before writeSessionList runs, so a lenient
// re-parse here cannot mask a malformed value.
func sessionFirstPage(r *http.Request) bool {
	q := r.URL.Query()
	if q.Get("page_token") != "" {
		return false
	}
	if off, err := strconv.Atoi(q.Get("offset")); err == nil && off > 0 {
		return false
	}
	return true
}

// peerSessionsRequest maps the REST session filter query parameters onto a
// protobuf GetSessionsRequest with IncludePeer set, so the peer applies the
// SAME filters the local list did. Values are read leniently — the caller has
// already validated them (buildSessionQuery / the include_peer guard) before a
// peer fetch is attempted, and the peer re-validates on its own surface.
func peerSessionsRequest(r *http.Request) *pb.GetSessionsRequest {
	q := r.URL.Query()
	req := &pb.GetSessionsRequest{
		IncludePeer:       true,
		Protocol:          q.Get("protocol"),
		SourcePrefix:      q.Get("source_prefix"),
		DestinationPrefix: q.Get("destination_prefix"),
		Application:       q.Get("application"),
		InterfaceFilter:   q.Get("interface"),
		SourceNatPool:     q.Get("source_nat_pool"),
	}
	if z, err := strconv.ParseUint(q.Get("zone"), 10, 16); err == nil {
		req.Zone = uint32(z)
	}
	if p, err := strconv.ParseUint(q.Get("source_port"), 10, 16); err == nil {
		req.SourcePort = uint32(p)
	}
	if p, err := strconv.ParseUint(q.Get("destination_port"), 10, 16); err == nil {
		req.DestinationPort = uint32(p)
	}
	if b, err := strconv.ParseBool(q.Get("nat_only")); err == nil {
		req.NatOnly = b
	}
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		req.Limit = int32(l)
	}
	return req
}

// sessionListFromPB maps a protobuf session-list response (the peer node's
// view) onto the REST SessionListResponse shape (#3423 M5).
func sessionListFromPB(p *pb.GetSessionsResponse) *SessionListResponse {
	out := &SessionListResponse{
		Total:         int(p.GetTotal()),
		Limit:         int(p.GetLimit()),
		Offset:        int(p.GetOffset()),
		NextPageToken: p.GetNextPageToken(),
		NodeID:        int(p.GetNodeId()),
		Sessions:      make([]SessionEntry, 0, len(p.GetSessions())),
	}
	for _, e := range p.GetSessions() {
		out.Sessions = append(out.Sessions, sessionEntryFromPB(e))
	}
	return out
}

// sessionEntryFromPB maps one protobuf SessionEntry onto the REST shape.
func sessionEntryFromPB(e *pb.SessionEntry) SessionEntry {
	return SessionEntry{
		SrcAddr:          e.GetSrcAddr(),
		DstAddr:          e.GetDstAddr(),
		SrcPort:          uint16(e.GetSrcPort()),
		DstPort:          uint16(e.GetDstPort()),
		Protocol:         e.GetProtocol(),
		State:            e.GetState(),
		PolicyID:         e.GetPolicyId(),
		PolicyName:       e.GetPolicyName(),
		IngressZoneName:  e.GetIngressZoneName(),
		EgressZoneName:   e.GetEgressZoneName(),
		InZone:           uint16(e.GetIngressZone()),
		OutZone:          uint16(e.GetEgressZone()),
		IngressInterface: e.GetIngressInterface(),
		EgressInterface:  e.GetEgressInterface(),
		Application:      e.GetApplication(),
		FwdPackets:       e.GetFwdPackets(),
		FwdBytes:         e.GetFwdBytes(),
		RevPackets:       e.GetRevPackets(),
		RevBytes:         e.GetRevBytes(),
		NAT:              e.GetNat(),
		NATSrcAddr:       e.GetNatSrcAddr(),
		NATSrcPort:       uint16(e.GetNatSrcPort()),
		NATDstAddr:       e.GetNatDstAddr(),
		NATDstPort:       uint16(e.GetNatDstPort()),
		Age:              e.GetAgeSeconds(),
		Idle:             e.GetIdleSeconds(),
		Timeout:          e.GetTimeoutSeconds(),
		SessionID:        e.GetSessionId(),
		HAActive:         e.GetHaActive(),
	}
}

// sessionSummaryFromPB maps a protobuf session summary (the peer node's view)
// onto the REST SessionSummary shape (#3423 M5).
func sessionSummaryFromPB(p *pb.GetSessionSummaryResponse) *SessionSummary {
	return &SessionSummary{
		TotalEntries: int(p.GetTotalEntries()),
		ForwardOnly:  int(p.GetForwardOnly()),
		Established:  int(p.GetEstablished()),
		IPv4Sessions: int(p.GetIpv4Sessions()),
		IPv6Sessions: int(p.GetIpv6Sessions()),
		SNATSessions: int(p.GetSnatSessions()),
		DNATSessions: int(p.GetDnatSessions()),
		NodeID:       int(p.GetNodeId()),
	}
}

func (s *Server) sessionSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeError(w, http.StatusServiceUnavailable, "dataplane not loaded")
		return
	}

	// include_peer opt-in HA flag (#3423 M5); fail closed on a bad value.
	includePeer, ok := sessionIncludePeer(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid include_peer: "+r.URL.Query().Get("include_peer"))
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

	summary.NodeID = s.nodeID()

	// Augment with the cluster peer's summary when the operator opted in and
	// an HA-aware service is wired (#3423 M5): the local summary alone
	// understates total HA state. A standalone node / unreachable peer
	// leaves Peer nil.
	if includePeer {
		if svc := s.clusterSession(); svc != nil {
			if pr, err := svc.GetSessionSummary(r.Context(), &pb.GetSessionSummaryRequest{IncludePeer: true}); err == nil {
				if peer := pr.GetPeer(); peer != nil {
					summary.Peer = sessionSummaryFromPB(peer)
				}
			}
		}
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
	// contract) proceeds. Test against r.URL.RawQuery (not url.Query(),
	// which silently drops un-decodable pairs like `?%zz` and could let a
	// non-empty query proceed to clear-all — SMR); a non-zero ContentLength
	// (including the chunked-transfer -1 sentinel) also rejects so a
	// body-carrying request cannot be misread as clear-all.
	if r.URL.RawQuery != "" || r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest,
			"filtered clear not supported on this endpoint; it clears all local sessions and accepts no parameters")
		return
	}

	// In an HA cluster the clear MUST also reach the peer: a local-only
	// clear leaves the peer/synced sessions, which can reappear as active
	// state on failover (#3423 H5). When the HA-aware session service is
	// wired (the gRPC server), delegate the clear-all to it so REST shares
	// the SAME service-layer path gRPC uses: local clear + peer propagation
	// (clearPeerSessions, x-peer-forwarded recursion guard) + partial-
	// failure summary. A nil service (standalone build / unit test) falls
	// back to the local-only clear — the pre-#3423 behavior.
	if svc := s.clusterSession(); svc != nil {
		resp, err := svc.ClearSessions(r.Context(), &pb.ClearSessionsRequest{})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, ClearSessionsResult{
			IPv4Cleared:    int(resp.GetIpv4Cleared()),
			IPv6Cleared:    int(resp.GetIpv6Cleared()),
			NodeID:         s.nodeID(),
			Failures:       int(resp.GetFailures()),
			FailureSummary: resp.GetFailureSummary(),
		})
		return
	}

	v4, v6, err := s.dp.ClearAllSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, ClearSessionsResult{IPv4Cleared: v4, IPv6Cleared: v6, NodeID: s.nodeID()})
}

// sessionZonePairHandler serves the zone-pair session breakdown. Like the
// /sessions/summary sibling it now stamps node_id so an operator knows which
// node the counts came from (#3423 M5). It does NOT support include_peer:
// unlike list/summary there is no gRPC zone-pair-summary RPC to forward to, so
// cross-node fan-out would need a new RPC. Tracked as a follow-up (#3592,
// referenced in pkg/api/README.md) rather than approximated client-side from a
// peer session list.
func (s *Server) sessionZonePairHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, ZonePairSummaryResponse{NodeID: s.nodeID(), ZonePairs: []ZonePairSessionSummary{}})
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
	writeOK(w, ZonePairSummaryResponse{NodeID: s.nodeID(), ZonePairs: result})
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
	// source/destination prefix + port filters (#3421 M2), mirroring the
	// gRPC sessionFilter src/dst predicates. A nil net / zero port means
	// "no filter" on that dimension.
	srcNet  *net.IPNet
	dstNet  *net.IPNet
	srcPort uint16
	dstPort uint16
	view    sessionView
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

	// Source/destination prefix + port filters (#3421 M2). These FAIL
	// CLOSED on a malformed value (HTTP 400) rather than zeroing the
	// predicate and widening the query — matching the gRPC sessionFilter
	// contract.
	if sp := r.URL.Query().Get("source_prefix"); sp != "" {
		n, err := parseSessionPrefix(sp)
		if err != nil {
			return q, "invalid source_prefix filter: " + sp
		}
		q.srcNet = n
	}
	if dp := r.URL.Query().Get("destination_prefix"); dp != "" {
		n, err := parseSessionPrefix(dp)
		if err != nil {
			return q, "invalid destination_prefix filter: " + dp
		}
		q.dstNet = n
	}
	srcPort, ok := queryUint16Strict(r, "source_port", 0)
	if !ok {
		return q, "invalid source_port filter: " + r.URL.Query().Get("source_port")
	}
	q.srcPort = srcPort
	dstPort, ok := queryUint16Strict(r, "destination_port", 0)
	if !ok {
		return q, "invalid destination_port filter: " + r.URL.Query().Get("destination_port")
	}
	q.dstPort = dstPort

	return q, ""
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
	if q.srcNet != nil && !q.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if q.dstNet != nil && !q.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if q.srcPort != 0 && ntohs(key.SrcPort) != q.srcPort {
		return false
	}
	if q.dstPort != 0 && ntohs(key.DstPort) != q.dstPort {
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
	if q.srcNet != nil && !q.srcNet.Contains(net.IP(key.SrcIP[:])) {
		return false
	}
	if q.dstNet != nil && !q.dstNet.Contains(net.IP(key.DstIP[:])) {
		return false
	}
	if q.srcPort != 0 && ntohs(key.SrcPort) != q.srcPort {
		return false
	}
	if q.dstPort != 0 && ntohs(key.DstPort) != q.dstPort {
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
