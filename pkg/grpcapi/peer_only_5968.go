package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #5968 — the REST include_peer double-WALK.
//
// A REST list / summary / zone-pair request with include_peer=1 walks the LOCAL
// session table in the REST handler, then delegates to the in-process gRPC
// service to obtain the PEER's table. That gRPC method walks the local table
// AGAIN to build its own local answer — and the REST caller discards it,
// keeping only `.Peer`.
//
// #5880 fixed the double-ACQUIRE on this path (the nested call re-acquired the
// shared limiter and self-rejected at capacity); the lease made the nested call
// reuse the parent's slot. The redundant WALK is a different defect and
// survived it: one slot, two full-table traversals, each contending with the
// live session-sync path for per-bucket map locks. On a large table that is a
// straight doubling of the most expensive thing these endpoints do.
//
// The peer-only entry points below fetch the peer table WITHOUT the local walk.
// They are in-process methods on the Go ClusterSessionService interface, not
// registered gRPC methods, so this costs no protobuf or wire change and no
// version negotiation — the REST bridge and the gRPC server are the same
// process by construction.
//
// ADMISSION IS UNCHANGED. Each of these acquires through the SAME lease-aware
// AcquireCtx the full methods use, so a REST caller holding the boundary slot
// reuses it (#5880) and a caller without a lease acquires one. Skipping
// admission here would have been tempting — these perform no local walk — but
// it would silently retire the #5880 lease-propagation guard on exactly the
// path that guard was written for, turning a live regression test vacuous. The
// change is about the WALK, not about the bound; slot accounting is identical
// before and after.
//
// A dedicated remote budget — bounding peer-directed work independently of
// local work — is the separate redesign #5968 also asks for, and is not built
// here.
//
// PEER-STATUS CLASSIFICATION is shared with the full paths through the
// attachPeer* helpers rather than duplicated. A divergence between "how the
// full method classified this peer fetch" and "how the peer-only method
// classified the same fetch" would ALWAYS be a bug, so it is single-sourced
// rather than bound by a test.

// attachPeerSessionSummary classifies one peer summary fetch onto resp (#5320
// semantics, unchanged): a fetch error is UNREACHABLE with the reason attached,
// a result is OK, and (nil, nil) is either a standalone node (NOT_APPLICABLE)
// or a clustered node whose peer heartbeat is currently lost (UNREACHABLE — a
// partition, not standalone).
func (s *Server) attachPeerSessionSummary(resp, peerResp *pb.GetSessionSummaryResponse, perr error) {
	switch {
	case perr != nil:
		slog.Warn("failed to fetch peer session summary", "err", perr)
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE
		resp.PeerError = perr.Error()
	case peerResp != nil:
		resp.Peer = peerResp
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_OK
	default:
		resp.PeerStatus = s.peerAbsentStatus()
	}
}

// attachPeerZonePairSummary is the zone-pair counterpart (#3592/#5320).
func (s *Server) attachPeerZonePairSummary(resp, peerResp *pb.GetZonePairSummaryResponse, perr error) {
	switch {
	case perr != nil:
		slog.Warn("failed to fetch peer zone-pair summary", "err", perr)
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE
		resp.PeerError = perr.Error()
	case peerResp != nil:
		resp.Peer = peerResp
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_OK
	default:
		resp.PeerStatus = s.peerAbsentStatus()
	}
}

// PeerSessions returns ONLY the cluster peer's session list, with no local
// table walk. The returned response carries `Peer` and nothing else; the caller
// already has its own local view.
//
// The request's filters are forwarded so the peer applies the same predicate
// the local list did. IncludePeer is forced on because fetchPeerSessions gates
// on it, and PageToken is preserved because that function suppresses the peer
// fetch on a non-first page — dropping it here would re-attach the peer table
// to every page and over-count it (#3423).
func (s *Server) PeerSessions(ctx context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, status.Error(codes.Unavailable, "dataplane not loaded")
	}
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()
	// Field-by-field rather than a struct copy: a protobuf message embeds a
	// MessageState containing a mutex, so `*req` would copy a lock (go vet
	// catches it). fetchPeerSessions rebuilds its own outbound request from
	// these fields; PageToken is carried because that function suppresses the
	// peer fetch on a non-first page, and dropping it here would re-attach the
	// peer table to every page and over-count it (#3423).
	peerReq := &pb.GetSessionsRequest{IncludePeer: true}
	if req != nil {
		peerReq.Limit = req.Limit
		peerReq.Offset = req.Offset
		peerReq.Zone = req.Zone
		peerReq.Protocol = req.Protocol
		peerReq.SourcePrefix = req.SourcePrefix
		peerReq.DestinationPrefix = req.DestinationPrefix
		peerReq.SourcePort = req.SourcePort
		peerReq.DestinationPort = req.DestinationPort
		peerReq.NatOnly = req.NatOnly
		peerReq.Application = req.Application
		peerReq.InterfaceFilter = req.InterfaceFilter
		peerReq.SourceNatPool = req.SourceNatPool
		peerReq.PageSize = req.PageSize
		peerReq.PageToken = req.PageToken
		peerReq.NoEnrich = req.NoEnrich
	}

	resp := &pb.GetSessionsResponse{}
	s.fetchPeerSessions(ctx, peerReq, resp)
	return resp, nil
}

// PeerSessionSummary returns ONLY the cluster peer's session summary, with no
// local table walk, classified identically to the full GetSessionSummary path.
func (s *Server) PeerSessionSummary(ctx context.Context) (*pb.GetSessionSummaryResponse, error) {
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	resp := &pb.GetSessionSummaryResponse{}
	peerResp, perr := s.proxyPeerSessionSummary(ctx)
	s.attachPeerSessionSummary(resp, peerResp, perr)
	return resp, nil
}

// PeerZonePairSummary returns ONLY the cluster peer's zone-pair breakdown, with
// no local table walk.
//
// The forwarded-request recursion guard is preserved: a request that is itself
// a peer-forwarded call must not fan out again. On the REST bridge that guard
// is always satisfied (a REST request carries no in-process peer marker), but
// checking it here keeps the peer-only path's behaviour identical to the full
// path's rather than relying on the caller to be the REST bridge.
func (s *Server) PeerZonePairSummary(ctx context.Context) (*pb.GetZonePairSummaryResponse, error) {
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted,
			"session scan concurrency limit reached; retry shortly")
	}
	defer release()

	resp := &pb.GetZonePairSummaryResponse{}
	if peerForwardedFromContext(ctx) {
		resp.PeerStatus = pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE
		return resp, nil
	}
	peerResp, perr := s.proxyPeerZonePairSummary(ctx, &pb.GetZonePairSummaryRequest{})
	s.attachPeerZonePairSummary(resp, peerResp, perr)
	return resp, nil
}
