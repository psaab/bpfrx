package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

// fakeClusterSessionService stands in for the live gRPC server's HA-aware
// session surface (#3423). It records the requests the REST handlers forward
// and returns canned responses so the tests can assert the REST endpoints
// route cross-node session operations through it.
type fakeClusterSessionService struct {
	clearCalled   bool
	clearReq      *pb.ClearSessionsRequest
	clearResp     *pb.ClearSessionsResponse
	getCalled     bool
	getReq        *pb.GetSessionsRequest
	getResp       *pb.GetSessionsResponse
	summaryCalled bool
	summaryReq    *pb.GetSessionSummaryRequest
	summaryResp   *pb.GetSessionSummaryResponse
}

func (f *fakeClusterSessionService) ClearSessions(_ context.Context, req *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	f.clearCalled = true
	f.clearReq = req
	return f.clearResp, nil
}

func (f *fakeClusterSessionService) GetSessions(_ context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	f.getCalled = true
	f.getReq = req
	return f.getResp, nil
}

func (f *fakeClusterSessionService) GetSessionSummary(_ context.Context, req *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error) {
	f.summaryCalled = true
	f.summaryReq = req
	return f.summaryResp, nil
}

func decodeClearResult(t *testing.T, body []byte) ClearSessionsResult {
	t.Helper()
	var resp struct {
		Success bool                `json:"success"`
		Data    ClearSessionsResult `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode clear response: %v; body=%s", err, body)
	}
	return resp.Data
}

func decodeSummary(t *testing.T, body []byte) SessionSummary {
	t.Helper()
	var resp struct {
		Success bool           `json:"success"`
		Data    SessionSummary `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode summary response: %v; body=%s", err, body)
	}
	return resp.Data
}

// TestRESTClearSessionsFansOutToPeer asserts the #3423 H5 contract: in an HA
// cluster the REST clear-sessions endpoint routes the clear through the same
// HA-aware service-layer path the gRPC clear uses — clearing the LOCAL node
// AND forwarding to the peer — and surfaces the node scope plus any peer
// (partial) failure on the response. Before #3423 the handler called only
// s.dp.ClearAllSessions(): peer/synced sessions survived and could reappear as
// active state on failover, with no indication to the operator.
//
// FAIL-ON-REVERT: reverting clearSessionsHandler to the local-only
// s.dp.ClearAllSessions() path makes the cluster service never get the clear
// (clearCalled stays false) and drops Failures/FailureSummary/NodeID from the
// response — flipping every assertion below red.
func TestRESTClearSessionsFansOutToPeer(t *testing.T) {
	fake := &fakeClusterSessionService{
		clearResp: &pb.ClearSessionsResponse{
			Ipv4Cleared:    3,
			Ipv6Cleared:    1,
			Failures:       1,
			FailureSummary: "peer clear: dial peer: connection refused",
		},
	}
	dp := &clearAllDP{Manager: dataplane.New()}
	s := &Server{
		dp:               dp,
		nodeIDFn:         func() int { return 1 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}

	rr := httptest.NewRecorder()
	s.clearSessionsHandler(rr, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !fake.clearCalled {
		t.Fatal("REST clear did not route through the HA-aware cluster service (peer was not cleared)")
	}
	// The handler must NOT also take the local-only path: the cluster
	// service performs the local clear (same dataplane in production).
	if dp.cleared {
		t.Fatal("REST clear took the local-only ClearAllSessions path instead of the HA-aware service")
	}
	got := decodeClearResult(t, rr.Body.Bytes())
	if got.IPv4Cleared != 3 || got.IPv6Cleared != 1 {
		t.Fatalf("cleared counts = v4 %d v6 %d, want 3/1", got.IPv4Cleared, got.IPv6Cleared)
	}
	if got.NodeID != 1 {
		t.Fatalf("node_id = %d, want 1 (scope not surfaced)", got.NodeID)
	}
	if got.Failures != 1 {
		t.Fatalf("failures = %d, want 1 (peer-clear failure not surfaced)", got.Failures)
	}
	if !strings.Contains(got.FailureSummary, "peer clear") {
		t.Fatalf("failure_summary = %q, want it to mention the peer clear", got.FailureSummary)
	}
}

// TestRESTClearSessionsLocalFallback asserts a standalone build (no HA-aware
// service wired) still performs the local clear-all and reports node 0 — the
// pre-#3423 behavior is preserved when there is no cluster.
func TestRESTClearSessionsLocalFallback(t *testing.T) {
	dp := &clearAllDP{Manager: dataplane.New()}
	s := &Server{dp: dp} // no clusterSessionFn, no nodeIDFn

	rr := httptest.NewRecorder()
	s.clearSessionsHandler(rr, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !dp.cleared {
		t.Fatal("standalone clear did not call local ClearAllSessions")
	}
	got := decodeClearResult(t, rr.Body.Bytes())
	if got.IPv4Cleared != 1 || got.Failures != 0 || got.NodeID != 0 {
		t.Fatalf("standalone clear result = %+v, want v4=1 failures=0 node=0", got)
	}
}

// TestRESTSessionListNodeIDAndPeer asserts the #3423 M5 contract for the
// session LIST: the local node identity is always reported (so a dashboard
// knows which node it observed), and include_peer=true augments the local list
// with the cluster peer's sessions fetched via the HA-aware service.
//
// FAIL-ON-REVERT: dropping the node_id stamping makes NodeID 0 (want 5);
// dropping the include_peer peer fetch leaves Peer nil.
func TestRESTSessionListNodeIDAndPeer(t *testing.T) {
	fake := &fakeClusterSessionService{
		getResp: &pb.GetSessionsResponse{
			NodeId: 5, // local node's view as the gRPC server would report
			Peer: &pb.GetSessionsResponse{
				NodeId: 6,
				Total:  1,
				Sessions: []*pb.SessionEntry{{
					SrcAddr:  "10.0.9.9",
					DstAddr:  "10.0.9.1",
					SrcPort:  1111,
					DstPort:  22,
					Protocol: "TCP",
					State:    "Established",
				}},
			},
		},
	}
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 5 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}

	// Without include_peer: node id present, no peer fetch.
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeSessions(t, rr.Body.Bytes())
	if resp.NodeID != 5 {
		t.Fatalf("node_id = %d, want 5 (which-node identity missing)", resp.NodeID)
	}
	if resp.Peer != nil {
		t.Fatal("peer set without include_peer")
	}
	if fake.getCalled {
		t.Fatal("peer fetched without include_peer")
	}

	// With include_peer=true: peer list attached via the HA-aware service.
	rr = httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("include_peer status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp = decodeSessions(t, rr.Body.Bytes())
	if len(resp.Sessions) != 1 {
		t.Fatalf("local sessions = %d, want 1", len(resp.Sessions))
	}
	if !fake.getCalled || fake.getReq == nil || !fake.getReq.GetIncludePeer() {
		t.Fatal("include_peer=true did not fetch peer sessions via the HA-aware service")
	}
	if resp.Peer == nil {
		t.Fatal("include_peer=true did not attach the peer session list")
	}
	if resp.Peer.NodeID != 6 || len(resp.Peer.Sessions) != 1 {
		t.Fatalf("peer list = node %d, %d sessions; want node 6, 1 session", resp.Peer.NodeID, len(resp.Peer.Sessions))
	}
	if resp.Peer.Sessions[0].SrcAddr != "10.0.9.9" {
		t.Fatalf("peer session src = %q, want 10.0.9.9", resp.Peer.Sessions[0].SrcAddr)
	}
}

// TestRESTSessionSummaryNodeIDAndPeer is the summary companion to
// TestRESTSessionListNodeIDAndPeer (#3423 M5).
func TestRESTSessionSummaryNodeIDAndPeer(t *testing.T) {
	fake := &fakeClusterSessionService{
		summaryResp: &pb.GetSessionSummaryResponse{
			NodeId: 5,
			Peer: &pb.GetSessionSummaryResponse{
				NodeId:       6,
				TotalEntries: 12,
				ForwardOnly:  6,
				Established:  4,
				Ipv4Sessions: 5,
				Ipv6Sessions: 1,
			},
		},
	}
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 5 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}

	rr := httptest.NewRecorder()
	s.sessionSummaryHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	sum := decodeSummary(t, rr.Body.Bytes())
	if sum.NodeID != 5 {
		t.Fatalf("summary node_id = %d, want 5", sum.NodeID)
	}
	if sum.Peer != nil {
		t.Fatal("summary peer set without include_peer")
	}

	rr = httptest.NewRecorder()
	s.sessionSummaryHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("include_peer status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	sum = decodeSummary(t, rr.Body.Bytes())
	if !fake.summaryCalled || fake.summaryReq == nil || !fake.summaryReq.GetIncludePeer() {
		t.Fatal("include_peer=true did not fetch the peer summary via the HA-aware service")
	}
	if sum.Peer == nil {
		t.Fatal("include_peer=true did not attach the peer summary")
	}
	if sum.Peer.NodeID != 6 || sum.Peer.TotalEntries != 12 || sum.Peer.Established != 4 {
		t.Fatalf("peer summary = %+v, want node 6, total 12, established 4", sum.Peer)
	}
}

// TestRESTSessionIncludePeerInvalid asserts include_peer fails closed on a
// malformed value rather than being silently ignored (#3423 M5).
func TestRESTSessionIncludePeerInvalid(t *testing.T) {
	s := &Server{
		dp:       &oneSessionDP{Manager: dataplane.New()},
		eventBuf: logging.NewEventBuffer(8),
	}
	for _, path := range []string{
		"/api/v1/security/sessions?include_peer=bogus",
		"/api/v1/security/sessions/summary?include_peer=bogus",
	} {
		rr := httptest.NewRecorder()
		if strings.Contains(path, "summary") {
			s.sessionSummaryHandler(rr, httptest.NewRequest("GET", path, nil))
		} else {
			s.sessionsHandler(rr, httptest.NewRequest("GET", path, nil))
		}
		if rr.Code != 400 {
			t.Fatalf("%s: status = %d, want 400 (malformed include_peer not rejected)", path, rr.Code)
		}
	}
}
