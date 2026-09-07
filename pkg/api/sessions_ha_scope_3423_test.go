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
	clearCalled bool
	clearReq    *pb.ClearSessionsRequest
	clearResp   *pb.ClearSessionsResponse
	// clearErr (#9142) lets a cell drive the DELEGATED error path, which had
	// no coverage at all: TestRESTClearSessionsConcurrencyBound pins only the
	// clusterSessionFn == nil fallback, by its own comment.
	clearErr      error
	getCalled     bool
	getReq        *pb.GetSessionsRequest
	getResp       *pb.GetSessionsResponse
	summaryCalled bool
	summaryReq    *pb.GetSessionSummaryRequest
	summaryResp   *pb.GetSessionSummaryResponse
	zpCalled      bool
	zpReq         *pb.GetZonePairSummaryRequest
	zpResp        *pb.GetZonePairSummaryResponse

	// #5968 peer-only delegation.
	peerGetCalled     bool
	peerSummaryCalled bool
	peerZPCalled      bool
}

func (f *fakeClusterSessionService) ClearSessions(_ context.Context, req *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	f.clearCalled = true
	f.clearReq = req
	if f.clearErr != nil {
		return nil, f.clearErr
	}
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

func (f *fakeClusterSessionService) GetZonePairSummary(_ context.Context, req *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
	f.zpCalled = true
	f.zpReq = req
	return f.zpResp, nil
}

// #5968: the peer-ONLY entry points the REST handlers now delegate to. They
// return the SAME fixtures as their full-view siblings — the REST contract
// under test is "the peer view reaches the response", which did not change —
// and set their own *called* flags so a test can tell WHICH method the handler
// used. That distinction is the point: the old methods walked the local table a
// second time and had their local result discarded.
func (f *fakeClusterSessionService) PeerSessions(_ context.Context, req *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	f.peerGetCalled = true
	f.getReq = req
	return f.getResp, nil
}

func (f *fakeClusterSessionService) PeerSessionSummary(_ context.Context) (*pb.GetSessionSummaryResponse, error) {
	f.peerSummaryCalled = true
	return f.summaryResp, nil
}

func (f *fakeClusterSessionService) PeerZonePairSummary(_ context.Context) (*pb.GetZonePairSummaryResponse, error) {
	f.peerZPCalled = true
	return f.zpResp, nil
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
	if fake.peerGetCalled || fake.getCalled {
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
	// #5968: the delegate is PeerSessions now — peer view only, no redundant
	// local walk. The property is unchanged: the handler fetched the peer
	// through the HA-aware service and asked for the peer view.
	if !fake.peerGetCalled || fake.getReq == nil || !fake.getReq.GetIncludePeer() {
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
	// #5968: delegated to PeerSessionSummary, which takes no request — the
	// peer view is all it returns, so there is no IncludePeer flag to assert.
	if !fake.peerSummaryCalled {
		t.Fatal("include_peer=true did not fetch the peer summary via the HA-aware service")
	}
	if sum.Peer == nil {
		t.Fatal("include_peer=true did not attach the peer summary")
	}
	if sum.Peer.NodeID != 6 || sum.Peer.TotalEntries != 12 || sum.Peer.Established != 4 {
		t.Fatalf("peer summary = %+v, want node 6, total 12, established 4", sum.Peer)
	}
}

// TestRESTSessionListPeerOnlyOnFirstPage asserts the peer table is attached
// only on the FIRST page in BOTH pagination modes (#3423): the offset path
// never sets a page_token, so a page_token-only guard re-attached the FULL
// peer table on every offset page — a client summing peer.sessions across
// offset pages would over-count the peer. include_peer=true&offset=0 attaches
// the peer; include_peer=true&offset=<nonzero> must NOT.
//
// FAIL-ON-REVERT: reverting writeSessionList to the page_token-only guard
// attaches the peer on the offset>0 request, flipping the "no peer" assertion.
func TestRESTSessionListPeerOnlyOnFirstPage(t *testing.T) {
	newFake := func() *fakeClusterSessionService {
		return &fakeClusterSessionService{
			getResp: &pb.GetSessionsResponse{
				Peer: &pb.GetSessionsResponse{
					NodeId:   6,
					Total:    1,
					Sessions: []*pb.SessionEntry{{SrcAddr: "10.0.9.9", Protocol: "TCP"}},
				},
			},
		}
	}

	// offset=0 (first window): peer attached.
	fake := newFake()
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions?include_peer=true&offset=0", nil))
	if rr.Code != 200 {
		t.Fatalf("offset=0 status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if resp := decodeSessions(t, rr.Body.Bytes()); resp.Peer == nil {
		t.Fatal("offset=0 (first page) did not attach the peer list")
	}
	if !fake.peerGetCalled {
		t.Fatal("offset=0 did not fetch the peer")
	}

	// offset>0 (a later page): peer NOT attached — avoids over-counting.
	fake = newFake()
	s.clusterSessionFn = func() ClusterSessionService { return fake }
	rr = httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions?include_peer=true&offset=10", nil))
	if rr.Code != 200 {
		t.Fatalf("offset=10 status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if resp := decodeSessions(t, rr.Body.Bytes()); resp.Peer != nil {
		t.Fatal("offset=10 (later page) re-attached the peer table — over-counts the peer across offset pages")
	}
	if fake.peerGetCalled || fake.getCalled {
		t.Fatal("offset=10 fetched the peer table on a non-first page")
	}
}

// TestRESTSessionListPeerHonorsPageSize asserts the #4920 contract: a
// cursor-mode session list (page_size set, no limit) with include_peer=true
// forwards page_size to the peer fetch as PageSize, so the peer fan-out honors
// the SAME page bound the local list did. Before the fix peerSessionsRequest
// forwarded only offset-mode limit, so the peer gRPC request carried
// Limit==0 AND PageSize==0; getSessionsLegacy then defaulted the peer list to
// 100 sessions and the first REST page silently undercounted a peer holding
// >100 sessions.
//
// The dp is the cursor-capable multiSessionDP so the LOCAL request genuinely
// takes the page_size>0 cursor path (matching the real trigger). The peer fetch
// is exercised through the fakeClusterSessionService seam, which records the
// forwarded request — no real peer required.
//
// FAIL-ON-REVERT: dropping the page_size→PageSize forward in
// peerSessionsRequest makes the recorded peer request carry PageSize==0,
// flipping the want-1000 assertion red.
func TestRESTSessionListPeerHonorsPageSize(t *testing.T) {
	fake := &fakeClusterSessionService{
		getResp: &pb.GetSessionsResponse{
			NodeId: 5,
			Peer: &pb.GetSessionsResponse{
				NodeId: 6,
				Total:  1,
				Sessions: []*pb.SessionEntry{{
					SrcAddr: "10.0.9.9", Protocol: "TCP",
				}},
			},
		},
	}
	s := &Server{
		dp:               newMultiSessionDP(),
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 5 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}

	// Cursor mode: page_size set, NO limit. This is the real #4920 trigger.
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET",
		"/api/v1/security/sessions?page_size=1000&include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !fake.peerGetCalled || fake.getReq == nil {
		t.Fatal("include_peer=true did not fetch peer sessions via the HA-aware service")
	}
	if got := fake.getReq.GetPageSize(); got != 1000 {
		t.Fatalf("peer request PageSize = %d, want 1000 (cursor-mode page_size not forwarded — peer undercounts to the 100 default)", got)
	}
	// The peer request must carry include_peer (fetches the peer's Peer leg)
	// and must NOT drop page_size to the offset-mode limit default.
	if !fake.getReq.GetIncludePeer() {
		t.Fatal("peer request lost IncludePeer")
	}
	if fake.getReq.GetLimit() != 0 {
		t.Fatalf("peer request Limit = %d, want 0 (cursor mode sends page_size, not limit)", fake.getReq.GetLimit())
	}
	// And the peer leg must still attach to the REST response.
	resp := decodeSessions(t, rr.Body.Bytes())
	if resp.Peer == nil || resp.Peer.NodeID != 6 {
		t.Fatalf("peer leg not attached: %+v", resp.Peer)
	}
}

// TestRESTZonePairsNodeID asserts the zone-pair summary stamps node_id so it is
// consistent with its /sessions/summary sibling (#3423 M5). Before the fix it
// returned a bare array with no node identity.
//
// FAIL-ON-REVERT: reverting to the bare []ZonePairSessionSummary makes the
// response decode into ZonePairSummaryResponse with NodeID 0 (want 4).
func TestRESTZonePairsNodeID(t *testing.T) {
	s := &Server{
		dp:       &oneSessionDP{Manager: dataplane.New()},
		eventBuf: logging.NewEventBuffer(8),
		nodeIDFn: func() int { return 4 },
	}
	rr := httptest.NewRecorder()
	s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary/zone-pairs", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool                    `json:"success"`
		Data    ZonePairSummaryResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode zone-pairs response: %v; body=%s", err, rr.Body.String())
	}
	if resp.Data.NodeID != 4 {
		t.Fatalf("zone-pairs node_id = %d, want 4 (which-node identity missing)", resp.Data.NodeID)
	}
	if resp.Data.ZonePairs == nil {
		t.Fatal("zone-pairs response missing zone_pairs array")
	}
}

// TestRESTClearSessionsPartialFailureStatus pins the chosen partial-failure
// contract (#3423 FOLD 3): when the local clear succeeds but the peer clear
// fails, the endpoint returns HTTP 200 (NOT a 4xx/5xx) and surfaces the
// failure via failures/failure_summary. The project uses no 207 Multi-Status
// anywhere, so a status-only client would read 200 — the README documents that
// clients MUST inspect failures/failure_summary. A HARD local failure still
// returns 500 (covered by the gRPC ClearSessions error tests).
func TestRESTClearSessionsPartialFailureStatus(t *testing.T) {
	fake := &fakeClusterSessionService{
		clearResp: &pb.ClearSessionsResponse{
			Ipv4Cleared:    2,
			Failures:       1,
			FailureSummary: "peer clear: dial peer node 1: connection refused",
		},
	}
	s := &Server{
		dp:               &clearAllDP{Manager: dataplane.New()},
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.clearSessionsHandler(rr, httptest.NewRequest("POST", "/api/v1/security/sessions/clear", nil))
	if rr.Code != 200 {
		t.Fatalf("partial-failure status = %d, want 200 (documented must-read-failures contract)", rr.Code)
	}
	got := decodeClearResult(t, rr.Body.Bytes())
	if got.Failures != 1 || got.FailureSummary == "" {
		t.Fatalf("partial failure not surfaced on a 200: %+v", got)
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
