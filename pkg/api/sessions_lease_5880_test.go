package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// leaseProbeCluster is a ClusterSessionService that models the in-process gRPC
// session service: its GetSessions re-enters the SAME session-walk limiter via
// AcquireCtx (exactly as the real grpcapi.Server.GetSessions now does). With the
// REST boundary's admission lease propagated on ctx it reuses the slot; without
// it, at capacity 1, it self-rejects — the #5880 double-acquire.
type leaseProbeCluster struct {
	admitted   bool
	selfReject bool
}

func (c *leaseProbeCluster) GetSessions(ctx context.Context, _ *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		c.selfReject = true
		return nil, err
	}
	defer release()
	c.admitted = true
	// A non-nil Peer makes writeSessionList attach the peer set, so the REST
	// response observably proves the delegation succeeded end-to-end.
	return &pb.GetSessionsResponse{Peer: &pb.GetSessionsResponse{NodeId: 1}}, nil
}

func (c *leaseProbeCluster) ClearSessions(context.Context, *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	return &pb.ClearSessionsResponse{}, nil
}
func (c *leaseProbeCluster) GetSessionSummary(context.Context, *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error) {
	return &pb.GetSessionSummaryResponse{}, nil
}
func (c *leaseProbeCluster) GetZonePairSummary(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
	return &pb.GetZonePairSummaryResponse{}, nil
}

// #5968: the REST include_peer list now delegates to PeerSessions (peer view
// only, no redundant local walk). It re-enters the SAME limiter via AcquireCtx
// exactly as GetSessions did, so this probe keeps modelling the #5880
// double-acquire faithfully — the delegation target changed, the admission
// contract under test did not. Had the peer-only path skipped admission, this
// guard would have gone vacuous without failing.
func (c *leaseProbeCluster) PeerSessions(ctx context.Context, _ *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	release, _, err := sessionWalkLimiter.AcquireCtx(ctx)
	if err != nil {
		c.selfReject = true
		return nil, err
	}
	defer release()
	c.admitted = true
	return &pb.GetSessionsResponse{Peer: &pb.GetSessionsResponse{NodeId: 1}}, nil
}

func (c *leaseProbeCluster) PeerSessionSummary(context.Context) (*pb.GetSessionSummaryResponse, error) {
	return &pb.GetSessionSummaryResponse{}, nil
}

func (c *leaseProbeCluster) PeerZonePairSummary(context.Context) (*pb.GetZonePairSummaryResponse, error) {
	return &pb.GetZonePairSummaryResponse{}, nil
}

// TestRESTIncludePeerReusesLease_5880 proves a REST include_peer list at
// capacity 1 SUCCEEDS: the REST handler acquires the one slot, stamps the
// in-process admission lease on the request context, and the include_peer
// delegation to the in-process session service REUSES that slot rather than
// self-rejecting. The peer set is attached in the response.
//
// FAIL-ON-REVERT: drop the `r = r.WithContext(walkCtx)` re-stamp in
// sessionsHandler → the delegation runs on an unstamped context → the probe's
// AcquireCtx finds no lease, tries to acquire at capacity 1 (the REST slot is
// held), gets ErrBusy → selfReject=true, the peer is not attached → RED.
func TestRESTIncludePeerReusesLease_5880(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	defer func() { sessionWalkLimiter = orig }()

	probe := &leaseProbeCluster{}
	dp := &cancelCountDP{Manager: dataplane.New(), nV4: 0} // loaded, empty local table
	s := &Server{
		dp:               dp,
		clusterSessionFn: func() ClusterSessionService { return probe },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?include_peer=true", nil)
	s.sessionsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("REST include_peer at cap 1 returned HTTP %d, want 200 (self-reject regression): %s",
			rr.Code, rr.Body.String())
	}
	if probe.selfReject {
		t.Fatalf("in-process delegate self-rejected at cap 1 — the REST admission lease was NOT " +
			"propagated to the include_peer fan-out (#5880 double-acquire)")
	}
	if !probe.admitted {
		t.Fatalf("in-process delegate was never invoked/admitted")
	}

	// The handler wraps the list in {"success":true,"data":{...}}.
	var env struct {
		Success bool                `json:"success"`
		Data    SessionListResponse `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode REST body: %v", err)
	}
	if env.Data.Peer == nil {
		t.Fatalf("peer sessions not attached — the include_peer fan-out was rejected under the limiter")
	}
}

// TestRESTConcurrentDistinctRequestsBounded_5880 confirms the lease is
// per-request-graph, not a global disable: two DISTINCT external REST list
// requests at capacity 1 cannot both hold the slot — one is rejected with HTTP
// 429 while the other holds it. (A leaked global lease would let the second in.)
func TestRESTConcurrentDistinctRequestsBounded_5880(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	defer func() { sessionWalkLimiter = orig }()

	// Hold the single slot to simulate one in-flight distinct request.
	release, _, err := sessionWalkLimiter.AcquireCtx(context.Background())
	if err != nil {
		t.Fatalf("prime acquire: %v", err)
	}
	defer release()

	s := &Server{dp: &cancelCountDP{Manager: dataplane.New(), nV4: 0}}
	rr := httptest.NewRecorder()
	// A SECOND distinct external request (fresh context, no lease) must be
	// rejected — the limiter is at capacity.
	s.sessionsHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil))

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second distinct request at cap 1 returned HTTP %d, want 429 "+
			"(the lease must not globally open the limiter)", rr.Code)
	}
}
