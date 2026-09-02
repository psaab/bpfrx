package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #7294: a failed peer fetch on the session LIST surface must be visible.
//
// THE DEFECT. writeSessionList discarded the error:
//
//	if pr, err := svc.PeerSessions(...); err == nil { ... }
//
// so a refused or failed peer fetch produced HTTP 200 with the peer table
// simply absent. An operator could not tell "the peer has no sessions" from
// "we never asked" — a failure to a value indistinguishable from a legitimate
// result. The summary (sessions.go) and zone-pair surfaces have always
// classified this; the list surface was the one that did not, which is the
// shape that survives review because two of three places look right.
//
// WHY NOW, AND WHY THIS IS INDEPENDENTLY CORRECT. The path is currently
// UNREACHABLE: the REST handler acquires and stamps the session-walk lease
// before delegating, so PeerSessions takes AcquireCtx's lease-reuse arm and
// never returns ErrBusy. #7294 item 3 gives peer-directed work its own budget,
// at which point the REST caller arrives with no REMOTE lease, takes a real
// slot, and can be refused for the first time. But "unreachable today" is a
// property of the current call graph, not a guarantee, and the next change to
// that graph gets no warning — so this is fixed because it is wrong, not
// because item 3 needs it.
//
// A fetch error is also not always a partition: an admission refusal means the
// peer is REACHABLE and we declined to ask. Reporting that as "unreachable"
// sends an operator debugging a fabric problem after a network fault that does
// not exist.

type peerRefusalCluster struct{ err error }

func (c *peerRefusalCluster) GetSessions(context.Context, *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	return &pb.GetSessionsResponse{}, nil
}
func (c *peerRefusalCluster) ClearSessions(context.Context, *pb.ClearSessionsRequest) (*pb.ClearSessionsResponse, error) {
	return &pb.ClearSessionsResponse{}, nil
}
func (c *peerRefusalCluster) GetSessionSummary(context.Context, *pb.GetSessionSummaryRequest) (*pb.GetSessionSummaryResponse, error) {
	return &pb.GetSessionSummaryResponse{}, nil
}
func (c *peerRefusalCluster) GetZonePairSummary(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
	return &pb.GetZonePairSummaryResponse{}, nil
}
func (c *peerRefusalCluster) PeerSessions(context.Context, *pb.GetSessionsRequest) (*pb.GetSessionsResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &pb.GetSessionsResponse{Peer: &pb.GetSessionsResponse{NodeId: 1}}, nil
}
func (c *peerRefusalCluster) PeerSessionSummary(context.Context) (*pb.GetSessionSummaryResponse, error) {
	return &pb.GetSessionSummaryResponse{}, nil
}
func (c *peerRefusalCluster) PeerZonePairSummary(context.Context) (*pb.GetZonePairSummaryResponse, error) {
	return &pb.GetZonePairSummaryResponse{}, nil
}

func listPeerFields(t *testing.T, svc ClusterSessionService, url string) SessionListResponse {
	t.Helper()
	s := &Server{clusterSessionFn: func() ClusterSessionService { return svc }}
	rec := httptest.NewRecorder()
	s.writeSessionList(rec, httptest.NewRequest(http.MethodGet, url, nil), SessionListResponse{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the peer outcome rides IN the body, not the code)", rec.Code)
	}
	var env struct {
		Data SessionListResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	return env.Data
}

func TestPeerListFetchFailureIsVisible7294(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus string
	}{
		{
			// The case item 3 makes reachable.
			name:       "admission refusal is reported as busy, not as a partition",
			err:        status.Error(codes.ResourceExhausted, "session scan concurrency limit reached; retry shortly"),
			wantStatus: "busy",
		},
		{
			// The control on the OTHER side: a real partition must keep
			// saying unreachable, or the fix has simply renamed everything.
			name:       "a genuine fetch failure still reports unreachable",
			err:        errors.New("peer connection refused"),
			wantStatus: "unreachable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := listPeerFields(t, &peerRefusalCluster{err: tc.err},
				"/api/v1/security/sessions?include_peer=true")
			if got.PeerStatus != tc.wantStatus {
				t.Errorf("peer_status = %q, want %q", got.PeerStatus, tc.wantStatus)
			}
			if got.PeerError == "" {
				t.Error("peer_error is empty: the operator is told the fetch failed but not why, " +
					"which is half the information and cannot be acted on")
			}
			if got.Peer != nil {
				t.Error("a failed fetch attached a peer table")
			}
		})
	}
}

// TestPeerListSuccessAndOptOutAreUnchanged7294 is the false-positive control.
// A fix that reports a failure correctly but perturbs the success shape, or
// that starts emitting peer fields on requests that never asked for a peer, is
// an API change wearing the shape of a bug fix.
func TestPeerListSuccessAndOptOutAreUnchanged7294(t *testing.T) {
	ok := listPeerFields(t, &peerRefusalCluster{},
		"/api/v1/security/sessions?include_peer=true")
	if ok.Peer == nil {
		t.Error("a successful fetch did not attach the peer table")
	}
	if ok.PeerStatus != "ok" || ok.PeerError != "" {
		t.Errorf("success reported peer_status=%q peer_error=%q, want \"ok\" and empty",
			ok.PeerStatus, ok.PeerError)
	}

	// No include_peer: the response must be byte-identical to the pre-#7294
	// shape, i.e. carry no peer fields at all.
	optOut := listPeerFields(t, &peerRefusalCluster{},
		"/api/v1/security/sessions")
	if optOut.PeerStatus != "" || optOut.PeerError != "" || optOut.Peer != nil {
		t.Errorf("a request that did not opt in got peer fields: status=%q err=%q peer=%v",
			optOut.PeerStatus, optOut.PeerError, optOut.Peer != nil)
	}
}
