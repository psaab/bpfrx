package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

func decodeZonePairs(t *testing.T, body []byte) ZonePairSummaryResponse {
	t.Helper()
	var resp struct {
		Success bool                    `json:"success"`
		Data    ZonePairSummaryResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode zone-pairs response: %v; body=%s", err, body)
	}
	return resp.Data
}

// TestRESTZonePairsIncludePeer is the #3592 contract for the zone-pair summary
// endpoint: it gains include_peer cross-node fan-out matching its
// /sessions/summary sibling. Without include_peer the handler reports the LOCAL
// breakdown only (peer service untouched). With include_peer=true it forwards
// to the new gRPC GetZonePairSummary RPC (IncludePeer set) and attaches the
// cluster peer's OWN breakdown under the nested `peer` field. node_id stamping
// is preserved on both the local response and the peer.
//
// FAIL-ON-REVERT: dropping the include_peer fan-out in sessionZonePairHandler
// leaves resp.Peer nil and never calls the cluster service, flipping the
// peer-attached assertions red; dropping node_id stamping makes NodeID 0.
func TestRESTZonePairsIncludePeer(t *testing.T) {
	newFake := func() *fakeClusterSessionService {
		return &fakeClusterSessionService{
			zpResp: &pb.GetZonePairSummaryResponse{
				NodeId: 7, // local node's view as the gRPC server would report it
				Peer: &pb.GetZonePairSummaryResponse{
					NodeId: 8,
					ZonePairs: []*pb.ZonePairSessionSummary{{
						FromZone: "trust",
						ToZone:   "untrust",
						Tcp:      3,
						Udp:      1,
						Total:    4,
					}},
				},
			},
		}
	}

	// Without include_peer: local breakdown only, peer service NOT called.
	fake := newFake()
	s := &Server{
		dp:               &oneSessionDP{Manager: dataplane.New()},
		eventBuf:         logging.NewEventBuffer(8),
		nodeIDFn:         func() int { return 7 },
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary/zone-pairs", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp := decodeZonePairs(t, rr.Body.Bytes())
	if resp.NodeID != 7 {
		t.Fatalf("node_id = %d, want 7 (which-node identity missing)", resp.NodeID)
	}
	if resp.Peer != nil {
		t.Fatal("zone-pairs peer set without include_peer")
	}
	if fake.peerZPCalled || fake.zpCalled {
		t.Fatal("peer zone-pair summary fetched without include_peer")
	}
	// The local breakdown from oneSessionDP is a single zone-2 -> zone-3 TCP row.
	if len(resp.ZonePairs) != 1 || resp.ZonePairs[0].TCP != 1 {
		t.Fatalf("local zone-pairs = %+v, want one TCP row", resp.ZonePairs)
	}

	// With include_peer=true: peer breakdown attached via the HA-aware service.
	fake = newFake()
	s.clusterSessionFn = func() ClusterSessionService { return fake }
	rr = httptest.NewRecorder()
	s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary/zone-pairs?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("include_peer status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	resp = decodeZonePairs(t, rr.Body.Bytes())
	// #5968: delegated to PeerZonePairSummary, which takes no request.
	if !fake.peerZPCalled {
		t.Fatal("include_peer=true did not fetch the peer zone-pair summary via the HA-aware service")
	}
	if resp.NodeID != 7 {
		t.Fatalf("local node_id = %d, want 7", resp.NodeID)
	}
	if resp.Peer == nil {
		t.Fatal("include_peer=true did not attach the peer zone-pair breakdown")
	}
	if resp.Peer.NodeID != 8 {
		t.Fatalf("peer node_id = %d, want 8", resp.Peer.NodeID)
	}
	if len(resp.Peer.ZonePairs) != 1 {
		t.Fatalf("peer zone-pairs = %d rows, want 1", len(resp.Peer.ZonePairs))
	}
	zp := resp.Peer.ZonePairs[0]
	if zp.FromZone != "trust" || zp.ToZone != "untrust" || zp.TCP != 3 || zp.UDP != 1 || zp.Total != 4 {
		t.Fatalf("peer zone-pair row = %+v, want trust->untrust tcp=3 udp=1 total=4", zp)
	}
}

// TestRESTZonePairsIncludePeerInvalid asserts the zone-pair endpoint fails
// closed on a malformed include_peer value (HTTP 400) rather than silently
// ignoring the opt-in (#3592), matching /sessions and /sessions/summary.
func TestRESTZonePairsIncludePeerInvalid(t *testing.T) {
	s := &Server{
		dp:       &oneSessionDP{Manager: dataplane.New()},
		eventBuf: logging.NewEventBuffer(8),
	}
	rr := httptest.NewRecorder()
	s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary/zone-pairs?include_peer=bogus", nil))
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400 (malformed include_peer not rejected)", rr.Code)
	}
}

// TestRESTZonePairsPeerNotFetchedWhenServiceNil asserts a standalone build (no
// HA-aware service wired) returns the local breakdown with no peer even when
// include_peer=true — the pre-#3592 behavior is preserved when there is no
// cluster service.
func TestRESTZonePairsPeerNotFetchedWhenServiceNil(t *testing.T) {
	s := &Server{
		dp:       &oneSessionDP{Manager: dataplane.New()},
		eventBuf: logging.NewEventBuffer(8),
		nodeIDFn: func() int { return 0 },
		// no clusterSessionFn wired
	}
	rr := httptest.NewRecorder()
	s.sessionZonePairHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions/summary/zone-pairs?include_peer=true", nil))
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if resp := decodeZonePairs(t, rr.Body.Bytes()); resp.Peer != nil {
		t.Fatal("standalone build attached a peer breakdown without a cluster service")
	}
}
