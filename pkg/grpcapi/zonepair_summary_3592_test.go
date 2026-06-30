// #3592: GetZonePairSummary is the gRPC zone-pair-summary RPC the REST
// /sessions/summary/zone-pairs endpoint forwards to for include_peer cross-node
// fan-out. These tests pin the local breakdown, the include_peer peer fan-out,
// and the x-peer-forwarded recursion guard (mirroring GetSessionSummary +
// ClearSessions).
package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// twoZonePairDP yields two forward sessions (one TCP, one UDP) across the same
// zone pair (ingress 2 -> egress 3) plus a reverse entry that must be ignored,
// so the aggregation and protocol-class breakdown are exercised. No config is
// loaded, so zone names fall back to the synthetic "zone-N" form.
type twoZonePairDP struct {
	*dataplane.Manager
}

func (d *twoZonePairDP) IsLoaded() bool { return true }

func (d *twoZonePairDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	// Forward TCP.
	fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{IsReverse: 0, IngressZone: 2, EgressZone: 3})
	// Forward UDP, same zone pair.
	fn(dataplane.SessionKey{Protocol: 17}, dataplane.SessionValue{IsReverse: 0, IngressZone: 2, EgressZone: 3})
	// Reverse entry — must NOT be counted.
	fn(dataplane.SessionKey{Protocol: 6}, dataplane.SessionValue{IsReverse: 1, IngressZone: 3, EgressZone: 2})
	return nil
}

func (d *twoZonePairDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func newZonePairServer(t *testing.T, dp grpcRuntime) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
	}
}

// TestGetZonePairSummaryLocalBreakdown asserts the local aggregation: forward
// sessions are counted by zone pair and protocol class, the reverse entry is
// skipped, and the result is sorted.
func TestGetZonePairSummaryLocalBreakdown(t *testing.T) {
	s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})

	resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if len(resp.ZonePairs) != 1 {
		t.Fatalf("zone pairs = %d, want 1 (both forward sessions share one pair)", len(resp.ZonePairs))
	}
	zp := resp.ZonePairs[0]
	if zp.FromZone != "zone-2" || zp.ToZone != "zone-3" {
		t.Fatalf("zone pair = %s->%s, want zone-2->zone-3", zp.FromZone, zp.ToZone)
	}
	if zp.Tcp != 1 || zp.Udp != 1 || zp.Total != 2 {
		t.Fatalf("breakdown = tcp %d udp %d total %d, want 1/1/2 (reverse entry must be skipped)", zp.Tcp, zp.Udp, zp.Total)
	}
	if resp.Peer != nil {
		t.Fatal("peer set without include_peer")
	}
}

// TestGetZonePairSummaryFailsOnIteratorError asserts a backend iterator error
// fails the RPC (codes.Internal) rather than returning a partial breakdown as a
// healthy response (#2469), matching GetSessionSummary.
func TestGetZonePairSummaryFailsOnIteratorError(t *testing.T) {
	dp := &viewFaultGRPCDP{
		Manager: dataplane.New(),
		iterErr: errors.New("helper restart: session map closed"),
	}
	s := newZonePairServer(t, dp)

	_, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}

// TestGetZonePairSummaryFansOutToPeer asserts include_peer=true forwards to the
// peer via the proxy seam, stamps x-peer-forwarded on the outgoing request, and
// attaches the peer's breakdown under resp.Peer.
//
// FAIL-ON-REVERT: dropping the include_peer fan-out leaves resp.Peer nil;
// dropping the x-peer-forwarded stamp in proxyPeerZonePairSummary flips the
// forwarded assertion.
func TestGetZonePairSummaryFansOutToPeer(t *testing.T) {
	s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})

	var fwd bool
	var peerIncludePeer bool
	s.peerZonePairSummaryFn = func(ctx context.Context, req *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
		md, ok := metadata.FromOutgoingContext(ctx)
		fwd = ok && len(md.Get("x-peer-forwarded")) > 0
		peerIncludePeer = req.GetIncludePeer()
		return &pb.GetZonePairSummaryResponse{
			NodeId:    1,
			ZonePairs: []*pb.ZonePairSessionSummary{{FromZone: "trust", ToZone: "untrust", Tcp: 5, Total: 5}},
		}, nil
	}

	resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if !fwd {
		t.Fatal("peer request did not carry x-peer-forwarded metadata (recursion guard not stamped)")
	}
	if peerIncludePeer {
		t.Fatal("peer request carried include_peer=true — would recurse")
	}
	if resp.Peer == nil || resp.Peer.NodeId != 1 || len(resp.Peer.ZonePairs) != 1 {
		t.Fatalf("peer breakdown not attached: %+v", resp.Peer)
	}
}

// TestGetZonePairSummaryHonorsRecursionGuard asserts a request that ITSELF
// carries x-peer-forwarded (i.e. it arrived from the peer) does NOT fan out
// again, even with include_peer=true — preventing A->B->A recursion.
//
// FAIL-ON-REVERT: removing the !peerForwardedFromContext(ctx) guard in
// GetZonePairSummary makes the forwarded request invoke the peer fn, flipping
// this red.
func TestGetZonePairSummaryHonorsRecursionGuard(t *testing.T) {
	s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})

	called := false
	s.peerZonePairSummaryFn = func(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
		called = true
		return &pb.GetZonePairSummaryResponse{}, nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-peer-forwarded", "1"))
	resp, err := s.GetZonePairSummary(ctx, &pb.GetZonePairSummaryRequest{IncludePeer: true})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if called {
		t.Fatal("forwarded request fanned out to the peer again (recursion guard not honored)")
	}
	if resp.Peer != nil {
		t.Fatal("forwarded request attached a peer breakdown")
	}
}

// TestGetZonePairSummaryNoFanOutWithoutIncludePeer asserts the peer leg is not
// taken when include_peer is unset.
func TestGetZonePairSummaryNoFanOutWithoutIncludePeer(t *testing.T) {
	s := newZonePairServer(t, &twoZonePairDP{Manager: dataplane.New()})
	called := false
	s.peerZonePairSummaryFn = func(context.Context, *pb.GetZonePairSummaryRequest) (*pb.GetZonePairSummaryResponse, error) {
		called = true
		return &pb.GetZonePairSummaryResponse{}, nil
	}
	if _, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{}); err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if called {
		t.Fatal("peer fetched without include_peer")
	}
}

// TestGetZonePairSummaryNodeIDFromCluster asserts the local node id is stamped
// from the cluster manager.
func TestGetZonePairSummaryNodeIDFromCluster(t *testing.T) {
	s := &Server{
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:      &twoZonePairDP{Manager: dataplane.New()},
		cluster: cluster.NewManager(1, 1),
	}
	resp, err := s.GetZonePairSummary(context.Background(), &pb.GetZonePairSummaryRequest{})
	if err != nil {
		t.Fatalf("GetZonePairSummary() error = %v", err)
	}
	if resp.NodeId != 1 {
		t.Fatalf("node_id = %d, want 1 (from cluster manager)", resp.NodeId)
	}
}
