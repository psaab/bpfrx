package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #4693: the cluster-failover:<rgID>:node<N> handler branch must validate the
// node ID via cluster.IsSupportedClusterNodeID (the two-chassis 0/1 range)
// before the local/proxy routing decision, mirroring the sibling
// cluster-failover-data:node branch and the #4125 fabric-gate class. Without
// it, a local caller's node99 request (node99 != local NodeID) fell through to
// the outbound peer proxy-dial path instead of being rejected.
//
// RED-on-revert: removing the IsSupportedClusterNodeID check lets node99 reach
// proxyPeerSystemAction, which (no peerSystemActionFn wired, no reachable peer)
// returns a non-InvalidArgument error and this InvalidArgument assertion fires
// RED.
func TestSystemActionClusterFailoverRejectsUnsupportedTargetNode(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	// Fail the test loudly if the request ever reaches the peer proxy path:
	// a rejected node ID must never drive a proxy dial.
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		t.Fatalf("proxy dial attempted for unsupported node in action %q", req.Action)
		return nil, nil
	}

	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node99"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.InvalidArgument, err)
	}
}
