package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestSystemActionClusterFailoverProxiesPeerTarget(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	var gotAction string
	var forwarded bool
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		gotAction = req.Action
		md, ok := metadata.FromOutgoingContext(ctx)
		forwarded = ok && len(md.Get("x-peer-forwarded")) > 0
		return &pb.SystemActionResponse{Message: "proxied"}, nil
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if gotAction != "cluster-failover:1:node1" {
		t.Fatalf("proxied action = %q, want %q", gotAction, "cluster-failover:1:node1")
	}
	if !forwarded {
		t.Fatal("expected x-peer-forwarded metadata on proxied system action")
	}
	if resp.Message != "proxied" {
		t.Fatalf("response = %q, want %q", resp.Message, "proxied")
	}
}

func TestSystemActionClusterFailoverRejectsForwardLoop(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-peer-forwarded", "1"))
	_, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.FailedPrecondition, err)
	}
}

func TestSystemActionClusterFailoverDataProxiesPeerTarget(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	var gotAction string
	var forwarded bool
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		gotAction = req.Action
		md, ok := metadata.FromOutgoingContext(ctx)
		forwarded = ok && len(md.Get("x-peer-forwarded")) > 0
		return &pb.SystemActionResponse{Message: "proxied-data"}, nil
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if gotAction != "cluster-failover-data:node1" {
		t.Fatalf("proxied action = %q, want %q", gotAction, "cluster-failover-data:node1")
	}
	if !forwarded {
		t.Fatal("expected x-peer-forwarded metadata on proxied system action")
	}
	if resp.Message != "proxied-data" {
		t.Fatalf("response = %q, want %q", resp.Message, "proxied-data")
	}
}

func TestSystemActionClusterFailoverDataRejectsForwardLoop(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-peer-forwarded", "1"))
	_, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover-data:node1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.FailedPrecondition, err)
	}
}

func TestSystemActionClusterFailoverDataRejectsUnsupportedTargetNode(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node2"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.InvalidArgument, err)
	}
}
