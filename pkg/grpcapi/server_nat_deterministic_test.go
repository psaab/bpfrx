// FAIL-ON-REVERT: the GetNATDeterministic RPC must resolve the deterministic
// source-NAT forward (subscriber -> translated IPv4 + port block) AND reverse
// (translated IPv4 + port -> subscriber) mapping from the LAST-APPLIED NAT
// generation (#5794). Reverting the handler wiring (so it no longer calls
// pkg/nat.LookupForward/LookupReverse against the applied view) makes the
// forward/reverse assertions below go RED. The golden values match the Rust
// dataplane allocator vectors (userspace-dp/src/nat/tests_pool.rs).
package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/nat"
)

// appliedViewGRPCDP is a loaded DP that returns a fixed applied NAT view for
// the deterministic-mapping lookup. It embeds *dataplane.Manager to satisfy
// the rest of grpcRuntime.
type appliedViewGRPCDP struct {
	*dataplane.Manager
	view dpuserspace.AppliedNATView
}

func (d *appliedViewGRPCDP) IsLoaded() bool                             { return true }
func (d *appliedViewGRPCDP) AppliedNATView() dpuserspace.AppliedNATView { return d.view }

func deterministicV4AppliedView(gen uint64) dpuserspace.AppliedNATView {
	pool := &config.NATPool{
		Name:      "cgn-pool",
		Addresses: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/22",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"cgn-pool": pool}
	return dpuserspace.AppliedNATView{Config: cfg, AppliedGeneration: gen, Available: true}
}

func TestGetNATDeterministicForwardReverse(t *testing.T) {
	s := &Server{dp: &appliedViewGRPCDP{
		Manager: dataplane.New(),
		view:    deterministicV4AppliedView(11),
	}}

	// Forward: subscriber 100.64.0.5 -> 203.0.113.1, block [3584, 4095].
	fwd, err := s.GetNATDeterministic(context.Background(), &pb.GetNATDeterministicRequest{
		Direction:    pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD,
		Pool:         "cgn-pool",
		InternalHost: "100.64.0.5",
	})
	if err != nil {
		t.Fatalf("forward RPC error: %v", err)
	}
	if !fwd.Found {
		t.Fatalf("forward: expected found, got error_code=%q detail=%q", fwd.ErrorCode, fwd.ErrorDetail)
	}
	if fwd.ExternalIp != "203.0.113.1" || fwd.PortLow != 3584 || fwd.PortHigh != 4095 ||
		fwd.BlockSize != 512 || fwd.Mode != 1 || fwd.AppliedGeneration != 11 {
		t.Fatalf("forward result mismatch: %+v", fwd)
	}

	// Reverse: 203.0.113.1:3900 (inside block 5) -> subscriber 100.64.0.5.
	rev, err := s.GetNATDeterministic(context.Background(), &pb.GetNATDeterministicRequest{
		Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE,
		Pool:      "cgn-pool",
		NatIp:     "203.0.113.1",
		NatPort:   3900,
	})
	if err != nil {
		t.Fatalf("reverse RPC error: %v", err)
	}
	if !rev.Found {
		t.Fatalf("reverse: expected found, got error_code=%q detail=%q", rev.ErrorCode, rev.ErrorDetail)
	}
	if rev.InternalHost != "100.64.0.5" || rev.ExternalIp != "203.0.113.1" || rev.NatPort != 3900 ||
		rev.PortLow != 3584 || rev.PortHigh != 4095 || rev.AppliedGeneration != 11 {
		t.Fatalf("reverse result mismatch: %+v", rev)
	}
}

// TestGetNATDeterministicNoAppliedView asserts the RPC fails closed with the
// stable no-applied-view code when the dataplane has applied nothing.
func TestGetNATDeterministicNoAppliedView(t *testing.T) {
	s := &Server{dp: &appliedViewGRPCDP{
		Manager: dataplane.New(),
		view:    dpuserspace.AppliedNATView{Available: false},
	}}
	resp, err := s.GetNATDeterministic(context.Background(), &pb.GetNATDeterministicRequest{
		Direction:    pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD,
		Pool:         "cgn-pool",
		InternalHost: "100.64.0.5",
	})
	if err != nil {
		t.Fatalf("RPC error: %v", err)
	}
	if resp.Found || resp.ErrorCode != nat.ErrCodeNoAppliedView {
		t.Fatalf("expected no-applied-view, got found=%v code=%q", resp.Found, resp.ErrorCode)
	}
}

// TestGetNATDeterministicErrors covers the stable error codes surfaced in the
// response body.
func TestGetNATDeterministicErrors(t *testing.T) {
	s := &Server{dp: &appliedViewGRPCDP{
		Manager: dataplane.New(),
		view:    deterministicV4AppliedView(1),
	}}
	cases := []struct {
		name string
		req  *pb.GetNATDeterministicRequest
		want string
	}{
		{"unknown-pool", &pb.GetNATDeterministicRequest{
			Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD,
			Pool:      "nope", InternalHost: "100.64.0.5"}, nat.ErrCodeUnknownPool},
		{"malformed", &pb.GetNATDeterministicRequest{
			Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD,
			Pool:      "cgn-pool", InternalHost: "bogus"}, nat.ErrCodeMalformedInput},
		{"out-of-range", &pb.GetNATDeterministicRequest{
			Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_FORWARD,
			Pool:      "cgn-pool", InternalHost: "100.64.4.0"}, nat.ErrCodeOutOfRange},
		{"reverse-not-found", &pb.GetNATDeterministicRequest{
			Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE,
			Pool:      "cgn-pool", NatIp: "192.0.2.1", NatPort: 3584}, nat.ErrCodeNotFound},
		{"port-overflow", &pb.GetNATDeterministicRequest{
			Direction: pb.NATDeterministicDirection_NAT_DETERMINISTIC_DIRECTION_REVERSE,
			Pool:      "cgn-pool", NatIp: "203.0.113.1", NatPort: 70000}, nat.ErrCodeMalformedInput},
		{"no-direction", &pb.GetNATDeterministicRequest{
			Pool: "cgn-pool", InternalHost: "100.64.0.5"}, nat.ErrCodeMalformedInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.GetNATDeterministic(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("RPC error: %v", err)
			}
			if resp.Found || resp.ErrorCode != tc.want {
				t.Fatalf("expected code %q, got found=%v code=%q", tc.want, resp.Found, resp.ErrorCode)
			}
		})
	}
}
