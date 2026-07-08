package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGetBGPStatusRejectsUnvalidatedNeighborIP proves the #4588 boundary
// guard: GetBGPStatus is reachable over the UNAUTHENTICATED local gRPC
// listener, so a malformed / newline-bearing neighbor "IP" in the request
// Type must be rejected with codes.InvalidArgument BEFORE it is handed to
// the frr wrapper (which would otherwise concatenate it onto the vtysh
// command line). A real frr.Manager is wired so the handler passes the
// s.frr == nil gate; the ParseIP check fires first, so no vtysh shell-out
// happens for the malformed inputs.
//
// On revert (drop the net.ParseIP boundary check), these calls fall
// through to the frr wrappers and no longer return InvalidArgument.
func TestGetBGPStatusRejectsUnvalidatedNeighborIP(t *testing.T) {
	s := &Server{frr: frr.New()}

	bad := []string{
		"received-routes:1.1.1.1\nconfigure terminal",
		"received-routes:not-an-ip",
		"received-routes:", // empty
		"advertised-routes:1.1.1.1\nno router bgp 65000",
		"advertised-routes:garbage",
		"neighbor:1.1.1.1\nconfigure terminal",
		"neighbor:bogus",
	}
	for _, typ := range bad {
		resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: typ})
		if err == nil {
			t.Errorf("GetBGPStatus(%q): expected InvalidArgument, got nil (resp=%v)", typ, resp)
			continue
		}
		if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
			t.Errorf("GetBGPStatus(%q): code = %v, want InvalidArgument (err=%v)", typ, st.Code(), err)
		}
	}
}

// TestGetBGPStatusNeighborAllStillWorks proves the boundary guard does not
// break the legitimate "all neighbors" selectors: req.Type == "neighbor"
// and "neighbor:" (empty ip) must NOT be rejected as InvalidArgument
// (they select every neighbor). They reach the frr wrapper, which shells
// out to vtysh — in CI that returns codes.Internal (no vtysh binary), NOT
// InvalidArgument. The distinction is what this test asserts (#4588).
func TestGetBGPStatusNeighborAllStillWorks(t *testing.T) {
	s := &Server{frr: frr.New()}
	for _, typ := range []string{"neighbor", "neighbor:"} {
		_, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: typ})
		if st, _ := status.FromError(err); st.Code() == codes.InvalidArgument {
			t.Errorf("GetBGPStatus(%q): must not be rejected as InvalidArgument (all-neighbors selector)", typ)
		}
	}
}
