package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestMatchPoliciesRejectsMissingZone asserts the #3355 (H06) parity contract:
// the CLI surfaces (show security match-policies / test policy) require BOTH
// from-zone and to-zone; the gRPC MatchPolicies RPC must likewise reject a
// missing zone with InvalidArgument instead of evaluating the empty-string zone
// (which the #3355 defined-zone guard would silently route to the
// default-policy).
//
// FAIL-ON-REVERT: removing the missing-zone guard in MatchPolicies makes these
// cases return a default-policy verdict with no error, failing the want-error
// assertion.
func TestMatchPoliciesRejectsMissingZone(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}

	cases := []struct {
		name string
		req  *pb.MatchPoliciesRequest
	}{
		{"missing from-zone", &pb.MatchPoliciesRequest{ToZone: "untrust"}},
		{"missing to-zone", &pb.MatchPoliciesRequest{FromZone: "trust"}},
		{"both missing", &pb.MatchPoliciesRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.MatchPolicies(context.Background(), tc.req)
			if err == nil {
				t.Fatalf("MatchPolicies(%+v) err = nil, want InvalidArgument; resp = %+v", tc.req, resp)
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("status code = %v, want InvalidArgument", status.Code(err))
			}
			if resp != nil {
				t.Fatalf("resp = %+v, want nil on InvalidArgument", resp)
			}
		})
	}
}
