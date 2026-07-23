package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestGetSessionsRejectsNegativePageSize_5557 pins that GetSessions rejects a
// negative page_size with InvalidArgument, for symmetry with the existing
// Offset<0 guard. req.PageSize is a signed int32; a negative value silently
// fell through the `PageSize > 0` cursor guard into the legacy limit/offset
// path, surfacing bad input as a full page returned as success.
//
// FAIL-ON-REVERT: drop the `req.PageSize < 0` check in GetSessions and the RPC
// falls through to the legacy path, returning a (successful) empty response
// instead of InvalidArgument.
func TestGetSessionsRejectsNegativePageSize_5557(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("PageSize=-1: GetSessions err = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}

	// A non-negative page_size is not rejected by the guard: PageSize=0
	// routes to the legacy path and returns a clean empty response.
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: 0}); err != nil {
		t.Fatalf("PageSize=0: unexpected error %v", err)
	}
}
