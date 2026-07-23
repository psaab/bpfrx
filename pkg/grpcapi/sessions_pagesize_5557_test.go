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

// TestGetSessionsRejectsNegativeLimit_5557 pins that GetSessions rejects a
// negative limit with InvalidArgument, for symmetry with the Offset<0 and
// PageSize<0 guards (FINDING 3, #6393 review). req.Limit is a signed int32
// consumed only by the legacy path, where `limit <= 0` collapses to the
// default page of 100 — so a NEGATIVE limit silently behaved like the default
// rather than surfacing bad input. limit == 0 stays the legitimate default-100
// sentinel and must NOT be rejected.
//
// FAIL-ON-REVERT: drop the `req.Limit < 0` check in GetSessions and a negative
// limit is quietly coerced to the default page, returning a (successful)
// response instead of InvalidArgument.
func TestGetSessionsRejectsNegativeLimit_5557(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Limit: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Limit=-1: GetSessions err = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}

	// Limit=0 is the default-100 sentinel and must not be rejected.
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Limit: 0}); err != nil {
		t.Fatalf("Limit=0: unexpected error %v", err)
	}
}
