package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGetEventsRejectsOutOfRangeZone pins the #3334 fix: GetEvents must reject
// a zone filter above the uint16 range with InvalidArgument instead of
// narrowing it via an unchecked uint16() cast. Before the fix, 65536 wrapped
// to 0 (no filter) and 65537 wrapped to zone 1, so the RPC returned the wrong
// events. RED-on-revert: with the unchecked cast restored, these requests
// succeed (err == nil) and the test fails.
func TestGetEventsRejectsOutOfRangeZone(t *testing.T) {
	s := &Server{eventBuf: logging.NewEventBuffer(16)}

	// 65536 wraps to zone 0 (no filter), 65537 wraps to zone 1 under an
	// unchecked uint16() cast — both must be rejected instead.
	for _, z := range []uint32{65536, 65537} {
		resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: z})
		if err == nil {
			t.Fatalf("GetEvents(zone=%d) = nil error; want InvalidArgument (zone wrapped to %d instead of being rejected)", z, uint16(z))
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("GetEvents(zone=%d) code = %v; want InvalidArgument", z, status.Code(err))
		}
		if resp != nil {
			t.Fatalf("GetEvents(zone=%d) returned non-nil response alongside error", z)
		}
	}

	// An in-range zone filter must still be accepted (no over-rejection).
	if _, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 65535}); err != nil {
		t.Fatalf("GetEvents(zone=65535) = %v; want success for an in-range zone id", err)
	}
	if _, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 0}); err != nil {
		t.Fatalf("GetEvents(zone=0) = %v; want success", err)
	}
}
