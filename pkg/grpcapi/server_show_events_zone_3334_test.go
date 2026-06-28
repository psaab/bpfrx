package grpcapi

import (
	"context"
	"fmt"
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
		// Pin the exact reject message so a future divergence (e.g. the
		// wrong message or a different overflow value) is caught, not just
		// the status code.
		if got, want := status.Convert(err).Message(), fmt.Sprintf("invalid zone id %d", z); got != want {
			t.Fatalf("GetEvents(zone=%d) message = %q; want %q", z, got, want)
		}
		if resp != nil {
			t.Fatalf("GetEvents(zone=%d) returned non-nil response alongside error", z)
		}
	}

	// An in-range zone filter must still be accepted (no over-rejection).
	if _, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 65535}); err != nil {
		t.Fatalf("GetEvents(zone=65535) = %v; want success for an in-range zone id", err)
	}
}

// TestGetEventsZoneZeroIsNoFilter pins the zone-0 sentinel semantics: a Zone:0
// request is "no filter" (match-all), not "filter on zone 0". Seed events from
// two distinct zones and assert BOTH are returned for Zone:0 — checking only
// err==nil would not catch a regression that silently filtered.
func TestGetEventsZoneZeroIsNoFilter(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "session", InZone: 3, OutZone: 4})
	eb.Add(logging.EventRecord{Type: "session", InZone: 7, OutZone: 8})
	s := &Server{eventBuf: eb}

	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 0})
	if err != nil {
		t.Fatalf("GetEvents(zone=0) = %v; want success", err)
	}
	if got := len(resp.Events); got != 2 {
		t.Fatalf("GetEvents(zone=0) returned %d events; want 2 (zone 0 = no filter / match-all)", got)
	}

	// Sanity: an in-range non-zero zone DOES filter, so the match-all above
	// is the sentinel behavior and not an artifact of the filter being a
	// no-op. Only the event whose InZone/OutZone is 3 should match zone 3.
	resp3, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 3})
	if err != nil {
		t.Fatalf("GetEvents(zone=3) = %v; want success", err)
	}
	if got := len(resp3.Events); got != 1 {
		t.Fatalf("GetEvents(zone=3) returned %d events; want 1 (only the zone-3 event matches)", got)
	}
}
