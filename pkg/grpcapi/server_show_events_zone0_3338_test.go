package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

// TestGetEventsZoneZeroSelectableWithHasZone pins the #3338 fix on the gRPC
// surface: with has_zone=true, a zone=0 request isolates the zone-0 (unknown /
// unassigned) events instead of being swallowed by the legacy "zone 0 = no
// filter" sentinel. An unfiltered query still includes them, and the legacy
// bare zone=0 (has_zone=false) stays match-all for backward compatibility
// (the #3334 contract).
//
// FAIL-ON-REVERT: reverting GetEvents back to EventFilter{Zone: uint16(req.Zone)}
// (dropping HasZone) makes the has_zone=true + zone=0 request a no-op filter
// that returns both events, so the "want 1" assertion fails.
func TestGetEventsZoneZeroSelectableWithHasZone(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "POLICY_DENY", SrcAddr: "z0", InZone: 0, OutZone: 0})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "z3", InZone: 3, OutZone: 4})
	s := &Server{eventBuf: eb}

	// has_zone=true + zone=0 selects only the unknown-zone event.
	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 0, HasZone: true})
	if err != nil {
		t.Fatalf("GetEvents(zone=0, has_zone=true) = %v; want success", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("GetEvents(zone=0, has_zone=true) returned %d events; want exactly 1 (the zone-0 event)", len(resp.Events))
	}
	if resp.Events[0].SrcAddr != "z0" {
		t.Fatalf("GetEvents(zone=0, has_zone=true) returned %q; want the zone-0 event", resp.Events[0].SrcAddr)
	}

	// Backward compatibility: a bare zone=0 (has_zone unset) is still
	// match-all (#3334) — it must include the zone-0 event, not filter on it.
	resp0, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 0})
	if err != nil {
		t.Fatalf("GetEvents(zone=0) = %v; want success", err)
	}
	if len(resp0.Events) != 2 {
		t.Fatalf("GetEvents(zone=0) returned %d events; want 2 (no-filter match-all, including zone 0)", len(resp0.Events))
	}

	// Sanity: a non-zero zone still filters with has_zone unset.
	resp3, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{Zone: 3})
	if err != nil {
		t.Fatalf("GetEvents(zone=3) = %v; want success", err)
	}
	if len(resp3.Events) != 1 || resp3.Events[0].SrcAddr != "z3" {
		t.Fatalf("GetEvents(zone=3) = %v; want exactly the zone-3 event", resp3.Events)
	}
}
