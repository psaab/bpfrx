package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

// histZoneGRPCDP is a minimal dp that exposes a CURRENT-config ZoneIDs map via
// LastApplyResult. It models the post-rename config so the test can prove that
// GetEvents does NOT recompute a historical event's zone name from it.
type histZoneGRPCDP struct {
	*dataplane.Manager
	result *dataplane.ApplyResult
}

func (d *histZoneGRPCDP) IsLoaded() bool { return true }

func (d *histZoneGRPCDP) LastApplyResult() *dataplane.ApplyResult {
	return d.result.Clone()
}

// TestGetEventsPrefersStoredZoneName pins the #3335 fix: a historical event's
// IngressZoneName/EgressZoneName must come from the resolved-at-event-time
// EventRecord.InZoneName/OutZoneName, NOT be recomputed from the current
// config. Zone ID 3 was "trust" when the event fired and is "marketing" after
// a rename/renumber; an old event must still render as "trust".
//
// RED-on-revert: restoring `IngressZoneName: evZoneNames[ev.InZone]` recomputes
// from the current map and renders "marketing"/"sales", failing this test.
func TestGetEventsPrefersStoredZoneName(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	// Event captured under the OLD config: zone 3 = trust, zone 4 = untrust.
	eb.Add(logging.EventRecord{
		Type:        "SESSION_OPEN",
		InZone:      3,
		OutZone:     4,
		InZoneName:  "trust",
		OutZoneName: "untrust",
	})

	// CURRENT config reuses those IDs for different zone names (#3075).
	dp := &histZoneGRPCDP{result: &dataplane.ApplyResult{
		ZoneIDs: map[string]uint16{"marketing": 3, "sales": 4},
	}}
	s := &Server{eventBuf: eb, dp: dp}

	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents = %v; want success", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("GetEvents returned %d events; want 1", len(resp.Events))
	}
	ev := resp.Events[0]
	if ev.IngressZoneName != "trust" {
		t.Errorf("IngressZoneName = %q; want %q (must use the as-of-event stored name, not the renamed current-config name)", ev.IngressZoneName, "trust")
	}
	if ev.EgressZoneName != "untrust" {
		t.Errorf("EgressZoneName = %q; want %q (must use the as-of-event stored name)", ev.EgressZoneName, "untrust")
	}
}

// TestGetEventsFallsBackToCurrentMapForLegacyRecord pins the fallback half of
// #3335: a legacy record with NO stored InZoneName/OutZoneName (a record from
// before the field was populated) still resolves via the current-config map,
// so the fix does not regress display for records that lack the resolved name.
func TestGetEventsFallsBackToCurrentMapForLegacyRecord(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: 3, OutZone: 4}) // no stored names

	dp := &histZoneGRPCDP{result: &dataplane.ApplyResult{
		ZoneIDs: map[string]uint16{"trust": 3, "untrust": 4},
	}}
	s := &Server{eventBuf: eb, dp: dp}

	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents = %v; want success", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("GetEvents returned %d events; want 1", len(resp.Events))
	}
	if got := resp.Events[0].IngressZoneName; got != "trust" {
		t.Errorf("legacy IngressZoneName = %q; want %q (fallback to current map)", got, "trust")
	}
	if got := resp.Events[0].EgressZoneName; got != "untrust" {
		t.Errorf("legacy EgressZoneName = %q; want %q (fallback to current map)", got, "untrust")
	}
}
