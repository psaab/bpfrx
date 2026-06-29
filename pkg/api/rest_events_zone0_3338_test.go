package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/logging"
)

func decodeEvents(t *testing.T, body []byte) []EventEntry {
	t.Helper()
	var resp struct {
		Success bool         `json:"success"`
		Data    []EventEntry `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode events response: %v; body=%s", err, body)
	}
	return resp.Data
}

// TestRESTEventsZoneZeroSelectable pins the #3338 fix on the REST surface: the
// zone 0 (unknown / unassigned) events must be selectable via ?zone=0 and the
// word sentinels ?zone=unknown / ?zone=none, and an unfiltered query must still
// include them.
//
// FAIL-ON-REVERT: reverting eventsHandler back to queryUint16Strict(r,"zone",0)
// + EventFilter{Zone: zone} makes ?zone=0 collapse to the old "no filter"
// sentinel (returns both events, so the "want 1" assertion fails) and makes
// ?zone=unknown / ?zone=none a parse error → HTTP 400 (so the want-200 +
// want-1 assertions fail).
func TestRESTEventsZoneZeroSelectable(t *testing.T) {
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "POLICY_DENY", SrcAddr: "10.0.0.9:1", InZone: 0, OutZone: 0})
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", SrcAddr: "10.0.0.3:1", InZone: 3, OutZone: 4})
	s := &Server{eventBuf: eb}

	for _, z := range []string{"0", "unknown", "none", "UNKNOWN"} {
		rr := httptest.NewRecorder()
		s.eventsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/events?zone="+z, nil))
		if rr.Code != 200 {
			t.Fatalf("events?zone=%s status = %d; want 200; body=%s", z, rr.Code, rr.Body.String())
		}
		evs := decodeEvents(t, rr.Body.Bytes())
		if len(evs) != 1 {
			t.Fatalf("events?zone=%s returned %d events; want exactly 1 (the unknown-zone event)", z, len(evs))
		}
		if evs[0].InZone != 0 || evs[0].OutZone != 0 {
			t.Fatalf("events?zone=%s returned ingress/egress zone %d/%d; want 0/0", z, evs[0].InZone, evs[0].OutZone)
		}
	}

	// Unfiltered query must include the zone-0 event.
	rr := httptest.NewRecorder()
	s.eventsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/events", nil))
	if rr.Code != 200 {
		t.Fatalf("unfiltered events status = %d; want 200", rr.Code)
	}
	evs := decodeEvents(t, rr.Body.Bytes())
	if len(evs) != 2 {
		t.Fatalf("unfiltered events returned %d; want 2 (both zones, including zone 0)", len(evs))
	}

	// Sanity: a non-zero zone filter isolates exactly that zone.
	rr3 := httptest.NewRecorder()
	s.eventsHandler(rr3, httptest.NewRequest("GET", "/api/v1/security/events?zone=3", nil))
	evs3 := decodeEvents(t, rr3.Body.Bytes())
	if len(evs3) != 1 || evs3[0].InZone != 3 {
		t.Fatalf("events?zone=3 = %+v; want exactly the zone-3 event", evs3)
	}
}
