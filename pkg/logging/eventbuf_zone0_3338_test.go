package logging

import "testing"

// TestEventFilterZoneZeroSelectable pins the #3338 fix: zone 0 — the
// "unknown" / unassigned zone carried by pre-classification drops,
// host-inbound, and emitted-before-zone-resolution events — must be a
// selectable filter value. Before the fix, EventFilter overloaded Zone==0 as
// "no filter", so a query for the unknown zone silently matched everything and
// the zone-0 events could not be isolated.
//
// FAIL-ON-REVERT: reverting matches() back to `f.Zone != 0` makes the
// HasZone-gated zone-0 filter a no-op (it matches every event), so the
// "want 1" assertion below sees 2 events and the test fails. Reverting
// IsEmpty() back to `f.Zone == 0` flips the IsEmpty assertion red.
func TestEventFilterZoneZeroSelectable(t *testing.T) {
	eb := NewEventBuffer(16)
	eb.Add(EventRecord{Type: "POLICY_DENY", SrcAddr: "unknown-zone", InZone: 0, OutZone: 0})
	eb.Add(EventRecord{Type: "SESSION_OPEN", SrcAddr: "zone-3", InZone: 3, OutZone: 4})

	// A zone-0 filter is a real filter, not "empty".
	f0 := EventFilter{Zone: 0, HasZone: true}
	if f0.IsEmpty() {
		t.Fatal("EventFilter{Zone:0, HasZone:true}.IsEmpty() = true; want false — zone 0 is a real filter")
	}
	got := eb.LatestFiltered(16, f0)
	if len(got) != 1 {
		t.Fatalf("zone-0 filter returned %d events; want exactly 1 (only the unknown-zone event)", len(got))
	}
	if got[0].SrcAddr != "unknown-zone" {
		t.Fatalf("zone-0 filter returned %q; want the unknown-zone (InZone==0) event", got[0].SrcAddr)
	}

	// The zero-value filter is still "empty" (no zone filter set).
	if !(EventFilter{}).IsEmpty() {
		t.Fatal("zero EventFilter.IsEmpty() = false; want true")
	}

	// An unfiltered query must include the zone-0 event (it must not be
	// silently dropped by a default-to-named-zones policy).
	all := eb.Latest(16)
	if len(all) != 2 {
		t.Fatalf("unfiltered Latest returned %d events; want 2", len(all))
	}
	foundZ0 := false
	for _, e := range all {
		if e.InZone == 0 && e.OutZone == 0 {
			foundZ0 = true
		}
	}
	if !foundZ0 {
		t.Fatal("unfiltered Latest did not include the zone-0 (unknown-zone) event")
	}

	// Sanity: a non-zero zone filter still isolates exactly that zone, so the
	// zone-0 behavior above is the sentinel semantics and not a no-op filter.
	got3 := eb.LatestFiltered(16, EventFilter{Zone: 3, HasZone: true})
	if len(got3) != 1 || got3[0].SrcAddr != "zone-3" {
		t.Fatalf("zone-3 filter = %+v; want exactly the zone-3 event", got3)
	}
}
