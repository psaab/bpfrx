package monitoriface

import (
	"testing"
	"time"
)

func TestParseTrafficViewArgs(t *testing.T) {
	view, err := ParseTrafficViewArgs([]string{"errors", "avg"})
	if err != nil {
		t.Fatalf("ParseTrafficViewArgs returned error: %v", err)
	}
	if view.Unit != TrafficUnitErrors {
		t.Fatalf("unit = %v, want %v", view.Unit, TrafficUnitErrors)
	}
	if view.Type != TrafficTypeAverage {
		t.Fatalf("type = %v, want %v", view.Type, TrafficTypeAverage)
	}
}

func TestTrafficViewStateHandleKeyCycles(t *testing.T) {
	view := DefaultTrafficViewState()
	if action := view.HandleKey('u'); action != TrafficKeyChanged {
		t.Fatalf("HandleKey('u') = %v, want changed", action)
	}
	if view.Unit != TrafficUnitBits {
		t.Fatalf("unit = %v, want %v", view.Unit, TrafficUnitBits)
	}
	if action := view.HandleKey('t'); action != TrafficKeyChanged {
		t.Fatalf("HandleKey('t') = %v, want changed", action)
	}
	if view.Type != TrafficTypeMax {
		t.Fatalf("type = %v, want %v", view.Type, TrafficTypeMax)
	}
	refreshBefore := view.Refresh
	if action := view.HandleKey('+'); action != TrafficKeyChanged {
		t.Fatalf("HandleKey('+') = %v, want changed", action)
	}
	if view.Refresh != refreshBefore+100*time.Millisecond {
		t.Fatalf("refresh = %v, want %v", view.Refresh, refreshBefore+100*time.Millisecond)
	}
	if action := view.HandleKey('-'); action != TrafficKeyChanged {
		t.Fatalf("HandleKey('-') = %v, want changed", action)
	}
	if view.Refresh != refreshBefore {
		t.Fatalf("refresh = %v, want %v", view.Refresh, refreshBefore)
	}
}

func TestTrafficTrackerValues(t *testing.T) {
	now := time.Now()
	tracker := NewTrafficTracker(now)
	initial := map[string]*Snapshot{
		"wan0": {
			RxBytes:   1_000,
			TxBytes:   2_000,
			RxPkts:    10,
			TxPkts:    20,
			RxErrors:  1,
			TxErrors:  2,
			Timestamp: now,
		},
	}
	next := map[string]*Snapshot{
		"wan0": {
			RxBytes:   3_000,
			TxBytes:   5_000,
			RxPkts:    30,
			TxPkts:    50,
			RxErrors:  4,
			TxErrors:  6,
			Timestamp: now.Add(1 * time.Second),
		},
	}

	tracker.Update(initial)
	tracker.Update(next)

	rxRate, txRate := tracker.valuesFor("wan0", next["wan0"], TrafficViewState{Unit: TrafficUnitBytes, Type: TrafficTypeRate})
	if rxRate != 2_000 || txRate != 3_000 {
		t.Fatalf("rate values = %d/%d, want 2000/3000", rxRate, txRate)
	}

	rxSum, txSum := tracker.valuesFor("wan0", next["wan0"], TrafficViewState{Unit: TrafficUnitPackets, Type: TrafficTypeSum})
	if rxSum != 20 || txSum != 30 {
		t.Fatalf("sum values = %d/%d, want 20/30", rxSum, txSum)
	}

	rxErrMax, txErrMax := tracker.valuesFor("wan0", next["wan0"], TrafficViewState{Unit: TrafficUnitErrors, Type: TrafficTypeMax})
	if rxErrMax != 3 || txErrMax != 4 {
		t.Fatalf("max error values = %d/%d, want 3/4", rxErrMax, txErrMax)
	}
}
