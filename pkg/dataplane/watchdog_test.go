package dataplane

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func TestUpdateHAWatchdog_MapNotLoaded(t *testing.T) {
	m := &Manager{maps: make(map[string]*ebpf.Map)}
	err := m.UpdateHAWatchdog(0, 12345)
	if err == nil {
		t.Fatal("expected error when ha_watchdog map not loaded")
	}
	// #2114 A3: a never-armed (fresh) manager returns the typed gate
	// error at the first REQUIRED registry access; the pre-gate
	// "ha_watchdog map not found" text now appears only on an
	// armed-or-retained manager whose registry lacks the map.
	if !errors.Is(err, ErrDataplaneNotArmed) {
		t.Fatalf("unexpected error: %v (want errors.Is ErrDataplaneNotArmed)", err)
	}
}

func TestUpdateHAWatchdog_InterfaceCompliance_5328(t *testing.T) {
	// #5328 (A6-b3-F3): the pre-fix body was `var dp DataPlane; _ = dp`, which
	// asserted nothing about the method set — removing UpdateHAWatchdog from the
	// DataPlane interface left this test green (a vacuous placeholder). Exercise
	// the method THROUGH the interface with a runtime behavioral assertion
	// instead: a *Manager with no loaded ha_watchdog map, dispatched via a
	// DataPlane value, must return an error. Interface membership
	// itself is additionally compile-enforced by the real consumer that calls
	// c.dp.UpdateHAWatchdog through the interface (apply.go). #2114 A3: the
	// never-armed fixture classifies fresh, so the error is the typed gate
	// error.
	var dp DataPlane = &Manager{maps: make(map[string]*ebpf.Map)}
	err := dp.UpdateHAWatchdog(0, 12345)
	if err == nil {
		t.Fatal("expected an error dispatching UpdateHAWatchdog through DataPlane with no ha_watchdog map")
	}
	if !errors.Is(err, ErrDataplaneNotArmed) {
		t.Fatalf("unexpected error: %v (want errors.Is ErrDataplaneNotArmed)", err)
	}
}
