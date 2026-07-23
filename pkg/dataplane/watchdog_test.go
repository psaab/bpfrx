package dataplane

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestUpdateHAWatchdog_MapNotLoaded(t *testing.T) {
	m := &Manager{maps: make(map[string]*ebpf.Map)}
	err := m.UpdateHAWatchdog(0, 12345)
	if err == nil {
		t.Fatal("expected error when ha_watchdog map not loaded")
	}
	if err.Error() != "ha_watchdog map not found" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateHAWatchdog_InterfaceCompliance_5328(t *testing.T) {
	// #5328 (A6-b3-F3): the pre-fix body was `var dp DataPlane; _ = dp`, which
	// asserted nothing about the method set — removing UpdateHAWatchdog from the
	// DataPlane interface left this test green (a vacuous placeholder). Exercise
	// the method THROUGH the interface with a runtime behavioral assertion
	// instead: a *Manager with no loaded ha_watchdog map, dispatched via a
	// DataPlane value, must return the map-not-found error. Interface membership
	// itself is additionally compile-enforced by the real consumer that calls
	// c.dp.UpdateHAWatchdog through the interface (apply.go).
	var dp DataPlane = &Manager{maps: make(map[string]*ebpf.Map)}
	err := dp.UpdateHAWatchdog(0, 12345)
	if err == nil {
		t.Fatal("expected an error dispatching UpdateHAWatchdog through DataPlane with no ha_watchdog map")
	}
	if err.Error() != "ha_watchdog map not found" {
		t.Fatalf("unexpected error: %v", err)
	}
}
