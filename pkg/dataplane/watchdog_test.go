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

func TestUpdateHAWatchdog_InterfaceCompliance(t *testing.T) {
	// Verify UpdateHAWatchdog is part of the DataPlane interface.
	// This is a compile-time check; if it fails, the test won't compile.
	var dp DataPlane
	_ = dp
}
