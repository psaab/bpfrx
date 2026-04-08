package daemon

import (
	"net"
	"testing"
)

func TestRetainFabricFwdOnNeighborMissWithoutCachedEntry(t *testing.T) {
	d := &Daemon{}
	if d.retainFabricFwdOnNeighborMiss(0, net.ParseIP("10.99.13.2"), "fab0", false) {
		t.Fatal("expected missing neighbor without cached fabric state to remain not ready")
	}
	if d.fabricEntryPopulated(0) {
		t.Fatal("fabric entry should not become populated")
	}
}

func TestRetainFabricFwdOnNeighborMissWithCachedEntry(t *testing.T) {
	d := &Daemon{}
	d.fabricMu.Lock()
	d.fabricPopulated = true
	d.fabricMu.Unlock()

	if !d.retainFabricFwdOnNeighborMiss(0, net.ParseIP("10.99.13.2"), "fab0", false) {
		t.Fatal("expected cached fabric entry to survive a transient neighbor miss")
	}
	if !d.fabricEntryPopulated(0) {
		t.Fatal("cached fabric entry should remain populated")
	}
}

func TestRetainFabricFwdOnNeighborMissWithCachedSecondaryEntry(t *testing.T) {
	d := &Daemon{}
	d.fabricMu.Lock()
	d.fabric1Populated = true
	d.fabricMu.Unlock()

	if !d.retainFabricFwdOnNeighborMiss(1, net.ParseIP("10.99.13.1"), "fab1", false) {
		t.Fatal("expected cached secondary fabric entry to survive a transient neighbor miss")
	}
	if !d.fabricEntryPopulated(1) {
		t.Fatal("cached secondary fabric entry should remain populated")
	}
}
