package userspace

import (
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSyntheticLogicalIfindex_ExhaustionReturnsSentinel_5557 pins that
// syntheticLogicalIfindex degrades to the negative sentinel when its entire
// private range is already claimed, instead of panicking and crash-looping the
// daemon. Exhaustion is unreachable in practice (it needs >1<<20 logical-only
// VLAN units on one box), but the snapshot builder must not take down the whole
// daemon on it.
//
// FAIL-ON-REVERT: restore the panic() in syntheticLogicalIfindex and this test
// panics (a test panic is a FAIL) instead of observing the sentinel.
func TestSyntheticLogicalIfindex_ExhaustionReturnsSentinel_5557(t *testing.T) {
	span := syntheticInterfaceIfindexMax - syntheticInterfaceIfindexMin + 1
	used := make(map[int]struct{}, span)
	for v := syntheticInterfaceIfindexMin; v <= syntheticInterfaceIfindexMax; v++ {
		used[v] = struct{}{}
	}

	got := syntheticLogicalIfindex("reth0.80", 80, used)
	if got != syntheticIfindexExhausted {
		t.Fatalf("exhausted range: syntheticLogicalIfindex = %d, want sentinel %d", got, syntheticIfindexExhausted)
	}
}

// TestBuildInterfaceSnapshots_SkipsUnitOnIfindexExhaustion_5557 pins the CALLER
// side of the exhaustion contract that the helper-level test above does not
// reach: buildInterfaceSnapshots must DROP a logical-only RETH VLAN unit whose
// synthetic ifindex came back as the exhaustion sentinel, rather than emitting a
// snapshot row with a bogus negative ifindex (which the Rust dataplane would
// then key FIB/filter/CoS state by).
//
// The 1<<20-wide synthetic range cannot be exhausted through a real config in a
// unit test, so we temporarily shrink it to a single slot (the vars exist for
// exactly this) and configure TWO sibling logical-only RETH VLAN units on lo:
// the first claims the lone slot, the second exhausts the range and must be
// skipped. Exactly one of the two units may appear, and no emitted row may carry
// the negative sentinel.
//
// FAIL-ON-REVERT: drop the `if ifindex == syntheticIfindexExhausted { continue }`
// guard in buildInterfaceSnapshots (interfaces.go) and the second unit is emitted
// with Ifindex == syntheticIfindexExhausted — both assertions below go RED.
func TestBuildInterfaceSnapshots_SkipsUnitOnIfindexExhaustion_5557(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}

	// Shrink the synthetic range to a single slot for the duration of this
	// test, then restore it. min == max => span 1.
	origMin, origMax := syntheticInterfaceIfindexMin, syntheticInterfaceIfindexMax
	syntheticInterfaceIfindexMax = syntheticInterfaceIfindexMin
	t.Cleanup(func() {
		syntheticInterfaceIfindexMin, syntheticInterfaceIfindexMax = origMin, origMax
	})

	vlans := missingLoopbackVLANIDs(t, 2)
	unitA := fmt.Sprintf("reth0.%d", vlans[0])
	unitB := fmt.Sprintf("reth0.%d", vlans[1])
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"wan": {Name: "wan", Interfaces: []string{unitA}},
				"dmz": {Name: "dmz", Interfaces: []string{unitB}},
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"lo": {
					Name:            "lo",
					RedundantParent: "reth0",
				},
				"reth0": {
					Name: "reth0",
					Units: map[int]*config.InterfaceUnit{
						vlans[0]: {Number: vlans[0], VlanID: vlans[0]},
						vlans[1]: {Number: vlans[1], VlanID: vlans[1]},
					},
				},
			},
		},
	}

	present := 0
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name == unitA || snap.Name == unitB {
			present++
		}
		if snap.Ifindex == syntheticIfindexExhausted {
			t.Fatalf("snapshot %q emitted with the exhaustion sentinel ifindex %d; the caller-skip guard is missing",
				snap.Name, snap.Ifindex)
		}
	}
	if present != 1 {
		t.Fatalf("with a single synthetic slot exactly one of the two sibling RETH VLAN units must load; got %d present", present)
	}
}
