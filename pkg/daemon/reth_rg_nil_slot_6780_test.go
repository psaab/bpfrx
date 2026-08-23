package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6780: rethInterfacesMatchingRG is the third reading of "which interfaces
// belong to this redundancy group" on the RETH ownership path (alongside
// pkg/vrrp CollectRethInstances and RethVIPsForRG). It already skipped a nil
// INTERFACE but dereferenced unit values raw (`unit.VlanID`), so a
// present-but-nil unit nil-derefed the daemon while resolving RG membership —
// the same shape as the two collectors.
//
// Reachability is stated honestly in the pkg/vrrp companion test and enforced
// at the source by TestCompilerNeverEmitsNilConfigSlots (pkg/config): the
// compiler cannot currently emit such a slot. This guard makes the walk degrade
// rather than panic if that invariant is ever broken; the nil below is injected
// deliberately and does not reproduce a live panic.
//
// FAIL-ON-REVERT: drop the `if unit == nil { continue }` in
// rethInterfacesMatchingRG and this panics.
func TestRethInterfacesMatchingRGSkipsNilUnit(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name:            "reth0",
			RedundancyGroup: 1,
			Units: map[int]*config.InterfaceUnit{
				// A live VLAN unit the walk MUST still return, so a guard that
				// skipped everything cannot pass this test.
				50: {Number: 50, VlanID: 50},
				7:  nil, // the injected nil slot
			},
		},
		// A nil interface alongside it: already guarded, pinned here so the
		// existing guard cannot regress unnoticed either.
		"reth9-nil": nil,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("rethInterfacesMatchingRG panicked on a nil unit slot: %v\n"+
				"RG membership resolution must skip the slot, not nil-deref on "+
				"the HA ownership path", r)
		}
	}()

	names := rethInterfacesMatchingRG(cfg, func(rgID int) bool { return rgID == 1 })

	// The live VLAN sub-interface must still resolve.
	found := false
	for _, n := range names {
		if n == "reth0.50" {
			found = true
		}
	}
	if !found {
		t.Errorf("live VLAN unit missing from RG membership: got %v, want it to "+
			"contain reth0.50", names)
	}
}
