package vrrp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6780: both RETH ownership modes walk the interface tree to decide what this
// node owns, and both dereferenced map values raw.
//
//	VRRP-backed mode   → CollectRethInstances (synthesizes VRRP instances)
//	direct mode        → RethVIPsForRG        (no-reth-vrrp / private-rg-election)
//
// A present-but-nil interface / unit / redundancy-group slot nil-derefs and
// takes down the daemon on the HA ownership path. Their in-file sibling
// CollectInstances already skipped nil interfaces and units, and 6 of the 8
// RETH-ownership walks in pkg/daemon already skipped nil interfaces — these two
// collectors were the outliers.
//
// REACHABILITY, stated honestly: the compiler cannot currently emit such a slot
// (every container has one write site and each stores a freshly-allocated
// pointer; nothing deserializes a *config.Config). That invariant is now
// ENFORCED by TestCompilerNeverEmitsNilConfigSlots in pkg/config, which is
// where the class can actually be prevented. These guards make the
// highest-consequence consumer degrade (skip the slot) instead of panicking the
// daemon if that invariant is ever broken by a future ingress. They are not a
// fix for a live panic, and this test does not claim to reproduce one — the
// nil slots below are injected deliberately.
//
// FAIL-ON-REVERT: remove any one guard and the matching subtest panics, which
// the harness reports as a failure naming the mode and the slot type.

// rethCfgWithNilSlot builds the smallest config where the collectors must
// produce a REAL result alongside the nil slot. A fixture carrying ONLY a nil
// slot would still pass with the guard deleted for the wrong reason (nothing
// to collect), so each case pairs the nil with a live reth0 the collectors are
// required to return.
func rethCfgWithNilSlot(t *testing.T, nilIfc, nilUnit, nilRG, vlanTagged bool) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}

	// Both collectors branch on VlanTagging into SEPARATE unit loops, each with
	// its own nil-unit guard, so the fixture must cover both. An untagged-only
	// fixture leaves the tagged branch's guard mutation-INVISIBLE (measured: it
	// survived deletion until this parameter was added).
	live := &config.InterfaceConfig{
		Name:            "reth0",
		RedundancyGroup: 1,
		VlanTagging:     vlanTagged,
	}
	if vlanTagged {
		live.Units = map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.61.1/24"}},
		}
	} else {
		live.Units = map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}
	}
	cfg.Interfaces.Interfaces["reth0"] = live

	if nilIfc {
		// Sorts AFTER reth0, so the live interface is collected first and the
		// walk must survive reaching the nil one.
		cfg.Interfaces.Interfaces["reth9-nil"] = nil
	}
	if nilUnit {
		live.Units[7] = nil // alongside the real unit 0
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	if nilRG {
		cfg.Chassis.Cluster.RedundancyGroups = []*config.RedundancyGroup{
			nil,
			{ID: 1, GratuitousARPCount: 4},
		}
	}
	return cfg
}

func TestRethOwnershipModesSkipNilSlots(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		nilIfc, nilUnit, nilRG bool
	}{
		{"nil-interface", true, false, false},
		{"nil-unit", false, true, false},
		{"nil-redundancy-group", false, false, true},
		{"all-three", true, true, true},
	} {
		for _, tag := range []struct {
			name   string
			tagged bool
		}{{"untagged", false}, {"vlan-tagged", true}} {
			tc, tag := tc, tag
			t.Run(tc.name+"/"+tag.name, func(t *testing.T) {
				// VRRP-backed ownership mode.
				t.Run("vrrp-mode", func(t *testing.T) {
					cfg := rethCfgWithNilSlot(t, tc.nilIfc, tc.nilUnit, tc.nilRG, tag.tagged)
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("CollectRethInstances panicked on a %s slot: %v\n"+
								"the VRRP-backed RETH ownership mode must skip the slot, "+
								"not nil-deref on the HA ownership path", tc.name, r)
						}
					}()
					insts := CollectRethInstances(cfg, map[int]int{1: 200})
					// The live reth0 must still be collected — a guard that skipped
					// everything would otherwise pass this test.
					if len(insts) != 1 {
						t.Fatalf("expected the live reth0 instance to still be "+
							"collected alongside the nil slot, got %d instances", len(insts))
					}
					if got := insts[0].Interface; got == "" {
						t.Errorf("collected instance has no interface name")
					}
				})

				// Direct (no-reth-vrrp / private-rg-election) ownership mode.
				t.Run("direct-mode", func(t *testing.T) {
					cfg := rethCfgWithNilSlot(t, tc.nilIfc, tc.nilUnit, tc.nilRG, tag.tagged)
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("RethVIPsForRG panicked on a %s slot: %v\n"+
								"the direct RETH ownership mode must skip the slot, "+
								"not nil-deref on the HA ownership path", tc.name, r)
						}
					}()
					vips := RethVIPsForRG(cfg, 1)
					// The live reth0's VIP must still be returned.
					if len(vips) == 0 {
						t.Fatalf("expected the live reth0 VIP to still be returned " +
							"alongside the nil slot, got an empty map")
					}
					found := false
					for _, addrs := range vips {
						for _, a := range addrs {
							if a == "10.0.61.1/24" {
								found = true
							}
						}
					}
					if !found {
						t.Errorf("live reth0 VIP 10.0.61.1/24 missing from %v", vips)
					}
				})
			})
		}
	}
}
