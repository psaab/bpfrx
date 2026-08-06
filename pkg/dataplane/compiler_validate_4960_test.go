package dataplane

// #4960 binding test: a config that passes config-compile and fails a LATER
// dataplane phase must leave the host UNMUTATED.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// recordingDP counts the dataplane calls that mark how far CompileConfig got.
// SetZoneConfig is the probe for host mutation: programZoneMaps calls it once
// per zone BEFORE it iterates that zone's interfaces, and mapZoneInterface --
// the only caller of ensureVLANSubInterface / reconcileInterfaceAddresses, the
// only destructive netlink in the whole compile -- runs inside that iteration.
// So zero SetZoneConfig calls proves compileZones never started, which proves
// no host mutation occurred. SetVlanIfaceInfo is the tighter inner probe: it is
// invoked immediately after a successful ensureVLANSubInterface, so a nonzero
// count means a VLAN device was actually created.
type recordingDP struct {
	discardingDataPlane
	zoneConfigCalls   int
	vlanIfaceInfoCall int
}

func (r *recordingDP) SetZoneConfig(zoneID uint16, zc ZoneConfig) error {
	r.zoneConfigCalls++
	return nil
}

func (r *recordingDP) SetVlanIfaceInfo(subIfindex, parentIfindex int, vlanID uint16) error {
	r.vlanIfaceInfoCall++
	return nil
}

// failLaterPhaseConfig is accepted by the pure pkg/config compiler (the one
// `commit check` runs) but hard-errors in a LATER dataplane phase. The zone
// carries a VLAN sub-interface so that, absent the pre-pass, compileZones would
// create a real VLAN device before the failure is reached.
//
// The failure is compileApplications': a security policy references an
// application name that does not resolve, which returns
// `application %q not found`. That is the class userspace/flow.go documents as
// hard-erroring and aborting the apply -- i.e. the live, reachable input.
func failLaterPhaseConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"ge-0-0-0.50"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0-0-1.0"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {Name: "ge-0-0-0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"192.0.2.1/24"}},
		}},
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.1/24"}},
		}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust", ToZone: "untrust",
			Policies: []*config.Policy{
				{
					Name: "p-bad-app",
					Match: config.PolicyMatch{
						SourceAddresses:      []string{"any"},
						DestinationAddresses: []string{"any"},
						Applications:         []string{"no-such-application-4960"},
					},
					Action: config.PolicyPermit,
				},
			},
		},
	}
	return cfg
}

// The property: no host mutation until every validated phase has passed.
func TestNoHostMutationWhenALaterPhaseFails_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := failLaterPhaseConfig()

	_, err := CompileConfig(dp, cfg, false)
	if err == nil {
		t.Fatal("expected the unresolvable application reference to fail the " +
			"compile — the fixture no longer exercises a later-phase failure")
	}
	if !strings.Contains(err.Error(), "no-such-application-4960") {
		t.Fatalf("failed for the wrong reason, so this test would not bind the "+
			"property: %v", err)
	}

	if dp.zoneConfigCalls != 0 {
		t.Errorf("compileZones RAN before the failing phase was caught "+
			"(%d SetZoneConfig calls) — the host was mutated before a later "+
			"phase failed, which is #4960", dp.zoneConfigCalls)
	}
	if dp.vlanIfaceInfoCall != 0 {
		t.Errorf("a VLAN sub-interface was created before the failing phase was "+
			"caught (%d SetVlanIfaceInfo calls) — destructive netlink ran and "+
			"has no undo path (#4960)", dp.vlanIfaceInfoCall)
	}
}

// Control: a VALID config must still reach compileZones. Without this the test
// above is satisfied by a pre-pass that rejects everything, or by CompileConfig
// failing before it does any work at all.
func TestValidConfigStillReachesZoneCompile_4960(t *testing.T) {
	dp := &recordingDP{}
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"} // now resolvable

	_, err := CompileConfig(dp, cfg, false)
	if err != nil {
		t.Fatalf("valid config must compile: %v", err)
	}
	if dp.zoneConfigCalls == 0 {
		t.Fatal("a VALID config did not reach compileZones — the pre-pass is " +
			"rejecting good configs, or the phase order changed")
	}
}

// The pre-pass shim deliberately nil-panics on any method it does not
// override, so it cannot carry a FULL CompileConfig run. The control test needs
// one, because proving a valid config still reaches compileZones means letting
// the whole function execute. These stubs cover the rest of the compiler's
// dataplane surface for that purpose only.
func (*recordingDP) AddTxPort(ifindex int) error { return nil }
func (*recordingDP) SetZone(ifindex int, vlanID uint16, zoneID uint16, routingTable uint32, flags uint8, rgID uint8, screenFlags uint32) error {
	return nil
}
func (*recordingDP) SetMirrorConfig(ifindex int, mirrorIfindex int, rate uint32) error { return nil }
func (*recordingDP) ClearMirrorConfigs() error                                         { return nil }
func (*recordingDP) SetIfaceFilter(key IfaceFilterKey, filterID uint32) error          { return nil }
func (*recordingDP) SetFilterConfig(filterID uint32, cfg FilterConfig) error           { return nil }
func (*recordingDP) SetFilterRule(index uint32, rule FilterRule) error                 { return nil }
func (*recordingDP) SetPolicerConfig(id uint32, cfg PolicerConfig) error               { return nil }
func (*recordingDP) BumpFIBGeneration() (uint32, error)                                { return 0, nil }
func (*recordingDP) DeleteStaleIfaceZone(written map[IfaceZoneKey]bool)                {}
func (*recordingDP) DeleteStaleVlanIface(written map[uint32]bool)                      {}
func (*recordingDP) DeleteStaleIfaceFilter(written map[IfaceFilterKey]bool)            {}
func (*recordingDP) ZeroStaleFilterConfigs(startID uint32)                             {}
