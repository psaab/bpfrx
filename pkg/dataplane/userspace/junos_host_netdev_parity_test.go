package userspace

import (
	"reflect"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// snapshotZoneNetdevs recomputes the per-zone iifname netdev scope from the
// interface SNAPSHOT (the pre-F1 authority) using the SAME claim-counting the
// config SSOT (config.JunosHostZoneIngressNetdevs) now owns. It exists only to
// pin the two resolutions byte-for-byte so the #4146 iifname enforcement scope
// (config-computed) cannot drift from what the dataplane snapshot would produce.
func snapshotZoneNetdevs(cfg *config.Config) map[string][]string {
	snaps := buildInterfaceSnapshots(cfg)
	lifelines := hostInboundLifelineSet(cfg)
	cand := map[string]map[string]bool{}
	claims := map[string]map[string]bool{}
	addCand := func(zone, nd string) {
		if zone == "" || nd == "" {
			return
		}
		if cand[zone] == nil {
			cand[zone] = map[string]bool{}
		}
		cand[zone][nd] = true
		if claims[nd] == nil {
			claims[nd] = map[string]bool{}
		}
		claims[nd][zone] = true
	}
	for _, s := range snaps {
		if s.Zone == "" || hostInboundLifelineInterface(s.Name, lifelines) {
			continue
		}
		addCand(s.Zone, s.LinuxName)
		if s.VLANID != 0 && s.ParentLinuxName != "" {
			addCand(s.Zone, s.ParentLinuxName)
		}
	}
	out := map[string][]string{}
	for zone, nds := range cand {
		var keep []string
		for nd := range nds {
			if len(claims[nd]) == 1 {
				keep = append(keep, nd)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			out[zone] = keep
		}
	}
	return out
}

// TestJunosHostZoneNetdevsMatchSnapshot pins config.JunosHostZoneIngressNetdevs
// (the #4146 iifname SSOT the F1 fix routes BOTH the kernel emission and the
// #4168 warning through) to the dataplane interface-snapshot resolution, across
// representative topologies including the cross-zone-ambiguous trunk. Any drift
// in the ported snapshotLinuxName / buildInterfaceZoneMap logic fails this
// (guarding the enforcement iifname scope, which the smoke exercised as
// ge-0-0-1).
func TestJunosHostZoneNetdevsMatchSnapshot(t *testing.T) {
	cases := map[string]*config.Config{
		"physical + reth + vlan": func() *config.Config {
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.1.1/24"}}}},
				"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
					50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24"}},
					80: {Number: 80, VlanID: 80, Addresses: []string{"172.16.80.8/24"}}}},
				"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.0.61.1/24"}}}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trust": {Name: "trust", Interfaces: []string{"ge-0/0/1.0"}},
				"wan":   {Name: "wan", Interfaces: []string{"reth0.50", "reth0.80"}},
				"lan":   {Name: "lan", Interfaces: []string{"reth1"}},
			}
			return cfg
		}(),
		"cross-zone-ambiguous trunk": func() *config.Config {
			cfg := &config.Config{}
			cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
				"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
					0:  {Number: 0, Addresses: []string{"10.0.9.1/24"}},
					50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}},
					80: {Number: 80, VlanID: 80, Addresses: []string{"10.0.80.1/24"}}}},
			}
			cfg.Security.Zones = map[string]*config.ZoneConfig{
				"trunkzero": {Name: "trunkzero", Interfaces: []string{"ge-0/0/2.0"}},
				"vlanb":     {Name: "vlanb", Interfaces: []string{"ge-0/0/2.50"}},
				"vlanc":     {Name: "vlanc", Interfaces: []string{"ge-0/0/2.80"}},
			}
			return cfg
		}(),
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			want := snapshotZoneNetdevs(cfg)
			got := config.JunosHostZoneIngressNetdevs(cfg)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("config netdev SSOT diverged from snapshot:\n  config=%v\n  snap  =%v", got, want)
			}
		})
	}
}
