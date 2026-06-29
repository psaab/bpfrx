// #3429: source-NAT `match destination-port` / `match application` enforcement.
// These tests prove the Go snapshot builder carries the L4 match constraints
// onto the userspace SourceNATRuleSnapshot (the per-flow match itself is
// enforced Rust-side in nat::tests::*_3429). Before the fix these match fields
// were parsed and compiled but DROPPED at the snapshot boundary, so a
// port/app-scoped source-NAT rule silently widened to every port/protocol.
// Dropping the builder assignment turns these RED.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildSourceNATSnapshotsCarriesDestinationPortMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					// `destination-port 20000 to 20003` -> compiler stores the
					// range expanded to individual ports; the builder coalesces
					// them back to one wire range.
					DestinationPorts: []int{20000, 20001, 20002, 20003},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].MatchDestinationPorts
	want := []NatPortRangeWire{{Low: 20000, High: 20003}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchDestinationPorts = %+v, want %+v", got, want)
	}
}

func TestBuildSourceNATSnapshotsDropsOutOfRangePort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					// 0 and >65535 must be dropped (fail closed), 443 kept.
					DestinationPorts: []int{0, 443, 70000},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	got := snaps[0].MatchDestinationPorts
	want := []NatPortRangeWire{{Low: 443, High: 443}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("MatchDestinationPorts = %+v, want %+v (out-of-range dropped)", got, want)
	}
}

func TestBuildSourceNATSnapshotsCarriesApplicationMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-https": {Name: "app-https", Protocol: "tcp", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-https"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	if apps[0].Protocol != 6 { // tcp
		t.Fatalf("term protocol = %d, want 6 (tcp)", apps[0].Protocol)
	}
	if len(apps[0].Ports) != 1 || apps[0].Ports[0] != (NatPortRangeWire{Low: 443, High: 443}) {
		t.Fatalf("term ports = %+v, want [{443 443}]", apps[0].Ports)
	}
}

func TestBuildSourceNATSnapshotsUnresolvableApplicationFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "does-not-exist"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 || apps[0].Protocol != natProtoNever {
		t.Fatalf("MatchApplications = %+v, want one never-match term (proto %d)", apps, natProtoNever)
	}
}

func TestBuildSourceNATSnapshotsUnconstrainedHasNoL4Match(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps[0].MatchDestinationPorts) != 0 || len(snaps[0].MatchApplications) != 0 {
		t.Fatalf("unconstrained rule must carry no L4 match: %+v", snaps[0])
	}
}
