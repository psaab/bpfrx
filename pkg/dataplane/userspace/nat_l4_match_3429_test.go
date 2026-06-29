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

// #3471 AGY fail-open: a destination-port constraint whose ports are ALL out of
// range must NOT coalesce to an empty list — empty means "unconstrained" =
// match-any-port. It must emit the never-match sentinel so the rule matches
// nothing. RED-on-revert: with the plain coalescePortRanges (drop-to-empty),
// MatchDestinationPorts is empty and the rule widens to every port.
func TestBuildSourceNATSnapshotsAllOutOfRangePortFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationPorts: []int{0, 70000, 99999},
				},
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	got := snaps[0].MatchDestinationPorts
	if len(got) != 1 || got[0] != natNeverMatchPortRange {
		t.Fatalf("MatchDestinationPorts = %+v, want one never-match range %+v (fail closed, not empty wildcard)",
			got, natNeverMatchPortRange)
	}
}

// #3471 Codex fail-open: an application whose protocol is empty or unresolvable
// must emit the never-match protocol sentinel, NOT natProtoAny (256, wildcard).
// RED-on-revert: returning natProtoAny widens the app term to every protocol.
func TestBuildSourceNATSnapshotsAppEmptyProtocolFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-noproto": {Name: "app-noproto", Protocol: "", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-noproto"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	apps := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	if len(apps) != 1 || apps[0].Protocol != natProtoNever {
		t.Fatalf("MatchApplications = %+v, want one never-match term (proto %d), NOT natProtoAny %d",
			apps, natProtoNever, natProtoAny)
	}
}

func TestBuildSourceNATSnapshotsAppUnknownProtocolFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-bad": {Name: "app-bad", Protocol: "frobnicate", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-bad"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	apps := buildSourceNATSnapshots(cfg, nil)[0].MatchApplications
	if len(apps) != 1 || apps[0].Protocol != natProtoNever {
		t.Fatalf("MatchApplications = %+v, want one never-match term (proto %d)", apps, natProtoNever)
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

// #3491: the application's source-port constraint must be carried onto the
// snapshot term's SrcPorts. Before the fix buildSourceNATAppTerms read only
// DestinationPort, so a source-NAT rule whose `match application` constrained
// the source port widened to every source port (fail open). Dropping the
// SrcPorts assignment turns this RED.
func TestBuildSourceNATSnapshotsCarriesApplicationSourcePortMatch(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-svc": {Name: "app-svc", Protocol: "tcp", SourcePort: "12345", DestinationPort: "443"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-svc"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	if len(apps[0].Ports) != 1 || apps[0].Ports[0] != (NatPortRangeWire{Low: 443, High: 443}) {
		t.Fatalf("term ports = %+v, want [{443 443}]", apps[0].Ports)
	}
	if len(apps[0].SrcPorts) != 1 || apps[0].SrcPorts[0] != (NatPortRangeWire{Low: 12345, High: 12345}) {
		t.Fatalf("term src ports = %+v, want [{12345 12345}]", apps[0].SrcPorts)
	}
}

// #3491: an application whose source-port spec is non-empty but coalesces to
// nothing (all out of 1..65535) must fail CLOSED with the never-match sentinel,
// NOT widen to any source port (empty SrcPorts).
func TestBuildSourceNATSnapshotsAppAllOutOfRangeSourcePortFailsClosed(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"app-bad-sport": {Name: "app-bad-sport", Protocol: "tcp", SourcePort: "70000"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:     "rs",
			FromZone: "lan",
			ToZone:   "wan",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{Application: "app-bad-sport"},
				Then:  config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	apps := snaps[0].MatchApplications
	if len(apps) != 1 {
		t.Fatalf("MatchApplications = %+v, want 1 term", apps)
	}
	want := []NatPortRangeWire{natNeverMatchPortRange}
	if len(apps[0].SrcPorts) != len(want) || apps[0].SrcPorts[0] != want[0] {
		t.Fatalf("term src ports = %+v, want one never-match range %+v (fail closed, not empty wildcard)",
			apps[0].SrcPorts, want)
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
