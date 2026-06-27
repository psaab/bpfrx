// #3096: interface- and routing-instance-scoped NAT rule-set matching. These
// tests prove the Go snapshot builder carries the typed NATRuleSet /
// StaticNATRuleSet scope (FromInterface/ToInterface/FromRoutingInstance/
// ToRoutingInstance) onto the userspace snapshot rules. The per-flow match
// itself is enforced Rust-side (nat::tests::*from_interface_scope*); this is
// the Go-half wire-plumbing proof. Dropping the scope assignment in the builder
// turns these RED.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildSourceNATSnapshotsCarriesScope(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{
			Name:                "scoped",
			FromInterface:       "ge-0/0/1.0",
			ToRoutingInstance:   "VR1",
			FromRoutingInstance: "",
			Rules: []*config.NATRule{{
				Name: "r1",
				Then: config.NATThen{Type: config.NATSource, Interface: true},
			}},
		},
	}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.FromInterface != "ge-0/0/1.0" {
		t.Fatalf("FromInterface = %q, want ge-0/0/1.0", s.FromInterface)
	}
	if s.ToRoutingInstance != "VR1" {
		t.Fatalf("ToRoutingInstance = %q, want VR1", s.ToRoutingInstance)
	}
	if s.FromZone != "" || s.ToZone != "" {
		t.Fatalf("unexpected zone scope on interface/RI-scoped rule: %+v", s)
	}
}

func TestBuildStaticNATSnapshotsCarriesScope(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name:          "scoped",
			FromInterface: "ge-0/0/2.0",
			Rules: []*config.StaticNATRule{{
				Name:  "r1",
				Match: "203.0.113.10/32",
				Then:  "192.168.1.10/32",
			}},
		},
	}
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if snaps[0].FromInterface != "ge-0/0/2.0" {
		t.Fatalf("FromInterface = %q, want ge-0/0/2.0", snaps[0].FromInterface)
	}
}

func TestBuildDestinationNATSnapshotsCarriesScope(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "10.0.0.5"},
		},
		RuleSets: []*config.NATRuleSet{
			{
				Name:                "scoped",
				FromRoutingInstance: "VR1",
				Rules: []*config.NATRule{{
					Name: "r1",
					Match: config.NATMatch{
						DestinationAddress:   "203.0.113.10/32",
						DestinationAddresses: []string{"203.0.113.10/32"},
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
				}},
			},
		},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) == 0 {
		t.Fatalf("no destination NAT snapshots built")
	}
	if snaps[0].FromRoutingInstance != "VR1" {
		t.Fatalf("FromRoutingInstance = %q, want VR1", snaps[0].FromRoutingInstance)
	}
}
