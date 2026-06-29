// #3431 (Codex audit 095 H04/H05): the userspace NAT snapshot builders must
// expand EVERY value of a multi-value `match application` / `match protocol`
// list, not just the first. Before the fix the DNAT builder read the scalar
// rule.Match.Protocol / rule.Match.Application and published a single
// (protocol, app) term, silently narrowing a `match protocol [ tcp udp ]` to
// TCP only and a `match application [ a b ]` to the first app. The SNAT
// builder had the same single-application collapse.
//
// These build config structs directly (the snapshot-builder seam, like the
// #3437 tests) so they isolate the enforcement-path expansion from the parser
// fix. RED-on-revert: restoring the single rule.Match.Protocol /
// rule.Match.Application read collapses each case back to one entry/term.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildDNATSnapshotExpandsEveryProtocol proves a DNAT rule matching
// `protocol [ tcp udp ]` installs one snapshot entry per protocol (H05).
func TestBuildDNATSnapshotExpandsEveryProtocol(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10"},
		},
		RuleSets: []*config.NATRuleSet{{
			Name:     "rs",
			FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationAddress: "203.0.113.10",
					Protocol:           "tcp", // scalar = first (back-compat)
					Protocols:          []string{"tcp", "udp"},
				},
				Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			}},
		}},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	got := map[string]bool{}
	for _, s := range snaps {
		got[s.Protocol] = true
	}
	if !got["tcp"] || !got["udp"] {
		t.Fatalf("DNAT snapshots protocols = %v, want both tcp and udp (H05 multi-protocol collapse); snaps=%d", got, len(snaps))
	}
}

// TestBuildDNATSnapshotExpandsEveryApplication proves a DNAT rule matching
// `application [ web ssh ]` installs entries for BOTH applications (H04).
func TestBuildDNATSnapshotExpandsEveryApplication(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
		"ssh": {Name: "ssh", Protocol: "tcp", DestinationPort: "22"},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.168.1.10"},
		},
		RuleSets: []*config.NATRuleSet{{
			Name:     "rs",
			FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "r1",
				Match: config.NATMatch{
					DestinationAddress: "203.0.113.10",
					Application:        "web", // scalar = first
					Applications:       []string{"web", "ssh"},
				},
				Then: config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			}},
		}},
	}
	snaps := buildDestinationNATSnapshots(cfg, nil)
	ports := map[uint16]bool{}
	for _, s := range snaps {
		ports[s.DestinationPort] = true
	}
	if !ports[80] || !ports[22] {
		t.Fatalf("DNAT snapshots dest ports = %v, want both 80 (web) and 22 (ssh) (H04 multi-app collapse); snaps=%d", ports, len(snaps))
	}
}

// TestBuildSNATSnapshotExpandsEveryApplication proves a SNAT rule matching
// `application [ web dns ]` carries an app term for BOTH (H04, SNAT side).
func TestBuildSNATSnapshotExpandsEveryApplication(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
		"dns": {Name: "dns", Protocol: "udp", DestinationPort: "53"},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name:     "rs",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules: []*config.NATRule{{
			Name: "r1",
			Match: config.NATMatch{
				Application:  "web", // scalar = first
				Applications: []string{"web", "dns"},
			},
			Then: config.NATThen{Type: config.NATSource, Interface: true},
		}},
	}}
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	terms := snaps[0].MatchApplications
	protos := map[uint16]bool{}
	for _, term := range terms {
		protos[term.Protocol] = true
	}
	tcp := natAppProtoNumber("tcp")
	udp := natAppProtoNumber("udp")
	if !protos[tcp] || !protos[udp] {
		t.Fatalf("SNAT MatchApplications protocols = %v, want both tcp(%d) and udp(%d) (H04 SNAT multi-app collapse); terms=%+v",
			protos, tcp, udp, terms)
	}
}
