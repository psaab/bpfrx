package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildStaticNATSnapshotCarriesMappedPort is the #2491 wire half: the Go
// snapshot builder must carry MatchDestinationPort + MappedPort onto the
// StaticNATRuleSnapshot so the Rust dataplane can do port-mapped static NAT.
//
// Fail-on-revert: dropping the two field assignments in buildStaticNATSnapshots
// leaves both at 0 and this test goes RED.
func TestBuildStaticNATSnapshotCarriesMappedPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "statnat", FromZone: "untrust", Rules: []*config.StaticNATRule{{
			Name:                 "port-rule",
			Match:                "203.0.113.1/32",
			Then:                 "10.0.0.5/32",
			MatchDestinationPort: 8080,
			MappedPort:           80,
		}}},
	}

	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 static NAT snapshot, got %d", len(snaps))
	}
	s := snaps[0]
	if s.MatchDestinationPort != 8080 {
		t.Fatalf("MatchDestinationPort = %d, want 8080", s.MatchDestinationPort)
	}
	if s.MappedPort != 80 {
		t.Fatalf("MappedPort = %d, want 80", s.MappedPort)
	}
}

// TestBuildStaticNATSnapshotOutOfRangePortFailsClosed is the #5101 security
// fix. An out-of-range `match destination-port` (which can only reach the
// builder via the lenient load / peer-sync path; strict commit rejects it)
// must NOT collapse to the port-0 whole-address wildcard. Port 0 is the valid
// "match any port" sentinel that the Rust side installs as a whole-address 1:1
// mapping — so coercing an invalid 70000 to 0 exposes EVERY port of the
// external address (fail-OPEN). The builder must instead DROP the rule so it
// fails CLOSED.
//
// Fail-on-revert: removing the staticNATPortOutOfRange drop guard in
// buildStaticNATSnapshots re-instates the clampPort(70000)->0 collapse, which
// appends a whole-address (MatchDestinationPort==0) snapshot entry — this test
// then goes RED (it observes a produced entry / a port-0 whole-address entry).
func TestBuildStaticNATSnapshotOutOfRangePortFailsClosed(t *testing.T) {
	cases := []struct {
		name       string
		matchPort  int
		mappedPort int
	}{
		// The headline #5101 vector: an invalid external match port with no
		// mapped port. Old behaviour clamped match->0, mapped->0 => Rust (0,_)
		// whole-address exposure.
		{"match-out-of-range", 70000, 0},
		// A valid match port but an invalid mapped port: the translation
		// target is garbage, so the whole rule must fail closed too.
		{"mapped-out-of-range", 8080, 70000},
		// Both out of range (the pre-fix TestBuildStaticNATSnapshotClampsBadPort
		// input): must drop, not collapse to whole-address.
		{"both-out-of-range", 70000, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
				{Name: "statnat", Rules: []*config.StaticNATRule{{
					Name:                 "bad-port",
					Match:                "203.0.113.1/32",
					Then:                 "10.0.0.5/32",
					MatchDestinationPort: tc.matchPort,
					MappedPort:           tc.mappedPort,
				}}},
			}
			snaps := buildStaticNATSnapshots(cfg, nil)
			// Fail-closed: the rule is dropped entirely. In particular there
			// must be NO whole-address (port-0) entry for the invalid input.
			for _, s := range snaps {
				if s.MatchDestinationPort == 0 {
					t.Fatalf("out-of-range port must fail CLOSED (drop), got whole-address entry "+
						"external=%s match=%d mapped=%d", s.ExternalIP,
						s.MatchDestinationPort, s.MappedPort)
				}
			}
			if len(snaps) != 0 {
				t.Fatalf("out-of-range port must drop the rule, got %d snapshot(s)", len(snaps))
			}
		})
	}
}

// TestBuildStaticNATSnapshotAbsentPortWholeAddress is the no-regression twin:
// a GENUINELY-absent port (0, the common whole-address 1:1 static-NAT shape)
// must STILL produce a whole-address snapshot entry. The #5101 drop guard must
// distinguish absent (0 -> keep) from present-but-invalid (out-of-range -> drop).
func TestBuildStaticNATSnapshotAbsentPortWholeAddress(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "statnat", Rules: []*config.StaticNATRule{{
			Name:  "whole-address",
			Match: "203.0.113.1/32",
			Then:  "10.0.0.5/32",
			// MatchDestinationPort / MappedPort left 0 = absent.
		}}},
	}
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("absent-port whole-address rule must be kept, got %d snapshot(s)", len(snaps))
	}
	if snaps[0].MatchDestinationPort != 0 || snaps[0].MappedPort != 0 {
		t.Fatalf("absent-port rule must map whole-address (0/0), got match=%d mapped=%d",
			snaps[0].MatchDestinationPort, snaps[0].MappedPort)
	}
}
