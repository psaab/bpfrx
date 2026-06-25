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

// TestBuildStaticNATSnapshotClampsBadPort confirms an out-of-range port (which
// can only reach the builder via the lenient load path; strict commit rejects
// it) clamps to 0 ("no port translation") so it fails CLOSED on the wire
// instead of wrapping to a wrong u16.
func TestBuildStaticNATSnapshotClampsBadPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "statnat", Rules: []*config.StaticNATRule{{
			Name:                 "bad-port",
			Match:                "203.0.113.1/32",
			Then:                 "10.0.0.5/32",
			MatchDestinationPort: 70000,
			MappedPort:           -1,
		}}},
	}
	s := buildStaticNATSnapshots(cfg, nil)[0]
	if s.MatchDestinationPort != 0 || s.MappedPort != 0 {
		t.Fatalf("out-of-range ports must clamp to 0, got match=%d mapped=%d",
			s.MatchDestinationPort, s.MappedPort)
	}
}
