package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildStaticNATSnapshotDropsInet is the #5859 wire half. The Junos NAT64
// keyword `then static-nat inet` records rule.Then=="inet" in the compiler, but
// this same-family static_nat table stores an IP address in InternalIP. Emitting
// the literal string "inet" makes the Rust parse_nat_prefix fail and the rule is
// SILENTLY SKIPPED — a strict-valid config claims NAT64 translation but installs
// nothing. The builder must instead DROP the rule so the unparseable "inet"
// sentinel never reaches the dataplane (fail-closed). Strict commit rejects the
// keyword upstream; this drop backstops the tolerant load / peer-sync path.
//
// Fail-on-revert: removing the `rule.Then == "inet"` drop guard in
// buildStaticNATSnapshots re-instates the StaticNATRuleSnapshot{InternalIP:
// "inet"} sentinel emission — this test then goes RED (it observes a produced
// snapshot carrying the "inet" sentinel).
func TestBuildStaticNATSnapshotDropsInet(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "rs1", FromZone: "untrust", Rules: []*config.StaticNATRule{{
			Name:  "r1",
			Match: "64:ff9b::/96",
			Then:  "inet",
		}}},
	}

	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 0 {
		t.Fatalf("expected the `static-nat inet` rule to be DROPPED (0 snapshots), got %d: %+v", len(snaps), snaps)
	}
	// Belt-and-suspenders: no snapshot may ever carry the "inet" sentinel in the
	// IP-address field, regardless of count.
	for _, s := range snaps {
		if s.InternalIP == "inet" {
			t.Fatalf("snapshot carries the unparseable \"inet\" sentinel in InternalIP: %+v", s)
		}
	}
}

// TestBuildStaticNATSnapshotKeepsNormalPrefix guards that the #5859 drop is
// scoped to the `inet` sentinel ONLY — an ordinary `then static-nat prefix`
// rule alongside an `inet` rule still produces its snapshot.
func TestBuildStaticNATSnapshotKeepsNormalPrefix(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "rs1", FromZone: "untrust", Rules: []*config.StaticNATRule{
			{Name: "inet-rule", Match: "64:ff9b::/96", Then: "inet"},
			{Name: "prefix-rule", Match: "203.0.113.1/32", Then: "10.0.0.5/32"},
		}},
	}

	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("expected exactly the prefix rule to survive (1 snapshot), got %d: %+v", len(snaps), snaps)
	}
	s := snaps[0]
	if s.Name != "prefix-rule" || s.InternalIP != "10.0.0.5/32" {
		t.Fatalf("surviving snapshot = %+v, want the prefix-rule with InternalIP 10.0.0.5/32", s)
	}
}

// TestBuildNAT64SnapshotUnaffected is the regression guard for the SUPPORTED
// IPv6->IPv4 path: a native `security nat nat64` rule-set (cfg.Security.NAT.
// NAT64) still produces NAT64 state via buildNAT64Snapshots. The #5859 drop
// touches only the static-NAT table, never the native NAT64 snapshot builder.
func TestBuildNAT64SnapshotUnaffected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{Name: "rs64", Prefix: "64:ff9b::/96"},
	}

	snaps := buildNAT64Snapshots(cfg)
	if len(snaps) != 1 {
		t.Fatalf("expected 1 native NAT64 snapshot, got %d", len(snaps))
	}
	if snaps[0].Prefix != "64:ff9b::/96" {
		t.Fatalf("native NAT64 snapshot prefix = %q, want 64:ff9b::/96", snaps[0].Prefix)
	}
}
