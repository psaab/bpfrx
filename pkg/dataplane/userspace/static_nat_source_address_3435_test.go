// #3435: static-NAT `match source-address` snapshot plumbing. These tests prove
// the Go snapshot builder carries the typed StaticNATRule source-address
// constraint (SourceAddresses, with the singular SourceAddress fallback) onto
// the userspace StaticNATRuleSnapshot. The per-flow source match itself is
// enforced Rust-side (nat::tests::static_nat_*source_address*); this is the
// Go-half wire-plumbing proof. Dropping the SourceAddresses assignment in
// buildStaticNATSnapshots turns these RED — re-introducing the #3435 fail-open
// (an all-source 1:1/DNAT mapping).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildStaticNATSnapshotsCarriesSourceAddresses(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs1",
			Rules: []*config.StaticNATRule{{
				Name:            "r1",
				Match:           "203.0.113.10/32",
				Then:            "192.168.1.10/32",
				SourceAddress:   "198.51.100.0/24",
				SourceAddresses: []string{"198.51.100.0/24", "203.0.113.200/32"},
			}},
		},
	}
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	got := snaps[0].SourceAddresses
	want := []string{"198.51.100.0/24", "203.0.113.200/32"}
	if len(got) != len(want) {
		t.Fatalf("SourceAddresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SourceAddresses[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// A typed config that only set the singular SourceAddress (older path / peer
// sync) must still publish a one-entry source list, not an empty (match-any)
// one.
func TestBuildStaticNATSnapshotsSingularSourceFallback(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs1",
			Rules: []*config.StaticNATRule{{
				Name:          "r1",
				Match:         "203.0.113.10/32",
				Then:          "192.168.1.10/32",
				SourceAddress: "198.51.100.0/24",
			}},
		},
	}
	snaps := buildStaticNATSnapshots(cfg, nil)
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if got := snaps[0].SourceAddresses; len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("SourceAddresses = %v, want [198.51.100.0/24]", got)
	}
}

// An unscoped rule (no source-address) must publish an empty list = match any
// source, preserving the pre-#3435 whole-address 1:1 behavior.
func TestBuildStaticNATSnapshotsNoSourceIsUnscoped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{
			Name: "rs1",
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
	if got := snaps[0].SourceAddresses; len(got) != 0 {
		t.Fatalf("SourceAddresses = %v, want empty (unscoped = match any)", got)
	}
}
