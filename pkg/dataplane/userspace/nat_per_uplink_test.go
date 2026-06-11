// #1827 PR-3: per-uplink SNAT pool compilation. Two rule-sets that
// differ only in to-zone must compile into snapshot rules carrying
// their OWN zone matchers and pool addresses — the Go half of the
// "existing zone/rule-set matchers suffice" verification (the Rust
// half is nat::tests::per_uplink_pool_selected_by_to_zone; the
// to-zone itself is derived from the resolved egress ifindex on the
// session-miss path).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildSourceNATSnapshotsPerUplinkZones(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"isp-a-pool": {Name: "isp-a-pool", Addresses: []string{"203.0.113.10/32"}},
		"isp-b-pool": {Name: "isp-b-pool", Addresses: []string{"198.51.100.10/32"}},
	}
	rule := func(name, pool string) []*config.NATRule {
		return []*config.NATRule{{
			Name: name,
			Match: config.NATMatch{
				SourceAddresses:      []string{"10.0.0.0/8"},
				DestinationAddresses: []string{"0.0.0.0/0"},
			},
			Then: config.NATThen{Type: config.NATSource, PoolName: pool},
		}}
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "to-isp-a", FromZone: "trust", ToZone: "untrust-a", Rules: rule("snat-a", "isp-a-pool")},
		{Name: "to-isp-b", FromZone: "trust", ToZone: "untrust-b", Rules: rule("snat-b", "isp-b-pool")},
	}

	snaps := buildSourceNATSnapshots(cfg)
	if len(snaps) != 2 {
		t.Fatalf("len(snaps) = %d, want 2", len(snaps))
	}
	a, b := snaps[0], snaps[1]
	if a.ToZone != "untrust-a" || a.PoolName != "isp-a-pool" {
		t.Fatalf("snaps[0] = %+v, want untrust-a/isp-a-pool", a)
	}
	if len(a.PoolAddresses) != 1 || a.PoolAddresses[0] != "203.0.113.10/32" {
		t.Fatalf("snaps[0].PoolAddresses = %v", a.PoolAddresses)
	}
	if b.ToZone != "untrust-b" || b.PoolName != "isp-b-pool" {
		t.Fatalf("snaps[1] = %+v, want untrust-b/isp-b-pool", b)
	}
	if len(b.PoolAddresses) != 1 || b.PoolAddresses[0] != "198.51.100.10/32" {
		t.Fatalf("snaps[1].PoolAddresses = %v", b.PoolAddresses)
	}
	if a.PoolUnusable || b.PoolUnusable {
		t.Fatalf("pools marked unusable: a=%v b=%v", a.PoolUnusableReason, b.PoolUnusableReason)
	}
}
