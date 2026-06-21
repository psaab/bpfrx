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
	"github.com/psaab/xpf/pkg/dataplane"
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

	snaps := buildSourceNATSnapshots(cfg, nil)
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

// TestBuildNATSnapshotsStampCounterID is the #2218 fail-on-revert guard for
// the snapshot half: the compiler-assigned per-rule NAT counter IDs
// (CompileResult.NATCounterIDs, keyed "natType/ruleSet/ruleName" via
// dataplane.NATCounterKey) must be stamped onto
// the SNAT/DNAT/static rule snapshots so the Rust dataplane can attribute a
// translation hit to the matched rule. Without the CounterID plumbing the
// snapshots carry CounterID 0 and the hot path can never attribute a hit.
func TestBuildNATSnapshotsStampCounterID(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p": {Name: "p", Addresses: []string{"203.0.113.10/32"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{
		{Name: "srcnat", FromZone: "trust", ToZone: "untrust", Rules: []*config.NATRule{{
			Name:  "snat-rule",
			Match: config.NATMatch{SourceAddresses: []string{"10.0.0.0/8"}},
			Then:  config.NATThen{Type: config.NATSource, PoolName: "p"},
		}}},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "dstnat", FromZone: "untrust", Rules: []*config.NATRule{{
				Name: "dnat-rule",
				Match: config.NATMatch{
					DestinationAddress: "203.0.113.20",
					Protocol:           "tcp",
					DestinationPort:    443,
				},
				Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
			}}},
		},
	}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{
		{Name: "statnat", FromZone: "untrust", Rules: []*config.StaticNATRule{{
			Name: "static-rule", Match: "203.0.113.30/32", Then: "10.0.0.30/32",
		}}},
	}

	// #2218: counter-ID map keys are type-namespaced (dataplane.NATCounterKey)
	// so same-named rules across NAT types do not collide.
	natCounterIDs := map[string]uint16{
		dataplane.NATCounterKey(dataplane.NATCounterTypeSource, "srcnat", "snat-rule"):    5,
		dataplane.NATCounterKey(dataplane.NATCounterTypeDest, "dstnat", "dnat-rule"):      6,
		dataplane.NATCounterKey(dataplane.NATCounterTypeStatic, "statnat", "static-rule"): 7,
	}

	src := buildSourceNATSnapshots(cfg, natCounterIDs)
	if len(src) != 1 || src[0].CounterID != 5 {
		t.Fatalf("source NAT snapshot CounterID = %v, want 5 (got %+v)", srcCounterID(src), src)
	}
	dst := buildDestinationNATSnapshots(cfg, natCounterIDs)
	if len(dst) == 0 {
		t.Fatalf("no DNAT snapshots produced")
	}
	for _, d := range dst {
		if d.CounterID != 6 {
			t.Fatalf("DNAT snapshot CounterID = %d, want 6 (%+v)", d.CounterID, d)
		}
	}
	stat := buildStaticNATSnapshots(cfg, natCounterIDs)
	if len(stat) != 1 || stat[0].CounterID != 7 {
		t.Fatalf("static NAT snapshot CounterID mismatch (%+v)", stat)
	}

	// A nil counter-ID map (no compile result) must leave CounterID 0 —
	// pre-#2218 wire shape, no attribution.
	if got := buildSourceNATSnapshots(cfg, nil); len(got) != 1 || got[0].CounterID != 0 {
		t.Fatalf("nil natCounterIDs must leave CounterID 0, got %+v", got)
	}
}

func srcCounterID(s []SourceNATRuleSnapshot) uint16 {
	if len(s) == 0 {
		return 0
	}
	return s[0].CounterID
}
