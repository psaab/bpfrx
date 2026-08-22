package userspace

import (
	"fmt"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3721: BuildZoneHostInboundViews grouped interfaces by an ORDER-SENSITIVE
// signature (strings.Join of the token slices in source order), so two
// interfaces whose effective admission sets are semantically identical but
// authored in a different order ([ssh ping] vs [ping ssh]) fell into different
// groups and emitted duplicate nft rule blocks + deny counters, inflating the
// payload on large trunks. The fix keys the grouping on the CANONICAL
// (sorted/deduped) token signature. This is behavior-PRESERVING: admission per
// address is unchanged; only duplicate blocks collapse.

// countAddrViews returns the views for a zone that carry at least one address
// (an addressless seed view emits no deny and is not a rule block).
func countAddrViews(views []ZoneHostInboundView, zone string) []ZoneHostInboundView {
	var out []ZoneHostInboundView
	for _, v := range views {
		if v.Zone == zone && (len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0) {
			out = append(out, v)
		}
	}
	return out
}

func canonSet(toks []string) string {
	c := append([]string(nil), toks...)
	sort.Strings(c)
	return fmt.Sprintf("%v", c)
}

// Test_3721_ReorderedIdenticalSetsMergeToOneView is the perf/merge proof: two
// interfaces with reordered-but-identical effective sets ([ssh ping] and
// [ping ssh]) now share ONE address-bearing view. On revert (order-sensitive
// signature) they split into two views — this assertion goes RED.
func Test_3721_ReorderedIdenticalSetsMergeToOneView(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
		}},
	}
	// Empty zone-level stanza; each interface authors the SAME set in a DIFFERENT
	// order so the effective sets differ only by token order.
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trunk": {
			Name:       "trunk",
			Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0/0/0.0": {SystemServices: []string{"ssh", "ping"}},
				"ge-0/0/1.0": {SystemServices: []string{"ping", "ssh"}},
			},
		},
	}

	addrViews := countAddrViews(BuildZoneHostInboundViews(cfg), "trunk")
	if len(addrViews) != 1 {
		t.Fatalf("reordered-identical sets must merge into ONE address-bearing view, got %d: %+v", len(addrViews), addrViews)
	}
	v := addrViews[0]
	// Behavior-preserving: the single merged view admits exactly {ssh, ping} and
	// covers BOTH interface addresses — identical enforcement to two blocks.
	if canonSet(v.SystemServices) != canonSet([]string{"ssh", "ping"}) {
		t.Errorf("merged view services = %v, want the set {ssh, ping}", v.SystemServices)
	}
	gotAddrs := append([]string(nil), v.V4Addrs...)
	sort.Strings(gotAddrs)
	if !eqStr(gotAddrs, []string{"10.0.0.1", "10.0.1.1"}) {
		t.Errorf("merged view addrs = %v, want both interface addresses", gotAddrs)
	}
}

// Test_3721_DistinctSetsStaySeparate guards against over-merging: genuinely
// different effective sets must remain distinct views (canonical grouping must
// not collapse [ssh] and [ping] together).
func Test_3721_DistinctSetsStaySeparate(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trunk": {
			Name:       "trunk",
			Interfaces: []string{"ge-0/0/0.0", "ge-0/0/1.0"},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0/0/0.0": {SystemServices: []string{"ssh"}},
				"ge-0/0/1.0": {SystemServices: []string{"ping"}},
			},
		},
	}
	addrViews := countAddrViews(BuildZoneHostInboundViews(cfg), "trunk")
	if len(addrViews) != 2 {
		t.Fatalf("distinct sets must stay in separate views, got %d: %+v", len(addrViews), addrViews)
	}
}

// Test_3721_EnforcementPreserved is the behavior-preserving assertion: for every
// firewall-local address, the CANONICAL effective admitted set produced by
// BuildZoneHostInboundViews equals the set computed independently per interface
// (effectiveHostInboundTokens), regardless of how the grouping collapses. The
// grouping is an optimization over WHICH view carries an address, never over
// what that address admits.
//
// #6515 changed the per-interface effective set from zone ∪ override to the
// override alone; the grouping property under test is unchanged, and the fixture
// still exercises it — two interfaces with the SAME effective set collapse into
// one view, a third with a different set stays separate.
func Test_3721_EnforcementPreserved(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.0.1/24"}},
		}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.1.1/24"}},
		}},
		"ge-0/0/2": {Name: "ge-0/0/2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trunk": {
			Name:               "trunk",
			Interfaces:         []string{"ge-0/0/0.0", "ge-0/0/1.0", "ge-0/0/2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ping"}},
			InterfaceHostInbound: map[string]*config.HostInboundTraffic{
				"ge-0/0/0.0": {SystemServices: []string{"ssh"}},          // eff {ssh}
				"ge-0/0/1.0": {SystemServices: []string{"ssh"}},          // eff {ssh} (merges with ge-0/0/0.0)
				"ge-0/0/2.0": {SystemServices: []string{"https", "ssh"}}, // eff {https, ssh}
			},
		},
	}

	// #6515: each interface declares its own stanza, so the zone-level `ping`
	// reaches none of them.
	want := map[string]string{
		"10.0.0.1": canonSet([]string{"ssh"}),
		"10.0.1.1": canonSet([]string{"ssh"}),
		"10.0.2.1": canonSet([]string{"https", "ssh"}),
	}
	got := map[string]string{}
	for _, v := range BuildZoneHostInboundViews(cfg) {
		for _, a := range v.V4Addrs {
			got[a] = canonSet(v.SystemServices)
		}
	}
	for addr, wantSet := range want {
		if got[addr] != wantSet {
			t.Errorf("addr %s effective set = %s, want %s", addr, got[addr], wantSet)
		}
	}
	// The two {ssh} interfaces collapse to one view; {https, ssh} stays
	// separate — two address-bearing views for the zone.
	if n := len(countAddrViews(BuildZoneHostInboundViews(cfg), "trunk")); n != 2 {
		t.Errorf("address-bearing views = %d, want 2 (the two identical sets merged)", n)
	}
}

// BenchmarkBuildZoneHostInboundViews exercises a trunk whose units carry
// mostly-identical services in VARYING authored order — the #3721 pathological
// case where the old order-sensitive signature emitted one rule block per unit
// while the canonical signature collapses them to one group. Kept modest
// because the full builder resolves each unit through buildLinkSnapshot
// (netlink), which dominates the wall time; the point is to guard the grouping
// path against a regression, not to microbenchmark netlink.
func BenchmarkBuildZoneHostInboundViews(b *testing.B) {
	const nUnits = 64
	units := make(map[int]*config.InterfaceUnit, nUnits)
	overrides := make(map[string]*config.HostInboundTraffic, nUnits)
	refs := make([]string, 0, nUnits)
	orders := [][]string{{"ssh", "ping", "https"}, {"ping", "https", "ssh"}, {"https", "ssh", "ping"}}
	for i := 0; i < nUnits; i++ {
		units[i] = &config.InterfaceUnit{Number: i, Addresses: []string{fmt.Sprintf("10.%d.%d.1/24", i/256, i%256)}}
		ref := fmt.Sprintf("ge-0/0/0.%d", i)
		overrides[ref] = &config.HostInboundTraffic{SystemServices: orders[i%len(orders)]}
		refs = append(refs, ref)
	}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: units},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trunk": {Name: "trunk", Interfaces: refs, InterfaceHostInbound: overrides},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildZoneHostInboundViews(cfg)
	}
}
