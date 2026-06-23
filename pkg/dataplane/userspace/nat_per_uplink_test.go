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
	natCounterIDs := map[string]uint32{
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

// TestBuildDestinationNATSnapshotsCarriesSourceAddress is the Go half of the
// #2394 fail-open fix: a DNAT rule scoped to `match source-address` MUST carry
// that constraint into the snapshot so the Rust dataplane can enforce it. Before
// #2394 the compiler parsed source-address but dropped it here, leaving a
// destination-only entry that DNAT'd traffic from any source (fail-open). This
// test FAILS if the carry-through is removed.
func TestBuildDestinationNATSnapshotsCarriesSourceAddress(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*config.NATRuleSet{
			{Name: "scoped", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "scoped-dnat",
					Match: config.NATMatch{
						SourceAddresses:    []string{"198.51.100.0/24", "203.0.113.7/32"},
						DestinationAddress: "203.0.113.20",
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
				{
					// Singular SourceAddress (non-bracket form) must also carry.
					Name: "scoped-dnat-singular",
					Match: config.NATMatch{
						SourceAddress:      "10.1.0.0/16",
						DestinationAddress: "203.0.113.21",
						Protocol:           "tcp",
						DestinationPort:    80,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
				{
					// Unscoped DNAT (no source) must stay empty = match any.
					Name: "open-dnat",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.22",
						Protocol:           "tcp",
						DestinationPort:    8080,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)
	byName := map[string][]string{}
	for _, s := range snaps {
		byName[s.Name] = s.SourceAddresses
	}

	if got := byName["scoped-dnat"]; len(got) != 2 ||
		got[0] != "198.51.100.0/24" || got[1] != "203.0.113.7/32" {
		t.Fatalf("scoped-dnat SourceAddresses = %+v, want bracket list carried (fail-open if dropped)", got)
	}
	if got := byName["scoped-dnat-singular"]; len(got) != 1 || got[0] != "10.1.0.0/16" {
		t.Fatalf("scoped-dnat-singular SourceAddresses = %+v, want singular source carried", got)
	}
	if got := byName["open-dnat"]; len(got) != 0 {
		t.Fatalf("open-dnat SourceAddresses = %+v, want empty (unscoped DNAT = match any source)", got)
	}
}

// TestBuildDestinationNATSnapshotsMultiDestination is the Go half of the #2395
// collapse fix: a DNAT rule with `match destination-address [ A B C ]` MUST
// install a table entry for EVERY published destination, not just the first.
// Before #2395 the builder iterated only the singular DestinationAddress (the
// first list element), so traffic to B and C was forwarded untranslated. This
// test FAILS if the per-destination loop is removed (only one entry emitted).
func TestBuildDestinationNATSnapshotsMultiDestination(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp4": {Name: "dp4", Address: "10.0.0.5"},
			"dp6": {Name: "dp6", Address: "2001:db8:dead::5"},
		},
		RuleSets: []*config.NATRuleSet{
			{Name: "multi", FromZone: "untrust", Rules: []*config.NATRule{
				{
					// Bracket list (v4): all three destinations must DNAT.
					Name: "multi-dnat",
					Match: config.NATMatch{
						DestinationAddresses: []string{
							"203.0.113.20",
							"203.0.113.21/32", // CIDR suffix must be stripped
							"203.0.113.22",
						},
						DestinationAddress: "203.0.113.20", // compiler mirrors first
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp4"},
				},
				{
					// Bracket list combined with a source-address scope (#2394):
					// both source AND each destination must be carried.
					Name: "multi-dnat-scoped",
					Match: config.NATMatch{
						SourceAddresses: []string{"198.51.100.0/24"},
						SourceAddress:   "198.51.100.0/24",
						DestinationAddresses: []string{
							"203.0.113.30",
							"203.0.113.31",
						},
						DestinationAddress: "203.0.113.30",
						Protocol:           "tcp",
						DestinationPort:    80,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp4"},
				},
				{
					// Single destination (non-bracket) must still work.
					Name: "single-dnat",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.40",
						Protocol:           "tcp",
						DestinationPort:    8080,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp4"},
				},
				{
					// IPv6 bracket list.
					Name: "multi-dnat-v6",
					Match: config.NATMatch{
						DestinationAddresses: []string{
							"2001:db8:beef::10",
							"2001:db8:beef::11/128",
						},
						DestinationAddress: "2001:db8:beef::10",
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp6"},
				},
				{
					// All-malformed destination set => fail-closed (no entry),
					// must NOT broaden to match-any.
					Name: "bad-dnat",
					Match: config.NATMatch{
						DestinationAddresses: []string{"not-an-ip", "also/bad"},
						DestinationAddress:   "not-an-ip",
						Protocol:             "tcp",
						DestinationPort:      9999,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp4"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)

	// Collect destination addresses emitted per rule name.
	dstByName := map[string][]string{}
	srcByName := map[string][]string{}
	for _, s := range snaps {
		dstByName[s.Name] = append(dstByName[s.Name], s.DestinationAddress)
		srcByName[s.Name] = s.SourceAddresses
	}

	hasAll := func(got []string, want ...string) bool {
		set := map[string]bool{}
		for _, g := range got {
			set[g] = true
		}
		for _, w := range want {
			if !set[w] {
				return false
			}
		}
		return len(got) == len(want)
	}

	// All three v4 destinations must be installed (collapse bug => only first).
	if got := dstByName["multi-dnat"]; !hasAll(got, "203.0.113.20", "203.0.113.21", "203.0.113.22") {
		t.Fatalf("multi-dnat destinations = %+v, want all three (collapse bug installs only the first)", got)
	}
	// Source-scoped multi-dest: both destinations + the source constraint.
	if got := dstByName["multi-dnat-scoped"]; !hasAll(got, "203.0.113.30", "203.0.113.31") {
		t.Fatalf("multi-dnat-scoped destinations = %+v, want both", got)
	}
	if got := srcByName["multi-dnat-scoped"]; len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("multi-dnat-scoped SourceAddresses = %+v, want #2394 source constraint preserved", got)
	}
	// Single destination still works.
	if got := dstByName["single-dnat"]; !hasAll(got, "203.0.113.40") {
		t.Fatalf("single-dnat destinations = %+v, want single entry", got)
	}
	// IPv6 bracket list.
	if got := dstByName["multi-dnat-v6"]; !hasAll(got, "2001:db8:beef::10", "2001:db8:beef::11") {
		t.Fatalf("multi-dnat-v6 destinations = %+v, want both v6 entries (CIDR stripped)", got)
	}
	// All-malformed => fail-closed (no snapshot rows at all).
	if got := dstByName["bad-dnat"]; len(got) != 0 {
		t.Fatalf("bad-dnat destinations = %+v, want NONE (all-malformed fails closed, not match-any)", got)
	}
}

func srcCounterID(s []SourceNATRuleSnapshot) uint32 {
	if len(s) == 0 {
		return 0
	}
	return s[0].CounterID
}

// TestBuildDestinationNATSnapshotsNonTCPUDP is the Go half of #2396(a)/(b):
// the snapshot builder must carry a non-TCP/UDP protocol (GRE/ICMP) verbatim
// and emit an IP-only rule with an empty protocol + zero port (so the Rust
// table keys it under the protocol wildcard). The Rust side then honors these
// rather than dropping them (see nat::tests::dnat_protocol_gre_translates /
// dnat_ip_only_covers_all_protocols_incl_icmp). This test FAILS if the builder
// rewrites/drops the protocol or the IP-only shape regresses.
func TestBuildDestinationNATSnapshotsNonTCPUDP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp": {Name: "dp", Address: "10.0.0.9"},
		},
		RuleSets: []*config.NATRuleSet{
			{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
				{
					Name: "gre-dnat",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.10",
						Protocol:           "gre",
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
				{
					Name: "icmp-dnat",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.11",
						Protocol:           "icmp",
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
				{
					// IP-only: no protocol, no application, no port.
					Name: "ip-only-dnat",
					Match: config.NATMatch{
						DestinationAddress: "203.0.113.12",
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)
	byName := map[string]DestinationNATRuleSnapshot{}
	for _, s := range snaps {
		byName[s.Name] = s
	}

	if got, ok := byName["gre-dnat"]; !ok || got.Protocol != "gre" {
		t.Fatalf("gre-dnat protocol = %q (present=%v), want gre carried verbatim", got.Protocol, ok)
	}
	if got, ok := byName["icmp-dnat"]; !ok || got.Protocol != "icmp" {
		t.Fatalf("icmp-dnat protocol = %q (present=%v), want icmp carried verbatim", got.Protocol, ok)
	}
	if got, ok := byName["ip-only-dnat"]; !ok || got.Protocol != "" || got.DestinationPort != 0 {
		t.Fatalf("ip-only-dnat = {proto=%q port=%d present=%v}, want {proto=\"\" port=0} (wildcard shape)",
			got.Protocol, got.DestinationPort, ok)
	}
}
