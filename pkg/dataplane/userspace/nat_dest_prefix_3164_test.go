package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3164: a DNAT `match destination-address` that is a non-host prefix must be
// carried to the wire as a prefix (DestinationPrefix = canonical masked CIDR,
// DestinationAddress = the network base), while a host destination (bare IP,
// /32, /128) leaves DestinationPrefix empty and keys the exact-host fast path.
//
// FAIL-ON-REVERT: revert buildDestinationNATSnapshots to strip the mask and emit
// only the base host (the pre-#3164 behavior) and the prefix assertions go RED
// (DestinationPrefix is empty, the /24 collapses to a single host).
func TestBuildDestinationNATSnapshotsPrefix(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp4": {Name: "dp4", Address: "10.0.0.5"},
			"dp6": {Name: "dp6", Address: "2001:db8:dead::5"},
		},
		RuleSets: []*config.NATRuleSet{
			{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{
				{
					// Mixed list: two hosts + a /24 + a non-canonical /24.
					Name: "mixed",
					Match: config.NATMatch{
						DestinationAddresses: []string{
							"203.0.113.5",     // bare host
							"203.0.113.6/32",  // explicit host mask
							"192.0.2.0/24",    // canonical block
							"198.51.100.7/24", // non-canonical block -> normalized base
						},
						DestinationAddress: "203.0.113.5",
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp4"},
				},
				{
					// IPv6 /64 block.
					Name: "v6block",
					Match: config.NATMatch{
						DestinationAddress: "2001:db8:beef::/64",
						Protocol:           "tcp",
						DestinationPort:    443,
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp6"},
				},
			}},
		},
	}

	snaps := buildDestinationNATSnapshots(cfg, nil)

	type addrPrefix struct{ addr, prefix string }
	got := map[string][]addrPrefix{}
	for _, s := range snaps {
		got[s.Name] = append(got[s.Name], addrPrefix{s.DestinationAddress, s.DestinationPrefix})
	}

	has := func(name, addr, prefix string) bool {
		for _, ap := range got[name] {
			if ap.addr == addr && ap.prefix == prefix {
				return true
			}
		}
		return false
	}

	// Hosts: empty DestinationPrefix.
	if !has("mixed", "203.0.113.5", "") {
		t.Fatalf("bare host must emit empty DestinationPrefix, got %+v", got["mixed"])
	}
	if !has("mixed", "203.0.113.6", "") {
		t.Fatalf("/32 host must emit empty DestinationPrefix, got %+v", got["mixed"])
	}
	// Canonical /24: base + canonical CIDR.
	if !has("mixed", "192.0.2.0", "192.0.2.0/24") {
		t.Fatalf("a /24 destination must carry DestinationPrefix, got %+v", got["mixed"])
	}
	// Non-canonical /24: normalized to the network base + canonical CIDR.
	if !has("mixed", "198.51.100.0", "198.51.100.0/24") {
		t.Fatalf("a non-canonical /24 must normalize base+prefix, got %+v", got["mixed"])
	}
	// IPv6 /64.
	if !has("v6block", "2001:db8:beef::", "2001:db8:beef::/64") {
		t.Fatalf("a /64 v6 destination must carry DestinationPrefix, got %+v", got["v6block"])
	}
}

// TestDNATDestinationPartsClassification unit-tests the host-vs-prefix split.
func TestDNATDestinationPartsClassification(t *testing.T) {
	cases := []struct {
		raw    string
		base   string
		prefix string
		ok     bool
	}{
		{"203.0.113.5", "203.0.113.5", "", true},
		{"203.0.113.5/32", "203.0.113.5", "", true},
		{"2001:db8::1", "2001:db8::1", "", true},
		{"2001:db8::1/128", "2001:db8::1", "", true},
		{"192.0.2.0/24", "192.0.2.0", "192.0.2.0/24", true},
		{"192.0.2.5/24", "192.0.2.0", "192.0.2.0/24", true},
		{"2001:db8:beef::/64", "2001:db8:beef::", "2001:db8:beef::/64", true},
		{"not-an-ip", "", "", false},
		{"also/bad", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		base, prefix, ok := dnatDestinationParts(c.raw)
		if ok != c.ok || base != c.base || prefix != c.prefix {
			t.Errorf("dnatDestinationParts(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.raw, base, prefix, ok, c.base, c.prefix, c.ok)
		}
	}
}
