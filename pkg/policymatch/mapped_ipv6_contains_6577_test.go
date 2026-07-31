package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6577 fail-on-revert artifacts.
//
// An IPv4-MAPPED IPv6 address (`::ffff:a.b.c.d`) could never match ANY concrete
// IPv6 prefix in the simulator, because net.IPNet.Contains opens with
// `if x := ip.To4(); x != nil { ip = x }` — the mapped address folds to 4 bytes
// and then fails Contains' `len(ip) != len(nn)` length guard against every
// 16-byte v6 prefix, `::/0` included. The dataplane compares UNFOLDED 128-bit
// values (`userspace-dp/src/prefix.rs`: `(u128::from(ip) & self.mask) ==
// self.network`), so a mapped destination matched a v6 DENY on the box while
// the simulator fell through to a later PERMIT.
//
// RED on revert: change `containsAnyV6(v6nets, ip)` back to
// `containsAny(v6nets, ip)` in matchAddr. Every assertion below flips.

// TestMappedIPv6DestMatchesV6DenyPrefix_6577 is the operator-visible shape: a
// DENY scoped to a v6 prefix, followed by a permit-all. The mapped destination
// is inside `::/0`, so the DENY must win — reporting PERMIT here is the
// simulator claiming the box allows traffic it actually drops.
func TestMappedIPv6DestMatchesV6DenyPrefix_6577(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"v6-any": {Name: "v6-any", Value: "::/0"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust",
				&config.Policy{
					Name: "block-v6",
					Match: config.PolicyMatch{
						DestinationAddresses: []string{"v6-any"},
					},
					Action: config.PolicyDeny,
				},
				&config.Policy{
					Name:   "allow-rest",
					Match:  config.PolicyMatch{},
					Action: config.PolicyPermit,
				},
			),
		},
	}, config.ApplicationsConfig{})

	const dstText = "::ffff:198.51.100.9" // IPv4-mapped IPv6 literal

	// Precondition: the fold this fix defends against is real. If net.ParseIP
	// ever stops folding, the whole premise changes and this test should be
	// re-derived rather than silently passing.
	if net.ParseIP(dstText).To4() == nil {
		t.Fatalf("precondition: net.ParseIP(%q).To4() must be non-nil (the fold #6577 closes)", dstText)
	}
	// The colon-strict SSOT classifier routes the literal to the v6 branch —
	// which is exactly where the unfolded compare has to happen.
	if got := config.NATAddrFamily(dstText); got != "v6" {
		t.Fatalf("config.NATAddrFamily(%q) = %q, want v6", dstText, got)
	}

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("2001:db8::1"),
		DstIP:     net.ParseIP(dstText),
		SrcFamily: "v6",
		DstFamily: config.NATAddrFamily(dstText),
	})
	if res.Action != config.PolicyDeny {
		t.Fatalf("mapped dst %q is inside ::/0 so block-v6 must DENY (the dataplane does); got %v via policy %q",
			dstText, res.Action, res.PolicyName)
	}
	if res.PolicyName != "block-v6" {
		t.Fatalf("expected the DENY to be attributed to block-v6, got %q", res.PolicyName)
	}
}

// TestMappedIPv6ContainmentMirrorsRustMask_6577 pins containsAnyV6 directly
// against the boundaries the Rust `(u128 & mask) == network` produces, so a
// future refactor of the helper cannot regress the semantics without tripping
// here even if the policy-level test is restructured.
func TestMappedIPv6ContainmentMirrorsRustMask_6577(t *testing.T) {
	mustNet := func(cidr string) *net.IPNet {
		t.Helper()
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", cidr, err)
		}
		return n
	}

	mapped := net.ParseIP("::ffff:198.51.100.9")
	genuine := net.ParseIP("2001:db8::1")

	cases := []struct {
		cidr string
		ip   net.IP
		want bool
		why  string
	}{
		{"::/0", mapped, true, "mask 0 contains every address, mapped included (Rust: u128 & 0 == 0)"},
		{"::/0", genuine, true, "mask 0 contains a genuine v6 address"},
		{"::ffff:0:0/96", mapped, true, "the mapped range itself covers the address"},
		{"2001:db8::/32", mapped, false, "a disjoint prefix must NOT match — no over-matching"},
		{"2001:db8::/32", genuine, true, "a covering prefix still matches (no regression)"},
	}
	for _, c := range cases {
		got := containsAnyV6([]*net.IPNet{mustNet(c.cidr)}, c.ip)
		if got != c.want {
			t.Errorf("containsAnyV6(%s, %s) = %v, want %v — %s", c.cidr, c.ip, got, c.want, c.why)
		}
	}
}

// TestV4ContainmentUnaffectedByMappedFix_6577 is the over-reach guard. The v4
// branch KEEPS net.IPNet.Contains on purpose: net.ParseIP returns a 16-byte
// 4-in-6 slice for a dotted quad while addCIDRValue stores v4 prefixes 4-byte,
// so the fold is what makes those two widths meet. Applying the unfolded
// compare there would silently break every v4 policy — this pins that it did
// not happen.
func TestV4ContainmentUnaffectedByMappedFix_6577(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"trust-net": {Name: "trust-net", Value: "10.0.1.0/24"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "permit-trust-net",
				Match: config.PolicyMatch{
					DestinationAddresses: []string{"trust-net"},
				},
				Action: config.PolicyPermit,
			}),
		},
	}, config.ApplicationsConfig{})

	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP:     net.ParseIP("10.0.9.9"),
		DstIP:     net.ParseIP("10.0.1.5"),
		SrcFamily: "v4",
		DstFamily: "v4",
	})
	if res.Action != config.PolicyPermit {
		t.Fatalf("ordinary v4 containment must still match (10.0.1.5 in 10.0.1.0/24); got %v via %q",
			res.Action, res.PolicyName)
	}
}
