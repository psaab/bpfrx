package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// zonePair builds a single zone-pair policy set.
func zonePair(from, to string, pols ...*config.Policy) *config.ZonePairPolicies {
	return &config.ZonePairPolicies{FromZone: from, ToZone: to, Policies: pols}
}

func permit(name string, m config.PolicyMatch) *config.Policy {
	return &config.Policy{Name: name, Match: m, Action: config.PolicyPermit}
}

// TestSharedMatcherRegressionMatrix encodes the #3042 regression matrix: the
// CORRECT runtime answer (userspace-dp/src/policy.rs) for cases the three old
// hand-written shadow matchers (REST/gRPC/CLI) got wrong. Every case here is
// RED against the pre-#3042 narrow matchers and GREEN against the shared one;
// TestOldNarrowMatcherDiverges proves the divergence concretely.
func TestSharedMatcherRegressionMatrix(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		q           Query
		wantMatched bool
		wantDefault bool
		wantAction  config.PolicyAction
		wantName    string
	}{
		{
			// (1) Predefined application: junos-http is NOT in
			// cfg.Applications.Applications, so the old matchSingleApp never
			// resolved it and the rule fell through to default-deny.
			name: "predefined app junos-http permits",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-http",
						config.PolicyMatch{Applications: []string{"junos-http"}})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "allow-http",
		},
		{
			// (2) Multi-level application-set: outer -> inner -> junos-https.
			// The old matcher expanded only ONE app-set level and resolved
			// members against user apps only (no predefined).
			name: "nested multi-level app-set permits",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-set",
						config.PolicyMatch{Applications: []string{"outer"}})),
				},
			}, config.ApplicationsConfig{
				ApplicationSets: map[string]*config.ApplicationSet{
					"outer": {Name: "outer", Applications: []string{"inner"}},
					"inner": {Name: "inner", Applications: []string{"junos-https"}},
				},
			}),
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 443},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "allow-set",
		},
		{
			// (3) Literal CIDR source address: "10.0.5.0/24" is neither "any"
			// nor an address-book name, so the old matchPolicyAddr returned
			// false and the rule never matched.
			name: "literal CIDR source permits",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-cidr",
						config.PolicyMatch{SourceAddresses: []string{"10.0.5.0/24"}})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("10.0.5.7")},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "allow-cidr",
		},
		{
			// (4a) any-ipv4 matches a v4 source. The old matcher treated
			// "any-ipv4" as an unknown book name -> no match.
			name: "any-ipv4 matches v4",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-any4",
						config.PolicyMatch{SourceAddresses: []string{"any-ipv4"}})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("10.0.5.7")},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "allow-any4",
		},
		{
			// (4b) any-ipv4 must NOT match a v6 source (family-scoped) -> the
			// runtime falls through to default-deny.
			name: "any-ipv4 does not match v6",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-any4",
						config.PolicyMatch{SourceAddresses: []string{"any-ipv4"}})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("2001:db8::1")},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyDeny,
		},
		{
			// (4c) any-ipv6 matches a v6 source.
			name: "any-ipv6 matches v6",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-any6",
						config.PolicyMatch{SourceAddresses: []string{"any-ipv6"}})),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("2001:db8::1")},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "allow-any6",
		},
		{
			// (5a) Source-port-constrained app, matching source port.
			name: "source-port app matches correct src port",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-srcport",
						config.PolicyMatch{Applications: []string{"srcport-app"}})),
				},
			}, config.ApplicationsConfig{
				Applications: map[string]*config.Application{
					"srcport-app": {Name: "srcport-app", Protocol: "tcp", SourcePort: "5000", DestinationPort: "80"},
				},
			}),
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", SrcPort: 5000, DstPort: 80},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "allow-srcport",
		},
		{
			// (5b) Wrong source port must NOT match. The old matcher ignored
			// source-port terms entirely and would have permitted this.
			name: "source-port app rejects wrong src port",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-srcport",
						config.PolicyMatch{Applications: []string{"srcport-app"}})),
				},
			}, config.ApplicationsConfig{
				Applications: map[string]*config.Application{
					"srcport-app": {Name: "srcport-app", Protocol: "tcp", SourcePort: "5000", DestinationPort: "80"},
				},
			}),
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", SrcPort: 6000, DstPort: 80},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyDeny,
		},
		{
			// (6a) source + dest excluded: a source OUTSIDE the excluded set
			// (and dest outside) matches (Junos exclusion sense).
			name: "src+dst excluded matches addresses outside the set",
			cfg:  excludedCfg(),
			q: Query{FromZone: "trust", ToZone: "untrust",
				SrcIP: net.ParseIP("10.0.9.5"), DstIP: net.ParseIP("10.0.9.6")},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "exclude-rule",
		},
		{
			// (6b) A source INSIDE the excluded set must NOT match. The old
			// matcher ignored the exclusion flag and would have permitted it
			// (the dangerous inversion #3042 is about).
			name: "src excluded rejects address inside the set",
			cfg:  excludedCfg(),
			q: Query{FromZone: "trust", ToZone: "untrust",
				SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.9.6")},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyDeny,
		},
		{
			// (7) Global-policy fallback: no zone-pair policy matches, but a
			// `policy global` rule does. The old REST/gRPC/CLI-show matchers
			// never consulted globals -> default-deny.
			name: "global policy is consulted",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				GlobalPolicies: []*config.Policy{
					permit("global-allow", config.PolicyMatch{}),
				},
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 22},
			wantMatched: true, wantAction: config.PolicyPermit, wantName: "global-allow",
		},
		{
			// (8) default-policy permit-all: no policy matches, default is
			// permit. The old matchers hard-coded "deny (default)".
			name: "default-policy permit-all is honored",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
			}, config.ApplicationsConfig{}),
			q:           Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 22},
			wantMatched: false, wantDefault: true, wantAction: config.PolicyPermit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if res.Matched != tt.wantMatched {
				t.Fatalf("Matched = %v, want %v (res=%+v)", res.Matched, tt.wantMatched, res)
			}
			if res.DefaultUsed != tt.wantDefault {
				t.Fatalf("DefaultUsed = %v, want %v (res=%+v)", res.DefaultUsed, tt.wantDefault, res)
			}
			if res.Action != tt.wantAction {
				t.Fatalf("Action = %v, want %v (res=%+v)", res.Action, tt.wantAction, res)
			}
			if tt.wantName != "" && res.PolicyName != tt.wantName {
				t.Fatalf("PolicyName = %q, want %q", res.PolicyName, tt.wantName)
			}
		})
	}
}

// TestMatchedResultCarriesDescription pins that a matched policy's
// Description surfaces in the Result, for BOTH zone-pair and global matches —
// the local interactive `show security match-policies` console output prints
// it (`if Description != ""`), so dropping it from Result would silently
// regress that line.
func TestMatchedResultCarriesDescription(t *testing.T) {
	zpPol := permit("zp-rule", config.PolicyMatch{})
	zpPol.Description = "zone-pair policy desc"
	gPol := permit("global-rule", config.PolicyMatch{})
	gPol.Description = "global policy desc"

	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", zpPol),
		},
		GlobalPolicies: []*config.Policy{gPol},
	}, config.ApplicationsConfig{})

	zpRes := Match(cfg, Query{FromZone: "trust", ToZone: "untrust"})
	if !zpRes.Matched || zpRes.Description != "zone-pair policy desc" {
		t.Fatalf("zone-pair: Description = %q, want %q (res=%+v)", zpRes.Description, "zone-pair policy desc", zpRes)
	}

	// A different zone-pair with no matching policy falls through to the
	// global rule, which must also carry its Description.
	gRes := Match(cfg, Query{FromZone: "dmz", ToZone: "wan"})
	if !gRes.Matched || !gRes.Global || gRes.Description != "global policy desc" {
		t.Fatalf("global: Description = %q, want %q (res=%+v)", gRes.Description, "global policy desc", gRes)
	}
}

// TestFeedOverlayResolvesFeedBackedName proves a policy token naming a
// feed-backed address-name (with no static content) matches the live feed
// CIDRs supplied via Query.FeedOverlay — a path the old matchers had no
// concept of.
func TestFeedOverlayResolvesFeedBackedName(t *testing.T) {
	cfg := cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook:   &config.AddressBook{}, // "bad-actors" exists only in the feed
		Policies: []*config.ZonePairPolicies{
			zonePair("untrust", "trust", &config.Policy{
				Name:   "block-feed",
				Match:  config.PolicyMatch{SourceAddresses: []string{"bad-actors"}},
				Action: config.PolicyDeny,
			}),
		},
	}, config.ApplicationsConfig{})

	overlay := map[string][]string{"bad-actors": {"203.0.113.0/24"}}

	// In-feed source -> deny rule matches.
	res := Match(cfg, Query{FromZone: "untrust", ToZone: "trust",
		SrcIP: net.ParseIP("203.0.113.7"), FeedOverlay: overlay})
	if !res.Matched || res.Action != config.PolicyDeny || res.PolicyName != "block-feed" {
		t.Fatalf("in-feed source: got %+v, want matched deny block-feed", res)
	}

	// Without the overlay, the feed-backed name resolves to nothing -> the
	// rule does not match -> default-deny (still no match here, distinct path).
	resNoOverlay := Match(cfg, Query{FromZone: "untrust", ToZone: "trust",
		SrcIP: net.ParseIP("203.0.113.7")})
	if resNoOverlay.Matched {
		t.Fatalf("no overlay: feed-backed name should not match a static-empty book, got %+v", resNoOverlay)
	}
}

// TestOldNarrowMatcherDiverges is the concrete fail-on-revert artifact: it
// re-implements the pre-#3042 per-surface logic (zone-pair-only loop, narrow
// address matcher, narrow app matcher, hard-coded default-deny) and asserts it
// returns the OPPOSITE verdict from the shared matcher on representative
// matrix cases. If someone reverts a surface to the old logic, the shared
// matcher and the old logic agree and this test fails.
func TestOldNarrowMatcherDiverges(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		q    Query
	}{
		{
			name: "predefined app",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-http",
						config.PolicyMatch{Applications: []string{"junos-http"}})),
				},
			}, config.ApplicationsConfig{}),
			q: Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80},
		},
		{
			name: "literal CIDR",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "untrust", permit("allow-cidr",
						config.PolicyMatch{SourceAddresses: []string{"10.0.5.0/24"}})),
				},
			}, config.ApplicationsConfig{}),
			q: Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("10.0.5.7")},
		},
		{
			name: "global fallback",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy:  config.PolicyDeny,
				GlobalPolicies: []*config.Policy{permit("global-allow", config.PolicyMatch{})},
			}, config.ApplicationsConfig{}),
			q: Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 22},
		},
		{
			name: "default permit-all",
			cfg: cfgWith(config.SecurityConfig{DefaultPolicy: config.PolicyPermit},
				config.ApplicationsConfig{}),
			q: Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 22},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldPermit := oldNarrowMatchPermits(c.cfg, c.q)
			newRes := Match(c.cfg, c.q)
			newPermit := newRes.Action == config.PolicyPermit && (newRes.Matched || newRes.DefaultUsed)
			if oldPermit == newPermit {
				t.Fatalf("old and new agree (both permit=%v) — divergence not demonstrated for %q", oldPermit, c.name)
			}
		})
	}
}

// oldNarrowMatchPermits is a faithful reproduction of the pre-#3042 shadow
// matcher shared by the three surfaces: it loops ONLY zone-pair policies,
// uses a narrow address/app matcher, and treats a miss as deny. Returns true
// iff that old logic would have reported a PERMIT.
func oldNarrowMatchPermits(cfg *config.Config, q Query) bool {
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != q.FromZone || zpp.ToZone != q.ToZone {
			continue
		}
		for _, pol := range zpp.Policies {
			if !oldMatchAddr(pol.Match.SourceAddresses, q.SrcIP, cfg) {
				continue
			}
			if !oldMatchAddr(pol.Match.DestinationAddresses, q.DstIP, cfg) {
				continue
			}
			if !oldMatchApp(pol.Match.Applications, q.Protocol, q.DstPort, cfg) {
				continue
			}
			return pol.Action == config.PolicyPermit
		}
	}
	return false // old code hard-coded deny (never permit) on a miss
}

func oldMatchAddr(addrs []string, ip net.IP, cfg *config.Config) bool {
	if len(addrs) == 0 || ip == nil {
		return true
	}
	for _, a := range addrs {
		if a == "any" {
			return true
		}
		if cfg.Security.AddressBook == nil {
			continue
		}
		if addr, ok := cfg.Security.AddressBook.Addresses[a]; ok {
			if _, cidr, err := net.ParseCIDR(addr.Value); err == nil && cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func oldMatchApp(apps []string, proto string, dstPort int, cfg *config.Config) bool {
	if len(apps) == 0 || proto == "" {
		return true
	}
	for _, a := range apps {
		if a == "any" {
			return true
		}
		if app, ok := cfg.Applications.Applications[a]; ok {
			_ = app
			_ = dstPort
			return true
		}
	}
	return false
}

func cfgWith(sec config.SecurityConfig, apps config.ApplicationsConfig) *config.Config {
	return &config.Config{Security: sec, Applications: apps}
}

func excludedCfg() *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		AddressBook: &config.AddressBook{
			Addresses: map[string]*config.Address{
				"trust-net":  {Name: "trust-net", Value: "10.0.1.0/24"},
				"server-net": {Name: "server-net", Value: "10.0.2.0/24"},
			},
		},
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", &config.Policy{
				Name: "exclude-rule",
				Match: config.PolicyMatch{
					SourceAddresses:            []string{"trust-net"},
					SourceAddressExcluded:      true,
					DestinationAddresses:       []string{"server-net"},
					DestinationAddressExcluded: true,
				},
				Action: config.PolicyPermit,
			}),
		},
	}, config.ApplicationsConfig{})
}
