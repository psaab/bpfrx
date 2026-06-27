package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// zones builds a defined-zone set for globalScopeMatches resolution.
func zones(names ...string) map[string]*config.ZoneConfig {
	out := make(map[string]*config.ZoneConfig, len(names))
	for _, n := range names {
		out[n] = &config.ZoneConfig{Name: n}
	}
	return out
}

// TestWildcardZoneAndScopedGlobalPrecedence pins the #3283 parity fix: the
// simulator must replicate the dataplane precedence chain
// (userspace-dp/src/policy.rs evaluate_policy_result_with_icmp) —
//
//	exact zone-pair -> from-any/to-any single-wildcard (config order) ->
//	both-any -> global (scoped by #3148 match from/to-zone) -> default.
//
// Each case below returns the OPPOSITE verdict on the pre-#3283 simulator,
// which only knew exact-zone-pair -> unconditional-global -> default.
func TestWildcardZoneAndScopedGlobalPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		q          Query
		wantAction config.PolicyAction
		wantName   string // "" => default (no match)
		wantGlobal bool
	}{
		{
			// #3283 example 1: `from-zone any to-zone untrust deny` is invisible
			// to the old simulator, which then reports the default permit.
			name: "from-any wildcard deny beats default permit",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "untrust", deny("block-admin", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "block-admin",
		},
		{
			name: "to-any wildcard deny beats default permit",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("trust", "any", deny("lockdown", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "lockdown",
		},
		{
			name: "both-any wildcard deny beats default permit",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "any", deny("global-block", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "global-block",
		},
		{
			// Exact zone-pair MUST outrank a wildcard, even though the wildcard
			// is configured first.
			name: "exact zone-pair outranks earlier wildcard",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "untrust", deny("wild-deny", config.PolicyMatch{})),
					zonePair("trust", "untrust", permit("exact-permit", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyPermit, wantName: "exact-permit",
		},
		{
			// Single-wildcard tier merges from-any and to-any in config order:
			// `from-zone any to-zone trust deny` configured BEFORE
			// `from-zone untrust to-zone any permit` wins for untrust->trust.
			name: "single-wildcard tier honors config order across from/to-any",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyDeny,
				Zones:         zones("trust", "untrust"),
				Policies: []*config.ZonePairPolicies{
					zonePair("any", "trust", deny("any-to-trust-deny", config.PolicyMatch{})),
					zonePair("untrust", "any", permit("untrust-to-any-permit", config.PolicyMatch{})),
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "untrust", ToZone: "trust"},
			wantAction: config.PolicyDeny, wantName: "any-to-trust-deny",
		},
		{
			// #3283 example 2: a zone-scoped global must NOT apply outside its
			// scope. The old simulator applied every global unconditionally.
			name: "scoped global does NOT apply to non-matching zone",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust", "dmz"),
				GlobalPolicies: []*config.Policy{
					{Name: "scoped-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZone: "trust", ToZone: "untrust"}},
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "dmz", ToZone: "untrust"},
			wantAction: config.PolicyPermit, wantName: "", // falls through to default permit
		},
		{
			name: "scoped global applies to matching zone pair",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust", "dmz"),
				GlobalPolicies: []*config.Policy{
					{Name: "scoped-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZone: "trust", ToZone: "untrust"}},
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "scoped-deny", wantGlobal: true,
		},
		{
			// An unresolved (typo'd / undefined) global scope fails closed —
			// it matches nothing and the verdict is the default.
			name: "undefined global scope fails closed",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust"),
				GlobalPolicies: []*config.Policy{
					{Name: "typo-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZone: "trsut"}}, // typo
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "trust", ToZone: "untrust"},
			wantAction: config.PolicyPermit, wantName: "",
		},
		{
			// An empty/"any" global scope still applies to every zone pair.
			name: "unscoped global applies everywhere",
			cfg: cfgWith(config.SecurityConfig{
				DefaultPolicy: config.PolicyPermit,
				Zones:         zones("trust", "untrust", "dmz"),
				GlobalPolicies: []*config.Policy{
					{Name: "broad-deny", Action: config.PolicyDeny,
						Match: config.PolicyMatch{FromZone: "any"}}, // explicit any
				},
			}, config.ApplicationsConfig{}),
			q:          Query{FromZone: "dmz", ToZone: "untrust"},
			wantAction: config.PolicyDeny, wantName: "broad-deny", wantGlobal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Match(tt.cfg, tt.q)
			if res.Action != tt.wantAction {
				t.Errorf("Action = %v, want %v", res.Action, tt.wantAction)
			}
			if tt.wantName == "" {
				if res.Matched {
					t.Errorf("expected default (no match), got policy %q", res.PolicyName)
				}
				return
			}
			if !res.Matched {
				t.Errorf("expected match %q, got default", tt.wantName)
			}
			if res.PolicyName != tt.wantName {
				t.Errorf("PolicyName = %q, want %q", res.PolicyName, tt.wantName)
			}
			if res.Global != tt.wantGlobal {
				t.Errorf("Global = %v, want %v", res.Global, tt.wantGlobal)
			}
		})
	}
}
