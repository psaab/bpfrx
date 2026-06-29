package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3376 — a fail-closed policy-content rejection reason (#3261 keep-armed path)
// must name the SCOPE-qualified rule identity (from-zone->to-zone/name or
// global/name) plus the offending SIDE and configured object(s), so duplicate
// policy names across distinct zone pairs / global scope are distinguishable and
// the operator can jump straight to the poisoned token instead of hand-auditing
// every source/destination/application.

// dupNamePerZonePairCfg builds two zone pairs each carrying a policy literally
// named "web". Only the trust->dmz/web rule is unrepresentable (it names an
// undefined source-address book); trust->wan/web is fully representable.
func dupNamePerZonePairCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{
		"web-app": {Name: "web-app", Protocol: "tcp", DestinationPort: "443"},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth1"}},
		"wan":   {Name: "wan", Interfaces: []string{"reth0.80"}},
		"dmz":   {Name: "dmz", Interfaces: []string{"reth0.50"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "trust",
			ToZone:   "wan",
			Policies: []*config.Policy{{
				Name: "web",
				Match: config.PolicyMatch{
					SourceAddresses:      []string{"any"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"web-app"},
				},
				Action: config.PolicyPermit,
			}},
		},
		{
			FromZone: "trust",
			ToZone:   "dmz",
			Policies: []*config.Policy{{
				Name: "web",
				Match: config.PolicyMatch{
					// Undefined address book -> unrepresentable -> sentinel.
					SourceAddresses:      []string{"missing-book"},
					DestinationAddresses: []string{"any"},
					Applications:         []string{"web-app"},
				},
				Action: config.PolicyPermit,
			}},
		},
	}
	return cfg
}

func TestPolicyContentRejectionNamesScopeAndObject(t *testing.T) {
	snap, err := buildSnapshot(dupNamePerZonePairCfg(), config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	reasons := snap.Capabilities.PolicyContentRejected
	if len(reasons) != 1 {
		t.Fatalf("PolicyContentRejected = %v, want exactly one reason (only trust->dmz/web is unrepresentable)", reasons)
	}
	got := reasons[0]
	// Scope-qualified identity disambiguates the two "web" policies.
	if !strings.Contains(got, "trust->dmz/web") {
		t.Errorf("reason %q does not name the offending scope trust->dmz/web", got)
	}
	if strings.Contains(got, "trust->wan/web") {
		t.Errorf("reason %q names the GOOD scope trust->wan/web; the bare name was ambiguous and the fix must point only at the poisoned rule", got)
	}
	// Side-specific cause names the exact offending object.
	if !strings.Contains(got, "source-address") || !strings.Contains(got, "missing-book") {
		t.Errorf("reason %q does not name the offending side+object (source-address \"missing-book\")", got)
	}
	// The representable destination side must NOT be blamed.
	if strings.Contains(got, "destination-address") {
		t.Errorf("reason %q blames destination-address, but only the source side is unrepresentable", got)
	}
}

func TestPolicyContentRejectionNamesGlobalScopeAndApplication(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{
		"bad-app": {Name: "bad-app", Protocol: ""}, // protocol-less: unrepresentable
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth1"}},
	}
	cfg.Security.GlobalPolicies = []*config.Policy{{
		Name: "g-rule",
		Match: config.PolicyMatch{
			SourceAddresses:      []string{"any"},
			DestinationAddresses: []string{"any"},
			Applications:         []string{"bad-app"},
		},
		Action: config.PolicyDeny,
	}}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	reasons := snap.Capabilities.PolicyContentRejected
	if len(reasons) != 1 {
		t.Fatalf("PolicyContentRejected = %v, want exactly one reason", reasons)
	}
	got := reasons[0]
	if !strings.Contains(got, "global/g-rule") {
		t.Errorf("reason %q does not render the global scope as global/g-rule", got)
	}
	if !strings.Contains(got, "application") || !strings.Contains(got, "bad-app") {
		t.Errorf("reason %q does not name the offending application bad-app", got)
	}
}

// TestPolicyRejectionScopeRendering pins the scope helper directly across the
// zone-pair, plain-global, and zone-context-global shapes.
func TestPolicyRejectionScopeRendering(t *testing.T) {
	cases := []struct {
		name string
		rule PolicyRuleSnapshot
		want string
	}{
		{"zone-pair", PolicyRuleSnapshot{Name: "p", FromZone: "trust", ToZone: "wan"}, "trust->wan/p"},
		{"global", PolicyRuleSnapshot{Name: "g", FromZone: "junos-global", ToZone: "junos-global"}, "global/g"},
		{"global-ctx", PolicyRuleSnapshot{Name: "g", FromZone: "junos-global", ToZone: "junos-global", MatchFromZone: "trust"}, "global(trust->any)/g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyRejectionScope(&tc.rule); got != tc.want {
				t.Errorf("policyRejectionScope = %q, want %q", got, tc.want)
			}
		})
	}
}
