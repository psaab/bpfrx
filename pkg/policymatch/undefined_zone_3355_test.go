package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// undefinedZoneCfg builds a config with zones trust+untrust DEFINED, a
// `from-zone any to-zone untrust` wildcard permit, and a `junos-global` permit.
// It is used to prove that a query naming an UNDEFINED zone matches neither the
// wildcard nor the global tier (#3355), while a defined-zone query still does.
func undefinedZoneCfg() *config.Config {
	permitAny := func(name string) *config.Policy {
		return &config.Policy{
			Name:   name,
			Action: config.PolicyPermit,
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{"any"},
			},
		}
	}
	return &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{FromZone: "any", ToZone: "untrust", Policies: []*config.Policy{permitAny("wild-permit")}},
			},
			GlobalPolicies: []*config.Policy{permitAny("global-permit")},
		},
		Applications: config.ApplicationsConfig{},
	}
}

// TestUndefinedFromZoneNoWildcardMatch mirrors policy.rs's
// `from_id != 0 && to_id != 0` transit guard: a query whose from-zone is not a
// configured zone resolves to the unknown sentinel (id 0) in the runtime and is
// ineligible for the #3090 wildcard tiers. Before #3355 the simulator matched
// the `from-zone any to-zone untrust` rule for ANY from-zone, including a
// typo'd/undefined one.
//
// FAIL-ON-REVERT: removing the zoneKnown guard in Match makes the wildcard
// match (Matched=true, permit), failing the want-default-deny assertion.
func TestUndefinedFromZoneNoWildcardMatch(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "bogus", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("undefined from-zone matched a wildcard/global rule (#3355); res = %+v", res)
	}
	// #8318: verdict unchanged (deny); attribution moved. An undefined FROM
	// zone is the unconditional unzoned-ingress deny, not a default-policy
	// verdict — the runtime denies from_id == 0 without consulting
	// default-policy (#6682). This fixture is deny-all, where the two are
	// indistinguishable by action alone.
	if !res.UnzonedIngress || res.Action != config.PolicyDeny {
		t.Fatalf("want unzoned-ingress deny for an undefined from-zone, got %+v", res)
	}
	if res.DefaultUsed {
		t.Fatalf("an unzoned-ingress deny must not be attributed to default-policy, got %+v", res)
	}
}

// TestUndefinedToZoneNoMatch covers the egress side of the same guard.
func TestUndefinedToZoneNoMatch(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "nowhere", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("undefined to-zone matched (#3355); res = %+v", res)
	}
	if !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("want default-policy deny for an undefined to-zone, got %+v", res)
	}
}

// TestDefinedZoneStillMatchesWildcard is the positive control: the guard must
// NOT over-block a DEFINED zone. trust->untrust is fully defined, so the
// wildcard permit still applies.
func TestDefinedZoneStillMatchesWildcard(t *testing.T) {
	cfg := undefinedZoneCfg()

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("defined zone over-blocked by the #3355 guard; res = %+v", res)
	}
}

// TestNoZonesDefinedNoTransitMatch pins the faithful mirror of policy.rs's
// UNCONDITIONAL `from_id != 0 && to_id != 0` transit gate (policy.rs:1807): a
// config with an EMPTY Security.Zones map resolves every zone name to the
// unknown id 0 in the runtime, so the runtime matches NOTHING in the transit
// tiers. The simulator must agree — there is no empty-Zones leniency. This
// config is built directly (NOT via cfgWith, which injects the standard suite
// zones) so Security.Zones is genuinely empty.
//
// FAIL-ON-REVERT: restoring the `if len(cfg.Security.Zones) == 0 { return true }`
// leniency in zoneKnown makes this trust->untrust query match the permit
// (Matched=true), reintroducing the exact simulator-vs-runtime drift #3355
// closes.
func TestNoZonesDefinedNoTransitMatch(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			// Zones intentionally left nil/empty.
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Policies: []*config.Policy{{
						Name:   "allow-all",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					}},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	res := Match(cfg, Query{FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DstPort: 80})
	if res.Matched {
		t.Fatalf("no-zones config matched a transit rule the runtime would never evaluate (#3355 drift); res = %+v", res)
	}
	// #8318: with NO zones defined, "trust" is unknown on both sides; the FROM
	// check runs first, so this is the unzoned-ingress deny. Verdict unchanged.
	if !res.UnzonedIngress || res.Action != config.PolicyDeny {
		t.Fatalf("want unzoned-ingress deny for a no-zones config, got %+v", res)
	}
}

// TestUndefinedFromZoneJunosHostUnmatched covers matchJunosHost: an undefined
// ingress zone makes evaluate_junos_host_policy return None (from_id == 0), so
// the simulator returns HostInboundUnmatched (local delivery), never a matched
// host rule.
//
// FAIL-ON-REVERT: removing the zoneKnown guard in matchJunosHost makes the
// host rule match (Matched=true), failing the HostInboundUnmatched assertion.
func TestUndefinedFromZoneJunosHostUnmatched(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			DefaultPolicy: config.PolicyDeny,
			Zones:         zones("trust", "untrust"),
			Policies: []*config.ZonePairPolicies{
				{
					FromZone: "any",
					ToZone:   JunosHostZone,
					Policies: []*config.Policy{{
						Name:   "host-permit",
						Action: config.PolicyPermit,
						Match: config.PolicyMatch{
							SourceAddresses:      []string{"any"},
							DestinationAddresses: []string{"any"},
							Applications:         []string{"any"},
						},
					}},
				},
			},
		},
		Applications: config.ApplicationsConfig{},
	}

	res := Match(cfg, Query{FromZone: "bogus", ToZone: JunosHostZone, Protocol: "tcp", DstPort: 22})
	if res.Matched {
		t.Fatalf("undefined ingress zone matched a junos-host rule (#3355); res = %+v", res)
	}
	if !res.HostInboundUnmatched {
		t.Fatalf("want HostInboundUnmatched for an undefined ingress zone, got %+v", res)
	}
}
