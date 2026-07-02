package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3727 — runtime-behavior REFERENCE for the policy-simulator fail-closed
// parity fix (pkg/policymatch). A policy referencing an application-set that
// config.ExpandApplicationSet cannot expand makes the runtime fail the WHOLE
// snapshot closed: either buildSnapshot returns an error (pkg/appid BuildCatalog
// -> buildAppCatalogSnapshot rejects the malformed set, #3438) OR the published
// snapshot carries a non-empty Capabilities.PolicyContentRejected (the
// __unsupported__ sentinel the helper integrity preflight rejects, #3261).
// Either way the dataplane retains its previous-good snapshot / fresh-boots
// default-deny and enforces NONE of the config. This is the exact input the
// simulator now reports as ContentRejected — this test proves the runtime and
// the simulator agree on that input.
func malformedAppSetCfg(applications []string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyPermit
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		// References a member that does not resolve -> ExpandApplicationSet error.
		"bad-set": {Name: "bad-set", Applications: []string{"nonexistent-app"}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth1"}},
		"untrust": {Name: "untrust", Interfaces: []string{"reth0"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "trust",
		ToZone:   "untrust",
		Policies: []*config.Policy{{
			Name: "deny-badset",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         applications,
			},
			Action: config.PolicyDeny,
		}},
	}}
	return cfg
}

func assertRuntimeFailsClosed(t *testing.T, apps []string) {
	t.Helper()
	cfg := malformedAppSetCfg(apps)
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		// buildSnapshot rejected the config outright (BuildCatalog fail-close) —
		// the apply path retains prior state. Fail-closed.
		return
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatalf("apps=%v: buildSnapshot neither errored nor recorded PolicyContentRejected; the runtime did NOT fail closed on a malformed application-set", apps)
	}
}

func TestRuntimeFailsClosedOnMalformedAppSet3727(t *testing.T) {
	// Order-insensitive: bare, before `any`, and after `any` all fail closed at
	// runtime (the pkg/appid BuildCatalog walk is order-insensitive).
	assertRuntimeFailsClosed(t, []string{"bad-set"})
	assertRuntimeFailsClosed(t, []string{"bad-set", "any"})
	assertRuntimeFailsClosed(t, []string{"any", "bad-set"})
}
