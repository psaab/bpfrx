package config

import (
	"strings"
	"testing"
)

// #2396(c): a destination-NAT rule whose `match destination-address` resolves
// to NO parseable host IP (every configured token is malformed) compiles and
// commits, but the snapshot builder skips each bad destination and the Rust
// DNAT table drops the rule — so it silently translates NOTHING with no
// operator feedback. validateDestinationNATAddressesStrict hard-rejects it at
// commit / commit-check, and the tolerant load / peer-sync path downgrades the
// error to a warning (#1960 no-brick).
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

// dnatSet builds a minimal DNAT rule-set with one rule matching the given
// destination-address (raw token) and a valid pool. The from-zone is defined
// to avoid unrelated undefined-zone warnings.
func dnatSet(matchDest string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address " + matchDest,
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

func TestDNATValidDestinationCompiles(t *testing.T) {
	tree := buildTree(t, dnatSet("203.0.113.10"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DNAT rule with a valid destination must compile, got: %v", err)
	}
}

func TestDNATValidDestinationCIDRCompiles(t *testing.T) {
	// A /32 host CIDR is a valid destination (the builder strips the mask).
	tree := buildTree(t, dnatSet("203.0.113.10/32"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a DNAT rule with a /32 destination must compile, got: %v", err)
	}
}

func TestDNATAllInvalidDestinationRejected(t *testing.T) {
	// The only destination is a typo (not an IP) — reject at commit so the
	// operator sees the rule would never translate anything.
	tree := buildTree(t, dnatSet("not-an-ip"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a DNAT rule whose only destination-address is malformed must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination-nat") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "not-an-ip") {
		t.Fatalf("error must name the rule-set/rule + the malformed token, got: %v", err)
	}
}

func TestDNATPartialValidDestinationAccepted(t *testing.T) {
	// One malformed + one valid destination in a bracket list: the valid one
	// still installs (the builder emits an entry for it and skips the typo),
	// so this is NOT a total silent no-op. The gate must NOT reject it.
	//
	// Constructed at the struct level (not via flat-set syntax) because the
	// flat-set parser collapses a `[ a b ]` destination-address list to its
	// first token; the builder/gate operate on DestinationAddresses, which the
	// hierarchical parser and the dataplane snapshot path populate fully.
	cfg := &Config{}
	cfg.Security.NAT.Destination = &DestinationNATConfig{
		Pools: map[string]*NATPool{"dp": {Name: "dp", Address: "10.0.0.5"}},
		RuleSets: []*NATRuleSet{
			{Name: "rs1", FromZone: "untrust", Rules: []*NATRule{
				{
					Name: "r1",
					Match: NATMatch{
						DestinationAddresses: []string{"not-an-ip", "203.0.113.10"},
						DestinationAddress:   "not-an-ip",
					},
					Then: NATThen{Type: NATDestination, PoolName: "dp"},
				},
			}},
		},
	}
	if err := validateDestinationNATAddressesStrict(cfg); err != nil {
		t.Fatalf("a DNAT rule with at least one valid destination must pass the gate, got: %v", err)
	}
}

func TestDNATAllInvalidDestinationLenientWarns(t *testing.T) {
	// Tolerant load / peer-sync must NOT brick on a config that committed
	// before this gate existed — downgrade to a warning instead.
	cfg, err := CompileConfigLenient(buildTree(t, dnatSet("not-an-ip")))
	if err != nil {
		t.Fatalf("lenient load must NOT fail (brick-on-restart), got: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "destination-nat address") {
		t.Fatalf("lenient load must emit a destination-nat warning, warnings=%v", cfg.Warnings)
	}
}
