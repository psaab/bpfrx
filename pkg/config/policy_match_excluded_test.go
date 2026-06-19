package config

import "testing"

// buildPolicyConfig compiles a set-syntax config into a *Config.
func buildPolicyConfig(t *testing.T, setCommands []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}
	return cfg
}

func findPolicy(t *testing.T, cfg *Config, from, to, name string) *Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != from || zpp.ToZone != to {
			continue
		}
		for _, p := range zpp.Policies {
			if p != nil && p.Name == name {
				return p
			}
		}
	}
	t.Fatalf("policy %q (%s->%s) not found in compiled config", name, from, to)
	return nil
}

// TestPolicyMatchAddressExcluded asserts the Junos
// `source-address-excluded` / `destination-address-excluded` match
// modifiers are compiled into PolicyMatch (#2008 H2). Before the fix
// the compiler had no switch case for these tokens, so they were
// silently dropped and the booleans stayed false.
func TestPolicyMatchAddressExcluded(t *testing.T) {
	cfg := buildPolicyConfig(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address blocked 10.0.0.0/8",
		"set security policies from-zone trust to-zone untrust policy excl match source-address blocked",
		"set security policies from-zone trust to-zone untrust policy excl match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address blocked",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl match application any",
		"set security policies from-zone trust to-zone untrust policy excl then permit",
	})
	pol := findPolicy(t, cfg, "trust", "untrust", "excl")
	if !pol.Match.SourceAddressExcluded {
		t.Errorf("SourceAddressExcluded = false, want true")
	}
	if !pol.Match.DestinationAddressExcluded {
		t.Errorf("DestinationAddressExcluded = false, want true")
	}
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "blocked" {
		t.Errorf("SourceAddresses = %v, want [blocked]", pol.Match.SourceAddresses)
	}
}

// TestPolicyMatchAddressExcludedDefaultFalse guards against a stray
// always-true wiring: a normal policy without the modifier must keep
// the excluded flags false.
func TestPolicyMatchAddressExcludedDefaultFalse(t *testing.T) {
	cfg := buildPolicyConfig(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy plain match source-address any",
		"set security policies from-zone trust to-zone untrust policy plain match destination-address any",
		"set security policies from-zone trust to-zone untrust policy plain match application any",
		"set security policies from-zone trust to-zone untrust policy plain then permit",
	})
	pol := findPolicy(t, cfg, "trust", "untrust", "plain")
	if pol.Match.SourceAddressExcluded {
		t.Errorf("SourceAddressExcluded = true on a plain policy, want false")
	}
	if pol.Match.DestinationAddressExcluded {
		t.Errorf("DestinationAddressExcluded = true on a plain policy, want false")
	}
}

// TestPolicyMatchAnyIPv4IPv6Normalize asserts the Junos family-scoped
// wildcards `any-ipv4` / `any-ipv6` are normalized to concrete CIDRs
// at compile time (#2008 H11). Before the fix the tokens passed
// through verbatim and failed CIDR parsing in the dataplane, so a
// policy keyed on `any-ipv4` never matched v4 traffic.
func TestPolicyMatchAnyIPv4IPv6Normalize(t *testing.T) {
	cfg := buildPolicyConfig(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy v4only match source-address any-ipv4",
		"set security policies from-zone trust to-zone untrust policy v4only match destination-address any-ipv6",
		"set security policies from-zone trust to-zone untrust policy v4only match application any",
		"set security policies from-zone trust to-zone untrust policy v4only then permit",
	})
	pol := findPolicy(t, cfg, "trust", "untrust", "v4only")
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "0.0.0.0/0" {
		t.Errorf("SourceAddresses = %v, want [0.0.0.0/0] (any-ipv4 normalized)", pol.Match.SourceAddresses)
	}
	if len(pol.Match.DestinationAddresses) != 1 || pol.Match.DestinationAddresses[0] != "::/0" {
		t.Errorf("DestinationAddresses = %v, want [::/0] (any-ipv6 normalized)", pol.Match.DestinationAddresses)
	}
}

// TestPolicyMatchExcludedSchemaValidates asserts the new schema
// leaves are accepted by SchemaValidate (commit-time validation +
// CLI completion). Before the fix the schema had no
// source-address-excluded / destination-address-excluded children, so
// the path would be flagged as an unknown statement.
func TestPolicyMatchExcludedSchemaValidates(t *testing.T) {
	commands := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy excl match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address-excluded",
		"set security policies global policy g match source-address-excluded",
		"set security policies global policy g match destination-address-excluded",
	}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Errorf("SchemaValidate rejected the excluded match leaves: %v", err)
	}
}
