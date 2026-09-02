package config

import "testing"

// #8329: a source-NAT rule naming an UNDEFINED pool reported as ARMED.
//
// SourceNATRuleNotInstalledReason short-circuited on a map miss and returned
// "" — the value meaning "nothing is wrong" — while the snapshot builder marks
// exactly that rule unusable with the reason token "missing_pool"
// (dataplane/userspace/nat_source.go:98-102). A surface disagreeing with the
// builder is the #6534 defect, and this occurred inside the composition
// written to prevent it.
//
// THE FIXTURE MUST COMPILE LENIENTLY, and that is not a stylistic choice.
// CompileConfig (strict) REFUSES an undefined pool reference, so a strict
// fixture cannot construct the state at all and a strict test would pass on
// the broken code by never reaching the branch — the fixture-cannot-enter-the-
// state trap, guaranteed here rather than merely likely.
//
// Lenient is the stored-config load and HA peer-sync path: a node that booted
// from disk, or took a config from its peer. That is exactly where a config
// arrives without strict re-validation, and where the operator has no other
// signal that the rule is dead.

func natRuleSets8329(poolLine ...string) []string {
	base := []string{
		"set security nat source rule-set S from zone trust",
		"set security nat source rule-set S to zone untrust",
		"set security nat source rule-set S rule R match source-address 10.0.61.0/24",
	}
	return append(base, poolLine...)
}

func sourceRule8329(t *testing.T, cfg *Config) *NATRule {
	t.Helper()
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		t.Fatal("no source NAT compiled")
	}
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			if r.Name == "R" {
				return r
			}
		}
	}
	t.Fatal("rule R not found in the compiled config")
	return nil
}

func TestSourceNATRuleWithUndefinedPoolIsNotArmed8329(t *testing.T) {
	// The strict path cannot build this state — asserted, not assumed,
	// because it is the reason the lenient fixture below is mandatory.
	strictTree := buildTreeFromSet(t, natRuleSets8329(
		"set security nat source rule-set S rule R then source-nat pool ghost"))
	if _, err := CompileConfig(strictTree); err == nil {
		t.Fatal("CompileConfig ACCEPTED a rule naming an undefined pool; if strict now " +
			"permits this, the lenient-only framing of this test is stale and the " +
			"reachability argument needs re-deriving")
	}

	tree := buildTreeFromSet(t, natRuleSets8329(
		"set security nat source rule-set S rule R then source-nat pool ghost"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	rule := sourceRule8329(t, cfg)
	if cfg.Security.NAT.SourcePools["ghost"] != nil {
		t.Fatal("setup: the pool must NOT exist, or this tests nothing")
	}

	got := SourceNATRuleNotInstalledReason(cfg, rule)
	if got == "" {
		t.Error("a rule naming an undefined pool reports as ARMED; the builder marks it " +
			"unusable with \"missing_pool\", so every #7473 surface renders a dead rule " +
			"as installed")
	}
	// The token must be the BUILDER's, not a new one. Two vocabularies for one
	// verdict is how the renderer and the builder drift apart again.
	if got != "missing_pool" {
		t.Errorf("reason = %q, want %q — the token the snapshot builder sets", got, "missing_pool")
	}
	// And it must expand to operator prose rather than leaking the token.
	if txt := SourceNATDisarmReasonText(got); txt != "references an undefined pool" {
		t.Errorf("SourceNATDisarmReasonText(%q) = %q, want operator prose", got, txt)
	}
}

// TestInterfaceModeRuleStaysArmed8329 is the control that matters most.
//
// The empty-pool-name arm shares an exit with the branch fixed above and means
// the OPPOSITE thing: an interface-mode rule legitimately has no pool and IS
// armed. Conflating the two would disarm every interface-mode source-NAT rule
// in the tree — a far larger population than the one being fixed, and a
// regression that renders working NAT as dead.
func TestInterfaceModeRuleStaysArmed8329(t *testing.T) {
	tree := buildTreeFromSet(t, natRuleSets8329(
		"set security nat source rule-set S rule R then source-nat interface"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	rule := sourceRule8329(t, cfg)
	if rule.Then.PoolName != "" {
		t.Fatalf("setup: interface-mode rule has PoolName %q; the control is not "+
			"exercising the empty-pool-name arm", rule.Then.PoolName)
	}
	if got := SourceNATRuleNotInstalledReason(cfg, rule); got != "" {
		t.Errorf("an interface-mode rule reports NOT INSTALLED (%q); interface-mode "+
			"source NAT has no pool to be unusable and is armed", got)
	}
}

// TestDefinedUsablePoolStaysArmed8329 is the other control: a rule naming a
// pool that exists and is usable must still be armed. Without it, "an
// undefined pool is not armed" is satisfied by a predicate that disarms
// everything.
func TestDefinedUsablePoolStaysArmed8329(t *testing.T) {
	tree := buildTreeFromSet(t, natRuleSets8329(
		"set security nat source pool p1 address 203.0.113.1/32",
		"set security nat source rule-set S rule R then source-nat pool p1"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	rule := sourceRule8329(t, cfg)
	if cfg.Security.NAT.SourcePools["p1"] == nil {
		t.Fatal("setup: pool p1 must exist for this control to mean anything")
	}
	if got := SourceNATRuleNotInstalledReason(cfg, rule); got != "" {
		t.Errorf("a rule naming a defined, usable pool reports NOT INSTALLED (%q)", got)
	}
}
