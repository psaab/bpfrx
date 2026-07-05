package config

import "testing"

// TestFirewallInterfaceSpecificAdvisory pins fable-167 F-3a: interface-specific
// is captured and warned as accepted-but-inert. RED on revert: the token is
// dropped (unknown-keyword ignored) → no field, no advisory.
func TestFirewallInterfaceSpecificAdvisory(t *testing.T) {
	cfg := compileHB167(t, []string{
		"set firewall family inet filter guard interface-specific",
		"set firewall family inet filter guard term t1 then accept",
	})
	filter := cfg.Firewall.FiltersInet["guard"]
	if filter == nil || !filter.InterfaceSpecific {
		t.Fatalf("expected filter guard InterfaceSpecific=true, got %#v", filter)
	}
	if !hasWarningContaining(ValidateConfig(cfg), "interface-specific is accepted for compatibility") {
		t.Fatalf("expected interface-specific advisory, got %v", ValidateConfig(cfg))
	}
}

// TestCoSInetPrecedenceExpAdvisory pins fable-167 F-3b: inet-precedence
// classifiers/rewrite and exp rewrite are captured and warned as inert.
func TestCoSInetPrecedenceExpAdvisory(t *testing.T) {
	cfg := compileHB167(t, []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service classifiers inet-precedence prec-cl forwarding-class best-effort loss-priority low code-points 0",
		"set class-of-service rewrite-rules inet-precedence prec-rw forwarding-class best-effort loss-priority low code-point 0",
		"set class-of-service rewrite-rules exp exp-rw forwarding-class best-effort loss-priority low code-point 0",
		"set system dataplane-type userspace",
	})
	cos := cfg.ClassOfService
	if len(cos.INetPrecedenceClassifiers) == 0 {
		t.Fatal("expected inet-precedence classifier name recorded")
	}
	if len(cos.INetPrecedenceRewriteRules) == 0 {
		t.Fatal("expected inet-precedence rewrite-rule name recorded")
	}
	if len(cos.EXPRewriteRules) == 0 {
		t.Fatal("expected exp rewrite-rule name recorded")
	}
	warnings := ValidateConfig(cfg)
	for _, want := range []string{
		"classifiers inet-precedence is accepted for compatibility but inert",
		"rewrite-rules inet-precedence is accepted for compatibility but inert",
		"rewrite-rules exp is accepted for compatibility but inert",
	} {
		if !hasWarningContaining(warnings, want) {
			t.Fatalf("missing advisory %q in %v", want, warnings)
		}
	}
}
