package config

import (
	"strings"
	"testing"
)

// #4233: `security policies policy-rematch [extensive]` was absent from
// setSchema and from compilePolicies' child handling, so it committed clean
// and was silently dropped — an operator who set it believed in-progress
// sessions would be re-evaluated on a policy change, but xpf performs no
// session invalidation on commit at all. Per the #2078 / #2008 H13
// accepted-with-advisory doctrine the knob is now recorded and commit emits
// an accepted-only advisory. These tests pin that the leaf compiles (no
// silent drop) AND that the advisory fires. RED on revert: without the
// compiler/schema/warn wiring the advisory is never emitted.

// findPolicyRematchAdvisory returns the single #4233 policy-rematch advisory,
// or "" if none was emitted.
func findPolicyRematchAdvisory(cfg *Config) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security policies policy-rematch") &&
			strings.Contains(w, "accepted-only") &&
			strings.Contains(w, "#4233") {
			return w
		}
	}
	return ""
}

// The bare knob must compile (recorded on SecurityConfig, not dropped) AND
// emit the accepted-only advisory naming the enforcement follow-up.
func TestPolicyRematchAdvisory_Bare(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security policies policy-rematch",
	})
	if !cfg.Security.PolicyRematch {
		t.Fatal("policy-rematch did not compile onto Security.PolicyRematch (silent drop)")
	}
	if cfg.Security.PolicyRematchExtensive {
		t.Fatal("bare policy-rematch wrongly set the extensive sub-mode")
	}
	adv := findPolicyRematchAdvisory(cfg)
	if adv == "" {
		t.Fatalf("policy-rematch did not emit the #4233 advisory; warnings=%v", cfg.Warnings)
	}
	if !strings.Contains(adv, "#4234") {
		t.Fatalf("advisory does not reference the enforcement issue #4234: %q", adv)
	}
	// A bare knob must NOT claim the extensive sub-mode.
	if strings.Contains(adv, "extensive") {
		t.Fatalf("bare policy-rematch advisory wrongly names extensive: %q", adv)
	}
}

// The extensive sub-mode compiles onto the flag AND is named in the advisory.
func TestPolicyRematchAdvisory_Extensive(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security policies policy-rematch extensive",
	})
	if !cfg.Security.PolicyRematch {
		t.Fatal("policy-rematch extensive did not set Security.PolicyRematch")
	}
	if !cfg.Security.PolicyRematchExtensive {
		t.Fatal("policy-rematch extensive did not set Security.PolicyRematchExtensive")
	}
	adv := findPolicyRematchAdvisory(cfg)
	if adv == "" {
		t.Fatalf("policy-rematch extensive did not emit the #4233 advisory; warnings=%v", cfg.Warnings)
	}
	if !strings.Contains(adv, "extensive") {
		t.Fatalf("extensive advisory does not name the extensive sub-mode: %q", adv)
	}
}

// No policy-rematch stanza: no advisory, no false positive, no nil-deref.
func TestPolicyRematchAdvisory_AbsentNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone trust",
	})
	if cfg.Security.PolicyRematch {
		t.Fatal("PolicyRematch set with no policy-rematch stanza")
	}
	if adv := findPolicyRematchAdvisory(cfg); adv != "" {
		t.Fatalf("unexpected policy-rematch advisory with no stanza: %q", adv)
	}
}
