package config

import (
	"strings"
	"testing"
)

// #4233 recorded `security policies policy-rematch [extensive]` on
// SecurityConfig with an accepted-only advisory. #4234 then shipped the
// enforcement in two steps: first the Junos-DEFAULT deletion-clear (a deleted
// policy's sessions dropped at commit, independent of the knob), then the
// modified-policy re-evaluation gated on `policy-rematch` (a surviving policy
// whose match/action changed has its live sessions cleared,
// clearSessionsForModifiedPolicies). With the core enforced, the BARE knob no
// longer warns; only `extensive` — Junos re-evaluates sessions of UNCHANGED
// policies when a referenced object changes, which xpf does not do — keeps an
// advisory. These tests pin that contract. RED on revert: the bare-knob case
// flips back to expecting an advisory, and the extensive advisory loses its
// wording.

// findPolicyRematchExtensiveAdvisory returns the #4234 policy-rematch extensive
// advisory, or "" if none was emitted.
func findPolicyRematchExtensiveAdvisory(cfg *Config) string {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "security policies policy-rematch extensive") &&
			strings.Contains(w, "partially enforced") &&
			strings.Contains(w, "#4234") {
			return w
		}
	}
	return ""
}

// The bare knob must compile (recorded on SecurityConfig, not dropped) AND —
// now that the modified-policy re-eval core ships — emit NO advisory.
func TestPolicyRematchAdvisory_BareEnforcedNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security policies policy-rematch",
	})
	if !cfg.Security.PolicyRematch {
		t.Fatal("policy-rematch did not compile onto Security.PolicyRematch (silent drop)")
	}
	if cfg.Security.PolicyRematchExtensive {
		t.Fatal("bare policy-rematch wrongly set the extensive sub-mode")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy-rematch") {
			t.Fatalf("bare policy-rematch (core enforced) must not warn; got: %q", w)
		}
	}
}

// The extensive sub-mode compiles onto the flag AND still warns: only the
// unchanged-policy-object re-eval remains unenforced.
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
	adv := findPolicyRematchExtensiveAdvisory(cfg)
	if adv == "" {
		t.Fatalf("policy-rematch extensive did not emit the #4234 advisory; warnings=%v", cfg.Warnings)
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
	if adv := findPolicyRematchExtensiveAdvisory(cfg); adv != "" {
		t.Fatalf("unexpected policy-rematch advisory with no stanza: %q", adv)
	}
}
