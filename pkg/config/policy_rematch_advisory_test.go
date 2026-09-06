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
// clearSessionsForModifiedPolicies). With the core enforced, the BARE knob
// stopped warning.
//
// #8993 then shipped `extensive` as well: changedPolicyRuntimeIDs compares the
// RESOLVED form of each policy, so tightening an address-set or redefining an
// address or application re-evaluates the sessions of every policy that
// references it, even with no policy text changed. So NEITHER knob warns now,
// and this file pins that.
//
// THE EXTENSIVE CELL WAS INVERTED, NOT DELETED, and deliberately so. It used to
// assert the advisory EXISTS; asserting it is ABSENT keeps the same contract
// under measurement rather than dropping the case once it stopped failing. That
// is the same move the bare-knob cell made when its own core landed, one step
// below in this file.

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

// The extensive sub-mode compiles onto BOTH flags and — since #8993 shipped the
// referenced-object re-evaluation — emits NO advisory.
//
// The two flag assertions are the load-bearing half now. Without them this cell
// would pass on a config where `extensive` was never recorded at all: "no
// advisory" is also what an unparsed stanza produces, so the absence of a
// warning proves nothing on its own.
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
	if adv := findPolicyRematchExtensiveAdvisory(cfg); adv != "" {
		t.Fatalf("#8993: `extensive` still warns %q, but the referenced-object "+
			"re-evaluation it said was missing now ships (changedPolicyRuntimeIDs "+
			"-> policyReferencedObjectChanged). An advisory naming a gap that is "+
			"closed tells an operator a capability is absent when it exists.", adv)
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
