package config

import "testing"

// #4535: a `three-color-policer` with NEITHER `color-blind` nor `color-aware`
// configured must default to COLOR-BLIND mode, matching Junos (which accepts
// and enforces such a policer). Before the fix the compiler left
// ColorBlind=false for the unspecified case; that value drives the userspace
// capability gate (userspaceSupportsThreeColorPolicers) to treat the policer as
// unsupported color-aware mode and disarm the WHOLE dataplane
// (ForwardingSupported=false) — refusing a valid Junos config. Only the
// UNSPECIFIED case changed: explicit color-aware still compiles ColorBlind
// false (its documented unsupported-mode disarm is unchanged), explicit
// color-blind still true.

// compileThreeColorPolicer4535 compiles a single-rate `then discard`
// three-color-policer named p1 whose color statement is `colorLine` (empty for
// the UNSPECIFIED case) and returns the compiled policer. The rate/burst leaves
// keep validateThreeColorPolicersStrict happy so CompileConfig commits cleanly.
func compileThreeColorPolicer4535(t *testing.T, colorLine string) *ThreeColorPolicerConfig {
	t.Helper()
	lines := []string{
		"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
		"set firewall three-color-policer p1 single-rate committed-burst-size 15k",
		"set firewall three-color-policer p1 single-rate excess-burst-size 30k",
		"set firewall three-color-policer p1 then discard",
	}
	if colorLine != "" {
		lines = append(lines, colorLine)
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	pol := cfg.Firewall.ThreeColorPolicers["p1"]
	if pol == nil {
		t.Fatal("three-color-policer p1 missing from compiled config")
	}
	return pol
}

func TestThreeColorPolicerUnspecifiedDefaultsColorBlind4535(t *testing.T) {
	pol := compileThreeColorPolicer4535(t, "")
	// RED on revert: without the #4535 default the unspecified case compiles
	// ColorBlind=false, disarming forwarding.
	if !pol.ColorBlind {
		t.Fatal("unspecified color mode: ColorBlind = false, want true (Junos color-blind default)")
	}
	// The default must NOT masquerade as an explicit configuration: both
	// Configured flags stay false so the color-conflict validator and any
	// future ambiguity check see the true operator intent.
	if pol.ColorBlindConfigured || pol.ColorAwareConfigured {
		t.Fatalf("unspecified color mode must leave both Configured flags false, got blind=%v aware=%v",
			pol.ColorBlindConfigured, pol.ColorAwareConfigured)
	}
}

func TestThreeColorPolicerExplicitColorAwareStaysFalse4535(t *testing.T) {
	pol := compileThreeColorPolicer4535(t, "set firewall three-color-policer p1 single-rate color-aware")
	// Explicit color-aware is unchanged by the default: ColorBlind stays false,
	// which keeps its documented unsupported-mode disarm at the capability gate.
	if pol.ColorBlind {
		t.Fatal("explicit color-aware: ColorBlind = true, want false")
	}
	if !pol.ColorAwareConfigured {
		t.Fatal("explicit color-aware: ColorAwareConfigured = false, want true")
	}
}

func TestThreeColorPolicerExplicitColorBlindStaysTrue4535(t *testing.T) {
	pol := compileThreeColorPolicer4535(t, "set firewall three-color-policer p1 single-rate color-blind")
	if !pol.ColorBlind {
		t.Fatal("explicit color-blind: ColorBlind = false, want true")
	}
	if !pol.ColorBlindConfigured {
		t.Fatal("explicit color-blind: ColorBlindConfigured = false, want true")
	}
}
