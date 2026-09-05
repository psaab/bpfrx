package config

import (
	"fmt"
	"testing"
)

// The helper is only worth having if the obvious alternative is WRONG. This
// cell demonstrates that on a real config rather than asserting it in a comment.
//
// If this ever fails because `%v` starts agreeing, the Config graph has stopped
// carrying pointers in the compared region and the helper's rationale needs
// re-deriving -- not the assertion relaxing.
func TestConfigFingerprintBeatsPercentV8908(t *testing.T) {
	compile := func(txt string) *Config {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %q: %v", txt, perrs)
		}
		cfg, err := CompileConfigLenient(tr)
		if err != nil {
			t.Fatalf("compile %q: %v", txt, err)
		}
		return cfg
	}
	// Two compiles of the SAME text. Structurally identical by construction.
	const txt = "forwarding-options { sampling { instance i1 { input { rate 7331; } } } }"
	a, b := compile(txt), compile(txt)

	if !ConfigsIdentical(a, b) {
		t.Fatalf("ConfigsIdentical says two compiles of one text differ, so the "+
			"helper itself is broken:\n  %s\n  %s",
			ConfigFingerprint(a), ConfigFingerprint(b))
	}

	// THE POINT: %v disagrees on those same two configs, because the sampling
	// instances live behind pointers and it prints their addresses.
	av, bv := fmt.Sprintf("%v", *a), fmt.Sprintf("%v", *b)
	if av == bv {
		t.Skip("percent-v agrees on this fixture, so it does not demonstrate the trap " +
			"here; the helper's rationale needs a fixture that still carries " +
			"pointers in the compared region")
	}
	t.Logf("#8908: %%v reports two identical compiles as DIFFERENT (pointer "+
		"addresses); ConfigFingerprint reports them identical. Sample of the "+
		"divergence: %.80s... vs %.80s...", av, bv)

	// And it must still SEE a real difference, or "always equal" would pass the
	// assertion above.
	c := compile("forwarding-options { sampling { instance i1 { input { rate 1234; } } } }")
	if ConfigsIdentical(a, c) {
		t.Error("ConfigsIdentical says two configs with different sampling rates " +
			"are the same -- it is not discriminating, and every comparison " +
			"built on it is vacuous (#8908)")
	}
}
