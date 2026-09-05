package config

import (
	"strings"
	"testing"
)

// #8797: `forwarding-options family inet6 mode` was recorded for exactly one
// spelling — the one nothing produces.
//
// `family` is a compoundKey container, so the address family is the SECOND KEY
// OF THE SAME NODE, and the compiler walked FindChild("family").FindChild(
// "inet6") looking for a child that is not there. Every spelling an operator
// actually writes, INCLUDING flat `set`, left the field empty, so this was
// operator-facing rather than config-file-only.
//
// THE ASSERTION IS THE RECORDED VALUE PER SPELLING, never that the spellings
// agree: before the fix the compound and flat-set spellings agreed perfectly —
// both empty — which is the state the fix exists to end.
func TestInet6ForwardingModeIsRecorded8797(t *testing.T) {
	compile := func(t *testing.T, text string) *Config {
		t.Helper()
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil || cfg == nil {
			t.Fatalf("must COMMIT: %v", err)
		}
		return cfg
	}

	for _, c := range []struct{ name, text, want string }{
		// The compound spelling — what the parser builds from a config file.
		{"compound family inet6", `forwarding-options { family inet6 { mode packet-based; } }`, "packet-based"},
		{"compound family inet6, flow-based", `forwarding-options { family inet6 { mode flow-based; } }`, "flow-based"},
		// The nested spelling. It is the ONLY one that worked before, so it is
		// kept as a regression control: the fix must not trade one shape for
		// the other, which is the failure mode of "handle the new shape".
		{"nested family { inet6 }", `forwarding-options { family { inet6 { mode packet-based; } } }`, "packet-based"},
	} {
		if got := compile(t, c.text).ForwardingOptions.FamilyInet6Mode; got != c.want {
			t.Errorf("%s: FamilyInet6Mode=%q, want %q", c.name, got, c.want)
		}
	}

	// FLAT `set` — a SEPARATE CASE, not an assumed equivalent. CLAUDE.md
	// forbids hierarchical text as a stand-in for a `set` session, and this is
	// the spelling that makes the defect operator-facing rather than a
	// config-file curiosity.
	tree := &ConfigTree{}
	for _, cmd := range []string{"set forwarding-options family inet6 mode packet-based"} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil || cfg == nil {
		t.Fatalf("flat set must COMMIT: %v", err)
	}
	if got := cfg.ForwardingOptions.FamilyInet6Mode; got != "packet-based" {
		t.Errorf("flat `set` FamilyInet6Mode=%q, want %q. This is the spelling the CLI "+
			"produces: an operator typing the documented command had the value silently "+
			"discarded, and `show forwarding-options` then omitted a line the running "+
			"configuration contains", got, "packet-based")
	}

	// ABSENCE CONTROL: without the statement the field stays empty. Without
	// this, a compiler that hard-coded "packet-based" would pass everything
	// above.
	if got := compile(t, `forwarding-options { }`).ForwardingOptions.FamilyInet6Mode; got != "" {
		t.Errorf("no `mode` statement, yet FamilyInet6Mode=%q — want empty", got)
	}

	// THE ADVISORY. `packet-based` is a request the dataplane cannot honour —
	// it is flow-based, with no packet-mode path anywhere — so the operator is
	// told at commit rather than left with a knob that reads as configured.
	warned := func(cfg *Config) bool {
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "family inet6 mode") && strings.Contains(w, "accepted-only") {
				return true
			}
		}
		return false
	}
	if !warned(compile(t, `forwarding-options { family inet6 { mode packet-based; } }`)) {
		t.Error("`mode packet-based` raised no accepted-only advisory. Recording the value " +
			"without saying it changes nothing is worse than dropping it: the operator " +
			"now sees it echoed by `show` and reasonably concludes it took effect")
	}
	// NEGATIVE CONTROL: `flow-based` describes what xpf actually does, so it
	// must NOT warn. A warning that fires on correct configuration trains
	// operators to ignore warnings.
	if warned(compile(t, `forwarding-options { family inet6 { mode flow-based; } }`)) {
		t.Error("`mode flow-based` raised an accepted-only advisory, but flow-based is " +
			"exactly what the dataplane does")
	}
}
