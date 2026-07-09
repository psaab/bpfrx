package config

import (
	"strings"
	"testing"
)

// buildTree4953 assembles a ConfigTree from flat `set` commands using the
// ParseSetCommand + SetPath loop (the parser merges newline-separated lines,
// so the flat-set path is the only correct way to build a multi-line tree).
func buildTree4953(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// TestFirewallTCPFlagsStrictVsLenient_4953 proves the #4953 fix for the
// firewall `from tcp-flags` reject: an unrepresentable expression (a
// disjunction) is REJECTED on the strict commit path (CompileConfig) but
// DOWNGRADED to a warning (config still loads) on the tolerant load / peer-sync
// path (CompileConfigLenient / CompileConfigForNodeLenient).
//
// Fail-on-revert: re-inline the #3076 reject in compileFirewall (or drop the
// lenientFirewallTCPFlags gating) and the lenient legs go RED — the already-
// persisted config fails to load (boot blackout / HA sync loop), the exact
// regression this fix closes.
func TestFirewallTCPFlagsStrictVsLenient_4953(t *testing.T) {
	lines := []string{
		"set firewall family inet filter f term t from protocol tcp",
		"set firewall family inet filter f term t from tcp-flags \"ack | rst\"",
		"set firewall family inet filter f term t then discard",
		"set system dataplane-type userspace",
	}
	tree := buildTree4953(t, lines)

	// Strict commit: hard reject.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig must reject an unrepresentable tcp-flags disjunction")
	} else if !strings.Contains(err.Error(), "tcp-flags") {
		t.Fatalf("strict error must name tcp-flags, got: %v", err)
	}

	// Tolerant load: must LOAD (no error) and warn.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a persisted bad tcp-flags config (boot blackout): %v", err)
	}
	if cfg == nil {
		t.Fatal("CompileConfigLenient returned nil config for a bad tcp-flags config")
	}
	if !warningsContain(cfg.Warnings, "tcp-flags") {
		t.Fatalf("CompileConfigLenient must record a tcp-flags downgrade warning, got: %v", cfg.Warnings)
	}
	// The term is kept with its raw TCPFlags so the dataplane fails it closed.
	if got := lookupTermTCPFlags(cfg, "f", "t"); len(got) == 0 {
		t.Fatal("leniently-loaded term must retain its raw TCPFlags (deny sentinel), got none")
	}

	// Node-aware tolerant path (HA SyncApply) must also load.
	if _, err := CompileConfigForNodeLenient(tree, 0); err != nil {
		t.Fatalf("CompileConfigForNodeLenient must not fail on a persisted bad tcp-flags config: %v", err)
	}
}

// TestCoSNumericCodePointStrictVsLenient_4953 proves the #4953 fix for the
// class-of-service numeric DSCP/PCP code-point range reject: an out-of-range
// value is REJECTED on the strict commit path but DOWNGRADED to a warning
// (config still loads, offending entry dropped) on the tolerant path.
//
// Fail-on-revert: drop the lenientCoSNumericCodePoint gating (or restore the
// unconditional return) and the lenient legs go RED.
func TestCoSNumericCodePointStrictVsLenient_4953(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		value string
	}{
		{
			name:  "dscp-classifier",
			line:  "set class-of-service classifiers dscp c forwarding-class best-effort loss-priority low code-points 110",
			value: "110",
		},
		{
			name:  "pcp-classifier",
			line:  "set class-of-service classifiers ieee-802.1 c forwarding-class best-effort loss-priority low code-points 9",
			value: "9",
		},
		{
			name:  "dscp-rewrite",
			line:  "set class-of-service rewrite-rules dscp r forwarding-class best-effort loss-priority low code-point 200",
			value: "200",
		},
		{
			name:  "pcp-rewrite",
			line:  "set class-of-service rewrite-rules ieee-802.1 r forwarding-class best-effort loss-priority low code-point 9",
			value: "9",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set class-of-service forwarding-classes queue 0 best-effort",
				tc.line,
				"set system dataplane-type userspace",
			}
			tree := buildTree4953(t, lines)

			// Strict commit: hard reject naming the value + range.
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict CompileConfig must reject out-of-range code-point %s", tc.value)
			} else if !strings.Contains(err.Error(), tc.value) {
				t.Fatalf("strict error must name the value %s, got: %v", tc.value, err)
			}

			// Tolerant load: must LOAD and warn.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient must not fail on a persisted out-of-range code-point (boot blackout): %v", err)
			}
			if cfg == nil {
				t.Fatal("CompileConfigLenient returned nil config")
			}
			if !warningsContain(cfg.Warnings, "class-of-service") {
				t.Fatalf("CompileConfigLenient must record a class-of-service downgrade warning, got: %v", cfg.Warnings)
			}

			// Node-aware tolerant path must also load.
			if _, err := CompileConfigForNodeLenient(tree, 0); err != nil {
				t.Fatalf("CompileConfigForNodeLenient must not fail on a persisted out-of-range code-point: %v", err)
			}
		})
	}
}

func lookupTermTCPFlags(cfg *Config, filter, term string) []string {
	f := cfg.Firewall.FiltersInet[filter]
	if f == nil {
		return nil
	}
	for _, tm := range f.Terms {
		if tm != nil && tm.Name == term {
			return tm.TCPFlags
		}
	}
	return nil
}
