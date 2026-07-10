package config

import (
	"strings"
	"testing"
)

// TestCoSUnknownCodePointStrictVsLenient_5194 is the #5194 A3-b2-F12
// fail-on-revert guard. An UNKNOWN symbolic code-point token (a DSCP typo like
// `af99`, or any non-numeric token on the aliasless PCP side) was silently
// dropped in BOTH the strict and tolerant paths — inconsistent with the numeric
// out-of-range path (#2447/#4953) which rejects at commit and warns on tolerant
// load. The fix gives the typo the SAME treatment: STRICT-reject / LENIENT
// warn-and-drop, for both the classifier and rewrite surfaces, DSCP and PCP.
//
// Fail-on-revert: restore the `return nil, nil` / non-numeric skip in
// expandCoSCodePointToken and the two 802.1p closures, and every strict leg goes
// RED (the config compiles clean instead of rejecting the typo).
func TestCoSUnknownCodePointStrictVsLenient_5194(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		token string
	}{
		{
			name:  "dscp-classifier",
			line:  "set class-of-service classifiers dscp c forwarding-class best-effort loss-priority low code-points af99",
			token: "af99",
		},
		{
			name:  "pcp-classifier",
			line:  "set class-of-service classifiers ieee-802.1 c forwarding-class best-effort loss-priority low code-points foo",
			token: "foo",
		},
		{
			name:  "dscp-rewrite",
			line:  "set class-of-service rewrite-rules dscp r forwarding-class best-effort loss-priority low code-point zzz",
			token: "zzz",
		},
		{
			name:  "pcp-rewrite",
			line:  "set class-of-service rewrite-rules ieee-802.1 r forwarding-class best-effort loss-priority low code-point bar",
			token: "bar",
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

			// Strict commit: hard reject naming the offending token.
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict CompileConfig must reject unknown code-point token %q", tc.token)
			} else if !strings.Contains(err.Error(), tc.token) {
				t.Fatalf("strict error must name the token %q, got: %v", tc.token, err)
			}

			// Tolerant load: must LOAD (no boot blackout) and warn.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient must not fail on a persisted typo code-point: %v", err)
			}
			if cfg == nil {
				t.Fatal("CompileConfigLenient returned nil config")
			}
			if !warningsContain(cfg.Warnings, "class-of-service") {
				t.Fatalf("CompileConfigLenient must record a class-of-service downgrade warning, got: %v", cfg.Warnings)
			}

			// Node-aware tolerant path (HA SyncApply) must also load.
			if _, err := CompileConfigForNodeLenient(tree, 0); err != nil {
				t.Fatalf("CompileConfigForNodeLenient must not fail on a persisted typo code-point: %v", err)
			}
		})
	}
}
