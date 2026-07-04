package config

import (
	"strings"
	"testing"
)

// TestFRRPolicyValueControlCharsBlocked_4097 locks in that the #1798 free-text
// control-character defense already covers a `policy-options as-path` regex and
// a `policy-options community` member — the two frr.conf free-text values the
// #4097 report flagged. Both are ordinary AST node values, so the AST walk that
// runs at the top of every compile catches an embedded newline (which the lexer
// materializes from a `\n` escape) BEFORE it can reach the pkg/frr renderer:
//
//   - the STRICT commit path (CompileConfig) hard-rejects it
//     (validateNodesControlChars), so an injecting newline never commits;
//   - the LENIENT load / peer-sync / rollback path (CompileConfigLenient)
//     scrubs it in place (sanitizeNodesControlChars) and boots (#1960), so no
//     newline survives into the typed config the renderer sees.
//
// The render-side belt added in pkg/frr for #4097 (sanitizeFRRValue on the two
// permit lines) is the third, independent layer per the documented #1798 model
// — proven RED-on-revert in pkg/frr. This test guards the first two layers so a
// future refactor cannot silently drop these fields out of that coverage and
// re-open the injection.
func TestFRRPolicyValueControlCharsBlocked_4097(t *testing.T) {
	t.Run("strict commit rejects a newline in an as-path regex", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{`set policy-options as-path evil "^1$\n router bgp 65000\n neighbor 6.6.6.6 remote-as 65000"`})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected strict commit to reject an as-path regex with an embedded newline")
		}
		if !strings.Contains(err.Error(), "as-path evil") || !strings.Contains(err.Error(), "control character") {
			t.Fatalf("error should name the as-path and the control-character class; got: %v", err)
		}
	})

	t.Run("strict commit rejects a newline in a community member", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{`set policy-options community evilc members "65000:100\n router bgp 65000"`})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("expected strict commit to reject a community member with an embedded newline")
		}
		if !strings.Contains(err.Error(), "community evilc") || !strings.Contains(err.Error(), "control character") {
			t.Fatalf("error should name the community and the control-character class; got: %v", err)
		}
	})

	t.Run("lenient load scrubs the newline and boots", func(t *testing.T) {
		tree := buildTreeFromSet(t, []string{`set policy-options as-path evil "^1$\n router bgp 65000"`})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient path must boot (#1960), got error: %v", err)
		}
		if cfg == nil {
			t.Fatal("lenient path returned nil config")
		}
		// The newline must not survive into the typed regex the renderer reads.
		if ap := cfg.PolicyOptions.ASPaths["evil"]; ap != nil {
			if strings.ContainsAny(ap.Regex, "\n\r") {
				t.Fatalf("a control character survived into the leniently-loaded regex: %q", ap.Regex)
			}
		}
		flagged := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "as-path evil") {
				flagged = true
				break
			}
		}
		if !flagged {
			t.Fatalf("expected the tolerant path to flag the scrubbed value; warnings: %v", cfg.Warnings)
		}
	})

	t.Run("a normal as-path with a space and a normal community commit clean", func(t *testing.T) {
		// A legitimate multi-AS regex contains a space; FRR reads it as a
		// rest-of-line token, so it must commit unchanged — proving neither the
		// #1798 gate nor the render belt over-rejects a benign value.
		tree := buildTreeFromSet(t, []string{
			`set policy-options as-path good "^65001 65002$"`,
			"set policy-options community goodc members 65000:100",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("strict commit must accept a normal as-path/community, got: %v", err)
		}
		if ap := cfg.PolicyOptions.ASPaths["good"]; ap == nil || ap.Regex != "^65001 65002$" {
			t.Fatalf("normal as-path regex not preserved: %+v", cfg.PolicyOptions.ASPaths["good"])
		}
	})
}
