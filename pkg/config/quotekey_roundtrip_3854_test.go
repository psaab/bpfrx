package config

// Round-trip property test for quoteKey ↔ lexer symmetry (#3854,
// fable-review-161 F-005).
//
// quoteKey (ast.go) is the sole quoting function for every Format output
// path (QuotedKeyPath, joinQuotedKeys). The lexer's readString (lexer.go)
// un-escapes exactly three sequences on parse: `\"` -> `"`, `\\` -> `\`,
// and `\n` -> newline. Before #3854 quoteKey escaped only `"`, so any value
// containing a backslash immediately before `n`, `"`, or another backslash
// was CORRUPTED by every Format->Parse cycle: Format emitted the raw
// backslash and the lexer then re-interpreted it. That silently diverged
// the HA standby's config (config sync is Format->wire->Parse — e.g. an IKE
// pre-shared-key `ascii-text` with a backslash) and corrupted rollback
// slots serialized via Format.
//
// The fix makes the emitted escape set EXACTLY match the lexer's decode set
// (`\`, `"`, newline), so Format(Parse(x)) == x and Parse(Format(x)) == x
// for all values. This test asserts that round-trip identity and its
// idempotence over values containing backslashes, quotes, and newlines. It
// goes RED on any revert that drops the backslash (or newline) escape.

import "testing"

// roundTripValues are string leaf values that MUST survive a
// Format->Parse round-trip byte-for-byte. Several are chosen so the raw
// backslash they carry sits immediately before a lexer-significant byte
// (`n`, `"`, `\`) — those are the ones the pre-#3854 quoteKey corrupted, so
// this slice is what makes the test RED on revert.
var roundTripValues = []struct {
	name  string
	value string
}{
	// The issue's IKE PSK example. `\w`/`\b` are lexer default-case bytes,
	// so this particular value happened to survive the old code; kept for
	// provenance coverage.
	{"ike-psk-backslashes", `secret\with\backslashes`},
	// Backslash immediately before 'n': old code emitted `\n`, which the
	// lexer decoded to a literal newline -> corruption (RED on revert).
	{"backslash-before-n", `pass\node`},
	// A realistic IKE PSK whose backslash precedes 'n'.
	{"ike-psk-backslash-n", `P@ss\w0rd\next`},
	// Two consecutive backslashes: old code emitted `\\`, decoded back to a
	// single backslash -> a backslash is silently lost (RED on revert).
	{"double-backslash", `back\\slash`},
	// Backslash immediately before a quote: old code emitted `\` then `\"`,
	// decoded as `\` then string-terminating `"` -> truncation (RED).
	{"backslash-before-quote", `quote\"inside`},
	// A bare embedded quote (handled even by the old code) — regression
	// guard that escaping backslash first did not break quote escaping.
	{"bare-quote", `has"quote`},
	// A literal newline byte. Symmetric under both old and new code (the
	// lexer preserves a literal newline), but the new code emits it as the
	// escaped `\n` — assert it still round-trips to the same newline.
	{"literal-newline", "line1\nline2"},
	// Every special byte at once, plus structural chars that only survive
	// because the value is quoted.
	{"kitchen-sink", "a\\b\"c\nd{e}f;g"},
	// Empty value must stay empty ("" <-> "").
	{"empty", ""},
}

// leafValueTree wraps a value as the trailing key of a single hierarchical
// leaf, mirroring how a real config value (e.g. an IKE pre-shared-key) is
// stored in the AST.
func leafValueTree(value string) *ConfigTree {
	return &ConfigTree{Children: []*Node{
		{Keys: []string{"security"}, Children: []*Node{
			{Keys: []string{"ike"}, Children: []*Node{
				{Keys: []string{"policy", "ike-pol"}, Children: []*Node{
					{Keys: []string{"pre-shared-key", "ascii-text", value}, IsLeaf: true},
				}},
			}},
		}},
	}}
}

// findPSKLeaf walks the tree for the leaf whose first key is
// "pre-shared-key". The parser collapses `pre-shared-key ascii-text
// "value"` onto one leaf's Keys, so the value is that leaf's trailing key.
func findPSKLeaf(nodes []*Node) *Node {
	for _, n := range nodes {
		if len(n.Keys) > 0 && n.Keys[0] == "pre-shared-key" {
			return n
		}
		if found := findPSKLeaf(n.Children); found != nil {
			return found
		}
	}
	return nil
}

// extractLeafValue returns the trailing key of the pre-shared-key leaf, or
// fails the test if the tree shape is not what Format->Parse should yield.
func extractLeafValue(t *testing.T, tree *ConfigTree) string {
	t.Helper()
	node := findPSKLeaf(tree.Children)
	if node == nil {
		t.Fatalf("pre-shared-key leaf not found after round-trip")
	}
	if len(node.Keys) < 2 {
		t.Fatalf("pre-shared-key leaf has too few keys: %v", node.Keys)
	}
	return node.Keys[len(node.Keys)-1]
}

// TestQuoteKeyLexerSymmetry3854 is the unit-level RED signal: the bytes
// quoteKey emits must lex back to the original value. This directly pins
// quoteKey's escape set to the lexer's decode set.
func TestQuoteKeyLexerSymmetry3854(t *testing.T) {
	for _, tc := range roundTripValues {
		if tc.value == "" {
			continue // "" lexes as an empty string token; covered below.
		}
		t.Run(tc.name, func(t *testing.T) {
			quoted := quoteKey(tc.value)
			tok := NewLexer(quoted).Next()
			if tok.Type == TokenError {
				t.Fatalf("quoteKey(%q)=%q lexed to error token %q", tc.value, quoted, tok.Value)
			}
			if tok.Value != tc.value {
				t.Fatalf("quoteKey->lexer not symmetric: quoteKey(%q)=%q lexed back to %q",
					tc.value, quoted, tok.Value)
			}
		})
	}
}

// TestFormatParseRoundTrip3854 is the integration-level assertion over the
// real HA config-sync path: build a tree with a special value, Format it to
// text, and re-Parse the text. The recovered value must be byte-identical.
func TestFormatParseRoundTrip3854(t *testing.T) {
	for _, tc := range roundTripValues {
		t.Run(tc.name, func(t *testing.T) {
			tree := leafValueTree(tc.value)

			text := tree.Format()
			parsed, errs := NewParser(text).Parse()
			if len(errs) != 0 {
				t.Fatalf("Parse(Format(%q)) returned errors %v\nformatted:\n%s", tc.value, errs, text)
			}
			got := extractLeafValue(t, parsed)
			if got != tc.value {
				t.Fatalf("Format->Parse corrupted value: original %q != round-tripped %q\nformatted:\n%s",
					tc.value, got, text)
			}
		})
	}
}

// TestFormatParseIdempotent3854 asserts the round-trip reaches a fixed
// point: Parse(Format(x)) reconstructs a tree whose Format output is stable
// across further cycles. A non-symmetric escape would drift the text on each
// cycle (or fail to parse), so identical Format output across three cycles
// is the idempotence guarantee.
func TestFormatParseIdempotent3854(t *testing.T) {
	for _, tc := range roundTripValues {
		t.Run(tc.name, func(t *testing.T) {
			tree := leafValueTree(tc.value)

			f1 := tree.Format()
			p2, errs := NewParser(f1).Parse()
			if len(errs) != 0 {
				t.Fatalf("cycle 1 parse errors %v\n%s", errs, f1)
			}
			f2 := p2.Format()
			p3, errs := NewParser(f2).Parse()
			if len(errs) != 0 {
				t.Fatalf("cycle 2 parse errors %v\n%s", errs, f2)
			}
			f3 := p3.Format()

			if f1 != f2 {
				t.Fatalf("Format not a fixed point after one round-trip:\n--- f1 ---\n%s\n--- f2 ---\n%s", f1, f2)
			}
			if f2 != f3 {
				t.Fatalf("Format not idempotent across cycles:\n--- f2 ---\n%s\n--- f3 ---\n%s", f2, f3)
			}
		})
	}
}
