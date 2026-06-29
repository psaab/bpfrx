package config

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// filter_protocol_rust_mirror_3393_test.go is the #3393 cross-language drift
// guard for the firewall-filter protocol gate. It follows the established
// Go<->Rust source-parsing parity pattern (host_inbound_rust_parity_test.go,
// pkg/dataplane/retirement_boundary_canary_test.go) and reuses its helpers
// (rustSection / rustStringRe / assertSameSet, defined in
// host_inbound_rust_parity_test.go).
//
// The Rust dataplane test
// userspace-dp/src/filter/tests.rs::filter_protocol_accept_set_subset_of_resolver
// enumerates a HARDCODED mirror of the named tokens this Go commit gate
// (filterProtocolResolvable) accepts, and asserts each resolves through
// ip_proto::proto_number — proving the gate-accepted set is representable by the
// dataplane (the commit/apply parity invariant, the #1961 / #3393 class).
//
// That Rust list is hand-maintained: on its own it CANNOT notice a NAMED
// protocol being ADDED to (or removed from) filterProtocolResolvable here — its
// `for token in [...]` loop only iterates the tokens it already lists, so a new
// Go arm would simply go un-exercised, leaving the Rust mirror silently stale.
// This test closes that hole MECHANICALLY: it parses the literal named-token set
// out of BOTH the Go gate source (filterProtocolResolvable's switch arms in
// compiler_validate_strict.go) and the Rust mirror's `for token in [...]` array,
// and asserts the two sets are identical. Add or remove a named protocol on
// either side without the matching change on the other and this goes RED,
// naming the offending token(s).
//
// Numeric tokens (0..=255) and the empty/whitespace forms are out of scope: they
// are handled uniformly by both gate and resolver and covered by behavioral
// tests, not enumerated token-by-token. This guard pins only the NAMED alias
// set, which is what the Rust mirror lists.

const filterProtocolRustSource = "../../userspace-dp/src/filter/tests.rs"

func TestFilterProtocolNamedSetMatchesRustMirror(t *testing.T) {
	goSet := parseGoFilterProtocolNamedSet(t)

	raw, err := os.ReadFile(filterProtocolRustSource)
	if err != nil {
		t.Fatalf("reading Rust filter mirror %s: %v", filterProtocolRustSource, err)
	}
	src := rustStripComments(string(raw))
	// The named tokens live in the `for token in [ ... ]` array of the mirror
	// test. Anchor on the test fn first so a rename of the test cannot silently
	// turn this into a no-op, then carve out the array body.
	fnSection := rustSection(t, src,
		"fn filter_protocol_accept_set_subset_of_resolver(", "proto_number(token).is_some()")
	arraySection := rustSection(t, fnSection, "for token in [", "]")
	rustSet := map[string]bool{}
	for _, lit := range rustStringRe.FindAllStringSubmatch(arraySection, -1) {
		tok := lit[1]
		if isNumericProtoToken(tok) {
			continue // numeric arm handled uniformly; not part of the named set
		}
		rustSet[tok] = true
	}

	// Sanity: every token we parsed out of the Go gate source must actually be
	// accepted by filterProtocolResolvable. This proves the parser locked onto
	// the right switch (a broken parser that grabbed unrelated quoted strings
	// would trip here rather than silently weakening the set-equality below).
	for tok := range goSet {
		if !filterProtocolResolvable(tok) {
			t.Errorf("parsed Go token %q is not accepted by filterProtocolResolvable — "+
				"the source parser locked onto the wrong span", tok)
		}
	}

	assertSameSet(t,
		"filter protocol named set (filterProtocolResolvable vs Rust mirror "+
			"filter_protocol_accept_set_subset_of_resolver)",
		goSet, rustSet)
}

// parseGoFilterProtocolNamedSet extracts the NAMED (non-numeric) tokens
// filterProtocolResolvable accepts by reading its switch arms from the Go source
// (compiler_validate_strict.go in this package). It anchors on the function
// signature and collects quoted strings up to the `default:` arm (the numeric
// fallthrough), so it captures exactly the named case labels.
func parseGoFilterProtocolNamedSet(t *testing.T) map[string]bool {
	t.Helper()
	const src = "compiler_validate_strict.go"
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	// The named arms run from the function signature down to its `default:`
	// arm. rustStripComments is language-agnostic line-comment stripping (Go
	// and Rust share `//`), so a `"token"` mentioned in a comment cannot leak in.
	section := rustSection(t, rustStripComments(string(data)),
		"func filterProtocolResolvable(token string) bool {", "default:")

	set := map[string]bool{}
	for _, lit := range rustStringRe.FindAllStringSubmatch(section, -1) {
		tok := lit[1]
		if isNumericProtoToken(tok) {
			continue
		}
		set[tok] = true
	}
	if len(set) == 0 {
		t.Fatalf("parsed zero named tokens from filterProtocolResolvable in %s — parser broke", src)
	}
	return set
}

func isNumericProtoToken(tok string) bool {
	_, err := strconv.Atoi(strings.TrimSpace(tok))
	return err == nil
}
