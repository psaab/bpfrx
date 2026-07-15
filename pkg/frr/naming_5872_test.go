package frr

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/psaab/xpf/pkg/config"
)

// #5872: the route-filter access-list name derived from an operator-controlled
// prefix-list name must be namespaced, byte-length-bounded, deterministic, and
// collision-checked — not the pre-#5872 `fromPrefixList + "_rf"` concatenation.

// frrTruncate models FRR storing an identifier in a fixed 128-byte buffer: two
// names that share a >=128-byte prefix become the SAME stored token (the
// truncation-collision the bound + hash prevent).
func frrTruncate(s string) string {
	const frrStoredLimit = 128
	if len(s) > frrStoredLimit {
		return s[:frrStoredLimit]
	}
	return s
}

// TestRouteFilterACLNameBoundedAndNamespaced5872 pins the two structural
// guarantees for EVERY generated name: it stays under FRR's identifier limit and
// carries the reserved namespace prefix.
//
// RED on revert: restore `routeFilterACLName` to `prefixList + "_rf"` and the
// 200-char input yields a 204-byte name — the length assertion fails.
func TestRouteFilterACLNameBoundedAndNamespaced5872(t *testing.T) {
	inputs := []string{
		"SHORT",
		"with spaces and.dots",
		strings.Repeat("a", 200),
		strings.Repeat("Z9_", 90), // 270 bytes
	}
	for _, in := range inputs {
		for _, fam := range []string{"ip", "ipv6"} {
			name := routeFilterACLName(in, fam)
			if len(name) > frrACLNameMaxLen {
				t.Errorf("routeFilterACLName(%q,%q) = %q (%d bytes) exceeds bound %d",
					in, fam, name, len(name), frrACLNameMaxLen)
			}
			if len(name) >= 128 {
				t.Errorf("routeFilterACLName(%q,%q) = %d bytes, not below FRR's 128-byte limit", in, fam, len(name))
			}
			if !strings.HasPrefix(name, routeFilterACLNamespace) {
				t.Errorf("routeFilterACLName(%q,%q) = %q missing reserved namespace %q",
					in, fam, name, routeFilterACLNamespace)
			}
			if !utf8.ValidString(name) || strings.ContainsAny(name, " \t\n") {
				t.Errorf("routeFilterACLName(%q,%q) = %q is not a clean single-token identifier", in, fam, name)
			}
		}
	}
}

// TestRouteFilterACLNameNoTruncationCollision5872 pins (b): two DISTINCT long
// prefix-list names that share a 120+ byte prefix must map to DISTINCT names
// that also survive FRR's 128-byte truncation distinct.
//
// RED on revert: `prefixList + "_rf"` makes both names 200+ bytes of identical
// leading 'a's, so frrTruncate collapses them to the same 128-byte token — the
// distinctness assertion fails (and the length bound above already fails).
func TestRouteFilterACLNameNoTruncationCollision5872(t *testing.T) {
	name1 := strings.Repeat("a", 200) + "-alpha"
	name2 := strings.Repeat("a", 200) + "-bravo"
	for _, fam := range []string{"ip", "ipv6"} {
		a := routeFilterACLName(name1, fam)
		b := routeFilterACLName(name2, fam)
		if a == b {
			t.Fatalf("[%s] distinct inputs mapped to the same name %q", fam, a)
		}
		if frrTruncate(a) == frrTruncate(b) {
			t.Fatalf("[%s] names truncate-collide in FRR's 128-byte buffer:\n  %q\n  %q", fam, a, b)
		}
	}
}

// TestRouteFilterACLNameDeterministic5872 pins (e): the name is a pure function
// of (prefixList, family) — identical across repeated calls (daemon restarts),
// with no map-iteration-order or randomness.
func TestRouteFilterACLNameDeterministic5872(t *testing.T) {
	for _, in := range []string{"V6ONLY", strings.Repeat("mixWORD_", 40), "héllo→wörld"} {
		for _, fam := range []string{"ip", "ipv6"} {
			first := routeFilterACLName(in, fam)
			for i := 0; i < 5; i++ {
				if again := routeFilterACLName(in, fam); again != first {
					t.Fatalf("routeFilterACLName(%q,%q) non-deterministic: %q vs %q", in, fam, first, again)
				}
			}
		}
	}
}

// TestRouteFilterACLNameUnicode5872 pins (c): multibyte/unicode input (a
// tolerant-load / peer-sync / rollback value can carry anything) yields a pure
// ASCII, bounded, well-formed identifier, and byte-truncation never splits a
// rune (sanitizeFRRIdent emits ASCII).
func TestRouteFilterACLNameUnicode5872(t *testing.T) {
	in := strings.Repeat("名前→", 60) + "PL" // multibyte, > bound before sanitize
	name := routeFilterACLName(in, "ipv6")
	if len(name) > frrACLNameMaxLen {
		t.Fatalf("unicode input overflowed the bound: %d > %d (%q)", len(name), frrACLNameMaxLen, name)
	}
	for i, r := range name {
		if r >= 0x80 {
			t.Fatalf("generated name has a non-ASCII rune at %d: %q", i, name)
		}
	}
	// sanitizeFRRIdent collapses every non-[A-Za-z0-9_] rune to '_'.
	if got := sanitizeFRRIdent("a b.c/名"); got != "a_b_c__" {
		t.Fatalf("sanitizeFRRIdent(%q) = %q, want %q", "a b.c/名", got, "a_b_c__")
	}
}

// TestRouteFilterACLNameCollisionCheck5872 pins the fail-closed commit guard:
// (a) an operator prefix-list intruding on the reserved namespace is rejected,
// and a normal config passes.
func TestRouteFilterACLNameCollisionCheck5872(t *testing.T) {
	// Reserved-namespace intrusion → error.
	poBad := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			routeFilterACLNamespace + "sneaky": {Name: routeFilterACLNamespace + "sneaky", Prefixes: []string{"10.0.0.0/8"}},
		},
	}
	if err := routeFilterACLNameCollision(poBad); err == nil {
		t.Fatalf("routeFilterACLNameCollision must reject an operator prefix-list in the reserved %q namespace", routeFilterACLNamespace)
	}

	// Normal distinct prefix-lists → no error.
	poOK := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V6ONLY": {Name: "V6ONLY", Prefixes: []string{"2001:db8::/48"}},
			"V4ONLY": {Name: "V4ONLY", Prefixes: []string{"10.0.0.0/8"}},
			"MIXED":  {Name: "MIXED", Prefixes: []string{"10.0.0.0/8", "2001:db8::/48"}},
		},
	}
	if err := routeFilterACLNameCollision(poOK); err != nil {
		t.Fatalf("routeFilterACLNameCollision on a clean config: unexpected error %v", err)
	}
	if err := routeFilterACLNameCollision(nil); err != nil {
		t.Fatalf("routeFilterACLNameCollision(nil): unexpected error %v", err)
	}
}

// TestRouteFilterACLDefinitionMatchesReference5872 pins (d) IPv4 + IPv6 render
// AND (f) definition==reference: for each family the from-prefix-list renders as
// an access-list of the CORRECT FRR type whose DEFINITION name and route-map
// REFERENCE name are byte-identical (and equal the helper output).
func TestRouteFilterACLDefinitionMatchesReference5872(t *testing.T) {
	cases := []struct {
		name        string
		fam         string // "ip" | "ipv6"
		listPrefix  string
		rfPrefix    string
		aclKeyword  string // "access-list" | "ipv6 access-list"
		matchPrefix string // " match ip address " | " match ipv6 address "
	}{
		{"v4", "ip", "10.10.0.0/16", "10.0.0.0/8", "access-list", " match ip address "},
		{"v6", "ipv6", "2001:db8:aaaa::/48", "2001:db8::/32", "ipv6 access-list", " match ipv6 address "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			po := &config.PolicyOptionsConfig{
				PrefixLists: map[string]*config.PrefixList{
					"PL": {Name: "PL", Prefixes: []string{tc.listPrefix}},
				},
				PolicyStatements: map[string]*config.PolicyStatement{
					"P": {
						Name: "P",
						Terms: []*config.PolicyTerm{{
							Name:         "t1",
							Action:       "accept",
							RouteFilters: []*config.RouteFilter{{Prefix: tc.rfPrefix, MatchType: "orlonger"}},
							PrefixList:   []string{"PL"},
						}},
						DefaultAction: "reject",
					},
				},
			}
			got := m.generatePolicyOptions(po)
			want := routeFilterACLName("PL", tc.fam)

			// Reference: a `match <fam> address <NAME>` line whose target is NOT a
			// prefix-list (that is the route-filter's own match).
			refName := extractToken(got, tc.matchPrefix)
			if refName == "" || strings.HasPrefix(refName, "prefix-list") {
				t.Fatalf("no access-list reference in render:\n%s", got)
			}
			// Definition: an `[ipv6 ]access-list <NAME> seq ...` line.
			defName := extractToken(got, tc.aclKeyword+" ")
			if defName == "" {
				t.Fatalf("no access-list definition in render:\n%s", got)
			}
			if refName != defName {
				t.Fatalf("definition name %q != reference name %q (they must agree)", defName, refName)
			}
			if refName != want {
				t.Fatalf("rendered name %q != helper output %q", refName, want)
			}
			if !strings.Contains(got, tc.aclKeyword+" "+want+" seq 5 permit "+tc.listPrefix+" exact-match") {
				t.Fatalf("%s definition missing/malformed for %q:\n%s", tc.aclKeyword, want, got)
			}
		})
	}
}

// TestRouteFilterACLRenderDeterministic5872 pins (e) at the render level: the
// SAME policy-options renders byte-identical output across two calls.
func TestRouteFilterACLRenderDeterministic5872(t *testing.T) {
	m := New()
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"V6ONLY": {Name: "V6ONLY", Prefixes: []string{"2001:db8:ffff::/48"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"MIX": {
				Name: "MIX",
				Terms: []*config.PolicyTerm{{
					Name:         "t1",
					Action:       "accept",
					RouteFilters: []*config.RouteFilter{{Prefix: "2001:db8::/32", MatchType: "orlonger"}},
					PrefixList:   []string{"V6ONLY"},
				}},
				DefaultAction: "reject",
			},
		},
	}
	first := m.generatePolicyOptions(po)
	second := m.generatePolicyOptions(po)
	if first != second {
		t.Fatalf("render is not deterministic across calls:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	if !strings.Contains(first, routeFilterACLName("V6ONLY", "ipv6")) {
		t.Fatalf("render missing the generated ACL name:\n%s", first)
	}
}

// extractToken returns the first whitespace-delimited token that follows prefix
// on any line of s (trimmed), or "" if prefix is absent. For the access-list
// definition keyword it skips the route-filter's own `prefix-list ...` match by
// the caller checking the returned token.
func extractToken(s, prefix string) string {
	for _, line := range strings.Split(s, "\n") {
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len(prefix):])
		if rest == "" {
			continue
		}
		// A ` match <fam> address prefix-list <NAME>` line is the route-filter's
		// own match, not the access-list reference — skip it for the reference
		// lookup so the caller sees only the access-list token.
		if strings.HasPrefix(rest, "prefix-list ") {
			continue
		}
		return strings.Fields(rest)[0]
	}
	return ""
}
