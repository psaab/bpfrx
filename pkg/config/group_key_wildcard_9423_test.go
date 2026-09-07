package config

import (
	"sort"
	"strings"
	"testing"
)

// #9423 — a partial-glob group key was adopted VERBATIM as a phantom instance.
//
// `keysContainWildcard` compared each key for exact equality with `"<*>"`, so
// `<ge-*>` was not recognised as a wildcard at all: it fell through to the
// ordinary container path in mergeNodes, matched no destination, and was
// APPENDED. The compiled config gained an interface literally named `<ge-*>`
// carrying the group's content, while the real interface got nothing.
//
// The `<*>` row is the POSITIVE CONTROL that makes every other row a
// measurement of the PATTERN handling rather than of the fixture.

func groupWildcardSrc9423(pattern string) string {
	return `groups { G { interfaces { ` + pattern + ` { description FROM-GROUP; } } } }
apply-groups G;
interfaces {
  ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
  xe-1/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } }
}`
}

func compileWildcard9423(t *testing.T, src string) *Config {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func ifaceNames9423(cfg *Config) []string {
	var names []string
	for n := range cfg.Interfaces.Interfaces {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func TestGroupKeyWildcardNoPhantomInstance9423(t *testing.T) {
	cases := []struct {
		pattern string
		// wantApplied is the set of REAL interfaces the template must reach.
		wantApplied []string
	}{
		{"<*>", []string{"ge-0/0/0", "xe-1/0/0"}}, // POSITIVE CONTROL
		{"<ge-*>", []string{"ge-0/0/0"}},
		{"<*-0/0/0>", []string{"ge-0/0/0"}},
		{"<xe-1/0/0>", []string{"xe-1/0/0"}},
		{"<lo*>", nil}, // matches nothing: applies nothing, invents nothing
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			cfg := compileWildcard9423(t, groupWildcardSrc9423(tc.pattern))

			// (b) NO instance named after the pattern exists.
			for _, n := range ifaceNames9423(cfg) {
				if strings.ContainsAny(n, "<>*") {
					t.Fatalf("a group wildcard was adopted as a PHANTOM instance: "+
						"compiled interfaces = %v — xpfd reconciles the configured "+
						"interface set against the kernel, so an interface that can "+
						"never exist is fed into that (#9423)", ifaceNames9423(cfg))
				}
			}
			if got := ifaceNames9423(cfg); len(got) != 2 {
				t.Fatalf("the authored interfaces must survive unchanged: %v", got)
			}

			// (a) the template reached exactly the interfaces the pattern names.
			applied := map[string]bool{}
			for _, n := range ifaceNames9423(cfg) {
				if cfg.Interfaces.Interfaces[n].Description == "FROM-GROUP" {
					applied[n] = true
				}
			}
			if len(applied) != len(tc.wantApplied) {
				t.Fatalf("pattern %s applied to %v, want %v", tc.pattern, applied, tc.wantApplied)
			}
			for _, want := range tc.wantApplied {
				if !applied[want] {
					t.Fatalf("pattern %s did not reach %s (applied=%v)", tc.pattern, want, applied)
				}
			}
		})
	}
}

// The two-key policy wildcard is the shape docs/junos-config-display-reference.md
// §7.4 documents. It is the regression guard for the `<*>` half: broadening the
// recogniser must not change what the universal token already matched.
func TestGroupKeyWildcardPolicyPairStillMatches9423(t *testing.T) {
	cfg := compileWildcard9423(t, `groups { G { security { policies { from-zone <*> to-zone <*> {
  policy default-deny { match { source-address any; destination-address any; application any; } then { deny; } }
} } } } }
apply-groups G;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security {
  zones { security-zone trust { interfaces { ge-0/0/0.0; } } security-zone untrust; }
  policies { from-zone trust to-zone untrust { policy allow-all { match { source-address any; destination-address any; application any; } then { permit; } } } }
}`)
	var pair *ZonePairPolicies
	for _, p := range cfg.Security.Policies {
		if p.FromZone == "trust" && p.ToZone == "untrust" {
			pair = p
		}
	}
	if pair == nil {
		t.Fatalf("zone pair missing: %d pairs", len(cfg.Security.Policies))
	}
	var names []string
	for _, p := range pair.Policies {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "allow-all" || names[1] != "default-deny" {
		t.Fatalf("the `<*>` policy template did not reach the authored zone pair: %v", names)
	}
}

// A leaf whose key is wildcard-shaped is NOT an instance key and is left alone.
// The zone-member gate (#7029 family) already refuses it loudly, so nothing
// here quietly reinterprets a member as a pattern.
func TestGroupKeyWildcardLeafMemberStillRefused9423(t *testing.T) {
	tree, errs := NewParser(`groups { G { security { zones { security-zone trust { interfaces { <ge-*>; } } } } } }
apply-groups G;
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a wildcard-shaped zone MEMBER was accepted; it is not an instance key " +
			"and must stay loudly refused rather than silently reinterpreted")
	}
	if !strings.Contains(err.Error(), "<ge-*>") {
		t.Fatalf("refused, but the message does not name the token: %v", err)
	}
}

func TestGlobMatch9423(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "ge-0/0/0", true},
		{"*", "", true},
		{"ge-*", "ge-0/0/0", true}, // `*` must cross `/` — path.Match would not
		{"ge-*", "xe-0/0/0", false},
		{"*-0/0/0", "ge-0/0/0", true},
		{"*-0/0/0", "ge-0/0/1", false},
		{"ge-0/0/0", "ge-0/0/0", true},
		{"ge-0/0/0", "ge-0/0/1", false},
		{"*e-*", "xe-1/0/0", true},
		{"**", "anything", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"", "", true},
		{"", "x", false},
		// A `[...]` class is matched LITERALLY: it selects nothing rather than
		// mis-selecting, and either way no phantom is created.
		{"ge-[01]/0/0", "ge-0/0/0", false},
		{"ge-[01]/0/0", "ge-[01]/0/0", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestGroupKeyPattern9423(t *testing.T) {
	cases := []struct {
		key  string
		pat  string
		want bool
	}{
		{"<*>", "*", true},
		{"<ge-*>", "ge-*", true},
		{"<foo>", "foo", true},
		{"ge-0/0/0", "", false},
		{"<>", "", false}, // no room for a pattern
		{"<", "", false},
		{">", "", false},
		{"<a", "", false},
		{"a>", "", false},
	}
	for _, c := range cases {
		pat, ok := groupKeyPattern(c.key)
		if ok != c.want || (ok && pat != c.pat) {
			t.Errorf("groupKeyPattern(%q) = (%q, %v), want (%q, %v)", c.key, pat, ok, c.pat, c.want)
		}
	}
}
