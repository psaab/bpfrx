package config

import (
	"reflect"
	"testing"
)

// #5181 RED-on-revert: an application-set member leaf (`application` /
// `application-set` under `applications application-set <name>`) collapses a
// bracketed member list `application [ a b c ]` onto ONE leaf's Keys per the
// #2419 dual-shape pattern (Keys=["application","a","b","c"] — the lexer strips
// the brackets). compileApplications previously read only member.Keys[1] via
// nodeVal, compiling just the first member and silently dropping the rest.
// Because a security policy resolves an application-set through
// ExpandApplicationSet, the truncated set matched only the first application —
// a DENY policy therefore under-matched (fail-open), covering app1 but not
// app2/app3. This is the applications-side analogue of the #4791 address-set
// fix, which did NOT cover applications.
//
// IMPORTANT (per CLAUDE.md): flat-set syntax is built with ParseSetCommand +
// tree.SetPath, never NewParser (which merges all set lines into one node).
func setTree5181(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestApplicationSetBracketListFlatSetKeepsAllMembers exercises the flat-set
// (dual-AST) shape: a bracketed `application [ app1 app2 app3 ]` member list
// must record all three members, not just app1.
func TestApplicationSetBracketListFlatSetKeepsAllMembers(t *testing.T) {
	tree := setTree5181(t,
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application app2 protocol tcp destination-port 443",
		"set applications application app3 protocol tcp destination-port 22",
		"set applications application-set X application [ app1 app2 app3 ]",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	set := cfg.Applications.ApplicationSets["X"]
	if set == nil {
		t.Fatalf("application-set X missing from compiled applications")
	}
	want := []string{"app1", "app2", "app3"}
	if !reflect.DeepEqual(set.Applications, want) {
		t.Fatalf("application-set X members = %v, want %v (bracket-list tail dropped — #5181)",
			set.Applications, want)
	}
}

// TestApplicationSetBracketListHierarchicalKeepsAllMembers exercises the
// hierarchical (braced) AST shape produced by NewParser, confirming the
// dual-shape helper handles both shapes.
func TestApplicationSetBracketListHierarchicalKeepsAllMembers(t *testing.T) {
	input := `
applications {
    application app1 {
        protocol tcp;
        destination-port 80;
    }
    application app2 {
        protocol tcp;
        destination-port 443;
    }
    application app3 {
        protocol tcp;
        destination-port 22;
    }
    application-set X {
        application [ app1 app2 app3 ];
    }
}
`
	p := NewParser(input)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	set := cfg.Applications.ApplicationSets["X"]
	if set == nil {
		t.Fatalf("application-set X missing from compiled applications")
	}
	want := []string{"app1", "app2", "app3"}
	if !reflect.DeepEqual(set.Applications, want) {
		t.Fatalf("application-set X members = %v, want %v (bracket-list tail dropped — #5181)",
			set.Applications, want)
	}
}

// TestApplicationSetNestedSetBracketListKeepsAllMembers mirrors the primary
// case for the nested `application-set` member branch, which has the identical
// Keys[1]-only truncation bug.
func TestApplicationSetNestedSetBracketListKeepsAllMembers(t *testing.T) {
	tree := setTree5181(t,
		"set applications application a protocol tcp destination-port 1",
		"set applications application b protocol tcp destination-port 2",
		"set applications application c protocol tcp destination-port 3",
		"set applications application-set INNER1 application a",
		"set applications application-set INNER2 application b",
		"set applications application-set INNER3 application c",
		"set applications application-set OUTER application-set [ INNER1 INNER2 INNER3 ]",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	outer := cfg.Applications.ApplicationSets["OUTER"]
	if outer == nil {
		t.Fatalf("application-set OUTER missing from compiled applications")
	}
	want := []string{"INNER1", "INNER2", "INNER3"}
	if !reflect.DeepEqual(outer.Applications, want) {
		t.Fatalf("application-set OUTER nested members = %v, want %v (bracket-list tail dropped — #5181)",
			outer.Applications, want)
	}
	// The nested members must further expand to every leaf application, which
	// is what the runtime resolveUserspaceApplicationNames consumes to arm the
	// dataplane (ExpandApplicationSet). Pre-fix only INNER1→a survived.
	expanded, err := ExpandApplicationSet("OUTER", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(OUTER): %v", err)
	}
	for _, leaf := range []string{"a", "b", "c"} {
		if !contains(expanded, leaf) {
			t.Fatalf("expand(OUTER) = %v, missing %q (nested bracket-list tail dropped — #5181)",
				expanded, leaf)
		}
	}
}

// TestApplicationSetBracketPolicyDenyCoversAllMembers is the security crux of
// #5181: a DENY policy referencing a bracket-list application-set must match
// every member, not just app1. The runtime arms the dataplane by expanding the
// referenced set via ExpandApplicationSet; pre-fix the set truncated to app1,
// so deny traffic for app2/app3 was let through (fail-open under-match).
func TestApplicationSetBracketPolicyDenyCoversAllMembers(t *testing.T) {
	tree := setTree5181(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application app2 protocol tcp destination-port 443",
		"set applications application app3 protocol tcp destination-port 22",
		"set applications application-set BLOCKSET application [ app1 app2 app3 ]",
		"set security policies from-zone trust to-zone untrust policy deny-block match source-address any",
		"set security policies from-zone trust to-zone untrust policy deny-block match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-block match application BLOCKSET",
		"set security policies from-zone trust to-zone untrust policy deny-block then deny",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	expanded, err := ExpandApplicationSet("BLOCKSET", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(BLOCKSET): %v", err)
	}
	want := []string{"app1", "app2", "app3"}
	if !reflect.DeepEqual(expanded, want) {
		t.Fatalf("deny policy application-set expands to %v, want %v — app2/app3 escape the deny (#5181)",
			expanded, want)
	}
}

// TestApplicationSetSingleMember is the negative control: a single
// (non-bracketed) member must still compile to exactly one entry, proving the
// full-value extractor does not over-collapse or duplicate.
func TestApplicationSetSingleMember(t *testing.T) {
	tree := setTree5181(t,
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application-set X application app1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	set := cfg.Applications.ApplicationSets["X"]
	if set == nil {
		t.Fatalf("application-set X missing from compiled applications")
	}
	if want := []string{"app1"}; !reflect.DeepEqual(set.Applications, want) {
		t.Fatalf("single-member application-set X = %v, want %v", set.Applications, want)
	}
}
