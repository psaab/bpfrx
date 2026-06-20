package config

import (
	"strings"
	"testing"
)

// TestNestedApplicationSetFlatSet is the #2068 repro in flat-set (dual-AST)
// form. compileApplications' member loop previously read only `application`
// members and silently dropped a nested `application-set <child>` member, so
// ExpandApplicationSet("parent") returned only [app1] — app2 (reachable only
// via the nested child set) was missing. A security policy matching `parent`
// therefore never matched app2 traffic.
//
// Flat-set syntax MUST be built with ParseSetCommand/SetPath, never NewParser
// (the parser merges newline-separated set lines into one giant node).
func TestNestedApplicationSetFlatSet(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set applications application app1 protocol tcp destination-port 80",
		"set applications application app2 protocol tcp destination-port 443",
		"set applications application-set child application app2",
		"set applications application-set parent application app1",
		"set applications application-set parent application-set child",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	parent := cfg.Applications.ApplicationSets["parent"]
	if parent == nil {
		t.Fatal("application-set parent not found")
	}
	// The nested-set reference must be recorded as a member of the parent.
	// (Pre-fix this slice held only [app1] — the `application-set child`
	// member was dropped, so this assertion FAILS before the fix.)
	if !contains(parent.Applications, "child") {
		t.Fatalf("parent.Applications = %v, want to include nested set ref %q", parent.Applications, "child")
	}

	expanded, err := ExpandApplicationSet("parent", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(parent): %v", err)
	}
	if !contains(expanded, "app1") {
		t.Errorf("expand(parent) = %v, missing app1", expanded)
	}
	// The crux of #2068: app2 reaches `parent` only through the nested
	// `child` set. Pre-fix this is missing.
	if !contains(expanded, "app2") {
		t.Errorf("expand(parent) = %v, missing app2 (the dropped nested-set member)", expanded)
	}
}

// TestNestedApplicationSetHierarchical exercises the same #2068 case through
// the hierarchical AST shape (braced config), confirming the dual-AST member
// loop handles both shapes via nodeVal.
func TestNestedApplicationSetHierarchical(t *testing.T) {
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
    application-set child {
        application app2;
    }
    application-set parent {
        application app1;
        application-set child;
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

	parent := cfg.Applications.ApplicationSets["parent"]
	if parent == nil {
		t.Fatal("application-set parent not found")
	}
	if !contains(parent.Applications, "child") {
		t.Fatalf("parent.Applications = %v, want to include nested set ref %q", parent.Applications, "child")
	}

	expanded, err := ExpandApplicationSet("parent", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(parent): %v", err)
	}
	if !contains(expanded, "app1") || !contains(expanded, "app2") {
		t.Errorf("expand(parent) = %v, want both app1 and app2", expanded)
	}
}

// TestNestedApplicationSetDeep verifies a 3-level nest (grandparent ->
// parent -> child -> app) resolves through the recursion that
// ExpandApplicationSet already implements.
func TestNestedApplicationSetDeep(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set applications application leaf protocol udp destination-port 53",
		"set applications application-set child application leaf",
		"set applications application-set parent application-set child",
		"set applications application-set grandparent application-set parent",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	expanded, err := ExpandApplicationSet("grandparent", &cfg.Applications)
	if err != nil {
		t.Fatalf("ExpandApplicationSet(grandparent): %v", err)
	}
	if len(expanded) != 1 || expanded[0] != "leaf" {
		t.Errorf("expand(grandparent) = %v, want [leaf]", expanded)
	}
}

// TestNestedApplicationSetCycle verifies a self/mutually referential nest is
// bounded by the existing depth guard (expandAppSet errors past depth 3)
// rather than recursing forever.
func TestNestedApplicationSetCycle(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set applications application a protocol tcp destination-port 1",
		"set applications application-set s1 application a",
		"set applications application-set s1 application-set s2",
		"set applications application-set s2 application-set s1",
	} {
		if err := tree.SetPath(strings.Fields(cmd)[1:]); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if _, err := ExpandApplicationSet("s1", &cfg.Applications); err == nil {
		t.Fatal("ExpandApplicationSet(s1): expected depth-bound error on cyclic nest, got nil")
	}
}
