package config

import "testing"

// #2419 fold: `system domain-search` and `system name-server` are
// multi-value leaves (schema_system.go, multi:true). A flat-set bracket
// list collapses every value onto the leaf's Keys[1:] with NO children
// (verified: `set system domain-search [ a b c ]` →
// Keys=[domain-search a b c], IsLeaf, 0 children). The readers in
// compileSystem previously read only child.Keys[1] plus orphan leaf
// children — that orphan-children path WORKED on flat-set pre-#2419 (the
// bracket split into child leaves), so #2419's collapse silently dropped
// every value but the first. These are fail-on-revert guards: reverting
// compileSystem to the single-Keys[1]+children reader drops the trailing
// values and fails the len/element assertions below.

func TestSystemDomainSearchBracketListFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set system domain-search [ a.example.com b.example.com c.example.com ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.System.DomainSearch
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !equalStrs(got, want) {
		t.Errorf("DomainSearch = %v, want %v (trailing domains dropped without the Keys[1:] fix)", got, want)
	}
}

func TestSystemDomainSearchBracketListHierarchical(t *testing.T) {
	src := `system {
    domain-search [ a.example.com b.example.com c.example.com ];
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.System.DomainSearch
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !equalStrs(got, want) {
		t.Errorf("DomainSearch = %v, want %v", got, want)
	}
}

func TestSystemNameServerBracketListFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set system name-server [ 8.8.8.8 9.9.9.9 1.1.1.1 ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.System.NameServers
	want := []string{"8.8.8.8", "9.9.9.9", "1.1.1.1"}
	if !equalStrs(got, want) {
		t.Errorf("NameServers = %v, want %v (trailing servers dropped without the Keys[1:] fix)", got, want)
	}
}

func TestSystemNameServerBlockListHierarchical(t *testing.T) {
	// Hierarchical block form `name-server { ip; ip; }` carries one leaf
	// child per server — firewallMatchValues reads child.Keys[1:] (empty)
	// plus each child leaf, so this shape must still yield all servers.
	src := `system {
    name-server {
        8.8.8.8;
        9.9.9.9;
    }
}`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.System.NameServers
	want := []string{"8.8.8.8", "9.9.9.9"}
	if !equalStrs(got, want) {
		t.Errorf("NameServers = %v, want %v", got, want)
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
