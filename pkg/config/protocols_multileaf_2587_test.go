package config

import "testing"

// #2587: a set of routing-protocol compilers read a `multi: true` export /
// import / members leaf via only child.Keys[1] (no Keys[1:] slice, no
// child.Children iteration). A bracketed list `[ a b c ]` collapses onto a
// single leaf's Keys in BOTH AST shapes (#2419), so those readers silently
// kept only the FIRST value — `protocols ospf export [ connected static ]`
// redistributed only `connected`; `community c1 members [ 65000:1 65000:2 ]`
// truncated.
//
// The fix routes each reader through the shared firewallMatchValues SSOT
// (Keys[1:] + each child leaf). The schema leaves were already marked
// multi:true (schema_routing.go), so only the compiler readers changed.
//
// These are fail-on-revert guards: each asserts ALL N values survive on BOTH
// the flat-set bracket-list shape (via ParseSetCommand + SetPath, the
// CLAUDE.md-mandated harness for flat-set) and the hierarchical block shape.
// Reverting any reader to the single-Keys[1] form drops the trailing values
// and fails the len/element assertions. The dual-AST differential harness
// alone misses this class because both shapes collapse identically (#2585) —
// dedicated assertions are required.

// --- OSPF export ---

func TestOSPFExportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols ospf export [ connected static bgp ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.OSPF == nil {
		t.Fatalf("OSPF config nil")
	}
	got := cfg.Protocols.OSPF.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("OSPF.Export = %v, want %v (trailing policies dropped without firewallMatchValues)", got, want)
	}
}

func TestOSPFExportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    ospf {
        export [ connected static bgp ];
    }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.OSPF == nil {
		t.Fatalf("OSPF config nil")
	}
	got := cfg.Protocols.OSPF.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("OSPF.Export = %v, want %v", got, want)
	}
}

// --- BGP export + import ---

func TestBGPExportImportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols bgp export [ connected static ospf ]",
		"set protocols bgp import [ imp1 imp2 ]",
		"set policy-options policy-statement imp1 term t then accept",
		"set policy-options policy-statement imp2 term t then accept",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.BGP == nil {
		t.Fatalf("BGP config nil")
	}
	if got, want := cfg.Protocols.BGP.Export, []string{"connected", "static", "ospf"}; !equalStrs(got, want) {
		t.Errorf("BGP.Export = %v, want %v", got, want)
	}
	if got, want := cfg.Protocols.BGP.Import, []string{"imp1", "imp2"}; !equalStrs(got, want) {
		t.Errorf("BGP.Import = %v, want %v", got, want)
	}
}

func TestBGPExportImportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    bgp {
        export [ connected static ospf ];
        import [ imp1 imp2 ];
    }
}
policy-options {
    policy-statement imp1 { term t { then accept; } }
    policy-statement imp2 { term t { then accept; } }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.BGP == nil {
		t.Fatalf("BGP config nil")
	}
	if got, want := cfg.Protocols.BGP.Export, []string{"connected", "static", "ospf"}; !equalStrs(got, want) {
		t.Errorf("BGP.Export = %v, want %v", got, want)
	}
	if got, want := cfg.Protocols.BGP.Import, []string{"imp1", "imp2"}; !equalStrs(got, want) {
		t.Errorf("BGP.Import = %v, want %v", got, want)
	}
}

// --- OSPFv3 export ---

func TestOSPFv3ExportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols ospf3 export [ connected static ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.OSPFv3 == nil {
		t.Fatalf("OSPFv3 config nil")
	}
	got := cfg.Protocols.OSPFv3.Export
	want := []string{"connected", "static"}
	if !equalStrs(got, want) {
		t.Errorf("OSPFv3.Export = %v, want %v", got, want)
	}
}

func TestOSPFv3ExportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    ospf3 {
        export [ connected static ];
    }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.OSPFv3 == nil {
		t.Fatalf("OSPFv3 config nil")
	}
	got := cfg.Protocols.OSPFv3.Export
	want := []string{"connected", "static"}
	if !equalStrs(got, want) {
		t.Errorf("OSPFv3.Export = %v, want %v", got, want)
	}
}

// --- IS-IS export ---

func TestISISExportMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set protocols isis export [ connected static bgp ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.ISIS == nil {
		t.Fatalf("ISIS config nil")
	}
	got := cfg.Protocols.ISIS.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("ISIS.Export = %v, want %v", got, want)
	}
}

func TestISISExportMultiValueHierarchical(t *testing.T) {
	src := `protocols {
    isis {
        export [ connected static bgp ];
    }
}`
	cfg := mustCompile(t, src)
	if cfg.Protocols.ISIS == nil {
		t.Fatalf("ISIS config nil")
	}
	got := cfg.Protocols.ISIS.Export
	want := []string{"connected", "static", "bgp"}
	if !equalStrs(got, want) {
		t.Errorf("ISIS.Export = %v, want %v", got, want)
	}
}

// --- policy-options community members ---

func TestCommunityMembersMultiValueFlatSet(t *testing.T) {
	cfg, err := compileSet(t, []string{
		"set policy-options community c1 members [ 65000:1 65000:2 65000:3 ]",
	})
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	cd := cfg.PolicyOptions.Communities["c1"]
	if cd == nil {
		t.Fatalf("community c1 not compiled")
	}
	got := cd.Members
	want := []string{"65000:1", "65000:2", "65000:3"}
	if !equalStrs(got, want) {
		t.Errorf("community c1 Members = %v, want %v (trailing members dropped without firewallMatchValues)", got, want)
	}
}

func TestCommunityMembersMultiValueHierarchical(t *testing.T) {
	src := `policy-options {
    community c1 {
        members [ 65000:1 65000:2 65000:3 ];
    }
}`
	cfg := mustCompile(t, src)
	cd := cfg.PolicyOptions.Communities["c1"]
	if cd == nil {
		t.Fatalf("community c1 not compiled")
	}
	got := cd.Members
	want := []string{"65000:1", "65000:2", "65000:3"}
	if !equalStrs(got, want) {
		t.Errorf("community c1 Members = %v, want %v", got, want)
	}
}

// mustCompile parses a hierarchical config source and compiles it, failing the
// test on any parse or compile error.
func mustCompile(t *testing.T, src string) *Config {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}
