package config

import "testing"

// TestRIPExportRedistributeMultiValue_3904 is the F-162 RED-on-revert guard:
// a RIP `group G export [ a b ]` bracket list and a top-level
// `redistribute [ static direct ]` bracket list must each compile to EVERY
// value, not just the first. Before #3904 both compiler arms read only Keys[1]
// (the RIP arm of the #2419 bracket-list-truncation class), so the second
// export policy / redistribute protocol was silently dropped.
func TestRIPExportRedistributeMultiValue_3904(t *testing.T) {
	tree := buildTree3904(t, []string{
		"set protocols rip group g export [ pol-a pol-b ]",
		"set protocols rip redistribute [ static direct ]",
	})
	// The RIP config must also be commit-valid (schema-accepted).
	var scfg Config
	if err := SchemaValidate(tree, &scfg); err != nil {
		t.Fatalf("SchemaValidate: %v", err)
	}

	var proto ProtocolsConfig
	if err := compileProtocols(tree.FindChild("protocols"), &proto); err != nil {
		t.Fatalf("compileProtocols: %v", err)
	}
	if proto.RIP == nil {
		t.Fatal("RIP not compiled")
	}
	// group export → Redistribute, then top-level redistribute → Redistribute.
	want := []string{"pol-a", "pol-b", "static", "direct"}
	if !equalStrs3904(proto.RIP.Redistribute, want) {
		t.Errorf("RIP.Redistribute = %v, want %v (bracket list truncated)", proto.RIP.Redistribute, want)
	}
}

// TestRIPRedistributeSingle_3904 confirms the single-value form still compiles
// to exactly one entry (the multi leaf must not regress it).
func TestRIPRedistributeSingle_3904(t *testing.T) {
	tree := buildTree3904(t, []string{
		"set protocols rip redistribute static",
	})
	var proto ProtocolsConfig
	if err := compileProtocols(tree.FindChild("protocols"), &proto); err != nil {
		t.Fatalf("compileProtocols: %v", err)
	}
	if proto.RIP == nil || !equalStrs3904(proto.RIP.Redistribute, []string{"static"}) {
		t.Errorf("single redistribute = %v, want [static]", proto.RIP.Redistribute)
	}
}
