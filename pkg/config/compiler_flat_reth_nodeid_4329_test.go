package config

import "testing"

// #4329: a canonical vSRX chassis-cluster config encodes node ownership in
// the FPC slot (ge-0/0/N=node0, ge-7/0/N=node1) and runs the SAME flat config
// on both nodes with NO `chassis cluster node` leaf. Before the fix,
// CompileConfigForNode never stamped Cluster.NodeID from the runtime node-id,
// so Cluster.NodeID sat at its zero default on BOTH nodes and RethToPhysical
// scored every reth member as node 0 — binding every reth to the node-0
// physical member on node 1 (reth breaks on the secondary).

// flatRethClusterConfig is the canonical leaf-less vSRX form: a chassis
// cluster stanza (cluster-id + reth-count) with NO `node` leaf, and both
// per-node physical members carrying `redundant-parent reth0`.
func flatRethClusterConfig() []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster reth-count 2",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set interfaces ge-7/0/0 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
	}
}

// TestFlatRethResolvesLocalMemberPerNode_4329 is the RED-on-revert regression
// guard: the flat two-member form (no `node` leaf) must resolve reth0 to the
// LOCAL member on each node — ge-0/0/0 on node 0 AND ge-7/0/0 on node 1.
// RED on revert: without the NodeID stamp both nodes resolve to ge-0/0/0
// (Cluster.NodeID==0 default → node 0's member wins the score on both).
func TestFlatRethResolvesLocalMemberPerNode_4329(t *testing.T) {
	tree := buildTree(t, flatRethClusterConfig())

	cfg0, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode(node 0): %v", err)
	}
	if got := cfg0.RethToPhysical()["reth0"]; got != "ge-0/0/0" {
		t.Fatalf("node 0: reth0 → %q, want ge-0/0/0", got)
	}
	if cfg0.Chassis.Cluster == nil || cfg0.Chassis.Cluster.NodeID != 0 {
		t.Fatalf("node 0: stamped NodeID = %+v, want 0", cfg0.Chassis.Cluster)
	}

	cfg1, err := CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("CompileConfigForNode(node 1): %v", err)
	}
	// The load-bearing assertion: the secondary must bind reth0 to its OWN
	// FPC-7 member, not the node-0 member.
	if got := cfg1.RethToPhysical()["reth0"]; got != "ge-7/0/0" {
		t.Fatalf("node 1: reth0 → %q, want ge-7/0/0 (RED-on-revert: pre-fix binds ge-0/0/0)", got)
	}
	if cfg1.Chassis.Cluster == nil || cfg1.Chassis.Cluster.NodeID != 1 {
		t.Fatalf("node 1: stamped NodeID = %+v, want 1", cfg1.Chassis.Cluster)
	}
	// The stamp must NOT fabricate the explicit-leaf flag: NodeIDSet stays
	// false so crossCheckNodeID still treats this as a leaf-less config.
	if cfg1.Chassis.Cluster.NodeIDSet {
		t.Error("node 1: NodeIDSet must stay false — the stamp derives from the runtime node-id, not a `node` leaf")
	}

	// ResolveReth (the runtime resolver every reth consumer drives) must
	// follow the corrected map on node 1.
	if got := cfg1.ResolveReth("reth0.80"); got != "ge-7/0/0.80" {
		t.Fatalf("node 1: ResolveReth(reth0.80) = %q, want ge-7/0/0.80", got)
	}
}

// TestFlatRethExplicitNodeLeafNotClobbered_4329 pins the precedence rule: an
// explicit `chassis cluster node <id>` leaf is the operator's SSOT and MUST
// win over the runtime node-id — the stamp only fills a leaf-less config.
// A config with `node 0` compiled FOR node 1 keeps NodeID==0 (and resolves
// reth0 to node 0's member), exactly as before the fix.
func TestFlatRethExplicitNodeLeafNotClobbered_4329(t *testing.T) {
	lines := append(flatRethClusterConfig(), "set chassis cluster node 0")
	tree := buildTree(t, lines)

	cfg, err := CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("CompileConfigForNode(node 1, explicit node 0 leaf): %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if !cfg.Chassis.Cluster.NodeIDSet {
		t.Error("NodeIDSet must stay true — an explicit `node` leaf was present")
	}
	if cfg.Chassis.Cluster.NodeID != 0 {
		t.Fatalf("NodeID = %d, want 0 — the stamp must NOT clobber an explicit leaf", cfg.Chassis.Cluster.NodeID)
	}
	// With the explicit leaf naming node 0, reth0 stays bound to the node-0
	// member even though we compiled for node 1 (crossCheckNodeID rejects
	// this mismatch on the commit path; here we only assert precedence).
	if got := cfg.RethToPhysical()["reth0"]; got != "ge-0/0/0" {
		t.Fatalf("reth0 → %q, want ge-0/0/0 (explicit node 0 leaf must decide)", got)
	}
}

// TestFlatRethGroupsFormUnaffected_4329 confirms the GROUPS form (the xpf loss
// cluster shape: groups node0/node1 each carrying an explicit `node` leaf and
// only ITS own member, applied via `apply-groups "${node}"`) is bit-identical
// under the fix. Each node's expanded config carries an explicit `node` leaf
// (NodeIDSet==true → stamp skipped) and a single candidate member.
func TestFlatRethGroupsFormUnaffected_4329(t *testing.T) {
	tree := buildTree(t, []string{
		"set groups node0 chassis cluster node 0",
		"set groups node0 interfaces ge-0/0/0 gigether-options redundant-parent reth0",
		"set groups node1 chassis cluster node 1",
		"set groups node1 interfaces ge-7/0/0 gigether-options redundant-parent reth0",
		`set apply-groups "${node}"`,
		"set chassis cluster cluster-id 1",
		"set chassis cluster reth-count 2",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
	})

	cfg0, err := CompileConfigForNode(tree, 0)
	if err != nil {
		t.Fatalf("CompileConfigForNode(node 0, groups): %v", err)
	}
	if !cfg0.Chassis.Cluster.NodeIDSet || cfg0.Chassis.Cluster.NodeID != 0 {
		t.Fatalf("node 0 groups: Cluster = %+v, want explicit node 0", cfg0.Chassis.Cluster)
	}
	if got := cfg0.RethToPhysical()["reth0"]; got != "ge-0/0/0" {
		t.Fatalf("node 0 groups: reth0 → %q, want ge-0/0/0", got)
	}

	cfg1, err := CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("CompileConfigForNode(node 1, groups): %v", err)
	}
	if !cfg1.Chassis.Cluster.NodeIDSet || cfg1.Chassis.Cluster.NodeID != 1 {
		t.Fatalf("node 1 groups: Cluster = %+v, want explicit node 1", cfg1.Chassis.Cluster)
	}
	if got := cfg1.RethToPhysical()["reth0"]; got != "ge-7/0/0" {
		t.Fatalf("node 1 groups: reth0 → %q, want ge-7/0/0", got)
	}
}

// TestFlatRethStandaloneCompileUnchanged_4329 pins that the standalone
// (non-cluster) compile path is untouched: CompileConfig (nodeID == -1)
// routes through compileConfigWithOpts, never the node-aware stamp, so a
// leaf-less config keeps NodeIDSet==false and its zero-default NodeID.
func TestFlatRethStandaloneCompileUnchanged_4329(t *testing.T) {
	tree := buildTree(t, flatRethClusterConfig())

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig (standalone): %v", err)
	}
	if cfg.Chassis.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if cfg.Chassis.Cluster.NodeIDSet {
		t.Error("standalone: NodeIDSet must stay false — CompileConfig must not stamp")
	}
	if cfg.Chassis.Cluster.NodeID != 0 {
		t.Errorf("standalone: NodeID = %d, want 0 (zero default, unstamped)", cfg.Chassis.Cluster.NodeID)
	}
}
