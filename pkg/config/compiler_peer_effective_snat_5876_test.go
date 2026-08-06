package config

import (
	"strings"
	"testing"
)

// #5876: strict SOURCE-NAT validation ran ONLY against the SUBMITTING node's
// effective compiled view. The strict commit gate compiles
// CompileConfigForNode(s.nodeID) alone, so a source-NAT pool / reference error
// that is valid on the origin's `${node}` effective view but INVALID on the
// peer's — a per-node pool `port range`, a per-node pool address, a top-level
// rule referencing a pool only a peer `groups nodeN` block defines — passed the
// originating commit green and then failed only when the standby lenient-loaded
// the config-synced snapshot (Store.SyncApply → CompileConfigForNodeLenient),
// where the strict SNAT gate is downgraded to a warning and the dataplane fails
// the translation closed. A green commit stranded the standby's SNAT.
//
// The fix (ValidatePeerEffectiveStrict, wired into
// configstore.compileTreeStrict) re-runs the strict SOURCE-NAT validators
// against the PEER node's effective compile — the same
// CompileConfigForNodeLenient transform the standby applies — so a peer-only
// source-NAT error is rejected at the origin commit, proving BOTH node-effective
// views are representable before promotion.
//
// These tests use ParseSetCommand + tree.SetPath (buildTreeFromSet) per
// CLAUDE.md — NewParser must not be used for multi-line set input. A faithful HA
// candidate defines BOTH `groups node0` and `groups node1` (apply-groups
// "${node}" requires the per-node group to exist on each node) so each node's
// own effective view resolves while the OTHER node's SNAT diverges.

// peerDivergentSNATPortRange builds a shared HA candidate whose source-NAT pool
// P carries a VALID `port range` on node0 and a REVERSED (invalid) range on
// node1 via apply-groups "${node}". node0's effective view is clean; node1's
// folds a reversed range that validateSourceNATPoolStrict rejects.
func peerDivergentSNATPortRange() []string {
	return []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set groups node0 security nat source pool P address 203.0.113.5/32",
		"set groups node0 security nat source pool P port range 1024 to 2048",
		"set groups node1 security nat source pool P address 203.0.113.5/32",
		"set groups node1 security nat source pool P port range 5000 to 100",
		`set apply-groups "${node}"`,
	}
}

// TestPeerOnlySNATPortRangeRejectedAtOriginCommit_5876 is the core RED-on-revert
// case. node0's local compile is CLEAN (green commit today), yet the peer node1
// effective view carries a reversed source-pool port range that would strand the
// standby. ValidatePeerEffectiveStrict(tree, 0) must REJECT, naming the
// peer node and the offending pool.
//
// FAIL-ON-REVERT: revert ValidatePeerEffectiveStrict to `return nil`
// (or drop its call from compileTreeStrict) and node0 compiles clean — this
// assertion goes RED because the peer-only error is never surfaced.
func TestPeerOnlySNATPortRangeRejectedAtOriginCommit_5876(t *testing.T) {
	tree := buildTreeFromSet(t, peerDivergentSNATPortRange())

	// The originating node (node0) compiles CLEAN — this is the green commit the
	// pre-fix contract wrongly promoted.
	if _, err := CompileConfigForNode(tree, 0); err != nil {
		t.Fatalf("node0 local compile must be clean (its own view has a valid port range): %v", err)
	}

	// The peer-effective gate run at a node0 commit must reject the node1-only
	// reversed range.
	err := ValidatePeerEffectiveStrict(tree, 0)
	if err == nil {
		t.Fatal("node0 commit ACCEPTED a peer-only source-NAT reversed port range (node1 view) — the #5876 divergent-commit fail-open")
	}
	for _, want := range []string{"node1", "P", "port range", "source-nat pool"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("peer-effective SNAT reject missing %q: %v", want, err)
		}
	}
}

// TestPeerOnlySNATDivergenceVectors_5876 exercises the divergence classes the
// issue enumerates: a per-node pool ADDRESS error and a top-level rule that
// references a pool only the peer's `groups` block defines (a dangling reference
// in the peer view). In every case node0's own view is clean and the peer
// (node1) view is unrepresentable, so ValidatePeerEffectiveStrict(tree,
// 0) rejects while the node0 local compile succeeds.
func TestPeerOnlySNATDivergenceVectors_5876(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string // substrings the reject must name
	}{
		{
			name: "per-node-pool-address-grammar",
			cmds: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 then source-nat pool Q",
				"set groups node0 security nat source pool Q address 203.0.113.5/32",
				"set groups node1 security nat source pool Q address not-an-ip",
				`set apply-groups "${node}"`,
			},
			want: []string{"node1", "Q"},
		},
		{
			name: "top-level-rule-references-node0-only-pool",
			cmds: []string{
				// Rule is SHARED (top-level); the pool it references lives ONLY in
				// groups node0, so the peer (node1) view has a dangling reference.
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 then source-nat pool OnlyNode0",
				"set groups node0 security nat source pool OnlyNode0 address 203.0.113.9/32",
				// groups node1 must exist so apply-groups "${node}" resolves on
				// node1 (harmless, unrelated leaf) — but it does NOT define the pool.
				"set groups node1 system host-name fw1",
				`set apply-groups "${node}"`,
			},
			want: []string{"node1", "OnlyNode0"},
		},
		{
			// #6048 review residual: a peer-only `match application` divergence.
			// The application is defined only in groups node0, so the shared
			// source-NAT rule references an UNDEFINED application on the node1
			// (peer) view. validateNATMatchApplicationsStrict fails OPEN in the
			// dataplane (undefined app -> wildcard translation), so if the peer
			// gate did not run it, node0 would green-commit and strand node1 with
			// a fail-open source-NAT rule.
			name: "peer-only-undefined-match-application",
			cmds: []string{
				"set security nat source rule-set RS from zone trust",
				"set security nat source rule-set RS to zone untrust",
				"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
				"set security nat source rule-set RS rule R1 match application AppOnNode0",
				"set security nat source rule-set RS rule R1 then source-nat interface",
				"set groups node0 applications application AppOnNode0 protocol tcp destination-port 80",
				// node1 group exists (so apply-groups resolves) but does NOT define
				// the application, leaving the node1 view's rule referencing it.
				"set groups node1 system host-name fw1",
				`set apply-groups "${node}"`,
			},
			want: []string{"node1", "AppOnNode0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.cmds)
			if _, err := CompileConfigForNode(tree, 0); err != nil {
				t.Fatalf("node0 local compile must be clean: %v", err)
			}
			err := ValidatePeerEffectiveStrict(tree, 0)
			if err == nil {
				t.Fatalf("node0 commit ACCEPTED a peer-only source-NAT error (%s)", tc.name)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("%s: peer-effective reject missing %q: %v", tc.name, want, err)
				}
			}
		})
	}
}

// TestPeerEffectiveSNATSymmetry_5876 proves the both-views-representable
// contract from the OTHER direction: the reversed range lives in node1's group,
// so a node1 commit catches it in its OWN local compile, and the peer gate run
// at a node1 commit (checking node0's clean view) does NOT false-reject.
func TestPeerEffectiveSNATSymmetry_5876(t *testing.T) {
	tree := buildTreeFromSet(t, peerDivergentSNATPortRange())

	// node1's own local compile already rejects (its view has the reversed range).
	if _, err := CompileConfigForNode(tree, 1); err == nil {
		t.Fatal("node1 local compile should reject its own reversed source-pool port range")
	}
	// The peer gate run at a node1 commit checks node0's view (clean) — no
	// false-reject.
	if err := ValidatePeerEffectiveStrict(tree, 1); err != nil {
		t.Fatalf("node1 commit peer gate false-rejected node0's clean source-NAT view: %v", err)
	}
}

// TestPeerEffectiveSNATBothViewsValidClean_5876 is the primary over-reject
// guard: a clustered candidate whose source-NAT pool is valid on BOTH nodes must
// pass the peer gate at either node's commit. The pool port range is valid in
// both per-node groups.
func TestPeerEffectiveSNATBothViewsValidClean_5876(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set groups node0 security nat source pool P address 203.0.113.5/32",
		"set groups node0 security nat source pool P port range 1024 to 2048",
		"set groups node1 security nat source pool P address 198.51.100.5/32",
		"set groups node1 security nat source pool P port range 3000 to 4000",
		`set apply-groups "${node}"`,
	})
	for _, nodeID := range []int{0, 1} {
		if _, err := CompileConfigForNode(tree, nodeID); err != nil {
			t.Fatalf("node%d local compile of a both-valid config failed: %v", nodeID, err)
		}
		if err := ValidatePeerEffectiveStrict(tree, nodeID); err != nil {
			t.Fatalf("node%d peer gate false-rejected a config valid on both nodes: %v", nodeID, err)
		}
	}
}

// TestPeerEffectiveSNATStandaloneNoOp_5876 pins the standalone guarantee: with
// no cluster (localNodeID < 0) there is no peer, so the gate is a pure no-op even
// when the config carries a source-NAT error — standalone behavior is unchanged.
func TestPeerEffectiveSNATStandaloneNoOp_5876(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set security nat source pool P address 203.0.113.5/32",
		"set security nat source pool P port range 5000 to 100", // reversed, but standalone → no peer
	})
	if err := ValidatePeerEffectiveStrict(tree, -1); err != nil {
		t.Fatalf("standalone (nodeID -1) must be a no-op, got: %v", err)
	}
	// An out-of-cluster node id with no defined 2-node peer is also a no-op.
	if err := ValidatePeerEffectiveStrict(tree, 5); err != nil {
		t.Fatalf("nodeID 5 has no 2-node peer, must be a no-op, got: %v", err)
	}
}

// TestPeerNodeID_5876 unit-tests the 2-node peer selector.
func TestPeerNodeID_5876(t *testing.T) {
	cases := []struct {
		in       int
		wantPeer int
		wantOK   bool
	}{
		{0, 1, true},
		{1, 0, true},
		{-1, 0, false},
		{2, 0, false},
	}
	for _, tc := range cases {
		peer, ok := peerNodeID(tc.in)
		if ok != tc.wantOK || (ok && peer != tc.wantPeer) {
			t.Fatalf("peerNodeID(%d) = (%d, %v), want (%d, %v)", tc.in, peer, ok, tc.wantPeer, tc.wantOK)
		}
	}
}
