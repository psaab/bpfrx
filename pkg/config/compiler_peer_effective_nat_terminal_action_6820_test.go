package config

import (
	"strings"
	"testing"
)

// #6820 re-gate: the NAT terminal-action cardinality gate is registered in the
// PEER-EFFECTIVE strict subject list (validateSourceNATStrictView,
// compiler_peer_effective_snat.go), but nothing measured that registration.
// Deleting its call there left pkg/config, pkg/configstore,
// pkg/dataplane/userspace and pkg/cluster all green — the strict commit path
// still rejected a LOCAL contradiction via runUniformGates, so every existing
// case passed through a different call site and the peer-effective one was
// pure ballast.
//
// Why that matters is the #5876 shape, spelled out in
// compiler_peer_effective_snat.go's own header: the standby ingests the synced
// config through Store.SyncApply -> CompileConfigForNodeLenient, which
// DOWNGRADES this gate to a warning (#1960 no-brick). So the origin's
// peer-effective run is the ONLY strict adjudication the peer view ever gets. A
// `${node}` / `groups nodeN` divergence that adds a second terminal action on
// the peer alone therefore commits green on the origin and lands malformed on
// the standby, where a FIXED precedence picks the survivor and the other
// authored action is discarded.
//
// Not "whatever was authored second" — author order is irrelevant to the
// precedence, and in this fixture the second-authored action (`off`, from the
// node1 group) is the one that WINS over the top-level `pool P`. An
// order-flavoured description would be doubly wrong: wrong about the mechanism,
// and wrong about this very case.
//
// Set-command construction per CLAUDE.md: ParseSetCommand + tree.SetPath via
// buildTreeFromSet, never NewParser (which merges newline-separated set lines
// into one node). A faithful HA candidate defines BOTH `groups node0` and
// `groups node1`, because apply-groups "${node}" needs the per-node group to
// exist on each node.

// peerDivergentSNATTerminalAction builds a shared HA candidate whose source-NAT
// rule R1 carries exactly ONE terminal action (`pool P`) on node0 and TWO
// (`pool P` + `off`) on node1, via apply-groups "${node}".
//
// Pool P is defined identically under BOTH group blocks rather than at the top
// level so the ONLY thing that differs between the two effective views is the
// extra `off`. If P existed on one node only, the peer view would be rejected
// by validateNATPoolReferencesStrict — an earlier subject in the same
// validateSourceNATStrictView chain — and this test would pass without the
// terminal-action gate ever running.
func peerDivergentSNATTerminalAction() []string {
	return []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set groups node0 security nat source pool P address 203.0.113.5/32",
		"set groups node1 security nat source pool P address 203.0.113.5/32",
		// node1 ONLY: a second, mutually-exclusive terminal action on the same rule.
		"set groups node1 security nat source rule-set RS rule R1 then source-nat off",
		`set apply-groups "${node}"`,
	}
}

// TestPeerOnlyNATTerminalActionRejectedAtOriginCommit_6820 is the RED-on-delete
// case for the peer-effective terminal-action call. node0's own compile is
// clean (one action), so the pre-fix contract promotes a green commit; node1's
// effective view carries two and would strand the standby with a rule whose
// authored `pool P` is silently discarded in favour of the `off` exemption.
//
// FAIL-ON-DELETE: remove the `validateNATTerminalActionCardinalityStrict` call
// from validateSourceNATStrictView (compiler_peer_effective_snat.go) and this
// goes RED — no other registered subject sees a cardinality error, and the
// local strict path never compiles node1's view.
func TestPeerOnlyNATTerminalActionRejectedAtOriginCommit_6820(t *testing.T) {
	tree := buildTreeFromSet(t, peerDivergentSNATTerminalAction())

	// The originating node (node0) compiles CLEAN — one terminal action. This is
	// the green commit the peer-effective gate has to intercept.
	if _, err := CompileConfigForNode(tree, 0); err != nil {
		t.Fatalf("node0 local compile must be clean (its own view carries exactly one "+
			"terminal action): %v", err)
	}

	err := ValidatePeerEffectiveStrict(tree, 0)
	if err == nil {
		t.Fatal("node0 commit ACCEPTED a peer-only NAT terminal-action contradiction " +
			"(node1 view carries `pool P` + `off` on one rule) — the origin's " +
			"peer-effective run is the only strict adjudication the peer view gets, " +
			"since the standby's SyncApply downgrades this gate to a warning")
	}
	for _, want := range []string{"node1", "RS", "R1", "mutually-exclusive"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("peer-effective terminal-action reject missing %q: %v", want, err)
		}
	}
}

// TestPeerEffectiveNATTerminalActionSymmetryAndCleanCase_6820 is the
// over-reject control. Two things could make the test above pass for the wrong
// reason: a peer-effective gate that rejects any chassis-cluster candidate, and
// one that rejects this candidate from EITHER node's perspective (which would
// mean the divergence, not the peer view, is what it sees).
//
//   - The node1-perspective run of THIS GATE must ACCEPT: from node1 the peer
//     is node0, whose effective view carries one action. Rejecting here would
//     prove the gate is reading the submitting node's own view, not the peer's.
//     Note the scope precisely (#6820 round 3): this calls
//     ValidatePeerEffectiveStrict alone, so it proves peer-effective acceptance
//     and nothing more. It is NOT "node1 commits clean" — a real node1 commit
//     also compiles node1's OWN view, which carries the two-action rule and is
//     rejected by the same gate through runUniformGates. Calling this leg a
//     commit would assert the opposite of what a node1 commit does.
//   - A candidate with the SAME two-action divergence removed must be accepted
//     from both perspectives, so the rejection above is attributable to the
//     extra `off` and nothing else about `${node}` expansion.
func TestPeerEffectiveNATTerminalActionSymmetryAndCleanCase_6820(t *testing.T) {
	diverged := buildTreeFromSet(t, peerDivergentSNATTerminalAction())
	if err := ValidatePeerEffectiveStrict(diverged, 1); err != nil {
		t.Fatalf("the PEER-EFFECTIVE gate run from node1 REJECTED although its peer "+
			"(node0) carries exactly one terminal action — the gate is adjudicating "+
			"the submitting node's own view, not the peer's. (This is the gate alone, "+
			"not a node1 commit: a node1 commit ALSO compiles node1's own two-action "+
			"view and is rejected.): %v", err)
	}

	clean := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source rule-set RS rule R1 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule R1 then source-nat pool P",
		"set groups node0 security nat source pool P address 203.0.113.5/32",
		"set groups node1 security nat source pool P address 203.0.113.6/32",
		`set apply-groups "${node}"`,
	}
	cleanTree := buildTreeFromSet(t, clean)
	for _, nodeID := range []int{0, 1} {
		if err := ValidatePeerEffectiveStrict(cleanTree, nodeID); err != nil {
			t.Fatalf("node%d commit REJECTED a candidate whose BOTH effective views carry "+
				"exactly one terminal action — the gate over-rejects: %v", nodeID, err)
		}
	}
}
