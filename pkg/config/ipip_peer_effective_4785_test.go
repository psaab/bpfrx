package config

import (
	"fmt"
	"strings"
	"testing"
)

// #4785 fold F1: the hard IPIP gate must hold for the node that actually
// RECEIVES the config, not only for the node that submits it.
//
// The strict commit gate compiles ONLY the submitting node's effective view
// (configstore.compileTreeStrict -> CompileConfigForNode(tree, localNodeID)).
// What synchronises to the peer is the RAW group tree (Store.ShowActive ->
// s.active.Format() -> QueueConfig), and the standby ingests it through the
// TOLERANT path (Store.SyncApply -> CompileConfigForNodeLenient), which
// downgrades every strict gate to a warning so an already-persisted config
// still boots (#1960).
//
// So for a shared `${node}` config where only `groups node1` carries a complete
// IPIP endpoint: node 0 commits GREEN, node 1 leniently expands the same tree,
// and the dead endpoint installs on node 1. Measured at the PR head before this
// gate existed:
//
//	node 0 strict: PASS
//	node 1 strict: FAIL ... tunnel endpoint "ip-0/0/0" has mode ipip
//	CompileConfigForNodeLenient(tree, 1): ERR=<nil> MODE=ipip emitted=1
//
// The fix pulls the peer's strict IPIP check forward to the ORIGIN's commit,
// where it is the only strict gate this config ever gets. SyncApply stays
// lenient — a config already on disk must still boot.

// peerOnlyIpipTree builds a shared cluster candidate where ONLY the given node's
// `groups nodeN` block carries a complete IPIP endpoint. The other node's group
// exists (so apply-groups resolves on both views) and is tunnel-free, which is
// what makes the origin's local compile clean.
//
// The mode is never typed: an `ip-*` interface infers `mode ipip` in
// compileInterfaces, which is the shape a real vSRX config arrives in.
func peerOnlyIpipTree(t *testing.T, ipipNode int) *ConfigTree {
	t.Helper()
	clean, dead := 1, 0
	if ipipNode == 1 {
		clean, dead = 0, 1
	}
	return ipipTree(t,
		fmt.Sprintf("set groups node%d interfaces ge-0/0/9 unit 0 family inet address 10.7.7.1/24", clean),
		fmt.Sprintf("set groups node%d interfaces ip-0/0/0 tunnel source 10.9.9.1", dead),
		fmt.Sprintf("set groups node%d interfaces ip-0/0/0 tunnel destination 10.9.9.2", dead),
		`set apply-groups "${node}"`,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	)
}

// TestPeerEffectiveStrictRejectsPeerOnlyIpip_4785 is the fail-on-revert guard.
// It runs both directions so the gate is not accidentally keyed to one node id.
//
// RED-on-revert: drop the tunnel subject from peerEffectiveStrictSubjects and
// both subtests fail at "ACCEPTED a peer-only IPIP endpoint".
func TestPeerEffectiveStrictRejectsPeerOnlyIpip_4785(t *testing.T) {
	for _, tc := range []struct {
		name       string
		originNode int
		ipipNode   int
	}{
		{name: "node0_commits_node1_gets_the_dead_tunnel", originNode: 0, ipipNode: 1},
		{name: "node1_commits_node0_gets_the_dead_tunnel", originNode: 1, ipipNode: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := peerOnlyIpipTree(t, tc.ipipNode)

			// Precondition: the ORIGIN's own view is clean, so the local strict
			// gate cannot be what rejects. Without this the test would pass on
			// broken code, satisfied by the local gate firing.
			if _, err := CompileConfigForNode(tree, tc.originNode); err != nil {
				t.Fatalf("origin node%d local compile must be CLEAN, else this test "+
					"proves nothing about the peer path: %v", tc.originNode, err)
			}
			// Precondition: the peer's lenient receive path really does install
			// the dead endpoint. This is the damage the gate exists to prevent.
			peerCfg, err := CompileConfigForNodeLenient(tree, tc.ipipNode)
			if err != nil || peerCfg == nil {
				t.Fatalf("peer lenient compile must succeed (that is how SyncApply "+
					"ingests it): err=%v cfg==nil=%v", err, peerCfg == nil)
			}
			if got := len(effectiveIpipTunnelSites(peerCfg)); got != 1 {
				t.Fatalf("peer view must emit exactly 1 dead ipip endpoint, got %d — "+
					"the fixture does not reproduce the bypass", got)
			}

			err = ValidatePeerEffectiveStrict(tree, tc.originNode)
			if err == nil {
				t.Fatalf("ValidatePeerEffectiveStrict(node%d) ACCEPTED a peer-only IPIP "+
					"endpoint. node%d commits green, node%d lenient-loads the synced tree "+
					"and installs a tunnel the dataplane drops in both directions — the "+
					"hard gate this PR adds does not hold for the node that receives the "+
					"config (#4785)", tc.originNode, tc.originNode, tc.ipipNode)
			}
			for _, want := range []string{
				fmt.Sprintf("node%d", tc.ipipNode), // names the offending peer
				"mode ipip",
				"ip-0/0/0",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("peer rejection must contain %q so the operator knows which "+
						"node and which endpoint; got %v", want, err)
				}
			}
		})
	}
}

// TestPeerEffectiveStrictAcceptsPeerOnlyGre_4785 is the over-reach guard for the
// MODE. The peer gate must key on the compiled mode, exactly as the local gate
// does — a peer-only GRE tunnel is a working tunnel and must still commit.
//
// Stays GREEN under the revert.
func TestPeerEffectiveStrictAcceptsPeerOnlyGre_4785(t *testing.T) {
	tree := ipipTree(t,
		"set groups node0 interfaces ge-0/0/9 unit 0 family inet address 10.7.7.1/24",
		"set groups node1 interfaces gr-0/0/0 tunnel source 10.9.9.1",
		"set groups node1 interfaces gr-0/0/0 tunnel destination 10.9.9.2",
		`set apply-groups "${node}"`,
	)
	peerCfg, err := CompileConfigForNodeLenient(tree, 1)
	if err != nil || peerCfg == nil {
		t.Fatalf("peer lenient compile: err=%v cfg==nil=%v", err, peerCfg == nil)
	}
	if got := len(EmitTunnelEndpointNames(peerCfg)); got != 1 {
		t.Fatalf("the fixture must emit a peer-only endpoint, got %d — otherwise this "+
			"guard would pass for the wrong reason (nothing to reject)", got)
	}
	if err := ValidatePeerEffectiveStrict(tree, 0); err != nil {
		t.Errorf("a peer-only GRE tunnel is a WORKING tunnel and must commit; the peer "+
			"gate rejected it: %v", err)
	}
}

// TestPeerEffectiveStrictStandaloneNoOp_4785 is the over-reach guard for the
// no-cluster case. A standalone box (nodeID < 0) has no peer, so the gate must
// do nothing at all — including for a config the LOCAL gate would reject, which
// is the local gate's job and not this one's.
//
// Stays GREEN under the revert.
func TestPeerEffectiveStrictStandaloneNoOp_4785(t *testing.T) {
	tree := ipipTree(t,
		"set interfaces ip-0/0/0 tunnel source 10.0.0.1",
		"set interfaces ip-0/0/0 tunnel destination 10.0.0.2",
	)
	// The local strict gate rejects this — that is the #4785 half-1 behaviour.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("precondition: the local strict gate must reject a plain dead IPIP")
	}
	for _, nodeID := range []int{-1, 5} {
		if err := ValidatePeerEffectiveStrict(tree, nodeID); err != nil {
			t.Errorf("ValidatePeerEffectiveStrict(nodeID=%d) must be a no-op — there is no "+
				"2-node peer — got %v", nodeID, err)
		}
	}
}

// TestPeerEffectiveStrictSubjectsRunAgainstOnePeerCompile_4785 pins the reason
// this is a registry rather than a second standalone entry point: the peer view
// is a FULL compile and must be built ONCE, however many subjects run.
//
// It is a structural claim and is stated as one. What it binds is that no
// subject compiles its own view — every fn takes an already-compiled *Config —
// so adding the next concern cannot silently add another compile. It does not
// prove the count at run time.
func TestPeerEffectiveStrictSubjectsRunAgainstOnePeerCompile_4785(t *testing.T) {
	if len(peerEffectiveStrictSubjects) < 2 {
		t.Fatalf("expected at least the source-NAT and tunnel subjects, found %d — this "+
			"guard is keyed to the registry and checks nothing otherwise",
			len(peerEffectiveStrictSubjects))
	}
	seen := map[string]bool{}
	for i, s := range peerEffectiveStrictSubjects {
		if s.fn == nil {
			t.Errorf("subject %d has no validator", i)
		}
		if !strings.Contains(s.format, "peer node%d") {
			t.Errorf("subject %d format must name the peer node: %q", i, s.format)
		}
		if !strings.HasSuffix(s.format, "%w") {
			t.Errorf("subject %d format must wrap the underlying error with %%w so "+
				"errors.Is/As still work through it: %q", i, s.format)
		}
		if seen[s.format] {
			t.Errorf("subject %d duplicates an earlier format: %q", i, s.format)
		}
		seen[s.format] = true
	}
}
