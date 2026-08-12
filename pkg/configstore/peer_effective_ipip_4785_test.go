package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4785 fold F1: the STORE wiring. ValidatePeerEffectiveStrict rejecting a
// peer-only IPIP endpoint is worth nothing unless the strict commit gate calls
// it — and pkg/config's own tests drive the validator directly, which leaves the
// call site unbound.
//
// This test drives compileTreeStrict, the real operator commit / commit-check /
// `xpfd check-config` pipeline, for a node0 commit whose LOCAL view is clean.
//
// FAIL-ON-REVERT: drop the tunnel subject from peerEffectiveStrictSubjects, or
// drop the config.ValidatePeerEffectiveStrict call from compileTreeStrict, and
// compileTreeStrict(tree, 0) returns nil — this test goes RED.

func peerOnlyIpipTree(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	cmds := []string{
		// node0's group is tunnel-free, so node0's own compile is clean.
		"set groups node0 interfaces ge-0/0/9 unit 0 family inet address 10.7.7.1/24",
		// node1 alone resolves an `ip-*` interface — mode ipip is INFERRED, the
		// operator never types it.
		"set groups node1 interfaces ip-0/0/0 tunnel source 10.9.9.1",
		"set groups node1 interfaces ip-0/0/0 tunnel destination 10.9.9.2",
		`set apply-groups "${node}"`,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestCompileTreeStrict_RejectsPeerOnlyIpip_4785 is the wiring guard.
func TestCompileTreeStrict_RejectsPeerOnlyIpip_4785(t *testing.T) {
	tree := peerOnlyIpipTree(t)

	// node0 (the submitting node) strict-compiles cleanly on its own view, so
	// only the peer gate can be what rejects below.
	if _, err := config.CompileConfigForNode(tree, 0); err != nil {
		t.Fatalf("node0 local compile must be clean, else this test proves nothing "+
			"about the peer path: %v", err)
	}
	// And node1 — the node that will actually receive this tree — is the one
	// carrying the dead endpoint.
	if _, err := config.CompileConfigForNode(tree, 1); err == nil {
		t.Fatal("precondition: node1's strict view must carry the dead IPIP endpoint")
	}

	_, err := compileTreeStrict(tree, 0)
	if err == nil {
		t.Fatal("compileTreeStrict(node0) ACCEPTED a config whose PEER gets a dead IPIP " +
			"tunnel. The raw group tree is what synchronises and the standby ingests it " +
			"leniently, so the hard #4785 gate never runs for the node that installs it")
	}
	for _, want := range []string{"node1", "mode ipip", "ip-0/0/0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("compileTreeStrict reject missing %q: %v", want, err)
		}
	}
}

// TestCompileTreeStrict_PeerOnlyGreStillCommits_4785 is the over-reach guard at
// the same wiring point: a peer-only GRE tunnel is a working tunnel, and the
// commit gate must not reject it.
//
// Stays GREEN under the revert.
func TestCompileTreeStrict_PeerOnlyGreStillCommits_4785(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set groups node0 interfaces ge-0/0/9 unit 0 family inet address 10.7.7.1/24",
		"set groups node1 interfaces gr-0/0/0 tunnel source 10.9.9.1",
		"set groups node1 interfaces gr-0/0/0 tunnel destination 10.9.9.2",
		`set apply-groups "${node}"`,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	if _, err := compileTreeStrict(tree, 0); err != nil {
		t.Errorf("compileTreeStrict rejected a peer-only GRE tunnel — the gate must key "+
			"on the compiled MODE, not on the presence of a peer-only tunnel: %v", err)
	}
}
