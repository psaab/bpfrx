package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6851: the on-box interactive CLI reaches the cluster peer by its OWN route.
//
// (c *CLI) fetchPeerSessions dials the peer daemon directly and sets no
// IncludePeer, so it passes through neither the grpcapi fan-out that sanitizes
// reserved policy ids nor the peer's own fan-out. Against a pre-#4626 peer,
// `show security flow session` in cluster mode therefore printed that peer's
// FIRST CONFIGURED POLICY as the name for every session stamped with reserved
// id 0 — the exact defect this branch closes, on the surface an operator
// actually types, during exactly the mixed-version window
// PeerSessionPolicyName exists for.
//
// The remote `cli` binary is not affected (it sets IncludePeer and arrives
// through grpcapi), and REST is not affected. This is specifically the on-box
// path, and before this test it had zero behavioural coverage.

func peerSessionsResp6851(policyID uint32, policyName string) *pb.GetSessionsResponse {
	return &pb.GetSessionsResponse{
		Sessions: []*pb.SessionEntry{{
			SrcAddr:    "10.0.1.5",
			DstAddr:    "10.0.2.9",
			Protocol:   "tcp",
			State:      "established",
			PolicyId:   policyID,
			PolicyName: policyName,
		}},
	}
}

// TestCLISanitizesPeerReservedPolicyName_6851 drives the sanitizer the CLI's
// peer ingress applies. Reverting that call makes the pre-#4626 peer's name
// survive to the renderer.
func TestCLISanitizesPeerReservedPolicyName_6851(t *testing.T) {
	const firstPolicy = "trust-to-untrust/allow-web"

	resp := peerSessionsResp6851(0, firstPolicy)
	sanitizePeerSessionPolicyNames(resp)

	got := resp.GetSessions()[0].GetPolicyName()
	if got == firstPolicy {
		t.Fatalf("the peer's policy_name %q survived for reserved id 0. An older peer "+
			"resolves id 0 as its first configured policy, and `show security flow "+
			"session` prints that name for host-inbound, fabric and tunnel sessions no "+
			"policy admitted (#6851)", got)
	}
	if got != dataplane.UnattributedPolicyName {
		t.Errorf("policy_name = %q, want %q", got, dataplane.UnattributedPolicyName)
	}
	// NOTE: no policy_id assertion here. The input id IS 0, so "want 0" is also
	// the zero value and cannot distinguish "preserved" from "zeroed" — an
	// expectation equal to the failure default. The surfacing claim is asserted
	// on the sentinel sibling below, where the value would differ.
}

// The default-policy sentinel is reserved on this path too: a pre-#3057 peer
// can send its own configured name for it.
func TestCLISanitizesPeerSentinelPolicyName_6851(t *testing.T) {
	resp := peerSessionsResp6851(dataplane.DefaultPolicySentinelID, "some-configured-policy")
	sanitizePeerSessionPolicyNames(resp)

	if got := resp.GetSessions()[0].GetPolicyName(); got != dataplane.DefaultPolicyName {
		t.Errorf("sentinel policy_name = %q, want %q", got, dataplane.DefaultPolicyName)
	}
	// The raw wire id must SURVIVE the substitution. Asserted here rather than
	// on the id-0 case because 0xFFFFFFFF is distinguishable from the zero
	// value, so this assertion can actually fail if the sanitizer clobbers the
	// id while rewriting the name.
	if id := resp.GetSessions()[0].GetPolicyId(); id != dataplane.DefaultPolicySentinelID {
		t.Errorf("policy_id = %d, want %d — the sanitizer rewrites the NAME only; the raw "+
			"wire value must still be surfaced beside it", id, dataplane.DefaultPolicySentinelID)
	}
}

// Over-rejection guard: an ordinary id keeps the name the PEER resolved. Policy
// ids are node-local, so the peer is authoritative for its own sessions and
// re-resolving against the local table would name whichever local policy
// happened to occupy that slot.
func TestCLIKeepsPeerNameForOrdinaryID_6851(t *testing.T) {
	const peerName = "dmz-to-untrust/allow-any"

	resp := peerSessionsResp6851(7, peerName)
	sanitizePeerSessionPolicyNames(resp)

	if got := resp.GetSessions()[0].GetPolicyName(); got != peerName {
		t.Errorf("policy_name = %q, want the peer's own %q — only RESERVED ids are "+
			"re-taken", got, peerName)
	}
}

// Robustness: nil response, nil entry, and a nested peer response must not
// panic and must still be sanitized. The CLI does not request a nested fan-out,
// but the guard should not depend on a peer-version invariant.
func TestCLISanitizePeerHandlesDegenerateShapes_6851(t *testing.T) {
	sanitizePeerSessionPolicyNames(nil) // must not panic

	resp := peerSessionsResp6851(0, "first-policy")
	resp.Sessions = append(resp.Sessions, nil)
	resp.Peer = peerSessionsResp6851(0, "peer-of-peer-first-policy")

	sanitizePeerSessionPolicyNames(resp)

	if got := resp.GetPeer().GetSessions()[0].GetPolicyName(); got != dataplane.UnattributedPolicyName {
		t.Errorf("nested peer response was not sanitized: policy_name = %q", got)
	}
}

// TestCLIPeerFetchCallsSanitizer_6851 binds the CALL, not just the sanitizer.
//
// The tests above drive sanitizePeerSessionPolicyNames directly, so they bind
// its behaviour and leave its one call site unbound — deleting
// `sanitizePeerSessionPolicyNames(resp)` from fetchPeerSessions compiles and
// keeps every one of them green while restoring the MAJOR whole. That was
// measured, not assumed: the mutation came back GREEN before this test existed.
//
// Binding it behaviourally needs a live peer dial through c.dialPeer, so it is
// bound structurally instead.
//
// SCOPE: this asserts only that fetchPeerSessions CONTAINS a call to the
// sanitizer. It does not prove the call precedes every return, it cannot see a
// sanitizer that was gutted, and it cannot see the argument — measured:
// `sanitizePeerSessionPolicyNames(nil)` contains the call, bypasses the
// sanitization entirely, and leaves every package green with the MAJOR fully
// restored.
//
// That residual cell — "call present, argument neutered" — is the same one
// disclosed for attachPeerSessions in grpcapi, and it is left uncovered
// deliberately rather than papered over with a guard invented to satisfy a
// reviewer. The class is covered from two other sides: deleting the call reds
// this test, and gutting the sanitizer's body reds the behavioural tests above.
func TestCLIPeerFetchCallsSanitizer_6851(t *testing.T) {
	const (
		file   = "session_filter.go"
		target = "fetchPeerSessions"
		helper = "sanitizePeerSessionPolicyNames"
	)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == target {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatalf("%s not found in %s — this canary is keyed to it by name, so a rename "+
			"must bring it along rather than silently disarm it", target, file)
	}

	called := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == helper {
			called = true
		}
		return true
	})
	if !called {
		t.Errorf("%s no longer calls %s. The on-box CLI dials the peer directly, so this is "+
			"its ONLY sanitization point — without it a pre-#4626 peer's first configured "+
			"policy is printed for every reserved-id session (#6851)", target, helper)
	}
}
