package grpcapi

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6851 MAJOR 2: a peer-supplied NAME bypasses the #4626 guard.
//
// The #4626 guard resolves a policy name from a raw id for rows THIS node
// renders. An include_peer fan-out is different: the peer resolved the name
// itself and we attach its response. A peer on a pre-#4626 build resolved
// reserved id 0 through its own compiled map and sent the name of ITS first
// configured policy, and that string was republished unchanged on every local
// surface — gRPC clients, the REST `peer` block via sessionListFromPB, and the
// CLI.
//
// The fixture models exactly that: a peer entry whose PolicyId is 0 and whose
// PolicyName is already populated with a real policy name. An entry with an
// empty name would pass against the unfixed code.
func oldPeerResponse6851() *pb.GetSessionsResponse {
	return &pb.GetSessionsResponse{
		Sessions: []*pb.SessionEntry{
			{
				// What a pre-#4626 peer sends for a host-inbound / fabric /
				// tunnel / older-peer-synced session.
				PolicyId:   0,
				PolicyName: "trust-to-untrust/allow-web",
			},
			{
				// A session a real policy on the PEER admitted.
				PolicyId:   7,
				PolicyName: "peer-only-policy/allow-ssh",
			},
			{
				PolicyId:   dataplane.DefaultPolicySentinelID,
				PolicyName: "whatever-the-old-peer-said",
			},
		},
	}
}

func TestAttachPeerSessionsOverridesReservedPolicyName_6851(t *testing.T) {
	resp := &pb.GetSessionsResponse{}
	peer := oldPeerResponse6851()

	attachPeerSessions(resp, peer)

	if resp.GetPeer() == nil {
		t.Fatalf("peer response was not attached — the guard must not drop the fan-out")
	}
	got := resp.GetPeer().GetSessions()
	if len(got) != 3 {
		t.Fatalf("attached %d peer sessions, want 3", len(got))
	}

	if got[0].GetPolicyName() == "trust-to-untrust/allow-web" {
		t.Fatalf("peer session with policy_id 0 still reports %q — the peer's own "+
			"misattribution was republished unchanged (#6851)", got[0].GetPolicyName())
	}
	if want := dataplane.UnattributedPolicyName; got[0].GetPolicyName() != want {
		t.Errorf("peer policy_id 0 name = %q, want %q", got[0].GetPolicyName(), want)
	}

	// THE DECISION, pinned: an UNRESERVED peer id keeps the PEER's name. Policy
	// ids are node-local, so the peer is authoritative for its own sessions;
	// re-resolving 7 against the LOCAL map would name whichever local policy
	// occupies that slot — a fresh misattribution on every mixed-config
	// cluster, not a fix. This assertion is what distinguishes the shipped
	// choice from "re-resolve everything from the id".
	if want := "peer-only-policy/allow-ssh"; got[1].GetPolicyName() != want {
		t.Errorf("unreserved peer id name = %q, want the PEER's own %q — an "+
			"unreserved id must not be re-resolved locally", got[1].GetPolicyName(), want)
	}

	// The other reserved id is taken authoritatively too.
	if want := dataplane.DefaultPolicyName; got[2].GetPolicyName() != want {
		t.Errorf("peer default-sentinel name = %q, want %q", got[2].GetPolicyName(), want)
	}

	// The raw id is untouched, so nothing is hidden by the substitution.
	if got[0].GetPolicyId() != 0 {
		t.Errorf("policy_id = %d, want 0 — the wire value must still be surfaced",
			got[0].GetPolicyId())
	}
}

// A peer that itself nested a fan-out response must be sanitized too. This
// should not happen (include_peer is not forwarded, to prevent recursion), but
// the guard must not depend on a remote node honouring that.
func TestAttachPeerSessionsSanitizesNestedPeer_6851(t *testing.T) {
	resp := &pb.GetSessionsResponse{}
	peer := oldPeerResponse6851()
	peer.Peer = oldPeerResponse6851()

	attachPeerSessions(resp, peer)

	nested := resp.GetPeer().GetPeer().GetSessions()
	if len(nested) == 0 {
		t.Fatalf("nested peer sessions missing")
	}
	if want := dataplane.UnattributedPolicyName; nested[0].GetPolicyName() != want {
		t.Errorf("nested peer policy_id 0 name = %q, want %q", nested[0].GetPolicyName(), want)
	}
}

// Degenerate inputs must not panic: a nil response, and a nil entry inside a
// response, are both reachable from a hostile or version-drifted peer.
func TestAttachPeerSessionsHandlesNils_6851(t *testing.T) {
	sanitizePeerPolicyNames(nil)

	resp := &pb.GetSessionsResponse{}
	attachPeerSessions(resp, &pb.GetSessionsResponse{
		Sessions: []*pb.SessionEntry{nil, {PolicyId: 0, PolicyName: "x"}},
	})
	got := resp.GetPeer().GetSessions()
	if want := dataplane.UnattributedPolicyName; got[1].GetPolicyName() != want {
		t.Errorf("entry after a nil = %q, want %q", got[1].GetPolicyName(), want)
	}
}
