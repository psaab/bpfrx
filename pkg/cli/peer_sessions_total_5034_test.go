// #5034 (C175-HC-073 remainder): the peer session-detail "Total sessions"
// must render the server's REAL filtered total (GetSessionsResponse.Total),
// not a CLI-side approximation. PR #5033 fell back to len(Sessions) to hide
// the old -1 sentinel; len(Sessions) undercounts once the peer caps its
// returned list. With the server returning a real total (#5034), the CLI
// renders Total directly.
//
// FAIL-ON-REVERT: changing peerSessionsTotal back to int32(len(resp.Sessions))
// makes the truncated-list case go RED (returns 2 instead of the real 4).
//
// The mixed-version case (Total=-1 from a pre-#5034 peer during ISSU) pins
// the retained sentinel fallback: dropping the `>= 0` guard makes
// peerSessionsTotal render the raw -1, re-exposing the #4908/#5033 display
// bug, and TestPeerSessionsTotalMixedVersionFallback goes RED.
package cli

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestPeerSessionsTotalRendersServerTotal(t *testing.T) {
	// The peer matched 4 sessions but returned a capped list of 2 — the
	// rendered "Total sessions" must be the real total (4), not len()=2.
	resp := &pb.GetSessionsResponse{
		Total:    4,
		Sessions: []*pb.SessionEntry{{}, {}},
	}
	if got := peerSessionsTotal(resp); got != 4 {
		t.Fatalf("peerSessionsTotal = %d, want 4 (the server's real filtered total, not len(Sessions)=2)", got)
	}

	// Exact (non-capped) case: total equals the returned count.
	exact := &pb.GetSessionsResponse{
		Total:    3,
		Sessions: []*pb.SessionEntry{{}, {}, {}},
	}
	if got := peerSessionsTotal(exact); got != 3 {
		t.Fatalf("peerSessionsTotal(exact) = %d, want 3", got)
	}

	// Nil-safe (peer unreachable): render 0, never panic.
	if got := peerSessionsTotal(nil); got != 0 {
		t.Fatalf("peerSessionsTotal(nil) = %d, want 0", got)
	}
}

// TestPeerSessionsTotalMixedVersionFallback pins the retained -1-sentinel
// fallback for a mixed-version cluster (ISSU): a NEW cli querying an OLD
// (pre-#5034) peer receives Total=-1 for a filtered query. The cli must NOT
// render the raw -1 (the #4908/#5033 bug) — it falls back to the returned
// count, exactly as #5033 did.
//
// FAIL-ON-REVERT: dropping the `>= 0` guard so peerSessionsTotal returns
// resp.GetTotal() unconditionally makes this return -1 → RED.
func TestPeerSessionsTotalMixedVersionFallback(t *testing.T) {
	// Old peer: Total=-1 sentinel, but a non-empty returned list.
	oldPeer := &pb.GetSessionsResponse{
		Total:    -1,
		Sessions: []*pb.SessionEntry{{}, {}, {}},
	}
	if got := peerSessionsTotal(oldPeer); got != 3 {
		t.Fatalf("peerSessionsTotal(old peer, Total=-1) = %d, want 3 (len(Sessions) fallback, never the raw -1)", got)
	}

	// Old peer with an empty list still never renders a negative count.
	emptyOldPeer := &pb.GetSessionsResponse{Total: -1}
	if got := peerSessionsTotal(emptyOldPeer); got != 0 {
		t.Fatalf("peerSessionsTotal(old peer, Total=-1, no sessions) = %d, want 0", got)
	}
}
