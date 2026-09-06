package grpcapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// #9074: ClearCounters clears the LOCAL node only, while ClearSessions fans out
// to the peer. That asymmetry is DELIBERATE and this file pins it, because
// today the behaviour and the documentation agree with each other and nothing
// asserts the agreement — so a future "make it consistent with ClearSessions"
// change would look like a tidy-up.
//
// WHY THE PARITY ARGUMENT DOES NOT CARRY. Sessions are REPLICATED between
// nodes, so a local-only session clear is undone by sync — that is the stated
// reason for the session fanout (#2468). Counters are NOT replicated, so a
// node-local clear is self-consistent and complete. The two operations are not
// analogous, and the fanout is not a feature ClearCounters is missing.
//
// AND FANNING OUT WOULD COST SOMETHING SPECIFIC. `ClearCounters` is absent from
// fabricAllowedUnaryMethods, so a fanout requires widening that allowlist —
// which #9059 has just argued must be done deliberately, per method, with its
// own rationale, rather than as a side effect of an unrelated change. Trading a
// documented node-local scope for a wider fabric surface is a bad exchange for
// a behaviour nothing has asked for.
//
// If node scoping IS wanted later, the shape is `node <local|peer|both>` in the
// grammar, not a silent fanout — and this cell should be updated in the change
// that adds it, not deleted.

// TestClearCountersIsNodeLocalByDesign9074 asserts the handler does not dial a
// peer, by reading its source. A behavioural assertion would need a two-node
// harness to prove a NEGATIVE — that nothing was sent — which is exactly the
// kind of absence a probe cannot establish.
func TestClearCountersIsNodeLocalByDesign9074(t *testing.T) {
	src, err := os.ReadFile("server_cluster.go")
	if err != nil {
		t.Fatalf("read server_cluster.go: %v", err)
	}
	body := clearCountersBody9074(t, string(src))

	for _, forbidden := range []string{
		"peerForwardedFromContext",
		"dialPeer",
		"peerClient",
		"fanout",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("ClearCounters mentions %q. If a peer fanout is being added, it "+
				"also needs ClearCounters on the fabric allowlist with its own "+
				"rationale (#9059), and the grammar's \"takes no scope\" wording "+
				"has to change with it — this cell is the reminder, not an "+
				"obstacle", forbidden)
		}
	}
	// POSITIVE CONTROL: the extraction really found the handler. Without this a
	// stale regex reports a clean board over an empty string.
	if !strings.Contains(body, "ClearAllCounters") {
		t.Fatalf("the extracted ClearCounters body does not call ClearAllCounters; "+
			"the extraction is stale and this case is asserting nothing:\n%s", body)
	}
	// And the CONTRAST that makes the assertion meaningful: ClearSessions DOES
	// fan out. If it ever stops, the reasoning above ("sessions are replicated,
	// counters are not") no longer explains the asymmetry and this file is
	// wrong rather than merely out of date.
	sess, err := os.ReadFile("server_sessions.go")
	if err != nil {
		t.Fatalf("read server_sessions.go: %v", err)
	}
	if !strings.Contains(string(sess), "peerForwardedFromContext") {
		t.Error("ClearSessions no longer fans out to the peer; the asymmetry this " +
			"file documents has disappeared, so its reasoning needs re-deriving")
	}
}

// clearCountersBody9074 extracts the ClearCounters function body.
func clearCountersBody9074(t *testing.T, src string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)func \(s \*Server\) ClearCounters\(.*?\n}\n`)
	m := re.FindString(src)
	if m == "" {
		t.Fatal("could not find func (s *Server) ClearCounters")
	}
	return m
}

// The grammar's own wording must keep disclaiming scope, in BOTH CLIs. The two
// copies are deliberately byte-identical so the two front ends reject the same
// input the same way; if one drifts, an operator gets different answers from
// the local console and the remote client.
func TestClearGrammarDisclaimsScope9074(t *testing.T) {
	const wording = "and takes no scope (per-scope clear is not supported)"
	for _, path := range []string{
		"../../cmd/cli/clear.go",
		"../cli/cli_clear.go",
	} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(src), wording) {
			t.Errorf("%s no longer disclaims scope. Today's behaviour (node-local) "+
				"and today's help text agree; if the behaviour gains node scoping "+
				"this text must change WITH it, and if the text changes alone the "+
				"two stop agreeing", path)
		}
	}
}
