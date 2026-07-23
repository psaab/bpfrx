package main

import (
	"strings"
	"testing"
)

// TestHandleShowSecurityPolicies_RejectsUnknownFilterToken_5557 is the
// OPERATOR-SURFACE (CLI-level, not renderer-level) fail-on-revert guard for the
// remote `show security policies` wrappers. FINDING 1 (#6393 review): the
// daemon-side gRPC parseZoneFilter rejects an unrecognized filter token, but the
// remote CLI wrappers built the forwarded filter by copying ONLY from-zone/
// to-zone pairs and silently DROPPED everything else — so a typo'd key
// (`from-zonee trust`) never reached the strict parser and the view silently
// widened to every zone.
//
// This drives handleShowSecurity directly (the path a real `cli` invocation
// takes) for BOTH the policies-detail and policies-hit-count subcases: the bad
// token must abort at the CLI with an error BEFORE any RPC is issued
// (showTextCalls stays 0), and a well-formed filter must still be forwarded.
//
// FAIL-ON-REVERT: relax validatePolicyZoneSelectors back to the loose parse
// (drop the unrecognized-token rejection) and the bad token is forwarded as an
// empty filter — handleShowSecurity returns nil and issues the ShowText RPC, so
// both the error assertion and the showTextCalls==0 assertion go RED.
func TestHandleShowSecurityPolicies_RejectsUnknownFilterToken_5557(t *testing.T) {
	for _, sub := range []string{"detail", "hit-count"} {
		t.Run(sub, func(t *testing.T) {
			// Bad token: aborts at the CLI, no RPC.
			badClient := &fakeBpfrxClient{}
			bad := &ctl{client: badClient}
			err := bad.handleShowSecurity([]string{"policies", sub, "from-zonee", "trust"})
			if err == nil {
				t.Fatalf("%s: unknown filter token accepted; expected a CLI-level rejection", sub)
			}
			if !strings.Contains(err.Error(), "unrecognized filter token") {
				t.Fatalf("%s: error = %q, want an 'unrecognized filter token' rejection", sub, err)
			}
			if badClient.showTextCalls != 0 {
				t.Fatalf("%s: ShowText RPC issued despite a bad filter token (%d calls); the widened query reached the daemon",
					sub, badClient.showTextCalls)
			}

			// Well-formed filter: forwarded to the daemon (no over-rejection).
			goodClient := &fakeBpfrxClient{}
			good := &ctl{client: goodClient}
			if err := good.handleShowSecurity([]string{"policies", sub, "from-zone", "trust", "to-zone", "untrust"}); err != nil {
				t.Fatalf("%s: valid filter wrongly rejected: %v", sub, err)
			}
			if goodClient.showTextCalls != 1 {
				t.Fatalf("%s: valid filter did not issue exactly one ShowText RPC (got %d)", sub, goodClient.showTextCalls)
			}
			wantTopic := "policies-" + sub
			if goodClient.showTextTopic != wantTopic {
				t.Fatalf("%s: ShowText topic = %q, want %q", sub, goodClient.showTextTopic, wantTopic)
			}
			if !strings.Contains(goodClient.showTextFilter, "from-zone trust") ||
				!strings.Contains(goodClient.showTextFilter, "to-zone untrust") {
				t.Fatalf("%s: forwarded filter = %q, want the from-zone/to-zone pair", sub, goodClient.showTextFilter)
			}
		})
	}
}
