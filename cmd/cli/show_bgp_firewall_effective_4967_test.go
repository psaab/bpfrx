package main

import (
	"strings"
	"testing"
)

// TestRemoteShowBGPAliasRoutesToProtocolsBGP is the RED-on-revert proof for the
// `show bgp` half of #4967. cmdtree advertises `show bgp` (an alias for `show
// protocols bgp`) and the local CLI implements it, but the remote dispatcher
// had no top-level `bgp` case, so an operator who tab-completed `show bgp
// summary` on the remote `cli` fell through to the wrong handler.
//
// After the fix the remote dispatcher routes `show bgp ...` to
// handleShowProtocols, which issues the GetBGPStatus RPC (exactly as
// `show protocols bgp ...` does). Removing the `case "bgp"` makes
// getBGPStatusCalls drop to 0 and this test fails.
func TestRemoteShowBGPAliasRoutesToProtocolsBGP(t *testing.T) {
	fake := &fakeBpfrxClient{getBGPStatusOutput: "Groups: 1 Peers: 1\n"}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"bgp", "summary"}); err != nil {
			t.Fatalf("handleShow(show bgp summary): %v", err)
		}
	})

	if fake.getBGPStatusCalls != 1 {
		t.Fatalf("`show bgp summary` must issue GetBGPStatus exactly once; got %d "+
			"(0 = pre-#4967: no remote bgp case, command fell through)", fake.getBGPStatusCalls)
	}
	if got := fake.getBGPStatusReq.GetType(); got != "summary" {
		t.Fatalf("GetBGPStatus type = %q, want %q (alias must carry the sub-command)", got, "summary")
	}
	if fake.showTextCalls != 0 {
		t.Fatalf("`show bgp` must not fall through to a raw showText topic; showTextCalls=%d topic=%q",
			fake.showTextCalls, fake.showTextTopic)
	}
	if !strings.Contains(out, "Groups: 1 Peers: 1") {
		t.Fatalf("output missing BGP status:\n%s", out)
	}
}

// TestRemoteShowFirewallEffectiveRoutesToEffectiveTopic is the RED-on-revert
// proof for the `show firewall effective` half of #4967. cmdtree advertises
// `show firewall effective` and the local CLI renders the compiled snapshot,
// but the remote dispatcher's firewall case recognized only `filter`, so
// `show firewall effective` fell through to showText("firewall") — the RAW
// config, a semantically DIFFERENT view than advertised.
//
// After the fix the remote dispatcher maps every effective form to the
// dedicated server topics. Reverting the effective handling routes them back to
// the raw "firewall" topic and these assertions fail.
func TestRemoteShowFirewallEffectiveRoutesToEffectiveTopic(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantTopic string
	}{
		{"all", []string{"firewall", "effective"}, "firewall-effective"},
		{"all-family", []string{"firewall", "effective", "family", "inet"}, "firewall-effective:inet"},
		{"filter", []string{"firewall", "filter", "f1", "effective"}, "firewall-effective-filter:f1"},
		{"filter-family", []string{"firewall", "filter", "f1", "effective", "family", "inet6"}, "firewall-effective-filter:f1:inet6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			_ = captureStdout(t, func() {
				if err := c.handleShow(tc.args); err != nil {
					t.Fatalf("handleShow(%v): %v", tc.args, err)
				}
			})
			if fake.showTextCalls != 1 {
				t.Fatalf("expected exactly one showText call, got %d", fake.showTextCalls)
			}
			if fake.showTextTopic != tc.wantTopic {
				t.Fatalf("show %v -> topic %q, want %q (pre-#4967 fell through to raw \"firewall\")",
					tc.args, fake.showTextTopic, tc.wantTopic)
			}
		})
	}
}

// TestRemoteShowFirewallNonEffectiveUnchanged pins that the raw / filter forms
// still route to their original topics — the effective handling must be additive
// and not disturb the pre-existing grammar (#4967).
func TestRemoteShowFirewallNonEffectiveUnchanged(t *testing.T) {
	cases := []struct {
		args      []string
		wantTopic string
	}{
		{[]string{"firewall"}, "firewall"},
		{[]string{"firewall", "filter", "f1"}, "firewall-filter:f1"},
		{[]string{"firewall", "filter", "f1", "family", "inet"}, "firewall-filter:f1:inet"},
	}
	for _, tc := range cases {
		fake := &fakeBpfrxClient{}
		c := &ctl{client: fake}
		_ = captureStdout(t, func() {
			if err := c.handleShow(tc.args); err != nil {
				t.Fatalf("handleShow(%v): %v", tc.args, err)
			}
		})
		if fake.showTextTopic != tc.wantTopic {
			t.Fatalf("show %v -> topic %q, want %q", tc.args, fake.showTextTopic, tc.wantTopic)
		}
	}
}
