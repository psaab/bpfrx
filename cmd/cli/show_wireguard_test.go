package main

import (
	"strings"
	"testing"
)

// TestShowSecurityWireguardPublicKeyTopicMapping verifies the REMOTE CLI
// maps `show security wireguard public-key` to the gRPC ShowText topic
// "wireguard-public-key" (cmd/cli/show.go). The fake client records the
// topic; the assertion bites if the mapping at the `public-key` case is
// changed (e.g. left as the default "wireguard" status topic, or the
// topic string typo'd). #1434 Increment 1.
//
// Mutation-verified: changing c.showText("wireguard-public-key") in
// show.go to any other topic string makes showTextTopic mismatch and the
// test fails.
func TestShowSecurityWireguardPublicKeyTopicMapping(t *testing.T) {
	fake := &fakeBpfrxClient{showTextOutput: "Local public key:   <rendered>\n"}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"security", "wireguard", "public-key"}); err != nil {
			t.Fatalf("handleShow security wireguard public-key: %v", err)
		}
	})

	if fake.showTextCalls != 1 {
		t.Fatalf("ShowText called %d times, want exactly 1", fake.showTextCalls)
	}
	if fake.showTextTopic != "wireguard-public-key" {
		t.Fatalf("ShowText topic = %q, want %q", fake.showTextTopic, "wireguard-public-key")
	}
	// The server-rendered output is printed back verbatim.
	if !strings.Contains(out, "Local public key:") {
		t.Fatalf("remote output missing server text:\n%s", out)
	}
}

// Guard the sibling mappings so a future refactor that re-orders the
// wireguard cases cannot silently cross-wire public-key with
// detail/status.
func TestShowSecurityWireguardTopicMappings(t *testing.T) {
	cases := []struct {
		args      []string
		wantTopic string
	}{
		{[]string{"security", "wireguard"}, "wireguard"},
		{[]string{"security", "wireguard", "detail"}, "wireguard-detail"},
		{[]string{"security", "wireguard", "public-key"}, "wireguard-public-key"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			fake := &fakeBpfrxClient{}
			c := &ctl{client: fake}
			if err := c.handleShow(tc.args); err != nil {
				t.Fatalf("handleShow(%v): %v", tc.args, err)
			}
			if fake.showTextTopic != tc.wantTopic {
				t.Fatalf("handleShow(%v) topic = %q, want %q", tc.args, fake.showTextTopic, tc.wantTopic)
			}
		})
	}
}
