package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestPhase2DHGroupParseRenderRoundTrip is the #2639 end-to-end guard:
// a Junos-native Phase 2 (ESP) proposal `dh-group group14` must compile
// (pkg/config) to DHGroup 14 and then render (pkg/ipsec) to the canonical
// swanctl modp2048 token. Before the fix the Phase 2 compiler dropped the
// prefixed spelling to DHGroup 0, so buildESPProposal emitted no DH group
// at all and PFS was silently disabled.
func TestPhase2DHGroupParseRenderRoundTrip(t *testing.T) {
	tree := &config.ConfigTree{}
	cmds := []string{
		"set security ipsec proposal esp-p2 protocol esp",
		"set security ipsec proposal esp-p2 encryption-algorithm aes-256-cbc",
		"set security ipsec proposal esp-p2 authentication-algorithm hmac-sha-256-128",
		"set security ipsec proposal esp-p2 dh-group group14",
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
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	prop := cfg.Security.IPsec.Proposals["esp-p2"]
	if prop == nil {
		t.Fatal("esp-p2 proposal not compiled")
	}
	if prop.DHGroup != 14 {
		t.Fatalf("parsed DHGroup = %d, want 14 (group14 must not be dropped)", prop.DHGroup)
	}
	got := buildESPProposal(prop, 0)
	const want = "aes256-sha256128-modp2048"
	if got != want {
		t.Errorf("rendered ESP proposal = %q, want %q", got, want)
	}
}
