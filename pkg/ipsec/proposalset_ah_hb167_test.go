package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// fable-review-167 render-side coverage:
//
//	V-1 (#4297): a predefined proposal-set renders the Junos-documented
//	             swanctl proposal tokens (end-to-end: compile -> render).
//	V-2 (#4298): a `protocol ah` proposal makes renderConfig SKIP the VPN
//	             rather than emit ESP with a fabricated cipher.

func compileToIPsec(t *testing.T, lines []string) *config.IPsecConfig {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return PrepareConfig(cfg)
}

// V-1: proposal-set standard renders the concrete swanctl proposals on both
// the Phase-1 (proposals =) and Phase-2 (esp_proposals =) lines.
//
// FAIL-ON-REVERT: without the compiler expansion the policies carry no
// resolvable proposal, so CompileConfig errors (compileToIPsec t.Fatalf) —
// the shorthand cannot commit a working tunnel.
func TestProposalSetStandardRenders_4297(t *testing.T) {
	prepared := compileToIPsec(t, []string{
		"set security zones security-zone untrust",
		"set security ike policy ike-pol proposal-set standard",
		"set security ike policy ike-pol pre-shared-key ascii-text secret123",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-pol",
		"set security ipsec policy esp-pol proposal-set standard",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 ike ipsec-policy esp-pol",
	})
	out := New().generateConfig(prepared)
	if !strings.Contains(out, "tun1 {") {
		t.Fatalf("proposal-set standard tunnel missing from render:\n%s", out)
	}
	// Phase-1: 3des-sha1-modp1024 (group2) and aes128-sha1-modp1024, comma-joined.
	if !strings.Contains(out, "3des-sha1-modp1024") || !strings.Contains(out, "aes128-sha1-modp1024") {
		t.Errorf("IKE proposals line missing the standard set members:\n%s", out)
	}
	// Phase-2: 3des-sha1 and aes128-sha1.
	if !strings.Contains(out, "esp_proposals = ") ||
		!strings.Contains(out, "3des-sha1") || !strings.Contains(out, "aes128-sha1") {
		t.Errorf("esp_proposals line missing the standard ESP set members:\n%s", out)
	}
}

// V-1: suiteb-gcm-128 renders the RFC 6379 AEAD tokens (aes128gcm16 + ecp256).
func TestProposalSetSuiteB128Renders_4297(t *testing.T) {
	prepared := compileToIPsec(t, []string{
		"set security zones security-zone untrust",
		"set security ike policy ike-sb proposal-set suiteb-gcm-128",
		"set security ike gateway gw1 address 172.16.0.1",
		"set security ike gateway gw1 ike-policy ike-sb",
		"set security ike gateway gw1 local-certificate my-cert",
		"set security ipsec policy esp-sb proposal-set suiteb-gcm-128",
		"set security ipsec vpn tun1 ike gateway gw1",
		"set security ipsec vpn tun1 ike ipsec-policy esp-sb",
	})
	out := New().generateConfig(prepared)
	if !strings.Contains(out, "aes128gcm16-prfsha256-ecp256") {
		t.Errorf("IKE suiteb-gcm-128 proposal token missing:\n%s", out)
	}
	if !strings.Contains(out, "aes128gcm16-ecp256") {
		t.Errorf("ESP suiteb-gcm-128 proposal token missing:\n%s", out)
	}
}

// V-2: a VPN whose ipsec-policy resolves to a `protocol ah` proposal is
// SKIPPED at render — never emitted as ESP with a fabricated cipher — while a
// healthy ESP VPN in the same config survives.
//
// FAIL-ON-REVERT: without the vpnUsesAHProposal belt, tun-ah renders an
// esp_proposals line (aes256 default) and "tun-ah {" appears — RED.
func TestRenderConfig_AHProposalSkipsVPN_4298(t *testing.T) {
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"ah-prop":  {Name: "ah-prop", Protocol: "ah", AuthAlg: "hmac-sha-256-128"},
			"esp-prop": {Name: "esp-prop", Protocol: "esp", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ah-pol":  {Name: "ah-pol", Proposals: []string{"ah-prop"}},
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-prop"}},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-ah":  {Name: "gw-ah", Address: "192.0.2.1"},
			"gw-esp": {Name: "gw-esp", Address: "192.0.2.2"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun-ah":  {Name: "tun-ah", Gateway: "gw-ah", IPsecPolicy: "ah-pol"},
			"tun-esp": {Name: "tun-esp", Gateway: "gw-esp", IPsecPolicy: "esp-pol"},
		},
	}
	out := New().generateConfig(cfg)
	if strings.Contains(out, "tun-ah {") {
		t.Errorf("AH VPN tun-ah must be skipped (never fabricated ESP):\n%s", out)
	}
	if !strings.Contains(out, "tun-esp {") {
		t.Errorf("healthy ESP VPN tun-esp missing from render:\n%s", out)
	}
}
