package ipsec

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #2270 render-side fail-closed coverage. resolveIKESettings must
// distinguish the intentional no-policy case (empty proposal, nil error)
// from a broken ike-policy chain (errIKEChainUnresolved), so renderConfig
// never silently emits a proposal-less connection that strongSwan would
// negotiate with its compiled-in defaults.

// resolveIKESettings returns a nil error and an empty proposal for the
// intentional no-policy case.
func TestResolveIKESettings_NoPolicyOK(t *testing.T) {
	cfg := &config.IPsecConfig{}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1"}
	_, prop, _, _, err := resolveIKESettings(cfg, gw)
	if err != nil {
		t.Fatalf("no-policy gateway must not error: %v", err)
	}
	if prop != "" {
		t.Errorf("no-policy gateway proposal = %q, want empty (strongSwan default chosen)", prop)
	}
}

// resolveIKESettings returns errIKEChainUnresolved when the gateway names
// an undefined ike-policy.
func TestResolveIKESettings_DanglingPolicyFailsClosed(t *testing.T) {
	cfg := &config.IPsecConfig{}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "does-not-exist"}
	_, prop, _, _, err := resolveIKESettings(cfg, gw)
	if err == nil {
		t.Fatal("dangling ike-policy must fail closed, got nil error")
	}
	if !errors.Is(err, errIKEChainUnresolved) {
		t.Errorf("error = %v, want errIKEChainUnresolved", err)
	}
	if prop != "" {
		t.Errorf("broken chain proposal = %q, want empty", prop)
	}
}

// resolveIKESettings returns errIKEChainUnresolved when the ike-policy
// resolves but its `proposals` reference dangles.
func TestResolveIKESettings_DanglingProposalFailsClosed(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: "no-such-proposal"},
		},
	}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"}
	_, _, _, _, err := resolveIKESettings(cfg, gw)
	if !errors.Is(err, errIKEChainUnresolved) {
		t.Fatalf("dangling proposal must fail closed with errIKEChainUnresolved, got: %v", err)
	}
}

// A fully resolvable chain returns the built proposal with no error.
func TestResolveIKESettings_ResolvableChain(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: "ike-prop"},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-prop": {
				Name:          "ike-prop",
				AuthMethod:    "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
	}
	gw := &config.IPsecGateway{Name: "gw1", Address: "192.0.2.1", IKEPolicy: "ike-pol"}
	_, prop, _, _, err := resolveIKESettings(cfg, gw)
	if err != nil {
		t.Fatalf("resolvable chain errored: %v", err)
	}
	if prop == "" {
		t.Fatal("resolvable chain produced an empty proposal")
	}
	if !strings.Contains(prop, "aes256") {
		t.Errorf("proposal %q missing encryption token", prop)
	}
}

// renderConfig SKIPS a VPN whose ike-policy chain is broken (so its
// connection and secret are omitted) while a healthy tunnel in the same
// config renders normally with a `proposals =` line. One bad reference
// never zeroes a healthy tunnel, and a proposal-less connection is never
// written for the broken one.
func TestRenderConfig_BrokenChainSkipsVPN_HealthyTunnelSurvives(t *testing.T) {
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"good-pol": {Name: "good-pol", Proposals: "good-prop", PSK: "secret-good"},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"good-prop": {
				Name:          "good-prop",
				AuthMethod:    "pre-shared-keys",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw-good": {Name: "gw-good", Address: "192.0.2.1", IKEPolicy: "good-pol"},
			"gw-bad":  {Name: "gw-bad", Address: "192.0.2.2", IKEPolicy: "missing-pol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun-good": {Name: "tun-good", Gateway: "gw-good"},
			"tun-bad":  {Name: "tun-bad", Gateway: "gw-bad"},
		},
	}

	m := New()
	out := m.generateConfig(cfg)

	// Healthy tunnel: connection block present, with a non-empty proposals
	// line carrying the configured crypto.
	if !strings.Contains(out, "tun-good {") {
		t.Errorf("healthy tunnel tun-good missing from render:\n%s", out)
	}
	if !strings.Contains(out, "proposals = aes256") {
		t.Errorf("healthy tunnel missing a non-empty proposals line:\n%s", out)
	}

	// Broken tunnel: connection block must NOT be emitted (no proposal-less
	// connection that would negotiate with strongSwan defaults).
	if strings.Contains(out, "tun-bad {") {
		t.Errorf("broken-chain tunnel tun-bad was rendered; it must be skipped:\n%s", out)
	}
	// And its secret must not be orphaned in the secrets block.
	if strings.Contains(out, "ike-tun-bad {") {
		t.Errorf("broken-chain tunnel tun-bad secret was emitted; must be skipped:\n%s", out)
	}
}

// A no-policy gateway renders a normal connection WITHOUT a proposals line
// (the intentional default case) and is NOT skipped.
func TestRenderConfig_NoPolicyGatewayRendersWithoutProposalsLine(t *testing.T) {
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "192.0.2.1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Name: "tun1", Gateway: "gw1"},
		},
	}
	m := New()
	out := m.generateConfig(cfg)
	if !strings.Contains(out, "tun1 {") {
		t.Errorf("no-policy tunnel tun1 missing from render:\n%s", out)
	}
	// The IKE-level (Phase 1) proposals line is intentionally absent. Guard
	// against the connection-level "    proposals = " (four-space indent),
	// distinct from the child "        esp_proposals = " line.
	if strings.Contains(out, "\n    proposals = ") {
		t.Errorf("no-policy tunnel must not emit an IKE proposals line:\n%s", out)
	}
}
