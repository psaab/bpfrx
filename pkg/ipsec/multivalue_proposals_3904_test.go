package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGenerateConfig_MultiProposal_3904 is the F-040/F-161 render RED-on-revert
// guard: an IKE / IPsec policy that lists two proposals must emit BOTH into the
// swanctl `proposals =` / `esp_proposals =` line (comma-joined), never just the
// first. Before #3904 IKEPolicy.Proposals / IPsecPolicyDef.Proposals were
// scalar strings, so the second proposal was dropped and crypto negotiation
// silently narrowed (a peer requiring the second proposal could not establish).
func TestGenerateConfig_MultiProposal_3904(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {Name: "ike-p1", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"ike-p2": {Name: "ike-p2", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Mode: "main", Proposals: []string{"ike-p1", "ike-p2"}, PSK: "secret"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "203.0.113.1", LocalAddress: "198.51.100.1", IKEPolicy: "ike-pol", Version: "v2-only"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-p1": {Name: "esp-p1", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
			"esp-p2": {Name: "esp-p2", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-256-128", DHGroup: 14},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-p1", "esp-p2"}},
		},
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {Name: "site-a", Gateway: "gw1", IPsecPolicy: "ipsec-pol"},
		},
	}
	got := m.generateConfig(cfg)

	// Both IKE proposals, comma-joined, in the phase-1 proposals line.
	if !strings.Contains(got, "proposals = aes256-sha256-modp2048,aes128-sha256-modp2048") {
		t.Errorf("IKE proposals line missing the full comma-joined set; got:\n%s", got)
	}
	// Both ESP proposals, comma-joined, in the phase-2 esp_proposals line.
	if !strings.Contains(got, "esp_proposals = aes256-sha256-modp2048,aes128-sha256-modp2048") {
		t.Errorf("ESP esp_proposals line missing the full comma-joined set; got:\n%s", got)
	}
}
