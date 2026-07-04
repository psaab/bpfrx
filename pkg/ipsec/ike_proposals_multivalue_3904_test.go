package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3904 (fable-161 F-040/F-161): a multi-proposal IKE/IPsec policy
// (`proposals [ p1 p2 ]`) must offer EVERY listed proposal in the generated
// swanctl config. Before #3904 IKEPolicy.Proposals / IPsecPolicyDef.Proposals
// were scalar strings that captured only the first reference, so phase-1/2
// negotiation silently narrowed — a peer requiring the second proposal could
// not establish. resolveIKESettings / resolveESPSettings now build every
// resolvable reference and comma-join them into the swanctl proposals list.
//
// fail-on-revert: restoring the scalar (single-proposal) render drops the
// second proposal from both the `proposals =` (IKE) and `esp_proposals =`
// (ESP) lines, so the "second proposal present" assertions go RED.

// TestGenerateConfig_MultiIKEProposals asserts both IKE proposals in a
// `proposals [ ike-a ike-b ]` policy reach the swanctl `proposals =` line,
// comma-joined and in order.
func TestGenerateConfig_MultiIKEProposals(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Gateway: "gw1", IPsecPolicy: "esp-pol"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {Name: "gw1", Address: "172.16.0.1", IKEPolicy: "ike-pol"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-a", "ike-b"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-a": {Name: "ike-a", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"ike-b": {Name: "ike-b", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 5},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-a"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: 14},
		},
	}
	got := m.generateConfig(cfg)
	want := "proposals = aes256-sha256-modp2048,aes128-sha256-modp1536"
	if !strings.Contains(got, want) {
		t.Errorf("expected both IKE proposals comma-joined (%q), got:\n%s", want, got)
	}
	// The second proposal alone would be dropped by the pre-#3904 scalar read.
	if !strings.Contains(got, "aes128-sha256-modp1536") {
		t.Errorf("second IKE proposal missing from swanctl output (crypto narrowing):\n%s", got)
	}
}

// TestGenerateConfig_MultiESPProposals asserts both ESP proposals in a
// `proposals [ esp-a esp-b ]` IPsec policy reach the `esp_proposals =` line.
func TestGenerateConfig_MultiESPProposals(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", Proposals: []string{"esp-a", "esp-b"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: 14},
			"esp-b": {Name: "esp-b", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-256", DHGroup: 5},
		},
	}
	got := m.generateConfig(cfg)
	want := "esp_proposals = aes256-sha256-modp2048,aes128-sha256-modp1536"
	if !strings.Contains(got, want) {
		t.Errorf("expected both ESP proposals comma-joined (%q), got:\n%s", want, got)
	}
	if !strings.Contains(got, "aes128-sha256-modp1536") {
		t.Errorf("second ESP proposal missing from swanctl output (crypto narrowing):\n%s", got)
	}
}

// TestGenerateConfig_MultiESPProposalsPFS asserts the policy-level PFS group
// is applied to EVERY proposal in the list (the DH suffix is the PFS group,
// not each proposal's own dh-group).
func TestGenerateConfig_MultiESPProposalsPFS(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "esp-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"esp-pol": {Name: "esp-pol", PFSGroup: 19, Proposals: []string{"esp-a", "esp-b"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256"},
			"esp-b": {Name: "esp-b", EncryptionAlg: "aes-128-cbc", AuthAlg: "hmac-sha-256"},
		},
	}
	got := m.generateConfig(cfg)
	want := "esp_proposals = aes256-sha256-ecp256,aes128-sha256-ecp256"
	if !strings.Contains(got, want) {
		t.Errorf("expected PFS group applied to both ESP proposals (%q), got:\n%s", want, got)
	}
}
