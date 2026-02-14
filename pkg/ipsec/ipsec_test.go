package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestGenerateConfig_Basic(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           "supersecret",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "connections {") {
		t.Error("missing connections block")
	}
	if !strings.Contains(got, "site-a {") {
		t.Error("missing connection name")
	}
	if !strings.Contains(got, "local_addrs = 10.0.1.1") {
		t.Error("missing local_addrs")
	}
	if !strings.Contains(got, "remote_addrs = 10.0.2.1") {
		t.Error("missing remote_addrs")
	}
	if !strings.Contains(got, "auth = psk") {
		t.Error("missing auth = psk")
	}
	if !strings.Contains(got, "if_id_in = 1") {
		t.Error("missing if_id_in for st0.0")
	}
	if !strings.Contains(got, "if_id_out = 1") {
		t.Error("missing if_id_out for st0.0")
	}
	if !strings.Contains(got, "secrets {") {
		t.Error("missing secrets block")
	}
	if !strings.Contains(got, `secret = "supersecret"`) {
		t.Error("missing PSK secret")
	}
}

func TestGenerateConfig_WithProposal(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "strong",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"strong": {
				Name:          "strong",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "esp_proposals = aes256-sha256128-modp2048") {
		t.Errorf("unexpected esp_proposals in: %s", got)
	}
}

func TestGenerateConfig_GCMNoAuth(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "gcm",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"gcm": {
				Name:          "gcm",
				EncryptionAlg: "aes256gcm128",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	got := m.generateConfig(cfg)
	// GCM mode should skip auth algorithm
	if strings.Contains(got, "sha256128-modp2048") {
		t.Errorf("GCM should not include auth alg: %s", got)
	}
	if !strings.Contains(got, "esp_proposals = aes256gcm128-modp2048") {
		t.Errorf("unexpected GCM proposal: %s", got)
	}
}

func TestXfrmiIfID(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"st0.0", 1},
		{"st1.0", 2},
		{"st5.0", 6},
		{"st0", 1},
		{"", 0},
		{"eth0", 0},
		{"st", 0},
	}
	for _, tt := range tests {
		if got := xfrmiIfID(tt.input); got != tt.want {
			t.Errorf("xfrmiIfID(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestDHGroupBits(t *testing.T) {
	tests := []struct {
		group int
		want  int
	}{
		{1, 768},
		{2, 1024},
		{5, 1536},
		{14, 2048},
		{15, 3072},
		{16, 4096},
		{19, 256},
		{20, 384},
		{99, 99}, // passthrough for unknown
	}
	for _, tt := range tests {
		if got := dhGroupBits(tt.group); got != tt.want {
			t.Errorf("dhGroupBits(%d) = %d, want %d", tt.group, got, tt.want)
		}
	}
}

func TestBuildESPProposal(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-sha256-dh14",
			&config.IPsecProposal{EncryptionAlg: "aes256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256128-modp2048",
		},
		{
			"defaults",
			&config.IPsecProposal{},
			"aes256",
		},
		{
			"gcm-no-auth",
			&config.IPsecProposal{EncryptionAlg: "aes256gcm128", AuthAlg: "hmac-sha512", DHGroup: 20},
			"aes256gcm128-modp384",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildESPProposal(tt.prop); got != tt.want {
				t.Errorf("buildESPProposal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSAOutput(t *testing.T) {
	output := `site-a: #1, ESTABLISHED
  local: 10.0.1.1 === 10.0.2.1
  site-a: #1, reqid 1, INSTALLED
    local_ts = 10.0.1.0/24
    remote_ts = 10.0.2.0/24
`
	sas := parseSAOutput(output)
	if len(sas) != 1 {
		t.Fatalf("expected 1 SA, got %d", len(sas))
	}
	if sas[0].Name != "site-a" {
		t.Errorf("name = %q, want %q", sas[0].Name, "site-a")
	}
	if sas[0].LocalAddr != "10.0.1.1" {
		t.Errorf("local addr = %q, want %q", sas[0].LocalAddr, "10.0.1.1")
	}
	if sas[0].RemoteAddr != "10.0.2.1" {
		t.Errorf("remote addr = %q, want %q", sas[0].RemoteAddr, "10.0.2.1")
	}
}

func TestGenerateConfig_GatewayReference(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"remote-gw": {
				Name:         "remote-gw",
				Address:      "10.0.2.1",
				LocalAddress: "10.0.1.1",
				IKEPolicy:    "ike-aes256",
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				Gateway:       "remote-gw", // reference to gateway name
				IPsecPolicy:   "esp-aes256",
				PSK:           "mysecret",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"ike-aes256": {
				Name:          "ike-aes256",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
			"esp-aes256": {
				Name:          "esp-aes256",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	got := m.generateConfig(cfg)

	// Should resolve gateway address, not use "remote-gw" as IP
	if !strings.Contains(got, "remote_addrs = 10.0.2.1") {
		t.Errorf("gateway address not resolved: %s", got)
	}
	// Should use gateway's local address
	if !strings.Contains(got, "local_addrs = 10.0.1.1") {
		t.Errorf("gateway local address not resolved: %s", got)
	}
	// Should have IKE proposals from gateway's ike-policy
	if !strings.Contains(got, "proposals = aes256-sha256128-modp2048") {
		t.Errorf("IKE proposals not generated: %s", got)
	}
	// Should have ESP proposals from VPN's ipsec-policy
	if !strings.Contains(got, "esp_proposals = aes256-sha256128-modp2048") {
		t.Errorf("ESP proposals not generated: %s", got)
	}
}

func TestGenerateConfig_DirectGatewayIP(t *testing.T) {
	// When gateway is an IP (not a reference), it should be used directly
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways:  map[string]*config.IPsecGateway{},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"direct": {
				Gateway:   "172.16.0.1",
				LocalAddr: "172.16.0.2",
				PSK:       "key123",
			},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "remote_addrs = 172.16.0.1") {
		t.Errorf("direct gateway IP not used: %s", got)
	}
	if !strings.Contains(got, "local_addrs = 172.16.0.2") {
		t.Errorf("direct local addr not used: %s", got)
	}
}

func TestBuildIKEProposal(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-sha256-dh14",
			&config.IPsecProposal{EncryptionAlg: "aes256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256128-modp2048",
		},
		{
			"defaults",
			&config.IPsecProposal{},
			"aes256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildIKEProposal(tt.prop); got != tt.want {
				t.Errorf("buildIKEProposal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSAOutput_Empty(t *testing.T) {
	sas := parseSAOutput("")
	if len(sas) != 0 {
		t.Errorf("expected 0 SAs for empty input, got %d", len(sas))
	}
}

func TestParseSAOutput_Multiple(t *testing.T) {
	output := `site-a: #1, ESTABLISHED
  local: 10.0.1.1 === 10.0.2.1
site-b: #2, CONNECTING
  local: 10.0.1.1 === 10.0.3.1
`
	sas := parseSAOutput(output)
	if len(sas) != 2 {
		t.Fatalf("expected 2 SAs, got %d", len(sas))
	}
	if sas[0].Name != "site-a" {
		t.Errorf("sa[0] name = %q", sas[0].Name)
	}
	if sas[1].Name != "site-b" {
		t.Errorf("sa[1] name = %q", sas[1].Name)
	}
	if sas[1].State != "CONNECTING" {
		t.Errorf("sa[1] state = %q, want CONNECTING", sas[1].State)
	}
}

func TestGenerateConfig_IKEChain(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name:          "ike-p1",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {
				Name:      "ike-pol",
				Mode:      "main",
				Proposals: "ike-p1",
				PSK:       "secret123",
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw1": {
				Name:            "gw1",
				Address:         "203.0.113.1",
				LocalAddress:    "198.51.100.1",
				IKEPolicy:       "ike-pol",
				Version:         "v2-only",
				NoNATTraversal:  true,
				DeadPeerDetect:  "always-send",
				LocalIDType:     "hostname",
				LocalIDValue:    "vpn.example.com",
				RemoteIDType:    "inet",
				RemoteIDValue:   "203.0.113.1",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {
				Name:          "esp-p2",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "hmac-sha-256-128",
				DHGroup:       14,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {
				Name:      "ipsec-pol",
				PFSGroup:  14,
				Proposals: "esp-p2",
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				Name:             "site-a",
				Gateway:          "gw1",
				IPsecPolicy:      "ipsec-pol",
				BindInterface:    "st0.0",
				DFBit:            "copy",
				EstablishTunnels: "immediately",
			},
		},
	}
	got := m.generateConfig(cfg)

	checks := []struct {
		name string
		want string
	}{
		{"IKE version", "version = 2"},
		{"local addr", "local_addrs = 198.51.100.1"},
		{"remote addr", "remote_addrs = 203.0.113.1"},
		{"no NAT-T", "encap = no"},
		{"DPD", "dpd_delay = 10s"},
		{"local identity", "id = @vpn.example.com"},
		{"remote identity", "id = 203.0.113.1"},
		{"IKE proposal", "proposals = aes256-sha256-modp2048"},
		{"ESP proposal", "esp_proposals = aes256-sha256128-modp2048"},
		{"copy DF", "copy_df = yes"},
		{"start action", "start_action = start"},
		{"XFRM if_id", "if_id_in = 1"},
		{"PSK from IKE policy", `secret = "secret123"`},
	}
	for _, c := range checks {
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: missing %q in:\n%s", c.name, c.want, got)
		}
	}
}

func TestGenerateConfig_DynamicHostname(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"dyn-gw": {
				Name:            "dyn-gw",
				DynamicHostname: "peer.example.com",
				IKEPolicy:       "pol1",
				Version:         "v2-only",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:       "dyn-gw",
				BindInterface: "st0.1",
				PSK:           "key456",
			},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "remote_addrs = peer.example.com") {
		t.Errorf("dynamic hostname not used as remote_addrs: %s", got)
	}
	if !strings.Contains(got, "version = 2") {
		t.Errorf("version not set: %s", got)
	}
}

func TestFormatIdentity(t *testing.T) {
	tests := []struct {
		idType, idValue, want string
	}{
		{"hostname", "vpn.example.com", "@vpn.example.com"},
		{"fqdn", "peer.example.com", "@peer.example.com"},
		{"inet", "10.0.0.1", "10.0.0.1"},
		{"", "10.0.0.1", "10.0.0.1"},
	}
	for _, tt := range tests {
		got := formatIdentity(tt.idType, tt.idValue)
		if got != tt.want {
			t.Errorf("formatIdentity(%q, %q) = %q, want %q", tt.idType, tt.idValue, got, tt.want)
		}
	}
}

func TestGenerateConfig_NATTraversal_Disable(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NATTraversal: "disable", NoNATTraversal: true},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "encap = no") {
		t.Errorf("disable NAT-T should produce 'encap = no': %s", got)
	}
	if strings.Contains(got, "forceencaps") {
		t.Errorf("disable NAT-T should not have forceencaps: %s", got)
	}
}

func TestGenerateConfig_NATTraversal_Force(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NATTraversal: "force"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "encap = yes") {
		t.Errorf("force NAT-T should produce 'encap = yes': %s", got)
	}
	if !strings.Contains(got, "forceencaps = yes") {
		t.Errorf("force NAT-T should produce 'forceencaps = yes': %s", got)
	}
}

func TestGenerateConfig_NATTraversal_Enable(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NATTraversal: "enable"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	got := m.generateConfig(cfg)
	// Enable is the strongSwan default — no encap/forceencaps lines needed.
	if strings.Contains(got, "encap = no") {
		t.Errorf("enable NAT-T should not have 'encap = no': %s", got)
	}
	if strings.Contains(got, "forceencaps") {
		t.Errorf("enable NAT-T should not have forceencaps: %s", got)
	}
}

func TestGenerateConfig_NATTraversal_Default(t *testing.T) {
	// When NATTraversal is empty (not set), and NoNATTraversal is false,
	// strongSwan auto-detects NAT — no encap lines needed.
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1"},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	got := m.generateConfig(cfg)
	if strings.Contains(got, "encap") {
		t.Errorf("default NAT-T should not have encap lines: %s", got)
	}
}

func TestGenerateConfig_NoNATTraversal_Legacy(t *testing.T) {
	// Legacy NoNATTraversal=true without NATTraversal field.
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "10.0.0.1", NoNATTraversal: true},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "key"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "encap = no") {
		t.Errorf("legacy NoNATTraversal should produce 'encap = no': %s", got)
	}
}

func TestGenerateConfig_AggressiveMode(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"aggr-pol": {
				Name:      "aggr-pol",
				Mode:      "aggressive",
				Proposals: "ike-p1",
				PSK:       "secret",
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:      "gw",
				Address:   "10.0.0.1",
				IKEPolicy: "aggr-pol",
				Version:   "v1-only",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "aggressive = yes") {
		t.Errorf("aggressive mode not set: %s", got)
	}
	if !strings.Contains(got, "version = 1") {
		t.Errorf("IKEv1 not set for aggressive mode: %s", got)
	}
}

func TestGenerateConfig_AggressiveMode_NotSet(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		IKEPolicies: map[string]*config.IKEPolicy{
			"main-pol": {
				Name: "main-pol",
				Mode: "main",
				PSK:  "secret",
			},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:      "gw",
				Address:   "10.0.0.1",
				IKEPolicy: "main-pol",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	got := m.generateConfig(cfg)
	if strings.Contains(got, "aggressive") {
		t.Errorf("main mode should not have aggressive: %s", got)
	}
}

func TestGenerateConfig_DFBit(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	tests := []struct {
		name  string
		dfbit string
		want  string
		notWant string
	}{
		{"copy", "copy", "copy_df = yes", "copy_df = no"},
		{"set", "set", "copy_df = no", "copy_df = yes"},
		{"clear", "clear", "", "copy_df"},
		{"empty", "", "", "copy_df"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.IPsecConfig{
				Proposals: map[string]*config.IPsecProposal{},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "10.0.0.1", DFBit: tt.dfbit},
				},
			}
			got := m.generateConfig(cfg)
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("df-bit %q: missing %q in:\n%s", tt.dfbit, tt.want, got)
			}
			if tt.notWant != "" && strings.Contains(got, tt.notWant) {
				t.Errorf("df-bit %q: unexpected %q in:\n%s", tt.dfbit, tt.notWant, got)
			}
		})
	}
}

func TestGenerateConfig_EstablishTunnels(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "10.0.0.1", EstablishTunnels: "immediately"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "start_action = start") {
		t.Errorf("establish-tunnels immediately should produce start_action: %s", got)
	}

	// on-traffic should NOT produce start_action
	cfg.VPNs["tun"].EstablishTunnels = "on-traffic"
	got = m.generateConfig(cfg)
	if strings.Contains(got, "start_action") {
		t.Errorf("on-traffic should not produce start_action: %s", got)
	}
}
