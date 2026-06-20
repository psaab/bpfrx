package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGenerateConfig_Basic(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
		{"st0.1", 2},
		{"st1.0", 65537},
		{"st5.0", 327681},
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
			if got := buildESPProposal(tt.prop, 0); got != tt.want {
				t.Errorf("buildESPProposal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildESPProposal_PFSOverride(t *testing.T) {
	prop := &config.IPsecProposal{
		EncryptionAlg: "aes256-cbc",
		AuthAlg:       "hmac-sha256-128",
		DHGroup:       2,
	}
	got := buildESPProposal(prop, 14)
	if got != "aes256-sha256128-modp2048" {
		t.Fatalf("buildESPProposal() with PFS override = %q, want aes256-sha256128-modp2048", got)
	}
}

// TestResolveESPSettings_DanglingProposalPreservesPFS is the #2073
// render-path safety net (Layer B): when an IPsec policy resolves and a
// PFS group is configured but its proposal reference is dangling, the
// renderer must NOT fall through to bare "default" (which drops PFS).
// Instead it must carry the configured PFS group on a valid fallback
// proposal that includes a cipher and integrity alg, using swanctl's
// canonical keyword spellings.
func TestResolveESPSettings_DanglingProposalPreservesPFS(t *testing.T) {
	cfg := &config.IPsecConfig{
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {
				Name:      "ipsec-pol",
				PFSGroup:  14,
				Proposals: "does-not-exist",
			},
		},
		// Proposals deliberately omits "does-not-exist" — dangling ref.
	}
	vpn := &config.IPsecVPN{IPsecPolicy: "ipsec-pol"}

	got, lifetime := resolveESPSettings(cfg, vpn)
	// Exact token, not a `modp` substring: a Contains("modp2048") check
	// would also pass for an invalid no-integrity "aes256-modp2048". The
	// integrity keyword MUST be the canonical "sha256" — strongSwan's
	// proposal parser does not recognize the "sha256128" spelling and
	// would discard the whole proposal.
	if got != "aes256-sha256-modp2048" {
		t.Fatalf("resolveESPSettings dropped PFS or emitted an invalid fallback: got %q, want aes256-sha256-modp2048", got)
	}
	if got == "default" {
		t.Fatal("PFS was silently dropped to the strongSwan default")
	}
	if lifetime != 0 {
		t.Errorf("lifetime = %d, want 0 (no resolvable proposal to take a lifetime from)", lifetime)
	}
}

// TestResolveESPSettings_DanglingProposalNoPFSStaysDefault verifies that a
// dangling proposal reference with NO configured PFS still falls to
// "default" — there is no security control to preserve, so the render
// behavior is unchanged from before #2073.
func TestResolveESPSettings_DanglingProposalNoPFSStaysDefault(t *testing.T) {
	cfg := &config.IPsecConfig{
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {
				Name:      "ipsec-pol",
				PFSGroup:  0,
				Proposals: "does-not-exist",
			},
		},
	}
	vpn := &config.IPsecVPN{IPsecPolicy: "ipsec-pol"}

	got, _ := resolveESPSettings(cfg, vpn)
	if got != "default" {
		t.Errorf("resolveESPSettings = %q, want default (no PFS configured)", got)
	}
}

// TestResolveESPSettings_NoPolicyStaysDefault is the (D) regression: a VPN
// with no IPsec policy emits "default" with no error and no PFS.
func TestResolveESPSettings_NoPolicyStaysDefault(t *testing.T) {
	cfg := &config.IPsecConfig{}
	vpn := &config.IPsecVPN{}
	got, lifetime := resolveESPSettings(cfg, vpn)
	if got != "default" || lifetime != 0 {
		t.Errorf("resolveESPSettings = (%q, %d), want (default, 0)", got, lifetime)
	}
}

// TestGenerateConfig_DanglingProposalPreservesPFS checks the full render:
// the emitted swanctl child block must carry the PFS modp group rather
// than esp_proposals = default, using the canonical sha256 keyword.
func TestGenerateConfig_DanglingProposalPreservesPFS(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				LocalID:     "10.0.1.0/24",
				RemoteID:    "10.0.2.0/24",
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", PFSGroup: 14, Proposals: "does-not-exist"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "esp_proposals = aes256-sha256-modp2048") {
		t.Errorf("rendered config dropped PFS or used the default set:\n%s", got)
	}
	if strings.Contains(got, "esp_proposals = default") {
		t.Errorf("PFS silently dropped to esp_proposals = default:\n%s", got)
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

func TestParseSAOutput_MultiChild(t *testing.T) {
	output := `site-a: #1, ESTABLISHED
  local: 10.0.1.1 === 10.0.2.1
  site-a-ts1: #1, reqid 1, INSTALLED
    local_ts = 10.0.1.0/24
    remote_ts = 10.0.2.0/24
  site-a-ts2: #2, reqid 2, INSTALLED
    local_ts = 10.0.3.0/24
    remote_ts = 10.0.4.0/24
`
	sas := parseSAOutput(output)
	if len(sas) != 2 {
		t.Fatalf("expected 2 child SAs, got %d", len(sas))
	}
	if sas[0].Name != "site-a-ts1" || sas[0].ConnectionName != "site-a" {
		t.Fatalf("unexpected first child: %+v", sas[0])
	}
	if sas[1].Name != "site-a-ts2" || sas[1].ConnectionName != "site-a" {
		t.Fatalf("unexpected second child: %+v", sas[1])
	}
}

func TestGenerateConfig_GatewayReference(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
				Name:           "gw1",
				Address:        "203.0.113.1",
				LocalAddress:   "198.51.100.1",
				IKEPolicy:      "ike-pol",
				Version:        "v2-only",
				NoNATTraversal: true,
				DeadPeerDetect: "always-send",
				LocalIDType:    "hostname",
				LocalIDValue:   "vpn.example.com",
				RemoteIDType:   "inet",
				RemoteIDValue:  "203.0.113.1",
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
		{"DPD timeout", "dpd_timeout = 50s"},
		{"local identity", "id = @vpn.example.com"},
		{"remote identity", "id = 203.0.113.1"},
		{"IKE proposal", "proposals = aes256-sha256-modp2048"},
		{"ESP proposal", "esp_proposals = aes256-sha256128-modp2048"},
		{"copy DF", "copy_df = yes"},
		{"start action", "start_action = start"},
		{"DPD action", "dpd_action = restart"},
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	if !strings.Contains(got, "if_id_in = 2") || !strings.Contains(got, "if_id_out = 2") {
		t.Errorf("expected st0.1 to map to if_id 2: %s", got)
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	tests := []struct {
		name    string
		dfbit   string
		want    string
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
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
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

func TestGenerateConfig_IKELifetime(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name:            "ike-p1",
				AuthMethod:      "pre-shared-keys",
				EncryptionAlg:   "aes-256-cbc",
				AuthAlg:         "sha-256",
				DHGroup:         14,
				LifetimeSeconds: 28800,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: "ike-p1", PSK: "secret"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "pol1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "rekey_time = 28800s") {
		t.Fatalf("expected IKE rekey_time from lifetime-seconds: %s", got)
	}
	if !strings.Contains(got, "rand_time = 0s") {
		t.Fatalf("expected deterministic IKE rand_time: %s", got)
	}
}

func TestGenerateConfig_ESPLifetime(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Proposals: map[string]*config.IPsecProposal{
			"esp-p2": {
				Name:            "esp-p2",
				EncryptionAlg:   "aes-256-cbc",
				AuthAlg:         "hmac-sha-256-128",
				LifetimeSeconds: 3600,
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: "esp-p2"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "203.0.113.1", IPsecPolicy: "ipsec-pol"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "rekey_time = 3600s") {
		t.Fatalf("expected child rekey_time from ESP lifetime-seconds: %s", got)
	}
}

func TestGenerateConfig_DPDModes(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:           "gw",
				Address:        "10.0.0.1",
				DeadPeerDetect: "probe-idle-tunnel",
				DPDInterval:    7,
				DPDThreshold:   3,
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", EstablishTunnels: "on-traffic"},
		},
	}
	got := m.generateConfig(cfg)
	for _, want := range []string{"dpd_delay = 7s", "dpd_timeout = 21s", "dpd_action = trap"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestGenerateConfig_JunosObfuscatedPSK(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "10.0.0.1", PSK: "$9$SpRrMLYgaZDirexdwgUDzFn9uO1RhlKW"},
		},
	}
	got, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig() error = %v", err)
	}
	if !strings.Contains(got, `secret = "QZ1agnL21L"`) {
		t.Fatalf("expected decoded Junos secret, got:\n%s", got)
	}
}

func TestGenerateConfig_PubkeyAuth(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		IKEProposals: map[string]*config.IKEProposal{
			"ike-p1": {
				Name:          "ike-p1",
				AuthMethod:    "rsa-signatures",
				EncryptionAlg: "aes-256-cbc",
				AuthAlg:       "sha-256",
				DHGroup:       14,
			},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"pol1": {Name: "pol1", Proposals: "ike-p1"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:             "gw",
				Address:          "203.0.113.1",
				IKEPolicy:        "pol1",
				LocalCertificate: "gw-cert.pem",
			},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw"},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "auth = pubkey") {
		t.Fatalf("expected pubkey auth, got:\n%s", got)
	}
	if !strings.Contains(got, "certs = gw-cert.pem") {
		t.Fatalf("expected local certificate, got:\n%s", got)
	}
	if strings.Contains(got, "secret = ") {
		t.Fatalf("pubkey auth should not emit PSK secrets:\n%s", got)
	}
}

func TestGenerateConfig_TrafficSelectors(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {
				Gateway: "10.0.0.1",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"corp-a": {Name: "corp-a", LocalIP: "10.0.1.0/24", RemoteIP: "10.10.1.0/24"},
					"corp-b": {Name: "corp-b", LocalIP: "10.0.2.0/24", RemoteIP: "10.10.2.0/24"},
				},
			},
		},
	}
	got := m.generateConfig(cfg)
	for _, want := range []string{
		"tun-corp-a {",
		"local_ts = 10.0.1.0/24",
		"remote_ts = 10.10.1.0/24",
		"tun-corp-b {",
		"local_ts = 10.0.2.0/24",
		"remote_ts = 10.10.2.0/24",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

// TestEffectiveTrafficSelectors_NilVPN guards the #2022 nil-deref: the
// vpn==nil branch previously dereferenced vpn.LocalID/vpn.RemoteID and
// panicked. A nil VPN must yield no children, not a panic. Run with
// t.Fatalf-on-panic so the test fails (not crashes) against pre-fix code.
func TestEffectiveTrafficSelectors_NilVPN(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("effectiveTrafficSelectors(nil) panicked: %v", r)
		}
	}()
	got := effectiveTrafficSelectors("tun", nil)
	if len(got) != 0 {
		t.Fatalf("nil VPN: want no children, got %d: %+v", len(got), got)
	}
}

// TestEffectiveTrafficSelectors_NoSelectors confirms the non-nil VPN with
// zero traffic selectors still falls back to a single default child built
// from LocalID/RemoteID — the behavior the broken nil-OR-empty guard used
// to share. The #2022 fix must not regress this path.
func TestEffectiveTrafficSelectors_NoSelectors(t *testing.T) {
	vpn := &config.IPsecVPN{LocalID: "10.0.1.0/24", RemoteID: "10.10.1.0/24"}
	got := effectiveTrafficSelectors("tun", vpn)
	if len(got) != 1 {
		t.Fatalf("want 1 default child, got %d: %+v", len(got), got)
	}
	c := got[0]
	if c.Name != "tun" || c.LocalTS != "10.0.1.0/24" || c.RemoteTS != "10.10.1.0/24" {
		t.Fatalf("unexpected default child: %+v", c)
	}
}

func TestPrepareConfig_ExternalInterfaceLocalAddress(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							PrimaryAddress: "198.51.100.1/24",
							Addresses:      []string{"198.51.100.1/24"},
						},
					},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {
						Name:          "gw",
						Address:       "203.0.113.1",
						ExternalIface: "wan0.0",
					},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Gateway: "gw"},
				},
			},
		},
	}

	prepared := PrepareConfig(cfg)
	if prepared.Gateways["gw"].LocalAddress != "198.51.100.1" {
		t.Fatalf("resolved local-address = %q, want 198.51.100.1", prepared.Gateways["gw"].LocalAddress)
	}
}

// #1798 belt test: a pre-shared key (or identity) carrying an embedded
// newline must not inject extra swanctl.conf sections/keys even if
// commit-time validation were bypassed.
func TestGenerateConfig_NewlineSecretDoesNotInject(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           "secret\ninclude /etc/evil.conf",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "include ") {
			t.Fatalf("injected swanctl directive leaked:\n%s", got)
		}
	}
	if !strings.Contains(got, `secret = "secret include /etc/evil.conf"`) {
		t.Errorf("sanitized secret missing:\n%s", got)
	}
}

// remoteAddrsValues returns every value rendered on a `remote_addrs = `
// line in the swanctl output (one per emitted connection), or an empty
// slice if there are none. It lets the #2074 tests assert specifically
// that a gateway config-object NAME never appears as a remote_addrs
// value (a substring match on the whole config would falsely flag the
// connection-name line).
func remoteAddrsValues(cfg string) []string {
	var out []string
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(t, "remote_addrs = "); ok {
			out = append(out, v)
		}
	}
	return out
}

// TestRenderConfig_GatewayNameNeverLeaks exercises #2074: a bare gateway
// config-object NAME must never reach swanctl `remote_addrs`. The render
// belt skips an unrenderable VPN rather than leaking its name; valid
// shapes (defined+addressed gateway, inline IP/FQDN, empty gateway) are
// preserved. These sub-cases fail against pre-fix code, which emitted
// `remote_addrs = <gateway-name>` for the dangling / addressless cases.
func TestRenderConfig_GatewayNameNeverLeaks(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}

	t.Run("resolved gateway with address", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"corp-gw": {Name: "corp-gw", Address: "203.0.113.7"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "corp-gw", PSK: "k"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		vals := remoteAddrsValues(got)
		if len(vals) != 1 || vals[0] != "203.0.113.7" {
			t.Fatalf("remote_addrs = %v, want [203.0.113.7]\n%s", vals, got)
		}
		for _, v := range vals {
			if v == "corp-gw" {
				t.Fatalf("gateway NAME leaked into remote_addrs:\n%s", got)
			}
		}
	})

	t.Run("dangling gateway name is skipped, no leak", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			// "typo-gw" is referenced but never defined, and is not a
			// usable IP / dotted hostname. Benign PSK auth so no other
			// render error path fires (this isolates the leak path).
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "typo-gw", PSK: "k"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v (skip should not error)", err)
		}
		if strings.Contains(got, "typo-gw") {
			t.Fatalf("dangling gateway NAME leaked into config:\n%s", got)
		}
		if vals := remoteAddrsValues(got); len(vals) != 0 {
			t.Fatalf("expected no remote_addrs, got %v\n%s", vals, got)
		}
		if strings.Contains(got, "ike-tun {") {
			t.Fatalf("skipped VPN should have no secret entry:\n%s", got)
		}
	})

	t.Run("addressless gateway is skipped, no leak", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				// Exists but has neither Address nor DynamicHostname.
				"bare-gw": {Name: "bare-gw"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "bare-gw", PSK: "k"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if strings.Contains(got, "bare-gw") {
			t.Fatalf("addressless gateway NAME leaked:\n%s", got)
		}
		if vals := remoteAddrsValues(got); len(vals) != 0 {
			t.Fatalf("expected no remote_addrs, got %v\n%s", vals, got)
		}
	})

	t.Run("dotless single-label name is skipped", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "vpnpeer", PSK: "k"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if vals := remoteAddrsValues(got); len(vals) != 0 {
			t.Fatalf("dotless name should be skipped, got remote_addrs %v\n%s", vals, got)
		}
	})

	t.Run("inline literal IP is preserved", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "198.51.100.9", PSK: "k"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if vals := remoteAddrsValues(got); len(vals) != 1 || vals[0] != "198.51.100.9" {
			t.Fatalf("remote_addrs = %v, want [198.51.100.9]\n%s", vals, got)
		}
	})

	t.Run("inline dotted hostname is preserved", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "peer.example.com", PSK: "k"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if vals := remoteAddrsValues(got); len(vals) != 1 || vals[0] != "peer.example.com" {
			t.Fatalf("remote_addrs = %v, want [peer.example.com]\n%s", vals, got)
		}
	})

	t.Run("empty gateway emits connection with no remote_addrs", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			VPNs: map[string]*config.IPsecVPN{
				"tun": {Gateway: "", PSK: "k", BindInterface: "st0.0"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if !strings.Contains(got, "  tun {\n") {
			t.Fatalf("empty-gateway VPN should still render a connection:\n%s", got)
		}
		if vals := remoteAddrsValues(got); len(vals) != 0 {
			t.Fatalf("empty gateway should emit no remote_addrs, got %v\n%s", vals, got)
		}
	})

	// Regression guard for the round-2 cold-boot defect: a healthy VPN
	// must still render (and keep its remote_addrs) when a sibling VPN is
	// skipped. Pre-fix / v1-style whole-render-abort would have dropped
	// the healthy tunnel too.
	t.Run("one bad VPN does not zero a healthy sibling", func(t *testing.T) {
		cfg := &config.IPsecConfig{
			Gateways: map[string]*config.IPsecGateway{
				"good-gw": {Name: "good-gw", Address: "192.0.2.10"},
			},
			VPNs: map[string]*config.IPsecVPN{
				"good": {Gateway: "good-gw", PSK: "k1"},
				"bad":  {Gateway: "missing-gw", PSK: "k2"},
			},
		}
		got, err := m.renderConfig(cfg)
		if err != nil {
			t.Fatalf("renderConfig() error = %v", err)
		}
		if !strings.Contains(got, "  good {\n") {
			t.Fatalf("healthy VPN was dropped:\n%s", got)
		}
		vals := remoteAddrsValues(got)
		if len(vals) != 1 || vals[0] != "192.0.2.10" {
			t.Fatalf("healthy remote_addrs = %v, want [192.0.2.10]\n%s", vals, got)
		}
		if strings.Contains(got, "missing-gw") {
			t.Fatalf("bad gateway NAME leaked:\n%s", got)
		}
		if strings.Contains(got, "  bad {\n") {
			t.Fatalf("bad VPN should be skipped:\n%s", got)
		}
		if strings.Contains(got, "ike-bad {") {
			t.Fatalf("skipped VPN should have no secret:\n%s", got)
		}
		if !strings.Contains(got, "ike-good {") {
			t.Fatalf("healthy VPN secret missing:\n%s", got)
		}
	})
}
