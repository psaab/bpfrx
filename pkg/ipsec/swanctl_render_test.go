package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuildESPProposal_JunosGCMSuffix is the #2125 ESP-render
// regression: a Junos-native GCM encryption-algorithm name renders to
// the canonical 16-octet-ICV swanctl token (aes256gcm16). Pre-fix the
// normalizer only stripped "-cbc"/"-" and produced the bare alias
// "aes256gcm", so these assertions FAIL on the old code
// (non-tautological). Note: the bare alias is ALSO valid strongSwan
// (it maps to ENCR_AES_GCM_ICV16), so this test pins the explicit-ICV
// spelling for clarity/consistency — it is not guarding against a parse
// failure. (The parse-affecting #2125 fix is the IKE PRF, covered by
// TestBuildIKEProposal_JunosGCMSuffixAndPRF below.)
func TestBuildESPProposal_JunosGCMSuffix(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-256-gcm dh14",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", DHGroup: 14},
			"aes256gcm16-modp2048",
		},
		{
			"aes-192-gcm dh14",
			&config.IPsecProposal{EncryptionAlg: "aes-192-gcm", DHGroup: 14},
			"aes192gcm16-modp2048",
		},
		{
			"aes-128-gcm dh14",
			&config.IPsecProposal{EncryptionAlg: "aes-128-gcm", DHGroup: 14},
			"aes128gcm16-modp2048",
		},
		{
			"aes-256-gcm no dh",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm"},
			"aes256gcm16",
		},
		{
			// GCM must never emit a separate integrity algorithm even
			// when AuthAlg is set — AEAD carries its own ICV.
			"aes-256-gcm ignores auth",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", AuthAlg: "hmac-sha-256", DHGroup: 14},
			"aes256gcm16-modp2048",
		},
		{
			// Already-suffixed legacy form is preserved unchanged.
			"legacy aes256gcm128 unchanged",
			&config.IPsecProposal{EncryptionAlg: "aes256gcm128", DHGroup: 14},
			"aes256gcm128-modp2048",
		},
		{
			// Non-GCM CBC path stays byte-identical to the old behavior.
			"non-gcm cbc unchanged",
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256128-modp2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildESPProposal(tt.prop, 0); got != tt.want {
				t.Errorf("buildESPProposal(%q) = %q, want %q", tt.prop.EncryptionAlg, got, tt.want)
			}
		})
	}
}

// TestBuildIKEProposal_JunosGCMSuffixAndPRF is the #2125 regression for
// IKE (Phase 1): a Junos GCM name must render to aes<N>gcm16 AND carry
// an explicit PRF (IKEv2 AEAD has no integrity alg to derive a PRF
// from). Pre-fix the IKE builders emitted bare "aes256gcm" with no PRF.
func TestBuildIKEProposal_JunosGCMSuffixAndPRF(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-256-gcm default prf",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", DHGroup: 14},
			"aes256gcm16-prfsha256-modp2048",
		},
		{
			"aes-256-gcm prf from sha384 auth",
			&config.IPsecProposal{EncryptionAlg: "aes-256-gcm", AuthAlg: "hmac-sha-384", DHGroup: 14},
			"aes256gcm16-prfsha384-modp2048",
		},
		{
			"aes-128-gcm prf from sha512 auth",
			&config.IPsecProposal{EncryptionAlg: "aes-128-gcm", AuthAlg: "hmac-sha-512", DHGroup: 14},
			"aes128gcm16-prfsha512-modp2048",
		},
		{
			"non-gcm cbc unchanged",
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256128-modp2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildIKEProposal(tt.prop); got != tt.want {
				t.Errorf("buildIKEProposal(%q) = %q, want %q", tt.prop.EncryptionAlg, got, tt.want)
			}
		})
	}
}

// TestBuildIKEProposalFromIKE_JunosGCMSuffixAndPRF mirrors the IKE GCM
// regression for the IKE-proposal-object path (buildIKEProposalFromIKE).
func TestBuildIKEProposalFromIKE_JunosGCMSuffixAndPRF(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IKEProposal
		want string
	}{
		{
			"aes-256-gcm default prf",
			&config.IKEProposal{EncryptionAlg: "aes-256-gcm", DHGroup: 14},
			"aes256gcm16-prfsha256-modp2048",
		},
		{
			"aes-256-gcm prf from sha-512 auth",
			&config.IKEProposal{EncryptionAlg: "aes-256-gcm", AuthAlg: "sha-512", DHGroup: 14},
			"aes256gcm16-prfsha512-modp2048",
		},
		{
			"non-gcm cbc unchanged",
			&config.IKEProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"aes256-sha256-modp2048",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildIKEProposalFromIKE(tt.prop); got != tt.want {
				t.Errorf("buildIKEProposalFromIKE(%q) = %q, want %q", tt.prop.EncryptionAlg, got, tt.want)
			}
		})
	}
}

// TestGenerateConfig_JunosGCM is an end-to-end render check that a
// Junos-native aes-256-gcm proposal produces a valid, ICV-suffixed
// esp_proposals line through generateConfig (#2125).
func TestGenerateConfig_JunosGCM(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {Gateway: "172.16.0.1", IPsecPolicy: "gcm"},
		},
		Proposals: map[string]*config.IPsecProposal{
			"gcm": {Name: "gcm", EncryptionAlg: "aes-256-gcm", DHGroup: 14},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "esp_proposals = aes256gcm16-modp2048") {
		t.Errorf("expected ICV-suffixed GCM esp_proposals, got:\n%s", got)
	}
	// The bare alias (valid strongSwan, but not the canonical spelling
	// we now emit) must no longer appear.
	if strings.Contains(got, "aes256gcm-modp2048") {
		t.Errorf("rendered the bare aes256gcm alias instead of the canonical aes256gcm16:\n%s", got)
	}
}

// TestEscapeSwanctlQuoted unit-tests the swanctl double-quoted-string
// escaper directly (#2126). Order matters: backslash doubled first,
// then quote escaped.
func TestEscapeSwanctlQuoted(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no special chars", "supersecret", "supersecret"},
		{"embedded quote", `pa"ss`, `pa\"ss`},
		{"embedded backslash", `pa\ss`, `pa\\ss`},
		{"backslash then n stays literal", `a\nb`, `a\\nb`},
		{"both quote and backslash", `a"\b`, `a\"\\b`},
		{"trailing quote", `secret"`, `secret\"`},
		{"leading quote", `"secret`, `\"secret`},
		{"quote then backslash order", `"\`, `\"\\`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeSwanctlQuoted(tt.in); got != tt.want {
				t.Errorf("escapeSwanctlQuoted(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestGenerateConfig_PSKWithQuote is the #2126 end-to-end regression: a
// PSK containing a double-quote must render as a balanced, escaped
// quoted secret (secret = "pa\"ss"), not the corrupted secret = "pa"ss"
// the pre-fix code produced.
func TestGenerateConfig_PSKWithQuote(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           `pa"ss`,
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, `secret = "pa\"ss"`) {
		t.Errorf("expected escaped quoted PSK, got:\n%s", got)
	}
	// The corrupting unescaped form must NOT appear.
	if strings.Contains(got, `secret = "pa"ss"`) {
		t.Errorf("rendered the corrupted unescaped PSK:\n%s", got)
	}
	assertBalancedSecretQuotes(t, got)
}

// TestGenerateConfig_PSKWithBackslash covers a PSK containing a literal
// backslash (#2126) — it must be doubled so the swanctl lexer reads one
// literal backslash back.
func TestGenerateConfig_PSKWithBackslash(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           `pa\ss`,
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, `secret = "pa\\ss"`) {
		t.Errorf("expected doubled backslash in PSK, got:\n%s", got)
	}
}

// TestGenerateConfig_PSKTrailingBackslash is the adversarial corner a PSK
// ending in a single backslash: it must render as a doubled backslash
// (secret = "pass\\") so the trailing backslash does NOT escape the
// closing quote. assertBalancedSecretQuotes is the lexer-accurate gate.
func TestGenerateConfig_PSKTrailingBackslash(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           `pass\`,
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, `secret = "pass\\"`) {
		t.Errorf("expected trailing backslash doubled, got:\n%s", got)
	}
	assertBalancedSecretQuotes(t, got)
}

// TestGenerateConfig_IdentityWithCommaQuoted is the #2126 regression for
// the identity lines: a distinguished-name identity with spaces/commas
// must render quoted so swanctl parses it as a single value rather than
// truncating at the first space/comma.
func TestGenerateConfig_IdentityWithCommaQuoted(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Gateway: "gw", PSK: "k"},
		},
		Gateways: map[string]*config.IPsecGateway{
			"gw": {
				Name:          "gw",
				Address:       "203.0.113.1",
				LocalAddress:  "198.51.100.1",
				LocalIDType:   "inet",
				LocalIDValue:  "CN=fw, O=acme",
				RemoteIDType:  "inet",
				RemoteIDValue: `peer"name`,
			},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, `id = "CN=fw, O=acme"`) {
		t.Errorf("expected quoted DN identity, got:\n%s", got)
	}
	if !strings.Contains(got, `id = "peer\"name"`) {
		t.Errorf("expected quoted+escaped remote identity, got:\n%s", got)
	}
}

// assertBalancedSecretQuotes verifies every "secret = " line has exactly
// the opening + closing quote with no unescaped interior double-quote —
// i.e. the rendered secret block is parseable by the swanctl lexer.
func assertBalancedSecretQuotes(t *testing.T, cfg string) {
	t.Helper()
	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "secret = ") {
			continue
		}
		val := strings.TrimPrefix(trimmed, "secret = ")
		if len(val) < 2 || val[0] != '"' {
			t.Errorf("secret value not opened with a quote: %q", val)
			continue
		}
		// Walk from after the opening quote exactly as the swanctl lexer
		// would: a backslash escapes the next char (so it can never
		// terminate the string), and the FIRST unescaped double-quote is
		// the real terminator. The line is balanced only if that
		// terminator is the last character — catching both an unescaped
		// interior quote (terminates early) and an odd trailing backslash
		// run that escapes the would-be closing quote (e.g. `"foo\"`).
		term := -1
		for i := 1; i < len(val); i++ {
			if val[i] == '\\' {
				i++ // skip the escaped char
				continue
			}
			if val[i] == '"' {
				term = i
				break
			}
		}
		switch {
		case term == -1:
			t.Errorf("secret value never closes (escaped/unterminated quote): %q", val)
		case term != len(val)-1:
			t.Errorf("secret value terminates before end of line (unescaped interior quote): %q", val)
		}
	}
}
