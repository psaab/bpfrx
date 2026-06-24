package ipsec

import (
	"fmt"
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

// TestFormatDHGroup_ECPandMODP is the #2392 regression: elliptic-curve DH
// groups must render their strongSwan ECP/curve keyword (group 19 ->
// ecp256, 20 -> ecp384, 21 -> ecp521, 31 -> curve25519), NOT modp<bits>.
// Pre-#2392 every builder formatted the suffix as fmt.Sprintf("modp%d",
// dhGroupBits(group)), so group 19/20 emitted the strongSwan-invalid
// tokens modp256/modp384 and the whole proposal was rejected at swanctl
// load. MODP groups (e.g. 14 -> modp2048) must keep rendering modp<bits>.
//
// Fail-on-revert: reverting formatDHGroup to fmt.Sprintf("modp%d",
// dhGroupBits(group)) makes group 19 render "modp256" instead of
// "ecp256", which fails the ecp* assertions below. The trailing
// counter-factual block reconstructs the pre-fix formula and proves it
// produces the invalid token, so the test is not tautological.
func TestFormatDHGroup_ECPandMODP(t *testing.T) {
	tests := []struct {
		group int
		want  string
	}{
		// MODP groups — unchanged pre-#2392 behaviour.
		{1, "modp768"},
		{2, "modp1024"},
		{5, "modp1536"},
		{14, "modp2048"},
		{15, "modp3072"},
		{16, "modp4096"},
		// Elliptic-curve (ECP) groups — the #2392 fix.
		{19, "ecp256"},
		{20, "ecp384"},
		{21, "ecp521"},
		{25, "ecp192"},
		{26, "ecp224"},
		// Brainpool ECP groups.
		{27, "ecp224bp"},
		{28, "ecp256bp"},
		{29, "ecp384bp"},
		{30, "ecp512bp"},
		// Montgomery curves.
		{31, "curve25519"},
		{32, "curve448"},
		// MODP-with-prime-order-subgroup (RFC 5114) — the #2604 fix.
		// Before #2604 these fell through to modp<dhGroupBits>; dhGroupBits
		// has no 22/23/24 case so they emitted the strongSwan-invalid
		// tokens modp22/modp23/modp24.
		{22, "modp1024s160"},
		{23, "modp2048s224"},
		{24, "modp2048s256"},
	}
	for _, tt := range tests {
		if got := formatDHGroup(tt.group); got != tt.want {
			t.Errorf("formatDHGroup(%d) = %q, want %q", tt.group, got, tt.want)
		}
	}

	// Counter-factual: the pre-fix formula renders the strongSwan-invalid
	// modp<bits> token. For the EC groups 19/20 this proves the #2392 fix
	// is load-bearing; for the RFC 5114 groups 22/23/24 it proves the #2604
	// fix is load-bearing (the old code WOULD fail the assertions above) —
	// neither is a tautology.
	for _, g := range []int{19, 20, 22, 23, 24} {
		old := fmt.Sprintf("modp%d", dhGroupBits(g))
		if got := formatDHGroup(g); got == old {
			t.Errorf("formatDHGroup(%d) = %q still matches the pre-fix invalid token %q",
				g, got, old)
		}
	}
}

// TestProposalBuilders_ECPGroupAcrossAllSites asserts that ALL FOUR
// proposal render sites route the DH-group suffix through formatDHGroup,
// so EC groups 19/20/21/31 emit ecp256/ecp384/ecp521/curve25519 and the
// RFC 5114 groups 22/23/24 emit modp1024s160/modp2048s224/modp2048s256
// (#2604) — not modp<bits> — and MODP group 14 still emits modp2048 (no
// regression):
//
//  1. buildIKEProposalFromIKE  (IKE proposal object path)
//  2. buildIKEProposal         (legacy IPsec-proposal-as-IKE path)
//  3. buildESPProposal         (ESP / Phase-2 path)
//  4. resolveESPSettings PFS fallback (undefined-proposal #2073 fallback)
func TestProposalBuilders_ECPGroupAcrossAllSites(t *testing.T) {
	type groupCase struct {
		group  int
		suffix string
	}
	groupCases := []groupCase{
		{14, "modp2048"}, // MODP no-regression
		{19, "ecp256"},
		{20, "ecp384"},
		{21, "ecp521"},
		{31, "curve25519"},
		// RFC 5114 MODP-with-prime-order-subgroup groups — the #2604 fix.
		{22, "modp1024s160"},
		{23, "modp2048s224"},
		{24, "modp2048s256"},
	}

	for _, gc := range groupCases {
		// Site 1: buildIKEProposalFromIKE.
		if got, want := buildIKEProposalFromIKE(
			&config.IKEProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: gc.group}),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildIKEProposalFromIKE(group %d) = %q, want %q", gc.group, got, want)
		}

		// Site 2: buildIKEProposal.
		if got, want := buildIKEProposal(
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: gc.group}),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildIKEProposal(group %d) = %q, want %q", gc.group, got, want)
		}

		// Site 3: buildESPProposal (DH group via the proposal field).
		if got, want := buildESPProposal(
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256", DHGroup: gc.group}, 0),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildESPProposal(DHGroup %d) = %q, want %q", gc.group, got, want)
		}

		// Site 3b: buildESPProposal with the PFS group override.
		if got, want := buildESPProposal(
			&config.IPsecProposal{EncryptionAlg: "aes-256-cbc", AuthAlg: "hmac-sha-256"}, gc.group),
			"aes256-sha256-"+gc.suffix; got != want {
			t.Errorf("buildESPProposal(pfs %d) = %q, want %q", gc.group, got, want)
		}

		// Site 4: resolveESPSettings PFS fallback. The IPsec policy resolves
		// but names a proposal that does not exist, so the #2073 fallback
		// carries the configured PFS group onto a conservative proposal.
		cfg := &config.IPsecConfig{
			Policies: map[string]*config.IPsecPolicyDef{
				"pol1": {Name: "pol1", PFSGroup: gc.group, Proposals: "missing-prop"},
			},
		}
		vpn := &config.IPsecVPN{IPsecPolicy: "pol1"}
		if got, _ := resolveESPSettings(cfg, vpn); got != "aes256-sha256-"+gc.suffix {
			t.Errorf("resolveESPSettings PFS fallback (group %d) = %q, want %q",
				gc.group, got, "aes256-sha256-"+gc.suffix)
		}
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
