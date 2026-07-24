package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildAddrCfg constructs the minimal renderable IPsecConfig used by the
// #6469 render-belt tests: one gateway + one VPN + a resolvable ike/ipsec
// policy chain so renderConfig emits a full connection block. The caller
// picks which endpoint field carries the value under test.
func buildAddrCfg(gwAddr, gwDyn, gwLocal, vpnLocal string) *config.IPsecConfig {
	// Mirror the proven-minimal endpoint_render_5630 fixture: gateway + VPN
	// + a resolvable ipsec policy/proposal is enough for renderConfig to emit
	// a full connection block with local_addrs / remote_addrs. No IKE policy
	// chain is required (an absent ike-policy does not skip the VPN).
	return &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: gwAddr, DynamicHostname: gwDyn, LocalAddress: gwLocal},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol", LocalAddr: vpnLocal},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes256", AuthAlg: "sha256"},
		},
	}
}

// hasBareDirectiveLine reports whether any rendered line, once its leading /
// trailing whitespace is stripped, is EXACTLY the given swanctl directive.
// A newline-injection payload that survives to render produces such a
// standalone line (`    reauth_time = 0`); a neutralized payload keeps the
// token mid-line inside the address value, so no line trims to it.
func hasBareDirectiveLine(rendered, directive string) bool {
	for _, line := range strings.Split(rendered, "\n") {
		if strings.TrimSpace(line) == directive {
			return true
		}
	}
	return false
}

// TestSwanctlAddrInjectionNeutralized_6469 is the fail-on-revert guard for
// #6469: the swanctl local_addrs / remote_addrs render sites must run the
// endpoint value through sanitizeSwanctlValue so an embedded newline cannot
// inject a live swanctl directive on a validation-bypassed path (HA peer-sync
// of a pre-fix config, or a directly-constructed IPsecConfig — both bypass
// the commit-time endpoint gate). Reverting the sanitize wrap back to a raw
// `%s` makes each case fail with a clean assertion: the injected directive
// reappears as its own indented line.
func TestSwanctlAddrInjectionNeutralized_6469(t *testing.T) {
	// Payload: a legitimate-looking address, an embedded newline, then an
	// indented swanctl directive the attacker wants promoted into the
	// connection block. reauth_time is emitted by NO code path in this
	// fixture, so its appearance as a bare line is proof of injection.
	const inject = "203.0.113.1\n    reauth_time = 0"
	const injectedDirective = "reauth_time = 0"

	cases := []struct {
		name string
		cfg  *config.IPsecConfig
		// addrLine is the sanitized address line that must be present,
		// proving the connection still rendered (the VPN was not skipped)
		// and the belt ran in place rather than dropping the field.
		addrLine string
	}{
		{
			name:     "remote via gateway Address",
			cfg:      buildAddrCfg(inject, "", "", ""),
			addrLine: "remote_addrs = 203.0.113.1",
		},
		{
			name:     "remote via gateway DynamicHostname",
			cfg:      buildAddrCfg("", inject, "198.51.100.7", ""),
			addrLine: "remote_addrs = 203.0.113.1",
		},
		{
			name:     "local via gateway LocalAddress",
			cfg:      buildAddrCfg("198.51.100.7", "", inject, ""),
			addrLine: "local_addrs = 203.0.113.1",
		},
		{
			name:     "local via vpn LocalAddr",
			cfg:      buildAddrCfg("198.51.100.7", "", "", inject),
			addrLine: "local_addrs = 203.0.113.1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			got := m.generateConfig(c.cfg)

			if hasBareDirectiveLine(got, injectedDirective) {
				t.Fatalf("swanctl injection NOT neutralized: %q rendered as a "+
					"live directive line — the newline in the endpoint value "+
					"was not stripped:\n%s", injectedDirective, got)
			}
			// The sanitized value must still lead the address line: the belt
			// collapses the newline to a space, so the address renders inert
			// on one line rather than the field being dropped or the VPN
			// skipped.
			if !strings.Contains(got, c.addrLine) {
				t.Fatalf("expected sanitized address line %q in render:\n%s",
					c.addrLine, got)
			}
		})
	}
}

// TestSwanctlAddrLegitPreserved_6469 is the over-escape guard: a legitimate
// endpoint — a single IPv4, a comma-separated multi-address list, an IPv6
// literal, and the responder-only "%any" sentinel — must render BYTE-
// IDENTICAL through the sanitize belt. sanitizeSwanctlValue only touches
// C0/DEL control bytes, so `.`, `,`, `:` and `%` all survive; this test pins
// that the #6469 fix does not mangle a real address list or IPv6 endpoint.
func TestSwanctlAddrLegitPreserved_6469(t *testing.T) {
	cases := []struct {
		name     string
		gwAddr   string
		wantLine string
	}{
		{
			name:     "single IPv4",
			gwAddr:   "203.0.113.1",
			wantLine: "remote_addrs = 203.0.113.1",
		},
		{
			name:     "comma-separated multi-address list",
			gwAddr:   "203.0.113.1,203.0.113.2",
			wantLine: "remote_addrs = 203.0.113.1,203.0.113.2",
		},
		{
			name:     "IPv6 literal",
			gwAddr:   "2001:db8::1",
			wantLine: "remote_addrs = 2001:db8::1",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			got := m.generateConfig(buildAddrCfg(c.gwAddr, "", "", ""))
			if !strings.Contains(got, c.wantLine) {
				t.Fatalf("legit endpoint over-escaped or dropped: want %q in "+
					"render:\n%s", c.wantLine, got)
			}
		})
	}

	// Responder-only (%any) must survive the belt untouched — '%' is not a
	// control byte, and this is the sentinel for a dynamic-IP peer.
	t.Run("responder-only %any", func(t *testing.T) {
		cfg := buildAddrCfg("", "", "", "")
		cfg.Gateways["gw"].ResponderOnly = true
		m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
		got := m.generateConfig(cfg)
		if !strings.Contains(got, "remote_addrs = %any") {
			t.Fatalf("responder-only %%any endpoint not preserved:\n%s", got)
		}
	})
}

// TestSwanctlProposalsInjectionNeutralized_6469 is the fold guard: the swanctl
// `proposals` (IKE, Phase 1) and `esp_proposals` (ESP, Phase 2, INSIDE the
// children{} block) render sites must run the built proposal string through
// sanitizeSwanctlValue. buildIKEProposal* / buildESPProposal append
// prop.EncryptionAlg / prop.AuthAlg VERBATIM on the unknown-algorithm
// fall-through (normalizeAuthAlg's default branch; normalizeEncAlg's generic
// gcm strip), so a control char in a peer-synced / directly-constructed
// proposal reaches the renderer. An embedded newline in esp_proposals injects
// a child-SA directive (`updown = <script>` runs as ROOT under charon) — a
// strictly worse vector than the endpoint one, on the identical
// validation-bypassed threat model. Reverting either wrap makes the matching
// case fail with a clean assertion: the injected directive is a live line.
func TestSwanctlProposalsInjectionNeutralized_6469(t *testing.T) {
	// IKE proposals: EncryptionAlg carries the payload, no AuthAlg / DHGroup,
	// so buildIKEProposalFromIKE emits the payload as the whole proposals
	// value (nothing is appended after the newline).
	ikeCfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "ike-pol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-prop"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-prop": {Name: "ike-prop", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes256\n    reauth_time = 0"},
		},
	}

	// ESP proposals: the ipsec-policy proposal's EncryptionAlg carries the
	// updown→root payload; no AuthAlg / DHGroup so esp_proposals is exactly
	// the payload. gw has a valid address so the VPN is not skipped.
	espCfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol"},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"prop1": {Name: "prop1", EncryptionAlg: "aes256\n        updown = /tmp/pwn.sh"},
		},
	}

	cases := []struct {
		name      string
		cfg       *config.IPsecConfig
		directive string // the injected line that must NOT render live
		wantSlot  string // the render slot that must still be present
	}{
		{
			name:      "IKE proposals newline injection",
			cfg:       ikeCfg,
			directive: "reauth_time = 0",
			wantSlot:  "proposals = aes256",
		},
		{
			name:      "ESP esp_proposals updown->root injection",
			cfg:       espCfg,
			directive: "updown = /tmp/pwn.sh",
			wantSlot:  "esp_proposals = aes256",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			got := m.generateConfig(c.cfg)
			if hasBareDirectiveLine(got, c.directive) {
				t.Fatalf("swanctl proposal injection NOT neutralized: %q rendered "+
					"as a live directive line — the newline in the proposal value "+
					"was not stripped:\n%s", c.directive, got)
			}
			if !strings.Contains(got, c.wantSlot) {
				t.Fatalf("expected sanitized proposal slot %q in render:\n%s",
					c.wantSlot, got)
			}
		})
	}
}

// TestSwanctlProposalsLegitPreserved_6469 is the over-escape guard for the
// proposal fold: a legitimate multi-proposal list — dashed swanctl tokens
// (aes256-sha256-modp2048) comma-joined for a `proposals [ p1 p2 ]` offer —
// must render BYTE-IDENTICAL through the sanitize belt on BOTH the IKE
// `proposals` and the ESP `esp_proposals` line. sanitizeSwanctlValue only
// touches control bytes, so `-` and `,` survive.
func TestSwanctlProposalsLegitPreserved_6469(t *testing.T) {
	cfg := &config.IPsecConfig{
		Gateways: map[string]*config.IPsecGateway{
			"gw": {Name: "gw", Address: "203.0.113.1", IKEPolicy: "ike-pol"},
		},
		VPNs: map[string]*config.IPsecVPN{
			"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol"},
		},
		IKEPolicies: map[string]*config.IKEPolicy{
			"ike-pol": {Name: "ike-pol", Proposals: []string{"ike-a", "ike-b"}},
		},
		IKEProposals: map[string]*config.IKEProposal{
			"ike-a": {Name: "ike-a", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"ike-b": {Name: "ike-b", AuthMethod: "pre-shared-keys", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"esp-a", "esp-b"}},
		},
		Proposals: map[string]*config.IPsecProposal{
			"esp-a": {Name: "esp-a", EncryptionAlg: "aes-256-cbc", AuthAlg: "sha-256", DHGroup: 14},
			"esp-b": {Name: "esp-b", EncryptionAlg: "aes-128-cbc", AuthAlg: "sha-256", DHGroup: 14},
		},
	}
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	got := m.generateConfig(cfg)

	const wantIKE = "    proposals = aes256-sha256-modp2048,aes128-sha256-modp2048\n"
	const wantESP = "        esp_proposals = aes256-sha256-modp2048,aes128-sha256-modp2048\n"
	if !strings.Contains(got, wantIKE) {
		t.Fatalf("legit IKE proposal list over-escaped or dropped: want %q in "+
			"render:\n%s", wantIKE, got)
	}
	if !strings.Contains(got, wantESP) {
		t.Fatalf("legit ESP proposal list over-escaped or dropped: want %q in "+
			"render:\n%s", wantESP, got)
	}
}
