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
