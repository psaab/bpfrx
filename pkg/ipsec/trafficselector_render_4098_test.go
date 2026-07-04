package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRenderTrafficSelectorSanitizesInjection is the #4098 render RED-on-revert
// guard. A `traffic-selector local-ip / remote-ip` whose value carries a
// materialized newline (the Junos lexer turns a quoted `\n` into a real
// newline) must NOT reach the swanctl.conf children{} block verbatim: the raw
// renderer emitted `local_ts = <value>` unescaped, so the newline started a
// fresh `updown = <script>` line inside the child block — a config-injection
// executed by the root charon daemon (root RCE). renderConfig now runs
// local_ts / remote_ts through sanitizeSwanctlValue (control chars -> spaces),
// parity with the sibling child SA name, so the injected line collapses onto
// the local_ts value and is inert.
//
// Reverting the sanitizeSwanctlValue wrap in policy.go makes the rendered
// config contain a standalone `updown = ...` line and this test goes RED.
func TestRenderTrafficSelectorSanitizesInjection(t *testing.T) {
	const injectedLocal = "10.0.0.0/24\n        updown = /tmp/pwn.sh"
	const injectedRemote = "10.0.1.0/24\n        esp_proposals = null-null"

	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: injectedLocal, RemoteIP: injectedRemote},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
	}

	got := m.generateConfig(cfg)

	// No rendered line may be a standalone injected swanctl setting. On the
	// raw (pre-fix) renderer the materialized newline splits the local_ts /
	// remote_ts value, so `updown = ...` and `esp_proposals = ...` appear on
	// their own lines inside the children block.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "updown") {
			t.Fatalf("injected updown line reached swanctl children block:\n%s", got)
		}
		if strings.HasPrefix(trimmed, "esp_proposals = null-null") {
			t.Fatalf("injected esp_proposals override reached swanctl children block:\n%s", got)
		}
	}

	// The sanitized value stays on the local_ts line (newline -> space), so
	// the tunnel still carries the operator's selector prefix — the belt does
	// not drop the whole value.
	if !strings.Contains(got, "local_ts = 10.0.0.0/24") {
		t.Fatalf("sanitized local_ts prefix missing from render:\n%s", got)
	}
}

// TestRenderTrafficSelectorNormalUnchanged is the over-reject negative control:
// a well-formed CIDR selector renders byte-for-byte as before (the sanitize
// belt is a no-op on a clean value).
func TestRenderTrafficSelectorNormalUnchanged(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Name:        "tun1",
				Gateway:     "172.16.0.1",
				IPsecPolicy: "ipsec-pol",
				TrafficSelectors: map[string]*config.IPsecTrafficSelector{
					"ts1": {Name: "ts1", LocalIP: "10.0.0.0/24", RemoteIP: "10.0.1.0/24"},
				},
			},
		},
		Policies: map[string]*config.IPsecPolicyDef{
			"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "local_ts = 10.0.0.0/24\n") {
		t.Fatalf("clean local_ts selector not rendered verbatim:\n%s", got)
	}
	if !strings.Contains(got, "remote_ts = 10.0.1.0/24\n") {
		t.Fatalf("clean remote_ts selector not rendered verbatim:\n%s", got)
	}
}
