package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestRenderValidEndpoints_5630 is the render-side companion to the #5630
// commit-time endpoint gate: it pins that a VALID IPv4 / IPv6 / FQDN remote
// gateway address, and a valid local-address, still render into the swanctl
// `remote_addrs` / `local_addrs` settings unchanged. The commit-time gate
// (validateIPsecEndpointsStrict, pkg/config) rejects only endpoints strongSwan
// would refuse; this test guards that the fix does not disturb the render of
// endpoints it accepts.
func TestRenderValidEndpoints_5630(t *testing.T) {
	cases := []struct {
		name       string
		gwAddr     string
		gwLocal    string
		wantRemote string
		wantLocal  string
	}{
		{
			name:       "IPv4 remote + IPv4 local",
			gwAddr:     "203.0.113.1",
			gwLocal:    "198.51.100.7",
			wantRemote: "remote_addrs = 203.0.113.1",
			wantLocal:  "local_addrs = 198.51.100.7",
		},
		{
			name:       "IPv6 remote + IPv6 local",
			gwAddr:     "2001:db8::1",
			gwLocal:    "2001:db8::2",
			wantRemote: "remote_addrs = 2001:db8::1",
			wantLocal:  "local_addrs = 2001:db8::2",
		},
		{
			name:       "FQDN remote",
			gwAddr:     "peer.example.com",
			gwLocal:    "",
			wantRemote: "remote_addrs = peer.example.com",
			wantLocal:  "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &Manager{configDir: "/tmp", configPath: "/tmp/xpf.conf"}
			cfg := &config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {Name: "gw", Address: c.gwAddr, LocalAddress: c.gwLocal},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {Name: "tun", Gateway: "gw", IPsecPolicy: "ipsec-pol"},
				},
				Policies: map[string]*config.IPsecPolicyDef{
					"ipsec-pol": {Name: "ipsec-pol", Proposals: []string{"prop1"}},
				},
				Proposals: map[string]*config.IPsecProposal{
					"prop1": {Name: "prop1", EncryptionAlg: "aes256", AuthAlg: "sha256"},
				},
			}
			got := m.generateConfig(cfg)
			if !strings.Contains(got, c.wantRemote) {
				t.Fatalf("rendered config missing %q:\n%s", c.wantRemote, got)
			}
			if c.wantLocal != "" && !strings.Contains(got, c.wantLocal) {
				t.Fatalf("rendered config missing %q:\n%s", c.wantLocal, got)
			}
		})
	}
}
