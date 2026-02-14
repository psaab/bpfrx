package grpcapi

import (
	"net"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestPolicyActionName(t *testing.T) {
	tests := []struct {
		action config.PolicyAction
		want   string
	}{
		{0, "permit"},
		{1, "deny"},
		{2, "reject"},
		{99, "permit"},
	}
	for _, tt := range tests {
		got := policyActionName(tt.action)
		if got != tt.want {
			t.Errorf("policyActionName(%d) = %q, want %q", tt.action, got, tt.want)
		}
	}
}

func TestMatchShowPolicyAddr(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"trust-net": {Value: "10.0.1.0/24"},
			"server1":   {Value: "192.168.1.1/32"},
		},
		AddressSets: map[string]*config.AddressSet{
			"all-internal": {Addresses: []string{"trust-net", "server1"}},
		},
	}

	tests := []struct {
		name  string
		addrs []string
		ip    net.IP
		want  bool
	}{
		{"any matches", []string{"any"}, net.ParseIP("1.2.3.4"), true},
		{"empty addrs matches", nil, net.ParseIP("1.2.3.4"), true},
		{"nil IP matches", []string{"trust-net"}, nil, true},
		{"addr match", []string{"trust-net"}, net.ParseIP("10.0.1.50"), true},
		{"addr no match", []string{"trust-net"}, net.ParseIP("10.0.2.50"), false},
		{"addr-set match", []string{"all-internal"}, net.ParseIP("192.168.1.1"), true},
		{"addr-set no match", []string{"all-internal"}, net.ParseIP("172.16.0.1"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchShowPolicyAddr(tt.addrs, tt.ip, cfg)
			if got != tt.want {
				t.Errorf("matchShowPolicyAddr(%v, %v) = %v, want %v", tt.addrs, tt.ip, got, tt.want)
			}
		})
	}
}

func TestMatchShowPolicyApp(t *testing.T) {
	cfg := &config.Config{}
	cfg.Applications.Applications = map[string]*config.Application{
		"junos-http":   {Protocol: "tcp", DestinationPort: "80"},
		"junos-ssh":    {Protocol: "tcp", DestinationPort: "22"},
		"custom-range": {Protocol: "tcp", DestinationPort: "8000-9000"},
	}
	cfg.Applications.ApplicationSets = map[string]*config.ApplicationSet{
		"web-apps": {Applications: []string{"junos-http"}},
	}

	tests := []struct {
		name    string
		apps    []string
		proto   string
		dstPort int
		want    bool
	}{
		{"any matches", []string{"any"}, "tcp", 80, true},
		{"empty apps matches", nil, "tcp", 80, true},
		{"empty proto matches", []string{"junos-http"}, "", 80, true},
		{"exact app match", []string{"junos-http"}, "tcp", 80, true},
		{"app wrong port", []string{"junos-http"}, "tcp", 443, false},
		{"app wrong proto", []string{"junos-http"}, "udp", 80, false},
		{"range match", []string{"custom-range"}, "tcp", 8080, true},
		{"range no match", []string{"custom-range"}, "tcp", 7999, false},
		{"app-set match", []string{"web-apps"}, "tcp", 80, true},
		{"app-set no match", []string{"web-apps"}, "tcp", 22, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchShowPolicyApp(tt.apps, tt.proto, tt.dstPort, cfg)
			if got != tt.want {
				t.Errorf("matchShowPolicyApp(%v, %q, %d) = %v, want %v",
					tt.apps, tt.proto, tt.dstPort, got, tt.want)
			}
		})
	}
}
