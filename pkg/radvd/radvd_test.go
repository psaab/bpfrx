package radvd

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestGenerateConfig_Basic(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{
					Prefix:     "2001:db8:1::/64",
					OnLink:     true,
					Autonomous: true,
				},
			},
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "interface trust0\n") {
		t.Error("missing interface trust0")
	}
	if !strings.Contains(got, "AdvSendAdvert on;") {
		t.Error("missing AdvSendAdvert")
	}
	if !strings.Contains(got, "prefix 2001:db8:1::/64") {
		t.Error("missing prefix")
	}
	if !strings.Contains(got, "AdvOnLink on;") {
		t.Error("missing AdvOnLink on")
	}
	if !strings.Contains(got, "AdvAutonomous on;") {
		t.Error("missing AdvAutonomous on")
	}
}

func TestGenerateConfig_ManagedStateful(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface:     "trust0",
			ManagedConfig: true,
			OtherStateful: true,
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "AdvManagedFlag on;") {
		t.Error("missing AdvManagedFlag")
	}
	if !strings.Contains(got, "AdvOtherConfigFlag on;") {
		t.Error("missing AdvOtherConfigFlag")
	}
}

func TestGenerateConfig_DNSServers(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface:  "trust0",
			DNSServers: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "RDNSS 2001:4860:4860::8888 2001:4860:4860::8844") {
		t.Errorf("DNS servers not found in: %s", got)
	}
}

func TestGenerateConfig_NAT64(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface:   "trust0",
			NAT64Prefix: "64:ff9b::/96",
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "PREF64 64:ff9b::/96") {
		t.Error("missing PREF64")
	}
}

func TestGenerateConfig_NAT64WithLifetime(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface:       "trust0",
			NAT64Prefix:     "64:ff9b::/96",
			NAT64PrefixLife: 1800,
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "PREF64 64:ff9b::/96") {
		t.Error("missing PREF64")
	}
	if !strings.Contains(got, "AdvPREF64Lifetime 1800;") {
		t.Errorf("missing AdvPREF64Lifetime 1800 in:\n%s", got)
	}
}

func TestGenerateConfig_LifetimeAndMTU(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface:       "trust0",
			DefaultLifetime: 1800,
			MaxAdvInterval:  600,
			MinAdvInterval:  200,
			LinkMTU:         1280,
			Prefixes: []*config.RAPrefix{
				{
					Prefix:        "2001:db8::/64",
					OnLink:        true,
					Autonomous:    true,
					ValidLifetime: 86400,
					PreferredLife: 14400,
				},
			},
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "AdvDefaultLifetime 1800;") {
		t.Error("missing AdvDefaultLifetime")
	}
	if !strings.Contains(got, "MaxRtrAdvInterval 600;") {
		t.Error("missing MaxRtrAdvInterval")
	}
	if !strings.Contains(got, "MinRtrAdvInterval 200;") {
		t.Error("missing MinRtrAdvInterval")
	}
	if !strings.Contains(got, "AdvLinkMTU 1280;") {
		t.Error("missing AdvLinkMTU")
	}
	if !strings.Contains(got, "AdvValidLifetime 86400;") {
		t.Error("missing AdvValidLifetime")
	}
	if !strings.Contains(got, "AdvPreferredLifetime 14400;") {
		t.Error("missing AdvPreferredLifetime")
	}
}

func TestGenerateConfig_MultipleInterfaces(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{Interface: "trust0", Prefixes: []*config.RAPrefix{{Prefix: "2001:db8:1::/64", OnLink: true, Autonomous: true}}},
		{Interface: "dmz0", Prefixes: []*config.RAPrefix{{Prefix: "2001:db8:2::/64", OnLink: true, Autonomous: false}}},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "interface trust0") {
		t.Error("missing trust0")
	}
	if !strings.Contains(got, "interface dmz0") {
		t.Error("missing dmz0")
	}
	if !strings.Contains(got, "AdvAutonomous off;") {
		t.Error("dmz0 should have AdvAutonomous off")
	}
}

func TestGenerateConfig_PrefixFlags(t *testing.T) {
	m := New()
	raConfigs := []*config.RAInterfaceConfig{
		{
			Interface: "trust0",
			Prefixes: []*config.RAPrefix{
				{Prefix: "2001:db8:1::/64", OnLink: false, Autonomous: false},
			},
		},
	}
	got := m.generateConfig(raConfigs)
	if !strings.Contains(got, "AdvOnLink off;") {
		t.Error("should have AdvOnLink off")
	}
	if !strings.Contains(got, "AdvAutonomous off;") {
		t.Error("should have AdvAutonomous off")
	}
}
