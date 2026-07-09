package config

import (
	"strings"
	"testing"
)

func hasWarn4788(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// TestIpipTunnelDeadWarning covers the #4788 advisory: a `mode ipip` tunnel
// (interface- or unit-level) warns that it is silently dead; `mode gre`/
// `mode wireguard` do not; and the advisory is wired into ValidateConfig.
func TestIpipTunnelDeadWarning(t *testing.T) {
	// (a) interface-level mode ipip → warns.
	cfgA := &Config{}
	cfgA.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ip-0/0/0": {Name: "ip-0/0/0", Tunnel: &TunnelConfig{Mode: "ipip"}},
	}
	if w := validateIpipTunnelDeadWarning(cfgA); !hasWarn4788(w, `interfaces "ip-0/0/0" tunnel mode ipip`) {
		t.Fatalf("(a) expected ipip dead-tunnel warning, got %v", w)
	}

	// (b) mode gre → no warning.
	cfgB := &Config{}
	cfgB.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{Mode: "gre"}},
	}
	if w := validateIpipTunnelDeadWarning(cfgB); len(w) != 0 {
		t.Fatalf("(b) expected no warning for mode gre, got %v", w)
	}

	// (c) unit-level mode ipip → warns naming the unit.
	cfgC := &Config{}
	cfgC.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ip-0/0/1": {Name: "ip-0/0/1", Units: map[int]*InterfaceUnit{
			5: {Tunnel: &TunnelConfig{Mode: "ipip"}},
		}},
	}
	if w := validateIpipTunnelDeadWarning(cfgC); !hasWarn4788(w, `interfaces "ip-0/0/1" unit 5 tunnel mode ipip`) {
		t.Fatalf("(c) expected unit-level ipip warning, got %v", w)
	}

	// (d) mode wireguard → no warning.
	cfgD := &Config{}
	cfgD.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"wg0": {Name: "wg0", Tunnel: &TunnelConfig{Mode: "wireguard"}},
	}
	if w := validateIpipTunnelDeadWarning(cfgD); len(w) != 0 {
		t.Fatalf("(d) expected no warning for mode wireguard, got %v", w)
	}

	// (e) REGISTRATION PIN: the advisory must be wired into ValidateConfig, not
	// merely callable — removing the append registration line must go red.
	if w := ValidateConfig(cfgA); !hasWarn4788(w, `interfaces "ip-0/0/0" tunnel mode ipip`) {
		t.Fatalf("(e) ValidateConfig must surface the ipip advisory (registration), got %v", w)
	}
}
