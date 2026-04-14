package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestResolveSourceAddr_PrimaryAddress(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth1": {
					Name: "reth1",
					Units: map[int]*config.InterfaceUnit{
						100: {
							Number:         100,
							Addresses:      []string{"10.0.1.10/24", "10.0.1.20/24"},
							PrimaryAddress: "10.0.1.20/24",
						},
					},
				},
			},
		},
	}

	got := resolveSourceAddr(cfg, "reth1.100")
	if got != "10.0.1.20" {
		t.Errorf("resolveSourceAddr() = %q, want %q", got, "10.0.1.20")
	}
}

func TestResolveSourceAddr_NoPrimary(t *testing.T) {
	// No PrimaryAddress configured — should fall through to kernel lookup
	// (which will fail in test env since the interface doesn't exist).
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"trust0": {
					Name: "trust0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number:    0,
							Addresses: []string{"10.0.1.10/24"},
						},
					},
				},
			},
		},
	}

	got := resolveSourceAddr(cfg, "trust0.0")
	// No PrimaryAddress, interface doesn't exist in kernel — empty string
	if got != "" {
		t.Errorf("resolveSourceAddr() = %q, want empty", got)
	}
}

func TestResolveSourceAddr_Unit0(t *testing.T) {
	// Interface without explicit unit suffix (no dot) should default to unit 0
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"trust0": {
					Name: "trust0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number:         0,
							Addresses:      []string{"10.0.1.10/24", "10.0.1.5/24"},
							PrimaryAddress: "10.0.1.5/24",
						},
					},
				},
			},
		},
	}

	got := resolveSourceAddr(cfg, "trust0")
	if got != "10.0.1.5" {
		t.Errorf("resolveSourceAddr() = %q, want %q", got, "10.0.1.5")
	}
}

func TestResolveSourceAddr_IPv6Primary(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*config.InterfaceUnit{
						0: {
							Number:         0,
							Addresses:      []string{"172.16.50.5/24", "2001:db8::5/64"},
							PrimaryAddress: "2001:db8::5/64",
						},
					},
				},
			},
		},
	}

	got := resolveSourceAddr(cfg, "wan0")
	if got != "2001:db8::5" {
		t.Errorf("resolveSourceAddr() = %q, want %q", got, "2001:db8::5")
	}
}

func TestResolveSourceAddr_InterfaceNotInConfig(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{},
		},
	}

	got := resolveSourceAddr(cfg, "nonexistent0.0")
	// Interface not in config AND not in kernel → empty
	if got != "" {
		t.Errorf("resolveSourceAddr() = %q, want empty", got)
	}
}
