package config

import (
	"testing"
)

func TestResolveSyslogSourceAddr_PrimaryAddress(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth1": {
					Name: "reth1",
					Units: map[int]*InterfaceUnit{
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

	got := ResolveSyslogSourceAddr(cfg, "reth1.100")
	if got != "10.0.1.20" {
		t.Errorf("ResolveSyslogSourceAddr() = %q, want %q", got, "10.0.1.20")
	}
}

func TestResolveSyslogSourceAddr_NoPrimary(t *testing.T) {
	// No PrimaryAddress configured — should fall through to kernel lookup
	// (which will fail in test env since the interface doesn't exist).
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"trust0": {
					Name: "trust0",
					Units: map[int]*InterfaceUnit{
						0: {
							Number:    0,
							Addresses: []string{"10.0.1.10/24"},
						},
					},
				},
			},
		},
	}

	got := ResolveSyslogSourceAddr(cfg, "trust0.0")
	// No PrimaryAddress, interface doesn't exist in kernel — empty string
	if got != "" {
		t.Errorf("ResolveSyslogSourceAddr() = %q, want empty", got)
	}
}

func TestResolveSyslogSourceAddr_Unit0(t *testing.T) {
	// Interface without explicit unit suffix (no dot) should default to unit 0
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"trust0": {
					Name: "trust0",
					Units: map[int]*InterfaceUnit{
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

	got := ResolveSyslogSourceAddr(cfg, "trust0")
	if got != "10.0.1.5" {
		t.Errorf("ResolveSyslogSourceAddr() = %q, want %q", got, "10.0.1.5")
	}
}

func TestResolveSyslogSourceAddr_IPv6Primary(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"wan0": {
					Name: "wan0",
					Units: map[int]*InterfaceUnit{
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

	got := ResolveSyslogSourceAddr(cfg, "wan0")
	if got != "2001:db8::5" {
		t.Errorf("ResolveSyslogSourceAddr() = %q, want %q", got, "2001:db8::5")
	}
}

func TestResolveSyslogSourceAddr_InterfaceNotInConfig(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{},
		},
	}

	got := ResolveSyslogSourceAddr(cfg, "nonexistent0.0")
	// Interface not in config AND not in kernel → empty
	if got != "" {
		t.Errorf("ResolveSyslogSourceAddr() = %q, want empty", got)
	}
}
