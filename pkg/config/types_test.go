package config

import "testing"

func TestRethToPhysical(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 2},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth1"},
				"trust0":   {Name: "trust0"},
			},
		},
	}

	m := cfg.RethToPhysical()
	if len(m) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(m))
	}
	if m["reth0"] != "ge-0/0/0" {
		t.Errorf("reth0 → %q, want ge-0/0/0", m["reth0"])
	}
	if m["reth1"] != "ge-0/0/1" {
		t.Errorf("reth1 → %q, want ge-0/0/1", m["reth1"])
	}
}

func TestRethToPhysical_Empty(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"trust0": {Name: "trust0"},
			},
		},
	}
	m := cfg.RethToPhysical()
	if len(m) != 0 {
		t.Errorf("expected empty map, got %v", m)
	}
}

func TestResolveReth(t *testing.T) {
	cfg := &Config{
		Interfaces: InterfacesConfig{
			Interfaces: map[string]*InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}

	tests := []struct {
		input string
		want  string
	}{
		{"reth0", "ge-0/0/0"},
		{"reth0.50", "ge-0/0/0.50"},
		{"trust0", "trust0"},
		{"trust0.0", "trust0.0"},
		{"reth1", "reth1"}, // not mapped
	}
	for _, tt := range tests {
		got := cfg.ResolveReth(tt.input)
		if got != tt.want {
			t.Errorf("ResolveReth(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
