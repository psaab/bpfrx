package daemon

import (
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestResolveJunosIfName(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			},
		},
	}

	tests := []struct {
		input string
		want  string
	}{
		// Junos interface with slashes → dashes
		{"ge-0/0/1", "ge-0-0-1"},
		// RETH → physical member with slashes → dashes
		{"reth0", "ge-0-0-0"},
		// RETH VLAN subinterface → physical member VLAN
		{"reth0.50", "ge-0-0-0.50"},
		// Already Linux name → unchanged
		{"trust0", "trust0"},
		// VLAN subinterface without reth → unchanged
		{"trust0.100", "trust0.100"},
		// Unmapped reth → unchanged (no member)
		{"reth1", "reth1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := resolveJunosIfName(cfg, tt.input)
			if got != tt.want {
				t.Errorf("resolveJunosIfName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShouldScheduleStandbyNeighborRefresh(t *testing.T) {
	base := time.Unix(100, 0)
	d := Daemon{startTime: base}
	first := base.Add(10 * time.Second)
	if !d.shouldScheduleStandbyNeighborRefresh(first) {
		t.Fatal("first standby neighbor refresh should schedule")
	}
	if d.shouldScheduleStandbyNeighborRefresh(first.Add(500 * time.Millisecond)) {
		t.Fatal("refresh inside debounce interval should not schedule")
	}
	if !d.shouldScheduleStandbyNeighborRefresh(first.Add(standbyNeighborRefreshMinInterval + time.Millisecond)) {
		t.Fatal("refresh after debounce interval should schedule")
	}
	if !d.shouldScheduleStandbyNeighborRefresh(first.Add(-time.Second)) {
		t.Fatal("clock step backwards should not suppress refresh scheduling")
	}
}
