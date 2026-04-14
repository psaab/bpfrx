package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestCollectAppliedTunnelsUsesAnchorModeForUserspace(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeUserspace
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:db8::1",
				Destination: "2001:db8::2",
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1", len(tunnels))
	}
	if !tunnels[0].AnchorOnly {
		t.Fatal("userspace tunnel should be anchor-only")
	}
}

func TestCollectAppliedTunnelsKeepsKernelModeForLegacyDataplane(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeEBPF
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:db8::1",
				Destination: "2001:db8::2",
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1", len(tunnels))
	}
	if tunnels[0].AnchorOnly {
		t.Fatal("legacy dataplane tunnel should not be anchor-only")
	}
}
