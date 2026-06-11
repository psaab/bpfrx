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

func TestCollectAppliedTunnelsUsesAnchorModeForDefaultDataplane(t *testing.T) {
	cfg := &config.Config{}
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
		t.Fatal("default userspace tunnel should be anchor-only")
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

// #1736 S2b regression: a WireGuard tunnel has no GRE-style `source`,
// and the Source!="" screen in collectAppliedTunnels must not drop it —
// otherwise the persistent wgN TUN is never created and the userspace
// WG control thread cannot attach (found live during S2b bring-up).
func TestCollectAppliedTunnelsKeepsWireguardWithoutSource(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.DataplaneType = dataplane.TypeUserspace
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Tunnel: &config.TunnelConfig{
				Name:            "wg0",
				Mode:            "wireguard",
				WgListenPort:    51820,
				WgPeerPubkeyHex: "b0202020202020202020202020202020202020202020202020202020202020b2",
			},
		},
	}

	tunnels := collectAppliedTunnels(cfg)
	if len(tunnels) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1 (wireguard tunnel without source was dropped)", len(tunnels))
	}
	if tunnels[0].Mode != "wireguard" || tunnels[0].Name != "wg0" {
		t.Fatalf("unexpected tunnel collected: %+v", tunnels[0])
	}
	// A GRE stanza with no source must STILL be screened out — the
	// wireguard exemption must not weaken the half-configured-GRE gate.
	cfg.Interfaces.Interfaces["gr-0/0/0"] = &config.InterfaceConfig{
		Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", Mode: "gre"},
	}
	if got := len(collectAppliedTunnels(cfg)); got != 1 {
		t.Fatalf("len(tunnels) = %d, want 1 (sourceless GRE must stay screened)", got)
	}
}
