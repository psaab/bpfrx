package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

func TestApplyConfigRuntimeResultDrivesDownstreamConsumers(t *testing.T) {
	networkDir := t.TempDir()
	installFakeNetworkctl(t)

	dp := &runtimeOnlyApplyTestDP{
		applyResult: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{"trust": 7},
			ManagedInterfaces: []networkd.InterfaceConfig{{
				Name:      "ge-0-0-0",
				Addresses: []string{"192.0.2.1/24"},
			}},
		},
	}
	ss := cluster.NewSessionSync(":0", "127.0.0.1:4785", nil)
	ss.IsPrimaryFn = func() bool { return false }
	ss.IsPrimaryForRGFn = func(rgID int) bool { return rgID == 2 }
	d := &Daemon{
		dp:          dp,
		networkd:    networkd.NewInDir(networkDir),
		sessionSync: ss,
		store:       configstore.New(filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:     vrrp.NewManager(),
		opts:        Options{NoDataplane: true},
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0": {
					Name:            "reth0",
					RedundancyGroup: 2,
				},
			},
		},
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{
				"trust": {
					Name:       "trust",
					Interfaces: []string{"reth0.0"},
				},
			},
		},
	}

	if err := d.applyConfigLocked(cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	if dp.applyCalls != 1 {
		t.Fatalf("ApplyConfig calls = %d, want 1", dp.applyCalls)
	}
	if !ss.ShouldSyncZone(7) {
		t.Fatal("session sync did not use runtime ApplyResult ZoneIDs")
	}
	if ss.ShouldSyncZone(8) {
		t.Fatal("session sync unexpectedly owns unmapped zone 8")
	}

	networkPath := filepath.Join(networkDir, "10-xpf-ge-0-0-0.network")
	data, err := os.ReadFile(networkPath)
	if err != nil {
		t.Fatalf("read generated networkd file: %v", err)
	}
	if !strings.Contains(string(data), "Address=192.0.2.1/24") {
		t.Fatalf("networkd file missing runtime managed address:\n%s", string(data))
	}
}

func installFakeNetworkctl(t *testing.T) {
	t.Helper()
	binDir := t.TempDir()
	networkctl := filepath.Join(binDir, "networkctl")
	if err := os.WriteFile(networkctl, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake networkctl: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
}
