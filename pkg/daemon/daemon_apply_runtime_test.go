package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// TestApplyConfigLockedSurfacesHostInboundFailure is the #3333 commit-level
// wiring proof: it drives the REAL applyConfigLocked body (not the
// applyHostInboundFilter helper directly) with an injected host-inbound nft
// failure via the nftApplyPayload seam, and asserts the returned commit error
// includes that failure. This pins the production wiring — the
// errors.Join(networkdErr, dhcpServerErr, hostInboundErr) at the tail of
// applyConfigLocked — which the helper-level seam tests do NOT cover.
//
// RED-on-revert: remove hostInboundErr from that join and this test goes RED
// (the apply completes and returns nil despite the host-inbound deny failing to
// install — the silent fail-open the issue describes).
func TestApplyConfigLockedSurfacesHostInboundFailure(t *testing.T) {
	installFakeNetworkctl(t)

	injected := errors.New("nft: host-inbound rule load failed")
	origApply := nftApplyPayload
	nftApplyPayload = func(string) ([]byte, error) { return []byte("Error: load failed\n"), injected }
	defer func() { nftApplyPayload = origApply }()

	networkDir := t.TempDir()
	d := &Daemon{
		dp:       &runtimeOnlyApplyTestDP{},
		networkd: networkd.NewInDir(networkDir),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}

	// Enforceable host-inbound config: a non-lifeline zone with a static
	// address and a host-inbound stanza, so applyConfigLocked reaches the APPLY
	// path and the injected nft failure is the deny-not-installed failure.
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.7.7.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}

	err := d.applyConfigLocked(context.Background(), cfg)
	if err == nil {
		t.Fatal("applyConfigLocked must surface the host-inbound nft failure " +
			"(fail-closed); got nil (the silent fail-open #3333 describes)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the host-inbound failure "+
			"via errors.Join wiring, got %v", err)
	}
}

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
		store:       newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
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

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
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
	// #3333: applyConfigLocked now surfaces a host-inbound `nft` apply/teardown
	// failure as a commit error (fail-closed). The CI/test host has no `nft`
	// binary, so without a benign stub these full-apply tests would fail on an
	// nft-not-found error unrelated to what they assert. Install a no-op nft
	// alongside networkctl (the host-inbound failure semantics themselves are
	// covered by the seam-injection tests in host_inbound_nft_test.go).
	nft := filepath.Join(binDir, "nft")
	if err := os.WriteFile(nft, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake nft: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
}
