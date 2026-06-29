package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3327: the gRPC GetScreen inventory dropped several screen checks the
// compiler and userspace dataplane fully enforce (port-scan, ip-sweep, the
// source/destination session limits, and the ICMP-fragment check) and exposed
// no numeric thresholds. This test injects a maximal screen profile into the
// live ActiveConfig and drives GetScreen, asserting every previously-omitted
// check name appears in Checks and every threshold appears in Thresholds.
// Reverting the surfacing (the screenChecks delegation to config.ScreenChecks
// or the si.Thresholds population from config.ScreenThresholds) makes the
// matching assertion fail (RED on revert).

func maximalScreenGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    screen {
        ids-option base {
            tcp { land; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if cfg.Security.Screen == nil {
		cfg.Security.Screen = map[string]*config.ScreenProfile{}
	}
	cfg.Security.Screen["max"] = &config.ScreenProfile{
		Name: "max",
		TCP: config.TCPScreen{
			SynFlood: &config.SynFloodConfig{
				AttackThreshold:      2000,
				AlarmThreshold:       1000,
				SourceThreshold:      100,
				DestinationThreshold: 200,
				Timeout:              20,
			},
			Land:              true,
			WinNuke:           true,
			SynFrag:           true,
			SynFin:            true,
			NoFlag:            true,
			FinNoAck:          true,
			PortScanThreshold: 25,
		},
		ICMP: config.ICMPScreen{PingDeath: true, Fragment: true, FloodThreshold: 1000},
		UDP:  config.UDPScreen{FloodThreshold: 5000},
		IP:   config.IPScreen{SourceRouteOption: true, TearDrop: true, IPSweepThreshold: 50},
		LimitSession: config.LimitSessionScreen{
			SourceIPBased:      128,
			DestinationIPBased: 256,
		},
	}
	return store
}

func TestGetScreenSurfacesOmittedChecksAndThresholds(t *testing.T) {
	s := &Server{store: maximalScreenGRPCStore(t)}
	resp, err := s.GetScreen(context.Background(), &pb.GetScreenRequest{})
	if err != nil {
		t.Fatalf("GetScreen error = %v", err)
	}

	var max *pb.ScreenInfo
	for _, si := range resp.Screens {
		if si.Name == "max" {
			max = si
			break
		}
	}
	if max == nil {
		t.Fatalf("profile %q not found in GetScreen response", "max")
	}

	have := map[string]bool{}
	for _, c := range max.Checks {
		have[c] = true
	}
	for _, want := range []string{
		config.ScreenCheckPortScan,
		config.ScreenCheckIPSweep,
		config.ScreenCheckLimitSessionSource,
		config.ScreenCheckLimitSessionDestination,
		config.ScreenCheckICMPFragment,
	} {
		if !have[want] {
			t.Errorf("Checks missing previously-omitted screen %q; got %v", want, max.Checks)
		}
	}

	wantThresholds := map[string]int64{
		config.ScreenCheckPortScan:                25,
		config.ScreenCheckIPSweep:                 50,
		config.ScreenCheckLimitSessionSource:      128,
		config.ScreenCheckLimitSessionDestination: 256,
		config.ScreenCheckICMPFlood:               1000,
		config.ScreenCheckUDPFlood:                5000,
		config.ScreenThreshSynFloodAttack:         2000,
		config.ScreenThreshSynFloodAlarm:          1000,
		config.ScreenThreshSynFloodSource:         100,
		config.ScreenThreshSynFloodDestination:    200,
		config.ScreenThreshSynFloodTimeout:        20,
	}
	for k, v := range wantThresholds {
		if got, ok := max.Thresholds[k]; !ok || got != v {
			t.Errorf("threshold %q = (%d, present=%v), want %d", k, got, ok, v)
		}
	}
}
