package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #3327: the REST screen inventory dropped several screen checks the compiler
// and userspace dataplane fully enforce (port-scan, ip-sweep, the source/
// destination session limits, and the ICMP-fragment check) and exposed no
// numeric thresholds. This test injects a maximal screen profile into the live
// ActiveConfig and drives screenHandler, asserting every previously-omitted
// check name appears in `checks` and every threshold appears in `thresholds`.
// Reverting the surfacing (the screenChecks delegation to config.ScreenChecks
// or the si.Thresholds = config.ScreenThresholds population) makes the matching
// assertion fail (RED on revert).

func maximalScreenStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Commit a minimal config so the active config (and its Screen map) exist;
	// then inject the maximal profile post-commit so no recompile normalizes it.
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

func TestScreenHandlerSurfacesOmittedChecksAndThresholds(t *testing.T) {
	s := &Server{store: maximalScreenStore(t)}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/screen", nil)
	s.screenHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Success bool         `json:"success"`
		Data    []ScreenInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body: %s", err, rr.Body.String())
	}
	if !resp.Success {
		t.Fatalf("success=false; body: %s", rr.Body.String())
	}

	var max *ScreenInfo
	for i := range resp.Data {
		if resp.Data[i].Name == "max" {
			max = &resp.Data[i]
			break
		}
	}
	if max == nil {
		t.Fatalf("profile %q not found in response; body: %s", "max", rr.Body.String())
	}

	have := map[string]bool{}
	for _, c := range max.Checks {
		have[c] = true
	}
	// The previously-omitted checks are the core of #3327.
	for _, want := range []string{
		config.ScreenCheckPortScan,
		config.ScreenCheckIPSweep,
		config.ScreenCheckLimitSessionSource,
		config.ScreenCheckLimitSessionDestination,
		config.ScreenCheckICMPFragment,
	} {
		if !have[want] {
			t.Errorf("checks missing previously-omitted screen %q; got %v", want, max.Checks)
		}
	}

	wantThresholds := map[string]int{
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
