package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3327 (text-renderer fold): PR #3538 fixed the structured REST/gRPC screen
// inventory and introduced the config.ScreenChecks / config.ScreenThresholds
// SSOT, but left three hand-built screen-inventory lists in the TEXT renderers
// that still omitted port-scan, ip-sweep, limit-session-source,
// limit-session-destination, and icmp-fragment:
//   - server_show_zones_text.go    ("show security zones" detail)
//   - server_show_security_text.go ("show security screen" + the screen
//     ids-option detail table)
// All three now route through the SSOT (the enabled-list summaries via
// screenEnabledCheckList -> config.ScreenChecks/ScreenThresholds; the detail
// table carries a row for every check). This test injects a maximal profile
// bound to a zone and asserts each previously-omitted check name appears in the
// text output of all three commands. Reverting any site back to its hand-built
// list makes the matching assertion fail (RED on revert).

func maximalScreenTextStore(t *testing.T) *config.Config {
	t.Helper()
	store := maximalScreenGRPCStore(t)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if cfg.Security.Zones == nil {
		cfg.Security.Zones = map[string]*config.ZoneConfig{}
	}
	cfg.Security.Zones["trust"] = &config.ZoneConfig{
		Name:          "trust",
		Interfaces:    []string{"ge-0-0-0"},
		ScreenProfile: "max",
	}
	return cfg
}

var omittedScreenCheckNames = []string{
	config.ScreenCheckPortScan,
	config.ScreenCheckIPSweep,
	config.ScreenCheckLimitSessionSource,
	config.ScreenCheckLimitSessionDestination,
	config.ScreenCheckICMPFragment,
}

func assertContainsAllOmitted(t *testing.T, label, out string) {
	t.Helper()
	for _, want := range omittedScreenCheckNames {
		if !strings.Contains(out, want) {
			t.Errorf("%s output missing previously-omitted screen check %q; got:\n%s", label, want, out)
		}
	}
}

func TestShowSecurityZonesTextSurfacesOmittedScreenChecks(t *testing.T) {
	cfg := maximalScreenTextStore(t)
	s := &Server{}
	var buf strings.Builder
	s.showZonesDetail(cfg, "", &buf)
	out := buf.String()
	if !strings.Contains(out, "Enabled checks:") {
		t.Fatalf("zones detail missing Enabled checks line; got:\n%s", out)
	}
	assertContainsAllOmitted(t, "show security zones", out)
	// A configured threshold must be surfaced too (SSOT thresholds path).
	if !strings.Contains(out, "port-scan(threshold:25)") {
		t.Errorf("zones detail missing port-scan threshold annotation; got:\n%s", out)
	}
}

func TestShowSecurityScreenTextSurfacesOmittedScreenChecks(t *testing.T) {
	cfg := maximalScreenTextStore(t)
	s := &Server{}
	var buf strings.Builder
	s.showScreen(cfg, &buf)
	out := buf.String()
	assertContainsAllOmitted(t, "show security screen", out)
	if !strings.Contains(out, "ip-sweep(threshold:50)") {
		t.Errorf("show security screen missing ip-sweep threshold annotation; got:\n%s", out)
	}
}

func TestShowScreenIDSOptionDetailSurfacesOmittedScreenChecks(t *testing.T) {
	cfg := maximalScreenTextStore(t)
	s := &Server{}
	var buf strings.Builder
	if _, err := s.showScreenIDSOptionDetail(&pb.ShowTextRequest{Topic: "screen-ids-option-detail:max"}, cfg, &buf); err != nil {
		t.Fatalf("showScreenIDSOptionDetail error = %v", err)
	}
	out := buf.String()
	assertContainsAllOmitted(t, "screen ids-option detail", out)
}

func TestShowScreenIDSOptionSurfacesOmittedScreenChecks(t *testing.T) {
	cfg := maximalScreenTextStore(t)
	s := &Server{}
	var buf strings.Builder
	if _, err := s.showScreenIDSOption(&pb.ShowTextRequest{Topic: "screen-ids-option:max"}, cfg, &buf); err != nil {
		t.Fatalf("showScreenIDSOption error = %v", err)
	}
	out := buf.String()
	assertContainsAllOmitted(t, "screen ids-option", out)
}
