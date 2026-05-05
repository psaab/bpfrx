package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #653: server-side renderer for `show services
// application-identification status`. The output must be
// honest about what xpf AppID actually does today: port +
// protocol matching, no L7 DPI / signature engine.

func TestShowApplicationIdentificationStatusRendersHonestContractWhenEnabled(t *testing.T) {
	cfg := &config.Config{
		Services: config.ServicesConfig{ApplicationIdentification: true},
	}
	var buf strings.Builder
	(&Server{}).showApplicationIdentificationStatus(cfg, &buf)
	out := buf.String()
	for _, want := range []string{
		"Application identification (AppID) status:",
		"Configured:                  yes",
		"Engine implementation:        port + protocol matching only",
		"L7 DPI / signature engine:    not implemented",
		"Signature package:            not supported",
		"Operator note:",
		"It does NOT enable L7 DPI",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestShowApplicationIdentificationStatusRendersHonestContractWhenDisabled(t *testing.T) {
	cfg := &config.Config{} // services.application-identification = false
	var buf strings.Builder
	(&Server{}).showApplicationIdentificationStatus(cfg, &buf)
	out := buf.String()
	for _, want := range []string{
		"Application identification (AppID) status:",
		"Configured:                  no",
		"Engine implementation:        port + protocol matching only",
		"L7 DPI / signature engine:    not implemented",
		"port→name heuristic",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	// The "Operator note:" block fires only when the knob is enabled.
	if strings.Contains(out, "Operator note:") {
		t.Errorf("operator note block must not render when AppID disabled:\n%s", out)
	}
}

func TestShowApplicationIdentificationStatusHandlesNilConfig(t *testing.T) {
	var buf strings.Builder
	(&Server{}).showApplicationIdentificationStatus(nil, &buf)
	out := buf.String()
	// nil config means we still render the static contract, just with
	// "(no active configuration)" in place of catalog stats.
	if !strings.Contains(out, "Application identification (AppID) status:") {
		t.Errorf("missing heading on nil config:\n%s", out)
	}
	if !strings.Contains(out, "(no active configuration)") {
		t.Errorf("expected nil-config sentinel:\n%s", out)
	}
}
