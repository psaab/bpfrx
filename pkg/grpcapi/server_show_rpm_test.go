package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestWriteRPMConfigReportsNoActiveConfiguration(t *testing.T) {
	var buf strings.Builder
	writeRPMConfig(&buf, nil)
	if got, want := buf.String(), "No active configuration\n"; got != want {
		t.Fatalf("writeRPMConfig(nil) = %q, want %q", got, want)
	}
}

func TestWriteRPMConfigRendersEffectiveSettings(t *testing.T) {
	cfg := &config.Config{
		Services: config.ServicesConfig{
			RPM: &config.RPMConfig{
				Probes: map[string]*config.RPMProbe{
					"monitor": {
						Name: "monitor",
						Tests: map[string]*config.RPMTest{
							"ping-test": {
								Name:   "ping-test",
								Target: "8.8.8.8",
							},
						},
					},
				},
			},
		},
	}

	var buf strings.Builder
	writeRPMConfig(&buf, cfg)
	out := buf.String()
	if !strings.Contains(out, "RPM Probe Configuration:\n") {
		t.Fatalf("writeRPMConfig() output = %q, want heading", out)
	}
	if !strings.Contains(out, "Probe interval: 5s") {
		t.Fatalf("writeRPMConfig() output = %q, want effective default interval", out)
	}
	if !strings.Contains(out, "Probe limit: unlimited") {
		t.Fatalf("writeRPMConfig() output = %q, want unlimited probe limit", out)
	}
}
