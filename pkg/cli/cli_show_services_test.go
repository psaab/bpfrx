package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/rpm"
)

func TestShowRPMProbeResultsFallsBackToConfigWhenLiveResultsEmpty(t *testing.T) {
	store := configstore.New(filepath.Join(t.TempDir(), "config.conf"))
	_, err := store.SyncApply(`services {
    rpm {
        probe monitor {
            test ping-test {
                target 8.8.8.8;
            }
        }
    }
}
`, nil)
	if err != nil {
		t.Fatalf("SyncApply() error = %v", err)
	}

	c := &CLI{
		store: store,
		rpmResultsFn: func() []*rpm.ProbeResult {
			return []*rpm.ProbeResult{}
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showRPMProbeResults()
	})
	if callErr != nil {
		t.Fatalf("showRPMProbeResults() error = %v", callErr)
	}
	if !strings.Contains(out, "RPM Probe Configuration:") {
		t.Fatalf("stdout = %q, want config fallback output", out)
	}
	if !strings.Contains(out, "Probe interval: 5s") {
		t.Fatalf("stdout = %q, want effective defaults in fallback output", out)
	}
}

func TestShowRPMProbeResultsReportsNoActiveConfiguration(t *testing.T) {
	c := &CLI{
		store: configstore.New(filepath.Join(t.TempDir(), "config.conf")),
		rpmResultsFn: func() []*rpm.ProbeResult {
			return []*rpm.ProbeResult{}
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showRPMProbeResults()
	})
	if callErr != nil {
		t.Fatalf("showRPMProbeResults() error = %v", callErr)
	}
	if strings.TrimSpace(out) != "No active configuration" {
		t.Fatalf("stdout = %q, want %q", out, "No active configuration\n")
	}
}
