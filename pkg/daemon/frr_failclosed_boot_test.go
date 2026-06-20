package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

// seededFRRConf writes a temp frr.conf carrying an xpf-managed section with a
// sentinel route line, and returns the conf path plus the sentinel so a test
// can assert the section was (or was not) stripped. The base "log syslog
// informational" line stands in for operator-owned content outside the markers,
// which must always survive.
func seededFRRConf(t *testing.T) (path, sentinel string) {
	t.Helper()
	begin, end := frr.ManagedSectionMarkersForTest()
	sentinel = "ip route 10.99.0.0/24 192.0.2.1"
	content := "log syslog informational\n" +
		begin + "\n" +
		sentinel + "\n" +
		end + "\n"
	path = filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("seed frr.conf: %v", err)
	}
	return path, sentinel
}

func readConf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frr.conf: %v", err)
	}
	return string(b)
}

// TestColdBootCompileFailedClearsFRR proves the #1993 fix: on a compile-failure
// cold boot (configCompileFailed=true), the daemon strips the last-good
// xpf-managed section from frr.conf and reloads FRR exactly once, so peers fail
// over to the HA partner instead of routing transit into this unarmed node.
//
// Non-tautological: without the clearFRRForFailClosedBoot call wired into the
// boot path the managed section survives, so this test fails on the unpatched
// tree.
func TestColdBootCompileFailedClearsFRR(t *testing.T) {
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{} // healthy reload (nil error)
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if strings.Contains(got, sentinel) {
		t.Fatalf("compile-failed cold boot must strip the managed section; frr.conf still has %q:\n%s", sentinel, got)
	}
	begin, _ := frr.ManagedSectionMarkersForTest()
	if strings.Contains(got, begin) {
		t.Fatalf("managed begin marker must be gone after clear; frr.conf:\n%s", got)
	}
	if !strings.Contains(got, "log syslog informational") {
		t.Fatalf("operator content outside the managed section must survive the clear; frr.conf:\n%s", got)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("expected exactly one FRR reload, got %d", rec.ReloadCalls)
	}
}

// TestColdBootNormalDoesNotClearFRR is the critical "don't wipe a healthy node"
// guard: on a normal / no-config bootstrap boot (configCompileFailed=false) the
// managed section must be UNTOUCHED and FRR must NOT be reloaded.
func TestColdBootNormalDoesNotClearFRR(t *testing.T) {
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	d.clearFRRForFailClosedBoot(false)

	got := readConf(t, confPath)
	if !strings.Contains(got, sentinel) {
		t.Fatalf("a normal boot must NOT touch the managed section; sentinel %q missing:\n%s", sentinel, got)
	}
	if rec.ReloadCalls != 0 {
		t.Fatalf("a normal boot must NOT reload FRR; got %d reloads", rec.ReloadCalls)
	}
}

// TestColdBootCompileFailedNilFRRIsSafe guards the NoDataplane / pre-manager
// path: clearing with a nil d.frr must not panic and must be a no-op.
func TestColdBootCompileFailedNilFRRIsSafe(t *testing.T) {
	d := &Daemon{} // d.frr == nil
	// Must not panic.
	d.clearFRRForFailClosedBoot(true)
}

// TestClearFRRReloadDegradedDoesNotAbortBoot proves a degraded reload
// (frr-reload.py unavailable → ErrFRRReloadDegraded) is tolerated: the on-disk
// managed section is still stripped (Clear writes before it reloads) and the
// helper returns normally so boot proceeds. The on-disk strip is what lets a
// later FRR restart converge even when the live reload degraded.
func TestClearFRRReloadDegradedDoesNotAbortBoot(t *testing.T) {
	confPath, sentinel := seededFRRConf(t)
	rec := &frr.RecordingExecutor{ReloadErr: frr.ErrFRRReloadDegraded}
	d := &Daemon{frr: frr.NewForTest(confPath, rec)}

	// Returns normally (no panic / no propagated error path) even on degraded.
	d.clearFRRForFailClosedBoot(true)

	got := readConf(t, confPath)
	if strings.Contains(got, sentinel) {
		t.Fatalf("degraded reload must still strip the managed section on disk; frr.conf:\n%s", got)
	}
	if rec.ReloadCalls != 1 {
		t.Fatalf("expected one reload attempt on the degraded path, got %d", rec.ReloadCalls)
	}
}
