package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// storeWithHost builds a config store, commits a config carrying the given
// host-name, and returns the store. ShowActive on the returned store therefore
// contains host-name <host>, letting the archive tests assert the periodic
// timer uploaded the CURRENT active config.
func storeWithHost(t *testing.T, host string) (*Daemon, chan string, chan time.Time, *int32) {
	t.Helper()
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name " + host); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	tickCh := make(chan time.Time, 1)
	captured := make(chan string, 8)
	var transfers int32
	d := &Daemon{
		store: store,
		opts:  Options{ConfigFile: filepath.Join(dir, "xpf.conf")},
		archiveNewTicker: func(time.Duration) (<-chan time.Time, func()) {
			return tickCh, func() {}
		},
		archiveTransfer: func(_ context.Context, srcPath, _ string) error {
			b, _ := os.ReadFile(srcPath)
			atomic.AddInt32(&transfers, 1)
			captured <- string(b)
			return nil
		},
	}
	return d, captured, tickCh, &transfers
}

// TestArchiveTimerFiresPeriodicArchive pins the #4078 fix: with
// `transfer-interval N` + archive-sites configured, a periodic timer archives
// the CURRENT active config to the sites — independent of transfer-on-commit.
//
// RED on revert: without the reconcileArchiveTimer/runArchiveTimer wiring the
// leaf is accepted-but-inert (compiled into TransferInterval but never read at
// runtime), so no goroutine consumes the tick and no transfer ever fires — the
// `<-captured` receive below times out and the test FAILS.
func TestArchiveTimerFiresPeriodicArchive(t *testing.T) {
	d, captured, tickCh, transfers := storeWithHost(t, "periodic-host")

	cfg := &config.Config{}
	// NOTE: transfer-on-commit deliberately NOT set — periodic archival must
	// fire on its own timer, not only on commit.
	cfg.System.Archival = &config.ArchivalConfig{
		TransferInterval: 30,
		ArchiveSites:     []string{"scp://user@host:/archive/"},
	}

	d.reconcileArchiveTimer(cfg)
	t.Cleanup(d.stopArchiveTimer)

	d.archiveTimerMu.Lock()
	armed := d.archiveTimerStop != nil
	d.archiveTimerMu.Unlock()
	if !armed {
		t.Fatal("timer not armed for transfer-interval + sites")
	}

	// Fire one tick; the periodic archive must invoke the archive-to-site path.
	tickCh <- time.Now()
	select {
	case got := <-captured:
		if !strings.Contains(got, "periodic-host") {
			t.Fatalf("periodic archive uploaded wrong config: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("periodic archive never fired — transfer-interval is inert (RED on revert)")
	}

	// A second tick archives again (it is a repeating timer, not one-shot).
	tickCh <- time.Now()
	select {
	case <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("second periodic archive never fired")
	}
	if n := atomic.LoadInt32(transfers); n < 2 {
		t.Fatalf("expected >= 2 periodic transfers, got %d", n)
	}
}

// TestArchiveTimerReschedulesAndStops covers the timer lifecycle: unchanged
// config does not bounce a healthy timer, an interval change reschedules
// (old goroutine stopped, new one armed), and removing the leaf stops it.
func TestArchiveTimerReschedulesAndStops(t *testing.T) {
	d, _, _, _ := storeWithHost(t, "lifecycle-host")
	t.Cleanup(d.stopArchiveTimer)

	cfg1 := &config.Config{}
	cfg1.System.Archival = &config.ArchivalConfig{
		TransferInterval: 30,
		ArchiveSites:     []string{"scp://user@host:/archive/"},
	}
	d.reconcileArchiveTimer(cfg1)

	d.archiveTimerMu.Lock()
	gen1 := d.archiveTimerStop
	d.archiveTimerMu.Unlock()
	if gen1 == nil {
		t.Fatal("timer not armed by cfg1")
	}

	// Unchanged config → same generation, no bounce.
	d.reconcileArchiveTimer(cfg1)
	d.archiveTimerMu.Lock()
	same := d.archiveTimerStop
	d.archiveTimerMu.Unlock()
	if same != gen1 {
		t.Fatal("healthy timer bounced on an unchanged config (hash gate broken)")
	}

	// Change the interval → reschedule: old goroutine stopped, new one armed.
	cfg2 := &config.Config{}
	cfg2.System.Archival = &config.ArchivalConfig{
		TransferInterval: 60,
		ArchiveSites:     []string{"scp://user@host:/archive/"},
	}
	d.reconcileArchiveTimer(cfg2)
	select {
	case <-gen1:
	default:
		t.Fatal("old timer not stopped on reschedule")
	}
	d.archiveTimerMu.Lock()
	gen2 := d.archiveTimerStop
	d.archiveTimerMu.Unlock()
	if gen2 == nil || gen2 == gen1 {
		t.Fatal("no fresh timer armed after reschedule")
	}

	// Remove the archival stanza → stop.
	d.reconcileArchiveTimer(&config.Config{})
	select {
	case <-gen2:
	default:
		t.Fatal("timer not stopped when transfer-interval removed")
	}
	d.archiveTimerMu.Lock()
	after := d.archiveTimerStop
	d.archiveTimerMu.Unlock()
	if after != nil {
		t.Fatal("timer still armed after removal")
	}
}

// TestArchiveTimerRequiresSitesAndPositiveInterval verifies the timer is NOT
// armed when there is nothing to archive to (no sites) or the interval is 0
// (transfer-on-commit-only), so a bare `transfer-on-commit` config never spins
// a pointless periodic goroutine.
func TestArchiveTimerRequiresSitesAndPositiveInterval(t *testing.T) {
	d, _, _, _ := storeWithHost(t, "gate-host")
	t.Cleanup(d.stopArchiveTimer)

	// interval set but no sites → not armed.
	cfg := &config.Config{}
	cfg.System.Archival = &config.ArchivalConfig{TransferInterval: 30}
	d.reconcileArchiveTimer(cfg)
	d.archiveTimerMu.Lock()
	armed := d.archiveTimerStop != nil
	d.archiveTimerMu.Unlock()
	if armed {
		t.Fatal("timer armed with no archive-sites")
	}

	// transfer-on-commit only (interval 0) with sites → not armed.
	cfg2 := &config.Config{}
	cfg2.System.Archival = &config.ArchivalConfig{
		TransferOnCommit: true,
		ArchiveSites:     []string{"scp://user@host:/archive/"},
	}
	d.reconcileArchiveTimer(cfg2)
	d.archiveTimerMu.Lock()
	armed2 := d.archiveTimerStop != nil
	d.archiveTimerMu.Unlock()
	if armed2 {
		t.Fatal("timer armed for transfer-on-commit-only (interval 0)")
	}
}
