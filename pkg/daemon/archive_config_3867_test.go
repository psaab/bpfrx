package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// TestArchiveConfigUploadsActiveNotBootFile pins the #3867 fix:
// transfer-on-commit must upload the CURRENT ACTIVE configuration serialized
// from the configstore (Store.ShowActive — the same text `show configuration`
// renders), NOT the boot-time d.opts.ConfigFile.
//
// The boot file /etc/xpf/xpf.conf is written once at install and is never
// rewritten after the configstore became DB-canonical, so the pre-fix code
// (`configFile := d.opts.ConfigFile; scp configFile dest`) uploaded the day-0
// config on every commit while scp still logged success — a silently-wrong
// DR/compliance archive.
//
// RED on revert: with the source reverted to d.opts.ConfigFile the captured
// bytes equal the day-0 boot file (contains "day0-boot") and NOT the
// just-committed active config (missing "committed-c1"), so both the
// exact-equality assertion and the boot-file guard trip.
func TestArchiveConfigUploadsActiveNotBootFile(t *testing.T) {
	dir := t.TempDir()

	// Day-0 boot file: parseable config that nothing rewrites post-boot.
	bootFile := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(bootFile, []byte("system {\n    host-name day0-boot;\n}\n"), 0600); err != nil {
		t.Fatalf("write boot file: %v", err)
	}

	// Build a store and commit C1 so the active config diverges from the
	// boot file (mirrors a post-boot operator commit).
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name committed-c1"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wantActive := store.ShowActive()
	if !strings.Contains(wantActive, "committed-c1") {
		t.Fatalf("active config missing committed host-name: %q", wantActive)
	}

	// Inject a capturing transfer that records the bytes of the uploaded
	// source file (the archive-source selection under test).
	var mu sync.Mutex
	var captured string
	done := make(chan struct{}, 1)
	d := &Daemon{
		store: store,
		opts:  Options{ConfigFile: bootFile},
		archiveTransfer: func(_ context.Context, srcPath, _ string) error {
			b, err := os.ReadFile(srcPath)
			mu.Lock()
			captured = string(b)
			mu.Unlock()
			select {
			case done <- struct{}{}:
			default:
			}
			return err
		},
	}

	cfg := &config.Config{}
	cfg.System.Archival = &config.ArchivalConfig{
		TransferOnCommit: true,
		ArchiveSites:     []string{"scp://user@host:/archive/"},
	}

	d.archiveConfig(cfg)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("archiveConfig never invoked the transfer")
	}

	mu.Lock()
	got := captured
	mu.Unlock()

	// The archived bytes must equal the just-committed active config exactly
	// (the same serializer `show configuration` uses).
	if got != wantActive {
		t.Fatalf("archived bytes != active config.\n got: %q\nwant: %q", got, wantActive)
	}
	// RED-on-revert guards: the reverted code scps d.opts.ConfigFile (the
	// day-0 boot file), so the captured content contains "day0-boot" and is
	// missing the committed host-name.
	if strings.Contains(got, "day0-boot") {
		t.Fatalf("archived the stale day-0 boot file, not the committed active config: %q", got)
	}
	if !strings.Contains(got, "committed-c1") {
		t.Fatalf("archived config missing the just-committed host-name: %q", got)
	}
}

// TestArchiveConfigRemovesTempFile verifies the transient serialized-config
// file is cleaned up after all uploads complete (no leaked temp files).
func TestArchiveConfigRemovesTempFile(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name cleanup-host"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var mu sync.Mutex
	var srcSeen string
	done := make(chan struct{}, 1)
	d := &Daemon{
		store: store,
		opts:  Options{ConfigFile: filepath.Join(dir, "xpf.conf")},
		archiveTransfer: func(_ context.Context, srcPath, _ string) error {
			mu.Lock()
			srcSeen = srcPath
			mu.Unlock()
			if _, err := os.Stat(srcPath); err != nil {
				t.Errorf("source file missing during transfer: %v", err)
			}
			select {
			case done <- struct{}{}:
			default:
			}
			return nil
		},
	}
	cfg := &config.Config{}
	cfg.System.Archival = &config.ArchivalConfig{
		TransferOnCommit: true,
		ArchiveSites:     []string{"scp://user@host:/archive/"},
	}
	d.archiveConfig(cfg)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("archiveConfig never invoked the transfer")
	}

	mu.Lock()
	src := srcSeen
	mu.Unlock()

	// The cleanup goroutine runs after wg.Wait(); poll briefly for removal.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(src); os.IsNotExist(err) {
			return // cleaned up
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("temp archive file not removed: %s", src)
}
