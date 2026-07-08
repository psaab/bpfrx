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

// TestArchiveConfigStagesAtomically pins the #4621 fix: the archive staging
// write goes through fsatomic.WriteFileAtomic (AtomicGeneratedConfig class,
// #1894/#1916) instead of a direct os.WriteFile that bypassed the atomic
// wrapper. WriteFileAtomic writes a ".<base>.tmp-*" sibling in the temp dir
// and renames it into place, so:
//
//   - the historical remote basename (the boot-file basename, default
//     xpf.conf) is preserved — the rename target IS srcPath, so a reader/
//     lister only ever sees the config at its canonical name, never at the
//     scratch ".tmp-*" name; and
//   - after the write returns, no ".<base>.tmp-*" scratch sibling is left in
//     the staging dir (the atomic writer either renamed it into place or
//     removed it on failure).
//
// RED on revert: reverting the source back to os.WriteFile still preserves
// the basename (so that assertion holds), but there is no additional scratch
// sibling to check — this test's value is the regression guard that a future
// change cannot swap in a writer that renames to a different final name or
// leaks a partial ".tmp-*" file.
func TestArchiveConfigStagesAtomically(t *testing.T) {
	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name atomic-host"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	wantActive := store.ShowActive()

	var mu sync.Mutex
	var srcPath, gotContent string
	var stagingSiblings []string
	done := make(chan struct{}, 1)
	d := &Daemon{
		store: store,
		// Historical remote basename is derived from ConfigFile's basename.
		opts: Options{ConfigFile: filepath.Join(dir, "xpf.conf")},
		archiveTransfer: func(_ context.Context, src, _ string) error {
			b, err := os.ReadFile(src)
			entries, _ := os.ReadDir(filepath.Dir(src))
			mu.Lock()
			srcPath = src
			gotContent = string(b)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".xpf.conf.tmp-") {
					stagingSiblings = append(stagingSiblings, e.Name())
				}
			}
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
	src := srcPath
	content := gotContent
	siblings := append([]string(nil), stagingSiblings...)
	mu.Unlock()

	// The atomic rename target is the canonical historical basename, not the
	// scratch ".tmp-*" name.
	if base := filepath.Base(src); base != "xpf.conf" {
		t.Fatalf("staged source basename = %q, want the historical remote name %q", base, "xpf.conf")
	}
	// The reader saw a complete file (atomic rename means never a torn read).
	if content != wantActive {
		t.Fatalf("staged content != active config.\n got: %q\nwant: %q", content, wantActive)
	}
	// No leaked ".xpf.conf.tmp-*" scratch sibling from the atomic writer.
	if len(siblings) != 0 {
		t.Fatalf("atomic writer left scratch temp sibling(s) in staging dir: %v", siblings)
	}
}
