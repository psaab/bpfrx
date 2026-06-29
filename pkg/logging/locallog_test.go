package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalLogWriter_HardenedOpen pins the #3477 hardening: the active
// security-log file is created mode 0600 (not world-readable 0644) and a
// symlink pre-planted at the path is refused (O_NOFOLLOW) rather than followed.
//
// RED-on-revert: restore the old
// `os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)` in
// NewLocalLogWriter and the mode sub-test fails (perm 0644) and the symlink
// sub-test fails (the raw open follows the link and creates the victim).
func TestLocalLogWriter_HardenedOpen(t *testing.T) {
	t.Run("mode-0600", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "security.log")
		lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		defer lw.Close()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("security-log mode = %o, want 0600 (world-readable audit data leak)", perm)
		}
	})

	t.Run("nofollow-symlink", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "security.log")
		target := filepath.Join(t.TempDir(), "victim")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
		if err == nil {
			if lw != nil {
				lw.Close()
			}
			t.Fatalf("NewLocalLogWriter opened through a symlink, want O_NOFOLLOW rejection")
		}
		if _, statErr := os.Stat(target); statErr == nil {
			t.Fatalf("symlink target %s was created (followed)", target)
		}
	})
}

// TestLocalLogWriter_WriteFailureObservable pins #3478: a write that fails
// increments DroppedWrites so an operator can detect lost audit lines.
//
// RED-on-revert: remove the `lw.droppedWrites.Add(1)` in Send and the counter
// stays 0.
func TestLocalLogWriter_WriteFailureObservable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	// Close the underlying fd out from under the writer so the next write
	// fails with EBADF while lw.file is still non-nil.
	if err := lw.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lw.Send(SyslogInfo, "after fd close"); err == nil {
		t.Fatal("expected Send to fail on a closed descriptor")
	}
	if got := lw.DroppedWrites(); got != 1 {
		t.Fatalf("DroppedWrites = %d, want 1 (write failure not observable)", got)
	}
}

// TestLocalLogWriter_RotationFailureObservable pins #3478 M03 + item 6: a
// rotation whose primary rename cannot complete (a) returns a non-nil error,
// (b) bumps FailedRotations, and (c) re-syncs `written` to the real file size
// rather than resetting it to a bogus 0. Calling rotate() directly pins all
// three invariants (a Send-only test cannot see the returned error or assert
// written).
//
// RED-on-revert: make rotate() ignore the rename result and unconditionally set
// written=0 / return nil (the pre-fix behavior) — the error-return, the
// written==realSize, and the FailedRotations assertions all fail.
func TestLocalLogWriter_RotationFailureObservable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	// MaxFiles=1 so the generation-shift loop does not run and cannot move our
	// blocking directory aside before the primary rename.
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path, MaxSize: 40, MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()

	// Seed real content so the post-failed-rotation re-stat sees a nonzero size.
	if _, err := lw.file.WriteString("0123456789012345678901234567890123456789\n"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	realSize := fi.Size()
	lw.written = 999 // deliberately wrong to prove rotate() re-syncs to real size

	// Pre-create a non-empty DIRECTORY at the archive path so
	// os.Rename(path, path+".1") fails.
	archive := path + ".1"
	if err := os.Mkdir(archive, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if rerr := lw.rotate(); rerr == nil {
		t.Fatal("rotate() returned nil on a failed primary rename, want a non-nil error")
	}
	if got := lw.FailedRotations(); got == 0 {
		t.Fatalf("FailedRotations = 0, want >=1 (failed rename not observable)")
	}
	if lw.written != realSize {
		t.Fatalf("written = %d after a failed rotation, want re-synced to real size %d (not a bogus 0/stale value)", lw.written, realSize)
	}
}

// TestLocalLogWriter_GenerationShiftFailureObservable pins #3478 item 2: when a
// retained generation cannot be shifted (old->next rename fails) but the
// active-file rotation itself succeeds, the failure is still counted in
// FailedRotations and surfaced as a non-nil rotate() error.
//
// RED-on-revert: drop the failedRotations.Add(1)+shiftErr in the shift loop and
// both assertions fail (the active rotation succeeds, masking the lost
// generation).
func TestLocalLogWriter_GenerationShiftFailureObservable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	// MaxFiles=2 so the shift loop runs once: rename path.1 -> path.2.
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()

	// A regular .1 so the shift attempts rename(.1 -> .2); a non-empty .2
	// directory so that shift rename fails while the primary rename
	// (path -> path.1, replacing the regular .1) still succeeds.
	if err := os.WriteFile(path+".1", []byte("gen1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".2", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".2", "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rerr := lw.rotate()
	if rerr == nil {
		t.Fatal("rotate() returned nil despite a failed generation shift, want a non-nil error")
	}
	if got := lw.FailedRotations(); got == 0 {
		t.Fatalf("FailedRotations = 0, want >=1 (generation-shift failure not observable)")
	}
}

// TestLocalLogWriter_NilFileDropObservable pins #3478 item 1/4: a write to a
// writer whose file handle is nil (here via Close, the same state a failed
// rotation reopen leaves) increments DroppedWrites rather than returning
// silently.
//
// RED-on-revert: restore the bare `return fmt.Errorf("log file closed")`
// without the droppedWrites.Add(1) and the counter stays 0.
func TestLocalLogWriter_NilFileDropObservable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	lw.Close() // file = nil

	if err := lw.Send(SyslogInfo, "dropped"); err == nil {
		t.Fatal("expected Send to fail on a nil file")
	}
	if err := lw.SendBinary([]byte("dropped")); err == nil {
		t.Fatal("expected SendBinary to fail on a nil file")
	}
	if got := lw.DroppedWrites(); got != 2 {
		t.Fatalf("DroppedWrites = %d, want 2 (nil-file drops not observable)", got)
	}
}

// TestLocalLogWriter_TightensExistingMode pins #3477 item 3: opening an
// existing world-readable (0644) security log tightens it to 0600 — the
// create-time mode is a no-op for an already-present file, so a pre-hardening
// upgrade would otherwise leave it world-readable.
//
// RED-on-revert: remove the fchmod-on-existing block in openHardenedAuditLog
// and the mode stays 0644.
func TestLocalLogWriter_TightensExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	if err := os.WriteFile(path, []byte("legacy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Defeat umask so the pre-existing file is genuinely 0644.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("existing security-log mode = %o after open, want tightened to 0600", perm)
	}
}

func TestLocalLogWriter_Send(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path, MaxSize: 1024, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()

	if err := lw.Send(SyslogInfo, "hello world"); err != nil {
		t.Fatal(err)
	}
	if err := lw.Send(SyslogWarning, "warning msg"); err != nil {
		t.Fatal(err)
	}
	if err := lw.Send(SyslogError, "error msg"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "[INFO] hello world") {
		t.Errorf("missing INFO line in %q", content)
	}
	if !strings.Contains(content, "[WARNING] warning msg") {
		t.Errorf("missing WARNING line in %q", content)
	}
	if !strings.Contains(content, "[ERROR] error msg") {
		t.Errorf("missing ERROR line in %q", content)
	}

	// Verify each line has a timestamp
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for _, line := range lines {
		// Format: "2006-01-02T15:04:05.000 [SEV] msg"
		if len(line) < 24 {
			t.Errorf("line too short: %q", line)
		}
	}
}

func TestLocalLogWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Small maxSize to trigger rotation quickly
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path, MaxSize: 50, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer lw.Close()

	// Write enough to trigger at least one rotation
	for i := 0; i < 10; i++ {
		lw.Send(SyslogInfo, "rotation test message")
	}

	// Check that rotated file exists
	if _, err := os.Stat(path + ".1"); os.IsNotExist(err) {
		t.Error("expected rotated file .1 to exist")
	}
	// Current file should exist and be small
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 200 {
		t.Errorf("current file should be small after rotation, got %d bytes", info.Size())
	}
}

func TestLocalLogWriter_ShouldSendEvent(t *testing.T) {
	lw := &LocalLogWriter{MinSeverity: SyslogWarning, Categories: CategorySession}

	// Severity filter: error passes, info blocked
	if !lw.ShouldSendEvent(SyslogError, CategorySession) {
		t.Error("error severity should pass")
	}
	if lw.ShouldSendEvent(SyslogInfo, CategorySession) {
		t.Error("info severity should be blocked by warning filter")
	}
	// Category filter: session passes, screen blocked
	if lw.ShouldSendEvent(SyslogWarning, CategoryScreen) {
		t.Error("screen category should be blocked")
	}

	// No filter = pass all
	lw2 := &LocalLogWriter{}
	if !lw2.ShouldSendEvent(SyslogInfo, CategoryScreen) {
		t.Error("no filter should pass all")
	}
}

func TestLocalLogWriter_DefaultPath(t *testing.T) {
	// Verify defaults are applied (we can't actually write to /var/log in tests,
	// so just verify the config logic)
	cfg := LocalLogConfig{}
	if cfg.Path == "" {
		cfg.Path = "/tmp/xpf-test-default.log"
	}
	lw, err := NewLocalLogWriter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lw.Close()
	os.Remove(cfg.Path)
}

func TestLocalLogWriter_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	// Close twice should not panic
	lw.Close()
	if err := lw.Close(); err != nil {
		t.Errorf("second close should return nil, got %v", err)
	}
}

func TestLocalLogWriter_SendAfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	lw.Close()

	err = lw.Send(SyslogInfo, "should fail")
	if err == nil {
		t.Error("expected error writing to closed file")
	}
}
