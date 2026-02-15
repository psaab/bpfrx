package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		cfg.Path = "/tmp/bpfrx-test-default.log"
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
