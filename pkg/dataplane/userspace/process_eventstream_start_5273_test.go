package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestEnsureProcessLockedFailsBeforeHelperOnEventStreamBindError_5273 pins the
// production adapter around EventStream.Start. A bind failure must abort before
// cmd.Start and must not retain a dead stream or cancellation handle.
func TestEnsureProcessLockedFailsBeforeHelperOnEventStreamBindError_5273(t *testing.T) {
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	dir := t.TempDir()
	m := New()
	cfg := config.UserspaceConfig{
		Binary:        testBinary,
		ControlSocket: filepath.Join(dir, "run", "control.sock"),
		StateFile:     filepath.Join(dir, "state", "state.json"),
		EventSocket:   filepath.Join(dir, "missing-event-dir", "events.sock"),
	}

	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()
	if err == nil {
		t.Fatal("ensureProcessLocked() = nil, want event-stream bind error")
	}
	if !strings.Contains(err.Error(), "start userspace dataplane event stream listener") {
		t.Fatalf("ensureProcessLocked() error = %q, want event-stream startup context", err)
	}
	if m.proc != nil {
		t.Fatalf("helper process retained after pre-spawn failure: %+v", m.proc)
	}
	if m.eventStream != nil {
		t.Fatalf("event stream retained after bind failure: %+v", m.eventStream)
	}
	if m.eventStreamCancel != nil {
		t.Fatal("event-stream cancellation handle retained after bind failure")
	}
	if _, err := os.Stat(cfg.ControlSocket); !os.IsNotExist(err) {
		t.Fatalf("control socket exists after pre-spawn failure: err=%v", err)
	}
}
