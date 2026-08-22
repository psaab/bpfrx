package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestHandleLoadBoundsTheReadItself_6753 binds the WIRING, not the helper.
//
// configstore.ReadBoundedConfigFile has its own tests; they stay green even if
// this call site is left on os.ReadFile, because they never execute the CLI.
// The defect #6753 describes is that the LOAD PATH reads unbounded, so the
// assertion has to run through handleLoad.
func TestHandleLoadBoundsTheReadItself_6753(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.conf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(configstore.MaxConfigSize + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	c := &CLI{}
	err = c.handleLoad([]string{"override", path})
	if err == nil {
		t.Fatal("handleLoad must refuse a file past MaxConfigSize at the READ, not after materialising it (#6753)")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("the refusal must come from the bounded read and name the limit, got %q", err)
	}
}

// A normal, small config must still load — the positive control. Without it a
// load path that refused every file would satisfy the test above.
func TestHandleLoadStillAcceptsANormalFile_6753(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.conf")
	if err := os.WriteFile(path, []byte("system {\n    host-name xpf;\n}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A real store is required: this file gets PAST the read, which is the
	// point of the control, and the load then reaches the store.
	st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	c := New(st, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err := c.handleLoad([]string{"override", path}); err != nil &&
		strings.Contains(err.Error(), "limit") {
		t.Fatalf("a normal config must not be refused by the size bound, got %q", err)
	}
}

// The "or blocks" half, through the CLI. A writerless FIFO must not hang the
// load path. A regression HANGS rather than failing, hence the deadline.
func TestHandleLoadDoesNotBlockOnAFIFO_6753(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo.conf")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		c := &CLI{}
		done <- c.handleLoad([]string{"override", path})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO must be refused by the load path")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handleLoad BLOCKED on a writerless FIFO (#6753)")
	}
}
