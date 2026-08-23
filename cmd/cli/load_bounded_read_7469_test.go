package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// The remote CLI surface had no wiring test when #6753 landed — only the local
// one in pkg/cli did. #7469: that asymmetry is exactly the shape #4883-D
// records, where the local and remote CLI diverged and the divergence itself
// produced the bug. The shared reader was unified; the error handling around it
// was not, and `cmd/cli` flattened the chain with %v so an errors.Is assertion
// would have succeeded locally and silently failed here.
//
// `package main` tests are established practice in this repo — cmd/xpfd's own
// check_config_bounded_4909_test.go, which this path delegates through, is one.
func TestCtlHandleLoadBoundsTheReadItself_7469(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.conf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(configstore.MaxConfigSize + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	c := &ctl{}
	err = c.handleLoad([]string{"override", path})
	if err == nil {
		t.Fatal("the remote CLI must refuse a file past MaxConfigSize at the READ (#6753)")
	}
	// Structural, not substring — and this is the assertion that fails if the
	// %v regresses, because %v flattens the chain errors.Is walks.
	if !errors.Is(err, configstore.ErrExceedsLimit) {
		t.Fatalf("the refusal must be identifiable via errors.Is(ErrExceedsLimit); "+
			"a %%v wrap here flattens the chain and breaks it. got %q", err)
	}
}

// The remote surface must not hang on a writerless FIFO either. A regression
// HANGS rather than failing, hence the deadline.
func TestCtlHandleLoadDoesNotBlockOnAFIFO_7469(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo.conf")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		c := &ctl{}
		done <- c.handleLoad([]string{"override", path})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO must be refused by the remote load path")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the remote handleLoad BLOCKED on a writerless FIFO (#6753/#7469)")
	}
}
