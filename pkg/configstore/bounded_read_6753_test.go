package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReadBoundedConfigFileRejectsOversizeWithoutMaterialising_6753 is the
// allocation half of #6753. The store's ceiling was previously enforced by
// checkConfigSize on an ALREADY-MATERIALISED string, so an over-cap file was
// read in full and only then refused.
func TestReadBoundedConfigFileRejectsOversizeWithoutMaterialising_6753(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.conf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// One byte past the ceiling is the smallest input that must be refused.
	if err := f.Truncate(MaxConfigSize + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	data, err := ReadBoundedConfigFile(path)
	if err == nil {
		t.Fatalf("an over-cap file must be refused; got %d bytes and nil error", len(data))
	}
	if data != nil {
		t.Fatalf("a refused read must yield no payload, got %d bytes", len(data))
	}
	// #7469: structural, not substring. This assertion previously matched the
	// word "limit", which couples the verdict to wording maintained elsewhere.
	if !errors.Is(err, ErrExceedsLimit) {
		t.Fatalf("an over-cap refusal must wrap ErrExceedsLimit, got %q", err)
	}
}

// A file exactly AT the ceiling is legal and must still be returned whole —
// the positive control. Without it a reader that refused everything would
// satisfy the test above.
func TestReadBoundedConfigFileAcceptsExactlyAtTheCeiling_6753(t *testing.T) {
	path := filepath.Join(t.TempDir(), "atmax.conf")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(MaxConfigSize); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	data, err := ReadBoundedConfigFile(path)
	if err != nil {
		t.Fatalf("a file exactly at the ceiling must be accepted, got %v", err)
	}
	if int64(len(data)) != MaxConfigSize {
		t.Fatalf("want %d bytes, got %d", int64(MaxConfigSize), len(data))
	}
}

// TestReadBoundedConfigFileDoesNotBlockOnAFIFO_6753 is the "or blocks" half of
// #6753, and it is a different defect from the size cap: opening a FIFO for
// reading BLOCKS until a writer appears, so the process hangs before any size
// check can run. A size-only fix leaves this untouched. The test asserts the
// call RETURNS — a regression hangs rather than failing, so it runs on its own
// goroutine behind a deadline.
func TestReadBoundedConfigFileDoesNotBlockOnAFIFO_6753(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo.conf")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	// No writer is ever opened, which is exactly the hanging case.
	done := make(chan error, 1)
	go func() {
		_, err := ReadBoundedConfigFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO is not a regular file and must be refused")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("want a not-a-regular-file refusal, got %q", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReadBoundedConfigFile BLOCKED on a writerless FIFO — the open must not wait for a writer (#6753)")
	}
}
