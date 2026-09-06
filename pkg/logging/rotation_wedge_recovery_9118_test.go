package logging

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func shortenReopenBackoff9118(t *testing.T) {
	t.Helper()
	old := reopenBackoff9118
	reopenBackoff9118 = time.Millisecond
	t.Cleanup(func() { reopenBackoff9118 = old })
}

// wedgeLocalWriter9118 puts a writer into the exact state a failed rotation
// reopen leaves it in: an open handle closed, and lw.file nil, with the writer
// NOT deliberately closed.
//
// It reproduces the state rather than injecting a fake, because the seam that
// would let a test fail openHardenedAuditLog is not exported and inventing one
// would make the cell a statement about the seam. What matters for the fix is
// the post-condition, and this is exactly it.
func wedgeLocalWriter9118(t *testing.T, lw *LocalLogWriter) {
	t.Helper()
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.file == nil {
		t.Fatal("writer was already nil; the fixture is not creating the wedge")
	}
	_ = lw.file.Close()
	lw.file = nil
}

// #9118: one transient error at a rotation boundary silenced the local audit
// channel indefinitely. rotate() nils the handle before reopening; every write
// path then took the nil arm; and rotate() is reached ONLY from `written >=
// maxSize`, which needs a successful write — so the only reopen in the file
// could never run again.
func TestWedgedLocalWriterRecoversOnTheNextWrite9118(t *testing.T) {
	shortenReopenBackoff9118(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	defer lw.Close()

	// REFERENCE ARM: an ordinary write works. Without it, "the write after the
	// wedge succeeded" could be true of a writer that was never functional.
	if err := lw.Send(6, "before the wedge"); err != nil {
		t.Fatalf("baseline write failed: %v", err)
	}

	wedgeLocalWriter9118(t, lw)

	if err := lw.Send(6, "after the wedge"); err != nil {
		t.Fatalf("a wedged writer did not recover: %v. One transient error at a "+
			"rotation boundary silences the audit channel until the next config "+
			"commit, and nothing else ever reopens the file", err)
	}
	if got := lw.RecoveredWrites(); got != 1 {
		t.Errorf("RecoveredWrites = %d, want 1 — an operator must be able to tell "+
			"'never broke' from 'broke and healed', and those look identical if "+
			"only the drop counter moves", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !containsAll9118(string(data), "after the wedge") {
		t.Errorf("the recovered write did not reach the file: %q", string(data))
	}
}

// A CLOSED writer must stay closed. Close() also nils the handle, so without an
// explicit flag the recovery path cannot tell a wedge from a retirement — and
// would recreate the audit file after shutdown, or resurrect a writer the
// daemon has just replaced on the ReplaceLocalWriters path.
func TestClosedLocalWriterIsNotResurrected9118(t *testing.T) {
	shortenReopenBackoff9118(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	if err := lw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if err := lw.Send(6, "after close"); err == nil {
		t.Error("a CLOSED writer accepted a write; the recovery path cannot tell a " +
			"deliberate close from a wedge")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a closed writer recreated its audit file; Close() must be final")
	}
	if got := lw.RecoveredWrites(); got != 0 {
		t.Errorf("RecoveredWrites = %d after Close, want 0", got)
	}
}

// The retry must be BACKED OFF. Under a durable failure — ENOSPC, EROFS — an
// unbounded retry turns every dropped line into an openat, so a full disk
// becomes a syscall storm on the logging path.
func TestWedgedWriterBacksOffItsReopen9118(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatalf("NewLocalLogWriter: %v", err)
	}
	defer lw.Close()
	// Full backoff, not the shortened one: this case is about the interval.
	wedgeLocalWriter9118(t, lw)

	// Make the reopen fail for real: replace the directory entry's parent with
	// a read-only directory so openat cannot create the file.
	// ORDER MATTERS: remove the file first, THEN make the directory
	// unwritable. Doing it the other way round leaves the remove itself
	// refused, and the case skips — asserting nothing while looking arranged.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove the log to force a create: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := lw.Send(6, "first attempt"); err == nil {
		t.Skip("the reopen unexpectedly succeeded (running as root?); the backoff " +
			"assertion needs a failing open")
	}
	first := lw.wedgeAttemptForTest9118()
	if err := lw.Send(6, "second attempt"); err == nil {
		t.Fatal("the second write succeeded after a failing reopen")
	}
	if second := lw.wedgeAttemptForTest9118(); !second.Equal(first) {
		t.Errorf("a second write within the backoff issued another reopen "+
			"(%v -> %v); under ENOSPC that is one openat per dropped line",
			first, second)
	}
}

func containsAll9118(h string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for i := 0; i+len(n) <= len(h); i++ {
			if h[i:i+len(n)] == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// The TRACE writer has the identical wedge — trace.go's rotate() also nils the
// handle before reopening, and WriteRecord also drops forever after. Covered
// separately rather than by inspection, because the two types open their files
// through different helpers (openTraceFile resolves under traceLogDir and takes
// a sanitized basename) and a fix that compiled for one could be inert for the
// other.
func TestWedgedTraceWriterRecoversOnTheNextWrite9118(t *testing.T) {
	shortenReopenBackoff9118(t)
	dir := t.TempDir()
	restore := SetTraceLogDirForTest(dir)
	defer restore()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{
		File: "trace.log", FileSize: 1 << 20, FileCount: 3,
		Flags: []string{"basic-datapath"},
	})
	if err != nil {
		t.Fatalf("NewTraceWriter: %v", err)
	}
	defer tw.Close()

	rec := EventRecord{Type: "SESSION_CREATE"}

	// REFERENCE ARM: an ordinary record reaches the file.
	tw.HandleEvent(rec, nil)
	// #9025: HandleEvent enqueues; drain before asserting on the file/counters.
	tw.SyncForTest()
	before, err := os.ReadFile(filepath.Join(dir, "trace.log"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(before) == 0 {
		t.Fatal("the baseline record wrote nothing; the fixture measures nothing")
	}

	tw.mu.Lock()
	_ = tw.file.Close()
	tw.file = nil
	tw.mu.Unlock()

	tw.HandleEvent(rec, nil)
	// #9025: HandleEvent enqueues; drain before asserting on the file/counters.
	tw.SyncForTest()
	if got := tw.RecoveredWrites(); got != 1 {
		t.Fatalf("RecoveredWrites = %d, want 1: the trace writer stayed wedged, so "+
			"`traceoptions` is silent until the next config commit", got)
	}
	after, err := os.ReadFile(filepath.Join(dir, "trace.log"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(after) <= len(before) {
		t.Errorf("the recovered record did not reach the file (%d -> %d bytes)",
			len(before), len(after))
	}
}
