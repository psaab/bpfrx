package lock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lockPath returns a short tmpdir lock path. We deliberately avoid /dev/shm
// TMPDIR collisions; t.TempDir() is process-scoped and cleaned per test.
func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "upgrade.lock")
}

func TestAcquireAndRelease(t *testing.T) {
	p := lockPath(t)
	h, err := AcquireAt(p, "upgrade", "1.2.3")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// The lock file must carry the owner metadata.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	if !strings.Contains(string(data), `"subcommand": "upgrade"`) ||
		!strings.Contains(string(data), `"target": "1.2.3"`) {
		t.Fatalf("owner metadata missing/incorrect: %s", data)
	}

	if err := h.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Release is idempotent.
	if err := h.Release(); err != nil {
		t.Fatalf("second release should be a no-op: %v", err)
	}

	// After release the lock is reacquirable.
	h2, err := AcquireAt(p, "upgrade", "1.2.4")
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	_ = h2.Release()
}

func TestSecondAcquireIsBusy(t *testing.T) {
	p := lockPath(t)
	h, err := AcquireAt(p, "upgrade --rolling", "2.0.0")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer h.Release()

	// flock is tied to the open file description; a second open()+flock()
	// on the SAME path from the SAME process still returns EWOULDBLOCK.
	_, err = AcquireAt(p, "upgrade", "2.0.1")
	if err == nil {
		t.Fatal("second acquire should fail while the lock is held")
	}
	if !IsBusy(err) {
		t.Fatalf("second acquire should be ErrBusy, got %T: %v", err, err)
	}
	// The busy error must NAME the owner, not just say "busy".
	if !strings.Contains(err.Error(), "rolling") || !strings.Contains(err.Error(), "2.0.0") {
		t.Fatalf("busy error should name the owner subcommand/target: %v", err)
	}
}

func TestReleaseOnPanicViaDefer(t *testing.T) {
	p := lockPath(t)

	func() {
		defer func() {
			_ = recover()
		}()
		h, err := AcquireAt(p, "upgrade", "panic-test")
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		defer h.Release() // must run on panic unwind
		panic("boom")
	}()

	// After the panic unwound through the deferred Release, the lock is
	// reacquirable.
	h, err := AcquireAt(p, "upgrade", "after-panic")
	if err != nil {
		t.Fatalf("lock not released after panic: %v", err)
	}
	_ = h.Release()
}

func TestReleaseOnErrorPath(t *testing.T) {
	p := lockPath(t)

	// Simulate a mutator that acquires, hits an error, and returns through
	// a deferred Release.
	run := func() (err error) {
		h, aerr := AcquireAt(p, "upgrade", "err-test")
		if aerr != nil {
			return aerr
		}
		defer h.Release()
		return os.ErrInvalid // simulated downstream error
	}
	if err := run(); err == nil {
		t.Fatal("expected the simulated error to propagate")
	}
	// Lock must be free now.
	h, err := AcquireAt(p, "upgrade", "after-err")
	if err != nil {
		t.Fatalf("lock not released after error path: %v", err)
	}
	_ = h.Release()
}

// TestReleaseOnProcessExit proves the kernel drops the flock when the
// holding PROCESS exits even without an explicit Release — the crash
// backstop. A child process acquires the lock and exits; the parent then
// acquires it.
func TestReleaseOnProcessExit(t *testing.T) {
	if os.Getenv("XPF_LOCK_CHILD") == "1" {
		// Child: acquire and exit immediately WITHOUT releasing.
		p := os.Getenv("XPF_LOCK_PATH")
		if _, err := AcquireAt(p, "upgrade", "child"); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}

	p := lockPath(t)
	cmd := exec.Command(os.Args[0], "-test.run", "TestReleaseOnProcessExit")
	cmd.Env = append(os.Environ(), "XPF_LOCK_CHILD=1", "XPF_LOCK_PATH="+p)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed to acquire/exit: %v\n%s", err, out)
	}

	// Child has exited; the kernel released its flock. We can acquire.
	deadline := time.Now().Add(2 * time.Second)
	for {
		h, err := AcquireAt(p, "upgrade", "parent")
		if err == nil {
			_ = h.Release()
			return
		}
		if !IsBusy(err) {
			t.Fatalf("unexpected acquire error: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock not released after child exit within deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMetadataWriteFailureStillHoldsLock proves the best-effort contract
// (Codex MAJOR #1): when recording owner metadata fails, Acquire must STILL
// return a held lock with a NIL error, because callers treat a non-nil
// Acquire error as "lock not held" and return WITHOUT deferring Release — a
// (held handle, non-nil error) pair would leak the fd until process exit.
func TestMetadataWriteFailureStillHoldsLock(t *testing.T) {
	p := lockPath(t)

	prev := writeOwnerFn
	writeOwnerFn = func(*os.File, Owner) error {
		return os.ErrInvalid // force the metadata write to fail
	}
	t.Cleanup(func() { writeOwnerFn = prev })

	h, err := AcquireAt(p, "upgrade", "meta-fail")
	if err != nil {
		t.Fatalf("metadata-write failure must NOT fail Acquire (would tempt callers to leak the held fd); got err=%v", err)
	}
	if h == nil {
		t.Fatal("Acquire returned a nil handle on a successful flock")
	}

	// The lock must genuinely be held: a second acquire is busy. Restore the
	// real writer first so the busy probe behaves normally.
	writeOwnerFn = prev
	if _, err2 := AcquireAt(p, "upgrade", "second"); !IsBusy(err2) {
		t.Fatalf("lock not actually held after a metadata-write failure; second acquire err=%v", err2)
	}

	// Releasing the held handle frees the lock.
	if rerr := h.Release(); rerr != nil {
		t.Fatalf("release: %v", rerr)
	}
	h2, err := AcquireAt(p, "upgrade", "after-release")
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	_ = h2.Release()
}

// staleOwnerJSON is a plausible previous-owner record used to seed the lock
// file in the stale-read regression tests. It mimics what a crashed holder
// (kernel-released flock, file never truncated) leaves behind.
const staleOwnerJSON = `{
  "pid": 424242,
  "subcommand": "upgrade --rolling",
  "target": "9.9.9-stale",
  "started_at": "2000-01-01T00:00:00Z"
}`

// TestReleaseTruncatesUnderLock proves Release zeroes the lock file BEFORE
// dropping the flock (#1984). After a normal acquire+release the file must be
// empty so the NEXT acquirer's busy readers never name the just-released
// owner. This test FAILS if the release-time Truncate(0) is removed — the
// file would still hold the released owner's JSON.
func TestReleaseTruncatesUnderLock(t *testing.T) {
	p := lockPath(t)

	h, err := AcquireAt(p, "upgrade", "1.0.0")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Sanity: while held, the file carries this owner's metadata.
	if data, rerr := os.ReadFile(p); rerr != nil || len(data) == 0 {
		t.Fatalf("held lock file should carry owner metadata; len=%d err=%v", len(data), rerr)
	}

	if rerr := h.Release(); rerr != nil {
		t.Fatalf("release: %v", rerr)
	}

	// The released file must be empty (the inode is kept; only contents are
	// cleared). os.Remove is intentionally NOT used, so the file still exists.
	data, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("lock file should still exist after release (os.Remove must NOT be used): %v", rerr)
	}
	if len(data) != 0 {
		t.Fatalf("release must truncate the lock file under the flock; file still holds %d bytes: %q", len(data), data)
	}

	// Cross-check the diagnostic consequence: a fresh busy reader sees no
	// owner. Hold the lock again and probe it from a second acquire.
	h2, err := AcquireAt(p, "upgrade", "2.0.0")
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	defer h2.Release()
	// h2 has written its OWN metadata by now, so a busy probe names h2 — that
	// is correct (current holder), not the released owner. Confirm it never
	// names the released "1.0.0".
	_, berr := AcquireAt(p, "upgrade", "3.0.0")
	if !IsBusy(berr) {
		t.Fatalf("expected busy, got %v", berr)
	}
	if strings.Contains(berr.Error(), "1.0.0") {
		t.Fatalf("busy error named the RELEASED owner instead of the current holder: %v", berr)
	}
}

// TestAcquireTruncatesStaleMetadataBeforeWrite proves the acquire-time
// Truncate(0) (#1984): a NEW holder zeroes the file the instant it holds the
// flock, BEFORE recording its own metadata, so a concurrent busy reader in
// the acquire->write window never reads a PREVIOUS owner's JSON.
//
// The file is seeded directly with stale JSON (simulating a crashed holder
// whose flock the kernel released but whose metadata was never cleared — the
// case the release-truncate cannot cover). A blocking writeOwnerFn seam pins
// the new holder between the acquire-truncate and the metadata write while a
// second acquire probes the file.
//
// This test FAILS if the acquire-time Truncate(0) is removed: the seeded
// stale owner would still be in the file when the probe reads it, so ErrBusy
// would name pid=424242 / "9.9.9-stale".
func TestAcquireTruncatesStaleMetadataBeforeWrite(t *testing.T) {
	p := lockPath(t)

	// Seed stale metadata as if a crashed prior holder left it. Create the
	// file with no flock held so the new holder below can acquire it.
	if err := os.WriteFile(p, []byte(staleOwnerJSON), 0o644); err != nil {
		t.Fatalf("seed stale metadata: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	prev := writeOwnerFn
	writeOwnerFn = func(f *os.File, o Owner) error {
		// We are now PAST the acquire-truncate and the flock is held. Signal
		// the probe, then block before writing this holder's metadata so the
		// probe observes the acquire->write window.
		close(entered)
		<-release
		return prev(f, o)
	}
	t.Cleanup(func() { writeOwnerFn = prev })

	acquired := make(chan *Handle, 1)
	acqErr := make(chan error, 1)
	go func() {
		h, err := AcquireAt(p, "upgrade", "new-holder")
		if err != nil {
			acqErr <- err
			return
		}
		acquired <- h
	}()

	select {
	case <-entered:
	case err := <-acqErr:
		t.Fatalf("new holder failed to acquire: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the new holder to enter writeOwner")
	}

	// The new holder now HOLDS the flock and has run the acquire-truncate but
	// has NOT yet written its metadata. Probe it: ErrBusy with a NIL owner.
	_, berr := AcquireAt(p, "upgrade", "probe")
	if !IsBusy(berr) {
		t.Fatalf("expected ErrBusy during acquire->write window, got %T: %v", berr, berr)
	}
	var be *ErrBusy
	if !errors.As(berr, &be) {
		t.Fatalf("expected *ErrBusy, got %T: %v", berr, berr)
	}
	if be.Owner != nil {
		t.Fatalf("busy read in the acquire->write window must NOT name an owner; got %s", be.Owner.String())
	}
	// Specifically: it must never report the seeded stale owner.
	if strings.Contains(berr.Error(), "424242") || strings.Contains(berr.Error(), "9.9.9-stale") {
		t.Fatalf("acquire-truncate failed: busy read named the STALE previous owner: %v", berr)
	}

	// Let the new holder finish writing its metadata, then confirm a busy
	// read now correctly names IT.
	close(release)
	select {
	case h := <-acquired:
		defer h.Release()
	case err := <-acqErr:
		t.Fatalf("new holder acquire returned error after unblock: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the new holder to finish acquiring")
	}
	_, berr2 := AcquireAt(p, "upgrade", "probe2")
	if !IsBusy(berr2) {
		t.Fatalf("expected busy after metadata written, got %v", berr2)
	}
	if !strings.Contains(berr2.Error(), "new-holder") {
		t.Fatalf("busy error should now name the new holder; got %v", berr2)
	}
}

// TestAcquireClearsStaleMetadataOnWriteFailure proves window 2 (#1984): when
// the metadata write fails AFTER the acquire-truncate, the file is left EMPTY
// (already cleared by the acquire-truncate) rather than holding the previous
// owner's JSON. A busy read therefore degrades to "owner unknown", never the
// stale owner.
//
// This test FAILS if the acquire-time Truncate(0) is removed: with a failing
// writeOwnerFn the seeded stale JSON would survive and a busy read would name
// it.
func TestAcquireClearsStaleMetadataOnWriteFailure(t *testing.T) {
	p := lockPath(t)

	if err := os.WriteFile(p, []byte(staleOwnerJSON), 0o644); err != nil {
		t.Fatalf("seed stale metadata: %v", err)
	}

	prev := writeOwnerFn
	writeOwnerFn = func(*os.File, Owner) error {
		return os.ErrInvalid // fail the metadata write AFTER acquire-truncate
	}
	t.Cleanup(func() { writeOwnerFn = prev })

	h, err := AcquireAt(p, "upgrade", "write-fails")
	if err != nil {
		// Best-effort contract: a metadata-write failure must NOT fail Acquire.
		t.Fatalf("metadata-write failure must not fail Acquire: %v", err)
	}
	defer h.Release()

	// The on-disk file must be empty: the acquire-truncate cleared the stale
	// JSON and the failed write left nothing behind.
	data, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("read lock file: %v", rerr)
	}
	if len(data) != 0 {
		t.Fatalf("acquire-truncate should have cleared stale metadata before the failed write; file holds %d bytes: %q", len(data), data)
	}

	// Restore the real writer so the busy probe behaves normally, then confirm
	// a busy read reports owner-unknown, NOT the seeded stale owner.
	writeOwnerFn = prev
	_, berr := AcquireAt(p, "upgrade", "probe")
	if !IsBusy(berr) {
		t.Fatalf("expected busy, got %v", berr)
	}
	if strings.Contains(berr.Error(), "424242") || strings.Contains(berr.Error(), "9.9.9-stale") {
		t.Fatalf("write-failure path leaked the stale owner into the busy error: %v", berr)
	}
	var be *ErrBusy
	if errors.As(berr, &be) && be.Owner != nil {
		t.Fatalf("busy read after a swallowed write failure must report owner-unknown; got %s", be.Owner.String())
	}
}

func TestMkdirCreatesRunDir(t *testing.T) {
	// Point at a nested non-existent dir; Acquire must mkdir -p it.
	p := filepath.Join(t.TempDir(), "xpf", "nested", "upgrade.lock")
	h, err := AcquireAt(p, "upgrade", "mkdir")
	if err != nil {
		t.Fatalf("acquire should create the parent dir: %v", err)
	}
	defer h.Release()
	if _, err := os.Stat(filepath.Dir(p)); err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
}
