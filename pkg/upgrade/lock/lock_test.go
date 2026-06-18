package lock

import (
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
