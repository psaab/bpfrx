package upgrade

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
)

// fakeUpgradeLockState records acquire/release activity on the indirected
// upgrade-lock seam (acquireUpgradeLock) so tests can assert that mutating
// flows take the lock exactly once, release it, and that a forced-busy
// acquire aborts BEFORE any live mutation (#1965).
type fakeUpgradeLockState struct {
	acquires int32
	releases int32
	held     int32 // current held count (must never exceed 1)
	maxHeld  int32
	// busy, when set, makes the next acquire fail as if another holder
	// owns the lock.
	busy atomic.Bool
}

type fakeLockHandle struct {
	st *fakeUpgradeLockState
}

func (h *fakeLockHandle) Release() error {
	atomic.AddInt32(&h.st.releases, 1)
	atomic.AddInt32(&h.st.held, -1)
	return nil
}

// install swaps acquireUpgradeLock to this fake for the duration of the
// test and returns a restore func (registered via t.Cleanup).
func (st *fakeUpgradeLockState) install(t *testing.T) {
	t.Helper()
	prev := acquireUpgradeLock
	acquireUpgradeLock = func(subcommand, target string) (lockHandle, error) {
		if st.busy.Load() {
			atomic.AddInt32(&st.acquires, 1)
			return nil, fmt.Errorf("simulated busy: another upgrade holds the lock")
		}
		atomic.AddInt32(&st.acquires, 1)
		h := atomic.AddInt32(&st.held, 1)
		if h > atomic.LoadInt32(&st.maxHeld) {
			atomic.StoreInt32(&st.maxHeld, h)
		}
		return &fakeLockHandle{st: st}, nil
	}
	t.Cleanup(func() { acquireUpgradeLock = prev })
}

// TestMain installs a no-op upgrade-lock seam by DEFAULT for the whole
// package so the many existing tests that call r.Run(Options{}) /
// runRollingWith do NOT touch the real /run/xpf/upgrade.lock path. Tests
// that want to assert lock behavior install their own fakeUpgradeLockState.
func TestMain(m *testing.M) {
	acquireUpgradeLock = func(string, string) (lockHandle, error) {
		return noopLockHandle{}, nil
	}
	os.Exit(m.Run())
}

type noopLockHandle struct{}

func (noopLockHandle) Release() error { return nil }
