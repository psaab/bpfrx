package upgrade

import (
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestRun_TakesAndReleasesLock proves the standalone cut acquires the
// host-wide upgrade lock exactly once and releases it on normal exit
// (#1965).
func TestRun_TakesAndReleasesLock(t *testing.T) {
	st := &fakeUpgradeLockState{}
	st.install(t)

	fs := newFakeSystem(t, "2.0.0")
	r, _ := testEnv(t, fs)

	if err := r.Run(Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := atomic.LoadInt32(&st.acquires); got != 1 {
		t.Fatalf("expected exactly 1 acquire, got %d", got)
	}
	if got := atomic.LoadInt32(&st.releases); got != 1 {
		t.Fatalf("expected exactly 1 release, got %d", got)
	}
	if got := atomic.LoadInt32(&st.held); got != 0 {
		t.Fatalf("lock still held after Run: held=%d", got)
	}
}

// TestRun_BusyLockAbortsBeforeAnyMutation proves a busy lock aborts the
// cut BEFORE any live mutation: no StopUnit, no flip, no verify, and no
// journal file written. This is the core #1965 guarantee — the second
// concurrent mutator exits before touching journal/symlink/systemd state.
func TestRun_BusyLockAbortsBeforeAnyMutation(t *testing.T) {
	st := &fakeUpgradeLockState{}
	st.busy.Store(true)
	st.install(t)

	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)

	err := r.Run(Options{})
	if err == nil {
		t.Fatal("expected Run to fail while the lock is busy")
	}

	// No System calls at all — the lock is taken before loadJournal and
	// before reading the staged version.
	if len(fs.calls) != 0 {
		t.Fatalf("busy lock must abort before any System mutation; calls=%v", fs.calls)
	}
	// No journal written.
	if _, statErr := os.Stat(cfg.JournalPath); statErr == nil {
		t.Fatalf("busy lock must abort before writing the journal at %s", cfg.JournalPath)
	}
	// The unit must still be running (we never stopped it).
	if !fs.unitRunning {
		t.Fatal("busy lock must not stop the unit")
	}
	// The (failed) acquire was attempted; no release of a lock we never held.
	if got := atomic.LoadInt32(&st.releases); got != 0 {
		t.Fatalf("busy path must not release a lock it never held; releases=%d", got)
	}
}

// TestRun_ReleasesLockOnError proves the lock is released even when the cut
// fails AFTER acquiring (deferred Release on the error path).
func TestRun_ReleasesLockOnError(t *testing.T) {
	st := &fakeUpgradeLockState{}
	st.install(t)

	fs := newFakeSystem(t, "2.0.0")
	fs.verifyErr = os.ErrInvalid // force a failure in the VERIFY phase
	r, _ := testEnv(t, fs)

	if err := r.Run(Options{}); err == nil {
		t.Fatal("expected Run to fail at verify")
	}
	if got := atomic.LoadInt32(&st.releases); got != 1 {
		t.Fatalf("lock must be released on the error path; releases=%d", got)
	}
	if got := atomic.LoadInt32(&st.held); got != 0 {
		t.Fatalf("lock still held after failed Run; held=%d", got)
	}
}

// TestRolling_HoldsLockAcrossDrainAndInnerCutDoesNotReacquire proves the
// rolling driver takes the lock ONCE at entry, holds it across the whole
// window (peer-check + drain + cut + rejoin), the inner r.Run() does NOT
// re-acquire (no EWOULDBLOCK self-deadlock), and the lock is released once
// at the end. The held count never exceeds 1 (#1965, plan §5).
func TestRolling_HoldsLockAcrossDrainAndInnerCutDoesNotReacquire(t *testing.T) {
	st := &fakeUpgradeLockState{}
	st.install(t)

	fs := newFakeSystem(t, "2.0.0")
	r, cfg := testEnv(t, fs)

	cl := &fakeCluster{
		peerAlive:  true,
		synced:     true,
		compatible: true,
		peerReady:  true,
		drainAfter: 1,
		localPri:   false,
	}

	// Drive the full rolling path with the lock held by RunRolling. We call
	// RunRolling (the lock acquirer) and inject the fake cluster via the
	// runRollingWith core through a thin shim: RunRolling builds its own
	// CLICluster, so instead we replicate RunRolling's acquire+inner-core
	// here to exercise the SAME lock contract with the injected cluster.
	err := runRollingWithLock(t, r, cfg, cl)
	if err != nil {
		t.Fatalf("rolling: %v", err)
	}

	if got := atomic.LoadInt32(&st.acquires); got != 1 {
		t.Fatalf("rolling must acquire the lock exactly once (inner cut must NOT re-acquire); acquires=%d", got)
	}
	if got := atomic.LoadInt32(&st.maxHeld); got > 1 {
		t.Fatalf("lock held count exceeded 1 (inner cut re-acquired — EWOULDBLOCK risk); maxHeld=%d", got)
	}
	if got := atomic.LoadInt32(&st.releases); got != 1 {
		t.Fatalf("rolling must release the lock exactly once; releases=%d", got)
	}
	if got := atomic.LoadInt32(&st.held); got != 0 {
		t.Fatalf("lock still held after rolling; held=%d", got)
	}
	// The cut actually happened (the inner r.Run ran).
	if !cl.forced || !cl.resetCalled {
		t.Fatalf("rolling did not run the full path: forced=%v reset=%v", cl.forced, cl.resetCalled)
	}
}

// runRollingWithLock mirrors RunRolling's lock contract (acquire at entry,
// hold through the injected-cluster core, release on return) so the test
// can inject a fakeCluster while still exercising the real acquire +
// LockAlreadyHeld inner-cut path. This is the same two-line wrapper as the
// production RunRolling, minus the NewCLICluster construction.
func runRollingWithLock(t *testing.T, r *Runner, _ Config, cl RollingCluster) (err error) {
	t.Helper()
	h, lerr := acquireUpgradeLock("upgrade --rolling", "")
	if lerr != nil {
		return lerr
	}
	defer func() { _ = h.Release() }()
	return runRollingWith(r, cl, RollingConfig{
		DrainDeadline:  time.Second,
		RejoinDeadline: time.Second,
		PollInterval:   time.Millisecond,
	})
}
