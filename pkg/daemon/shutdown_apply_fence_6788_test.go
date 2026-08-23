package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"golang.org/x/sync/semaphore"
)

// fenceTestDaemon returns a Daemon whose apply body is a counter, with a real
// weight-1 applySem and a store-less config path.
func fenceTestDaemon(t *testing.T) (*Daemon, *atomic.Int32) {
	t.Helper()
	var applies atomic.Int32
	d := &Daemon{
		applySem:  semaphore.NewWeighted(1),
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		daemonCtx: context.Background(),
	}
	d.applyBodyForTest = func(_ *config.Config) { applies.Add(1) }
	return d, &applies
}

// TestFencedDaemonRefusesEveryBackgroundApply6788 is the primary #6788
// fail-on-revert test.
//
// The shutdown drain is a drain-and-RELEASE, not a barrier: it acquires
// applySem to wait out an in-flight apply's closeout and hands the semaphore
// straight back. So any background applier that wakes AFTER it acquires
// immediately and runs a full apply into a half-torn-down daemon — FRR stopped,
// dataplane torn down, VIPs withdrawn. The DHCP lease-change callback reaches
// it on a 2s debounce timer; the feed publication and config-poll appliers take
// the same path.
//
// All THREE background entry points are asserted, not just the DHCP one. They
// are a family that must agree, and a background applier that skips the fence
// is exactly the defect this closes — testing one would leave the other two
// free to regress independently.
//
// FAIL-ON-REVERT: removing the fence check from beginBackgroundApply lets every
// arm apply and the counter reaches 3.
func TestFencedDaemonRefusesEveryBackgroundApply6788(t *testing.T) {
	d, applies := fenceTestDaemon(t)
	d.fenceBackgroundApplies()

	d.applyConfig(&config.Config{})
	d.applyActiveConfig()
	if err := d.applyActiveConfigResult(); err != nil {
		t.Errorf("a fenced daemon must report vacuous success to the feed publisher, not an error "+
			"(an error records publication DEBT for a process that is exiting); got %v", err)
	}

	if got := applies.Load(); got != 0 {
		t.Fatalf("%d background apply/applies ran on a daemon that is shutting down; a full apply "+
			"during teardown reconciles against subsystems the shutdown already stopped (#6788)", got)
	}
}

// TestUnfencedDaemonStillApplies6788 is the tightening control. Without it, a
// "fix" that refuses background applies unconditionally satisfies every
// assertion above while disabling DHCP lease reconciliation, dynamic feeds and
// the config-poll applier for the daemon's entire lifetime.
func TestUnfencedDaemonStillApplies6788(t *testing.T) {
	d, applies := fenceTestDaemon(t)

	d.applyConfig(&config.Config{})
	if got := applies.Load(); got != 1 {
		t.Fatalf("an UNfenced daemon must still run background applies, got %d; the fence must be "+
			"scoped to shutdown, not applied always", got)
	}
	if d.applyFencedForBackground() {
		t.Error("a daemon that never began shutting down must not report itself fenced")
	}
}

// TestApplierWaitingOnSemaphoreRefusesAfterFence6788 pins the window the
// before-acquire check alone cannot close, and it is the one that actually
// bites during a real shutdown.
//
// A background applier can already be BLOCKED on applySem behind an in-flight
// apply when shutdown fences. Checking the fence only BEFORE the acquire lets
// that waiter through the instant the in-flight apply releases — which is
// precisely the moment the shutdown drain is waiting for, so the refused-apply
// and the drain race for the same semaphore and the applier can win. Re-testing
// after the acquire is what makes the drain final.
//
// Deterministic: the test itself holds the semaphore (standing in for the
// in-flight apply), starts the applier, fences, then releases.
//
// FAIL-ON-REVERT: deleting the second fence test in beginBackgroundApply lets
// the waiter apply and the counter reaches 1.
func TestApplierWaitingOnSemaphoreRefusesAfterFence6788(t *testing.T) {
	d, applies := fenceTestDaemon(t)

	// Stand in for an in-flight apply holding the lock.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		d.applyConfig(&config.Config{})
		close(done)
	}()
	<-started
	// Give the applier time to reach the blocking Acquire.
	time.Sleep(50 * time.Millisecond)

	// Shutdown fences while the applier is parked on the semaphore.
	d.fenceBackgroundApplies()

	// The drain releases the semaphore; the parked applier now wakes.
	d.applySem.Release(1)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the parked background applier never returned")
	}

	if got := applies.Load(); got != 0 {
		t.Fatalf("a background applier parked on applySem when shutdown fenced ran its apply "+
			"anyway (%d): it inherited the semaphore the shutdown drain just freed, which is the "+
			"apply-after-the-drain this closes (#6788)", got)
	}
}

// TestFenceIsSetBeforeTheApplyDrain6788 binds the ORDERING inside
// runShutdownSequence rather than the helper it calls. The fence only makes the
// drain final if it is latched BEFORE the drain runs; latching it afterwards
// leaves exactly the window the issue describes. The helper cells above stay
// green if runShutdownSequence never fences at all — which is the bug.
//
// The probe is the apply body itself: a background apply attempted from inside
// the shutdown sequence (via the drain-time hook) must already be refused.
//
// FAIL-ON-REVERT: moving fenceBackgroundApplies() after the drain — or removing
// the call — lets the probe apply land.
func TestFenceIsSetBeforeTheApplyDrain6788(t *testing.T) {
	d, applies := fenceTestDaemon(t)

	// Hold the semaphore so the drain must WAIT, and probe from the holder:
	// at that instant the shutdown sequence has passed the fence call and is
	// parked in the drain, which is exactly the ordering under test.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	fencedDuringDrain := make(chan bool, 1)
	go func() {
		// Let runShutdownSequence reach the drain.
		time.Sleep(100 * time.Millisecond)
		fencedDuringDrain <- d.applyFencedForBackground()
		d.applySem.Release(1)
	}()

	runShutdownFenceFor6788(t, d)

	select {
	case fenced := <-fencedDuringDrain:
		if !fenced {
			t.Fatal("the background-apply fence was NOT set while the shutdown sequence was in its " +
				"apply drain: the fence must latch BEFORE the drain, or an applier that wakes " +
				"during/after the drain still runs a full apply (#6788)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe never ran")
	}

	if got := applies.Load(); got != 0 {
		t.Fatalf("an apply ran during shutdown, got %d", got)
	}
}

// runShutdownFenceFor6788 drives the real shutdown entry point far enough to
// cover the fence + drain, on a Daemon with no subsystems wired (every teardown
// step is nil-guarded).
func runShutdownFenceFor6788(t *testing.T, d *Daemon) {
	t.Helper()
	var wg sync.WaitGroup
	sentinel := context.Canceled
	done := make(chan error, 1)
	go func() { done <- d.runShutdownSequence(&wg, func() {}, sentinel) }()
	select {
	case got := <-done:
		if got != sentinel {
			t.Fatalf("runShutdownSequence returned %v, want the run error passed through", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runShutdownSequence did not return within 30s")
	}
}

// TestRunShutdownSequenceQuiescesDHCPClient6788 is the DHCP wiring cell. The
// pkg/dhcp cells (quiesce_6788_test.go) bind what Quiesce DOES; they stay green
// if runShutdownSequence never calls it — which is the bug, since the
// lease-change callback's 2s debounce timer is what fires the late apply.
//
// It also pins the half the apply fence does NOT cover, and that is the reason
// both mechanisms exist. onDHCPAddressChange does real work BEFORE and OUTSIDE
// any apply: it nudges the Surface-A DDNS reconcile, and on its
// management-only branch it runs applyMgmtVRFRoutes (netlink route writes) and
// reconcileDNSFromDHCP. None of that passes through beginBackgroundApply, so
// fencing applies alone would still let a late callback write routes during
// teardown. Stopping the callback is what closes it.
//
// FAIL-ON-REVERT: delete the d.dhcp.Quiesce() call from runShutdownSequence and
// the manager is not quiesced when the sequence returns.
func TestRunShutdownSequenceQuiescesDHCPClient6788(t *testing.T) {
	dm, err := dhcp.New(t.TempDir(), func() {}, func() {})
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	d, _ := fenceTestDaemon(t)
	d.dhcp = dm

	if dm.Quiesced() {
		t.Fatal("premise broken: a fresh DHCP manager must not start quiesced")
	}

	runShutdownFenceFor6788(t, d)

	if !dm.Quiesced() {
		t.Error("runShutdownSequence did not quiesce the DHCP client manager: its 2s lease-change " +
			"debounce timer can still fire after the apply drain, and its callback does netlink " +
			"route and DNS work outside the apply path that the apply fence does not cover (#6788)")
	}
}
