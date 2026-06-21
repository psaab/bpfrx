package vrrp

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vishvananda/netlink"
)

// #2156 — UpdateInstances build-before-teardown: a transient member-link or
// socket-open failure during a VIP-change restart must NOT orphan the RG out
// of VRRP election. The old instance keeps running and is retried once the
// interface returns. These tests drive the real UpdateInstances diff via the
// injectable resolveIface / openInstanceSocket / runInstance / stopInstance
// seams (no real sockets, no live run() goroutine).

// newTestManagerNoNetwork returns a Manager whose lifecycle seams never touch
// the network or spawn goroutines, plus recorders for asserting the
// teardown/start ordering. The link-watcher seams are stubbed so a tracked
// interface doesn't start a real netlink subscription.
func newTestManagerNoNetwork() (*Manager, *lifecycleRecorder) {
	m := NewManager()
	rec := &lifecycleRecorder{}

	m.linkState = func(string) (bool, error) { return true, nil }
	m.subscribeLinks = func(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error { return nil }

	// resolveIface returns a synthetic interface; failures are injected via
	// openInstanceSocket so we exercise the socket-open arm of the bug.
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 1}, nil
	}
	m.openInstanceSocket = func(vi *vrrpInstance) error {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.openCalls++
		if rec.openShouldFail.Load() {
			return errSocketOpenFailed
		}
		return nil
	}
	m.runInstance = func(vi *vrrpInstance) {
		rec.mu.Lock()
		rec.runCalls++
		rec.lastRun = vi
		rec.mu.Unlock()
		// Mark the instance "started" so stop() (if ever called on it)
		// would not deadlock: close stopped on a goroutine the way run()
		// does. Tests that assert no-stop never reach here for the old vi.
		close(vi.stopped)
	}
	m.stopInstance = func(vi *vrrpInstance) {
		rec.mu.Lock()
		rec.stopCalls++
		rec.stopped = append(rec.stopped, vi)
		rec.mu.Unlock()
		// Mimic vi.stop()'s observable effect without touching sockets.
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	}
	return m, rec
}

var errSocketOpenFailed = &socketOpenError{}

type socketOpenError struct{}

func (e *socketOpenError) Error() string { return "test: socket open failed" }

type lifecycleRecorder struct {
	mu             sync.Mutex
	openCalls      int
	runCalls       int
	stopCalls      int
	lastRun        *vrrpInstance
	stopped        []*vrrpInstance
	openShouldFail atomic.Bool
}

func (r *lifecycleRecorder) snapshot() (open, run, stop int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.openCalls, r.runCalls, r.stopCalls
}

// TestUpdateInstances_BuildBeforeTeardown_KeepsOldOnSocketFailure asserts the
// #2156 fix: when a VIP change forces a restart but the replacement's socket
// fails to open, the ORIGINAL instance stays in m.instances unchanged — it is
// neither deleted (orphaned) nor stopped, and the failed replacement is never
// started.
func TestUpdateInstances_BuildBeforeTeardown_KeepsOldOnSocketFailure(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	key := instanceKey{iface: "reth0.50", groupID: 101} // RETH VRID for RG 1

	// Seed an established, "running" instance with the original VIP set.
	orig := newInstance(Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}, &net.Interface{Name: "reth0.50", Index: 1}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[key] = orig
	m.mu.Unlock()

	// RGVRRPReady is truthful before the failed update.
	if ready, _ := m.RGVRRPReady(1, true); !ready {
		t.Fatal("RGVRRPReady(1) should be true with the original instance present")
	}

	// Inject a socket-open failure, then push a VIP change (forces restart).
	rec.openShouldFail.Store(true)
	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.2/24"}, // changed VIP
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	// The original instance must still own the key (no orphan).
	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	m.mu.RUnlock()
	if !ok || got != orig {
		t.Fatalf("after failed restart: key not owned by original instance (ok=%v same=%v)", ok, got == orig)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 instance, got %d", n)
	}

	// The original must NOT have been stopped, and the failed replacement
	// must NOT have been started (no double-run, no orphan).
	open, run, stop := rec.snapshot()
	if open != 1 {
		t.Errorf("openInstanceSocket calls = %d, want 1 (the failed attempt)", open)
	}
	if run != 0 {
		t.Errorf("runInstance calls = %d, want 0 (replacement never started)", run)
	}
	if stop != 0 {
		t.Errorf("stopInstance calls = %d, want 0 (original kept running)", stop)
	}

	// The original still advertises its OLD VIP set (strictly better than
	// dropping out of election).
	if got.cfg.VirtualAddresses[0] != "172.16.50.1/24" {
		t.Errorf("original VIP = %q, want 172.16.50.1/24 (unchanged)", got.cfg.VirtualAddresses[0])
	}

	// RGVRRPReady stays truthful — never a phantom-ready hole.
	if ready, reasons := m.RGVRRPReady(1, true); !ready {
		t.Fatalf("RGVRRPReady(1) should stay true through the failed restart: %v", reasons)
	}
}

// TestUpdateInstances_ReDriveRecoversOnLinkReturn asserts the bounded
// self-recovery (#2156 B1 at the manager layer): after a transient socket
// failure left the old instance running, a subsequent UpdateInstances with
// the socket now succeeding swaps in the new VIP set and stops the old one.
func TestUpdateInstances_ReDriveRecoversOnLinkReturn(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	key := instanceKey{iface: "reth0.50", groupID: 101}
	orig := newInstance(Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}, &net.Interface{Name: "reth0.50", Index: 1}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[key] = orig
	m.mu.Unlock()

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.2/24"},
	}}

	// Pass 1: socket fails — old instance survives (the deferred restart).
	rec.openShouldFail.Store(true)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 1: %v", err)
	}
	m.mu.RLock()
	if m.instances[key] != orig {
		m.mu.RUnlock()
		t.Fatal("pass 1: original instance was orphaned")
	}
	m.mu.RUnlock()

	// Pass 2: interface returned — socket now opens. The re-drive swaps in
	// the new VIP set and tears down the old instance.
	rec.openShouldFail.Store(false)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 2: %v", err)
	}

	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	m.mu.RUnlock()
	if !ok {
		t.Fatal("pass 2: key missing after successful re-drive")
	}
	if got == orig {
		t.Fatal("pass 2: instance was not replaced")
	}
	if n != 1 {
		t.Fatalf("pass 2: expected exactly 1 instance, got %d", n)
	}
	if got.cfg.VirtualAddresses[0] != "172.16.50.2/24" {
		t.Errorf("pass 2: new VIP = %q, want 172.16.50.2/24", got.cfg.VirtualAddresses[0])
	}

	// Ordering: exactly one stop (the old) and one run (the new), and the
	// old instance is the one that was stopped (build-before-teardown stops
	// only after the replacement is proven buildable).
	open, run, stop := rec.snapshot()
	if open != 2 {
		t.Errorf("openInstanceSocket calls = %d, want 2 (fail + success)", open)
	}
	if run != 1 {
		t.Errorf("runInstance calls = %d, want 1 (new instance started once)", run)
	}
	if stop != 1 {
		t.Errorf("stopInstance calls = %d, want 1 (old instance stopped once)", stop)
	}
	rec.mu.Lock()
	stoppedOld := len(rec.stopped) == 1 && rec.stopped[0] == orig
	startedNew := rec.lastRun == got
	rec.mu.Unlock()
	if !stoppedOld {
		t.Error("the stopped instance was not the original (teardown ordering wrong)")
	}
	if !startedNew {
		t.Error("the started instance was not the new replacement")
	}

	// RGVRRPReady remained truthful across both passes.
	if ready, _ := m.RGVRRPReady(1, true); !ready {
		t.Fatal("RGVRRPReady(1) should be true after recovery")
	}
}

// TestUpdateInstances_NewKeyFailureNoPhantom asserts that a brand-new key
// whose socket fails to open is simply not created (no phantom entry), and a
// retry creates it once the socket succeeds. This guards the symmetry of the
// build block for the new-key path.
func TestUpdateInstances_NewKeyFailureNoPhantom(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	rec.openShouldFail.Store(true)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances (fail): %v", err)
	}
	m.mu.RLock()
	n := len(m.instances)
	m.mu.RUnlock()
	if n != 0 {
		t.Fatalf("failed new-key build left %d phantom instance(s), want 0", n)
	}
	// Gate is not satisfied by a phantom — RG has RETH but no instance.
	if ready, _ := m.RGVRRPReady(1, true); ready {
		t.Fatal("RGVRRPReady(1) must be false when the only build attempt failed")
	}

	rec.openShouldFail.Store(false)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances (retry): %v", err)
	}
	m.mu.RLock()
	n = len(m.instances)
	m.mu.RUnlock()
	if n != 1 {
		t.Fatalf("retry created %d instance(s), want 1", n)
	}
	if ready, _ := m.RGVRRPReady(1, true); !ready {
		t.Fatal("RGVRRPReady(1) should be true after the retry created the instance")
	}
}
