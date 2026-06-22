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

// seedRunningInstance installs an already-"running" instance for the given key
// bound to the supplied ifindex. The instance's stopped channel is left open
// so the stub stopInstance (which only records) does not block; the real run()
// goroutine is never started in these no-network tests.
func seedRunningInstance(m *Manager, key instanceKey, cfg Instance, ifindex int) *vrrpInstance {
	vi := newInstance(cfg, &net.Interface{Name: cfg.Interface, Index: ifindex}, m.eventCh, nil)
	m.mu.Lock()
	m.instances[key] = vi
	m.mu.Unlock()
	return vi
}

// TestUpdateInstances_IfindexChange_RestartsRebind asserts the #2294 fix: when
// a running instance's member interface keeps the SAME xpf config but its
// kernel ifindex changes (netdev delete+recreate / rename), the reconcile path
// detects the drift and restarts the instance — stopping the stale-bound old
// one and starting a fresh instance bound to the NEW ifindex. Without the fix
// the byte-identical config hits the "No change" continue and the instance
// keeps its socket bound to the dead ifindex → permanent VRRP silence. This
// test FAILS if the ifindex-drift detection is reverted (no restart occurs).
func TestUpdateInstances_IfindexChange_RestartsRebind(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	// resolveIface returns whatever ifindex the test currently advertises.
	var liveIndex atomic.Int64
	liveIndex.Store(7)
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: int(liveIndex.Load())}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	cfg := Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}
	orig := seedRunningInstance(m, key, cfg, 7) // bound to ifindex 7

	// The netdev was deleted+recreated under the same name → new ifindex 9,
	// while the desired config is byte-identical.
	liveIndex.Store(9)
	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"}, // UNCHANGED config
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	open, run, stop := rec.snapshot()
	if open != 1 || run != 1 || stop != 1 {
		t.Fatalf("ifindex drift must restart: open=%d run=%d stop=%d, want 1/1/1", open, run, stop)
	}

	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	m.mu.RUnlock()
	if !ok || n != 1 {
		t.Fatalf("expected exactly 1 instance for the key, ok=%v n=%d", ok, n)
	}
	if got == orig {
		t.Fatal("instance was not replaced — stale ifindex socket kept (bug)")
	}
	if got.iface.Index != 9 {
		t.Fatalf("replacement bound to ifindex %d, want 9 (new live ifindex)", got.iface.Index)
	}

	rec.mu.Lock()
	stoppedOld := len(rec.stopped) == 1 && rec.stopped[0] == orig
	rec.mu.Unlock()
	if !stoppedOld {
		t.Fatal("the stopped instance was not the original (build-before-teardown ordering wrong)")
	}

	// Restart must preserve the configured priority/preempt/VIPs.
	if got.cfg.Priority != 200 || !got.cfg.Preempt {
		t.Fatalf("restart lost config: priority=%d preempt=%v, want 200/true", got.cfg.Priority, got.cfg.Preempt)
	}
	if !vipsEqual(got.cfg.VirtualAddresses, cfg.VirtualAddresses) {
		t.Fatalf("restart lost VIPs: %v, want %v", got.cfg.VirtualAddresses, cfg.VirtualAddresses)
	}
}

// TestUpdateInstances_IfindexUnchanged_NoRestart asserts the idempotence half
// of #2294: a reconcile pass where the resolved ifindex matches the bound
// ifindex and the config is unchanged must NOT restart the instance (no socket
// churn, no spurious failover). This is the steady-state every-2s reconcile
// case; a regression here would restart-storm every RG.
func TestUpdateInstances_IfindexUnchanged_NoRestart(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	// Live ifindex stays equal to the bound one.
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	cfg := Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}
	orig := seedRunningInstance(m, key, cfg, 5)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	// Drive the reconcile several times — must remain a no-op every time.
	for i := 0; i < 3; i++ {
		if err := m.UpdateInstances(desired); err != nil {
			t.Fatalf("UpdateInstances pass %d: %v", i, err)
		}
	}

	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("unchanged ifindex must NOT restart: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got != orig {
		t.Fatal("instance was replaced despite unchanged ifindex+config (idempotence broken)")
	}
}

// TestUpdateInstances_IfindexUnchanged_PriorityOnlyStaysInPlace asserts that a
// priority-only delta with an UNCHANGED ifindex still takes the cheap in-place
// updateConfig path (no restart) — the #2294 ifindex check must not turn a
// priority bump into a socket-churning restart. Guards against over-triggering.
func TestUpdateInstances_IfindexUnchanged_PriorityOnlyStaysInPlace(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 5}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	orig := seedRunningInstance(m, key, Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}, 5)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         150, // priority changed, VIPs + ifindex unchanged
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("priority-only delta must stay in-place: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got != orig {
		t.Fatal("priority-only delta replaced the instance (should be in-place)")
	}
	if got.cfg.Priority != 150 {
		t.Fatalf("in-place update did not apply priority: got %d, want 150", got.cfg.Priority)
	}
}

// TestUpdateInstances_IfindexChange_TransientResolveFailKeepsOld asserts that a
// resolve failure during the reconcile does NOT churn the instance: the old
// (possibly stale-bound) instance is kept until the interface resolves again,
// matching the build-before-teardown tolerance (#2156) and avoiding dropping
// the RG out of election on a transient netlink hiccup.
func TestUpdateInstances_IfindexChange_TransientResolveFailKeepsOld(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	resolveErr := atomic.Bool{}
	resolveErr.Store(true)
	m.resolveIface = func(name string) (*net.Interface, error) {
		if resolveErr.Load() {
			return nil, errSocketOpenFailed
		}
		return &net.Interface{Name: name, Index: 9}, nil
	}

	key := instanceKey{iface: "reth0.50", groupID: 101}
	cfg := Instance{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}
	orig := seedRunningInstance(m, key, cfg, 7)

	desired := []*Instance{{
		Interface:        "reth0.50",
		GroupID:          101,
		Priority:         200,
		Preempt:          true,
		VirtualAddresses: []string{"172.16.50.1/24"},
	}}

	// Pass 1: resolve fails — keep the old instance, no restart.
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 1: %v", err)
	}
	open, run, stop := rec.snapshot()
	if open != 0 || run != 0 || stop != 0 {
		t.Fatalf("resolve failure must keep old instance: open=%d run=%d stop=%d, want 0/0/0", open, run, stop)
	}
	m.mu.RLock()
	if m.instances[key] != orig {
		m.mu.RUnlock()
		t.Fatal("pass 1: old instance orphaned on transient resolve failure")
	}
	m.mu.RUnlock()

	// Pass 2: resolve returns the NEW ifindex — the drift restart fires.
	resolveErr.Store(false)
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances pass 2: %v", err)
	}
	open, run, stop = rec.snapshot()
	if open != 1 || run != 1 || stop != 1 {
		t.Fatalf("pass 2 ifindex drift must restart: open=%d run=%d stop=%d, want 1/1/1", open, run, stop)
	}
	m.mu.RLock()
	got := m.instances[key]
	m.mu.RUnlock()
	if got == orig || got.iface.Index != 9 {
		t.Fatalf("pass 2: not rebound to new ifindex (same=%v index=%d)", got == orig, got.iface.Index)
	}
}
