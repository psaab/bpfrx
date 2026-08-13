package userspace

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// #6871: PrepareLinkCycle's worker join is a MOMENT, not a barrier.
//
// It joins the workers and returns, releasing m.mu — and the daemon does not
// reach setDown until several netlink calls later. Every other holder of m.mu
// runs in that window, and the 1 Hz status tick is the busiest of them. It
// restarts the workers four different ways (helper respawn on a plan-key change,
// the #5134 deferred-worker arm, the busy-binding auto-rebind, the binding
// watchdog repair) and re-enables ctrl on a fifth, all against XSK sockets whose
// queues the link cycle is about to destroy.
//
// The tests below drive a REAL status loop concurrently with a REAL link cycle
// over a REAL control socket, and assert on the request stream the helper
// actually received. That is deliberate: a test that calls linkCycleInFlight()
// itself would pass with the production wiring severed, which is the exact defect
// class this PR exists to close. The observable here is what reached the helper,
// so a lease that is taken but never consulted — or consulted somewhere the tick
// does not pass through — fails.

// leaseControlServer is an UNBOUNDED control-socket server: it answers requests
// until the listener closes, recording every request Type in order. The existing
// startLinkCycleControlServer stops after len(responses) requests, which cannot
// express "and then nothing else arrived for 200ms".
type leaseControlServer struct {
	mu   sync.Mutex
	reqs []string
}

func (s *leaseControlServer) record(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, t)
}

func (s *leaseControlServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.reqs))
	copy(out, s.reqs)
	return out
}

func startLeaseControlServer(t *testing.T, sock string, status ProcessStatus) *leaseControlServer {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &leaseControlServer{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				srv.record(req.Type)
				resp := status
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true, Status: &resp})
			}()
		}
	}()
	return srv
}

// fastStatusLoop shortens the reconcile tick so a few hundred milliseconds of
// wall clock contains many real ticks. Without it each of these tests would need
// several seconds to prove the same thing.
func fastStatusLoop(t *testing.T, d time.Duration) {
	t.Helper()
	old := statusLoopInterval
	statusLoopInterval = d
	t.Cleanup(func() { statusLoopInterval = old })
}

// newLeaseTestManager builds a manager with a live helper process handle, a real
// control socket, and a #5134 worker-arm debt outstanding. The debt is what gives
// the tick a LOUD producer: retryDeferredWorkerArmLocked republishes the snapshot
// with DeferWorkers=false, i.e. it ARMS THE WORKERS, on every tick until the
// publish lands. Running that in the middle of a link cycle is the exact undo of
// the stop_workers PrepareLinkCycle just issued.
//
// Deliberately NO BPF maps. Map creation needs privileges this suite does not
// have by default (rlimit.RemoveMemlock -> EPERM), so a map-backed fixture makes
// the discriminator SKIP rather than run — a guard that is green because it never
// executed. The observable here is the control-socket request stream, which needs
// no maps at all: the tick's very first act is a "status" request, so a body that
// runs is visible whether or not applyHelperStatusLocked can reach a ctrl map.
func newLeaseTestManager(t *testing.T) (*Manager, *leaseControlServer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, sock)
	srv := startLeaseControlServer(t, sock, ProcessStatus{
		PID:      4242,
		Workers:  2,
		Bindings: []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}},
	})
	// Config stays nil: the required-protocol gates and the proactive neighbor
	// prewarm both short-circuit on it, so the only thing the tick can add to
	// the request stream is the producer this test is about.
	m.lastSnapshot = &ConfigSnapshot{Generation: 5, DeferWorkers: true}
	m.pendingWorkerArm = true
	return m, srv
}

// runStatusLoop starts the real statusLoop goroutine and stops it at test end.
func runStatusLoop(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	m.ensureStatusLoopLocked()
	m.mu.Unlock()
	t.Cleanup(func() {
		m.mu.Lock()
		cancel := m.syncCancel
		m.syncCancel = nil
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
}

// waitForRequest blocks until the helper has seen at least one request of the
// given type, or fails the test. It is the liveness proof these tests need: an
// empty request window means nothing at all unless the loop that would have
// filled it is demonstrably running.
func waitForRequest(t *testing.T, srv *leaseControlServer, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, r := range srv.requests() {
			if r == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q request within %s; the status loop is not running, so this test's "+
		"empty-window assertion would hold for the wrong reason. Requests seen: %v",
		want, within, srv.requests())
}

// requestsBetween returns the request types the helper saw strictly between the
// first `open` and the first `close` that follows it.
func requestsBetween(t *testing.T, reqs []string, open, close string) []string {
	t.Helper()
	start := -1
	for i, r := range reqs {
		if r == open {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no %q in the request stream %v — the link cycle never reached the helper",
			open, reqs)
	}
	for i := start + 1; i < len(reqs); i++ {
		if reqs[i] == close {
			return reqs[start+1 : i]
		}
	}
	t.Fatalf("no %q after %q in the request stream %v — the link cycle never completed",
		close, open, reqs)
	return nil
}

// TestStatusTickSendsNothingWhileLinkCycleInFlight_6871 is the discriminator.
//
// RED-on-revert: delete the `if m.linkCycleInFlight()` skip from statusLoop and
// this fails at "the status tick reached the helper DURING the link cycle",
// listing the status/apply_snapshot requests that landed between the
// stop_workers and the rebind.
func TestStatusTickSendsNothingWhileLinkCycleInFlight_6871(t *testing.T) {
	// The hold below and the control window above it MUST be the same length:
	// the control window is what proves the hold is dense enough for an empty
	// result to mean anything.
	const hold = 300 * time.Millisecond

	fastStatusLoop(t, 20*time.Millisecond)
	skipLinkCycleRebindSleep(t)
	m, srv := newLeaseTestManager(t)

	runStatusLoop(t, m)
	// LIVENESS, before the cycle: the loop is genuinely ticking and genuinely
	// talking to this helper.
	waitForRequest(t, srv, "status", 2*time.Second)

	// DENSITY, and it is what makes the empty window below load-bearing.
	// waitForRequest proves the loop is ALIVE; it does not prove the hold is
	// long enough to CONTAIN ticks. Inline statusLoopInterval back to its
	// production 1s at process_status.go and this test still passed — the 300ms
	// window then held zero ticks, so requestsBetween came back empty for the
	// wrong reason and the guard was green with the seam severed. Measure an
	// equal-length control window with no cycle in flight and require at least
	// two polls in it, so a seam that stops taking effect fails HERE, loudly,
	// instead of silently emptying the discriminator.
	countBefore := countRequests(srv.requests(), "status")
	time.Sleep(hold)
	if ticks := countRequests(srv.requests(), "status") - countBefore; ticks < 2 {
		t.Fatalf("only %d status polls in a %s control window with NO cycle in flight. The "+
			"discriminator below holds a cycle open for the same %s, so an empty window "+
			"there would prove nothing — the tick simply never fires inside it. Either "+
			"fastStatusLoop no longer reaches the loop's interval or the hold is too "+
			"short. Requests: %v", ticks, hold, hold, srv.requests())
	}

	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}
	// Hold the cycle open for the same window the control run just proved dense.
	// Every tick in it is an opportunity for the loop to undo the join.
	time.Sleep(hold)
	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}

	between := requestsBetween(t, srv.requests(), "stop_workers", "rebind")
	if len(between) != 0 {
		t.Errorf("the status tick reached the helper DURING the link cycle: %v.\n"+
			"PrepareLinkCycle had joined every worker and disabled ctrl; the daemon "+
			"has not yet taken the NIC down. A 'status' here means the whole tick "+
			"body ran, which restarts the workers (helper respawn on a plan-key "+
			"change, the #5134 deferred-worker arm, the busy-binding auto-rebind) "+
			"and re-enables ctrl on sockets whose queues are about to be destroyed. "+
			"An 'apply_snapshot' here IS that worker arm. Full stream: %v",
			between, srv.requests())
	}
}

// TestStatusTickResumesAfterLinkCycle_6871 is the over-reach guard, and the one
// that keeps the fix from being "wedge the reconcile loop forever". It must stay
// GREEN under the revert above — removing the skip only ever lets MORE traffic
// through, so a test asserting traffic RESUMES cannot be satisfied by it.
//
// It also pins the #5134 debt as level-triggered across the suppression: the arm
// republish the tick skipped during the cycle is not lost, it is retried.
func TestStatusTickResumesAfterLinkCycle_6871(t *testing.T) {
	fastStatusLoop(t, 20*time.Millisecond)
	skipLinkCycleRebindSleep(t)
	m, srv := newLeaseTestManager(t)

	runStatusLoop(t, m)
	waitForRequest(t, srv, "status", 2*time.Second)
	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}

	// After the rebind the lease is gone, so the tick must be reconciling again.
	deadline := time.Now().Add(2 * time.Second)
	for {
		reqs := srv.requests()
		after := false
		seenRebind := false
		for _, r := range reqs {
			if r == "rebind" {
				seenRebind = true
				continue
			}
			if seenRebind && r == "status" {
				after = true
				break
			}
		}
		if after {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no status poll after the rebind: the lease was never released, so "+
				"the 1 Hz reconcile is wedged for good — a worse outage than the race "+
				"it closes. Requests: %v", reqs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestLinkCycleLeaseExpiresAfterTTL_6871 pins the backstop. NotifyLinkCycle is
// reached on every path that takes a lease, but a caller that dies in between
// would otherwise suppress the reconcile forever. The TTL bounds that.
//
// It drives the clock through the linkCycleLeaseNow seam rather than sleeping out
// a real minute.
func TestLinkCycleLeaseExpiresAfterTTL_6871(t *testing.T) {
	now := time.Now()
	old := linkCycleLeaseNow
	linkCycleLeaseNow = func() time.Time { return now }
	t.Cleanup(func() { linkCycleLeaseNow = old })

	m := New()
	m.acquireLinkCycleLease()
	if !m.linkCycleInFlight() {
		t.Fatal("the lease must be held immediately after acquire")
	}
	now = now.Add(linkCycleLeaseTTL - time.Second)
	if !m.linkCycleInFlight() {
		t.Fatal("the lease must still be held one second inside the TTL; a lease that " +
			"expires early re-opens the race it exists to close")
	}
	now = now.Add(2 * time.Second)
	if m.linkCycleInFlight() {
		t.Fatalf("the lease must expire past %s: a stranded lease suppresses the 1 Hz "+
			"reconcile loop permanently", linkCycleLeaseTTL)
	}
	if got := m.linkCycleLeaseUntil.Load(); got != 0 {
		t.Errorf("expiry must clear the deadline (got %d), otherwise every later tick "+
			"re-walks the expired lease and re-logs the warning", got)
	}
}

// TestUpdateRGActiveCannotReEnableCtrlDuringLinkCycle_6871 is the second half of
// the lease, and the one a tick-only guard does NOT cover.
//
// UpdateRGActive ends in applyHelperStatusLocked, which writes the ctrl gate. It
// is driven by VRRP/cluster events and by reconcileRGStateLoop's 2s pass — NEITHER
// of which is serialized on the daemon's applySem — so it lands in the middle of a
// link cycle on its own schedule. Its existing rgTransitionInFlight guard does not
// help: on a demotion the flag is never set, and on an activation it is CLEARED
// before applyHelperStatusLocked runs (manager_ha.go, "the acked activation does
// not force one global ctrl-disabled cycle").
//
// RED-on-revert: drop `|| m.linkCycleInFlight()` from the ctrl gate in
// applyHelperStatusLocked and this fails at "ctrl was re-enabled".
func TestUpdateRGActiveCannotReEnableCtrlDuringLinkCycle_6871(t *testing.T) {
	for _, active := range []bool{true, false} {
		name := "demotion"
		if active {
			name = "activation"
		}
		t.Run(name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "control.sock")
			m, ctrlMap, _ := newLinkCycleTestManager(t, sock)
			seedUserspaceCtrl(t, ctrlMap, userspaceCtrlValue{
				Enabled:            0,
				MetadataVersion:    userspaceMetadataVersion,
				HeartbeatTimeoutMS: 30000,
			})
			// A helper that is up, armed and ready — i.e. every readiness gate
			// in applyHelperStatusLocked passes and ctrl WOULD be enabled.
			startLeaseControlServer(t, sock, ProcessStatus{
				PID:                9001,
				Workers:            2,
				Enabled:            true,
				ForwardingArmed:    true,
				NeighborGeneration: 7,
				Capabilities:       UserspaceCapabilities{ForwardingSupported: true},
				Bindings: []BindingStatus{{
					Slot: 1, Ifindex: 2, QueueID: 0,
					Registered: true, Armed: true, Bound: true,
					XSKRegistered: true, Ready: true, RXPackets: 5,
				}},
			})
			rgMap, err := ebpf.NewMap(&ebpf.MapSpec{
				Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: 16,
			})
			if err != nil {
				t.Fatalf("new rg_active map: %v", err)
			}
			t.Cleanup(func() { rgMap.Close() })
			injectShimMap(t, m.bpfShim, "rg_active", rgMap)
			m.neighborsPrewarmed = true
			m.xskLivenessProven = true

			// POSITIVE CONTROL: with no cycle in flight this fixture really does
			// enable ctrl. Without this the assertion below could hold because
			// the readiness gates never passed.
			if err := m.UpdateRGActive(1, active); err != nil {
				t.Fatalf("UpdateRGActive: %v", err)
			}
			if got := lookupUserspaceCtrl(t, ctrlMap); got.Enabled != 1 {
				t.Fatalf("control: ctrl.Enabled = %d with no link cycle in flight, want 1 — "+
					"this fixture does not reach the ctrl enable, so the guard assertion "+
					"below would pass vacuously", got.Enabled)
			}
			seedUserspaceCtrl(t, ctrlMap, userspaceCtrlValue{
				Enabled:            0,
				MetadataVersion:    userspaceMetadataVersion,
				HeartbeatTimeoutMS: 30000,
			})

			// THE DISCRIMINATOR: same call, one link cycle in flight.
			if err := m.PrepareLinkCycle(); err != nil {
				t.Fatalf("PrepareLinkCycle: %v", err)
			}
			if err := m.UpdateRGActive(1, active); err != nil {
				t.Fatalf("UpdateRGActive during link cycle: %v", err)
			}
			if got := lookupUserspaceCtrl(t, ctrlMap); got.Enabled != 0 {
				t.Errorf("ctrl was re-enabled (Enabled=%d) while a RETH MAC link cycle held "+
					"the dataplane. The workers are joined and the NIC is going down, so the "+
					"shim is now redirecting transit into dead XSK sockets. UpdateRGActive is "+
					"not on the status tick — it runs off VRRP events and reconcileRGStateLoop's "+
					"2s pass, neither serialized on applySem — so a tick-scoped guard does "+
					"not reach it (#6871)", got.Enabled)
			}
		})
	}
}

// TestNotifyLinkCycleReleasesLeaseBeforeItsOwnCtrlApply_6871 is the over-reach
// guard for the ctrl gate above: the gate must not suppress the ctrl enable on
// the very call that ENDS the cycle, or every RETH MAC link cycle costs an extra
// tick of fail-closed transit for no reason.
//
// It stays GREEN under the ctrl-gate revert (which only ever enables ctrl more
// readily) and goes RED if the lease release is moved to the end of
// NotifyLinkCycle instead of the top of its critical section.
func TestNotifyLinkCycleReleasesLeaseBeforeItsOwnCtrlApply_6871(t *testing.T) {
	skipLinkCycleRebindSleep(t)
	sock := filepath.Join(t.TempDir(), "control.sock")
	m, ctrlMap, _ := newLinkCycleTestManager(t, sock)
	seedUserspaceCtrl(t, ctrlMap, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		HeartbeatTimeoutMS: 30000,
	})
	startLeaseControlServer(t, sock, ProcessStatus{
		PID:                9002,
		Workers:            2,
		Enabled:            true,
		ForwardingArmed:    true,
		NeighborGeneration: 7,
		Capabilities:       UserspaceCapabilities{ForwardingSupported: true},
		Bindings: []BindingStatus{{
			Slot: 1, Ifindex: 2, QueueID: 0,
			Registered: true, Armed: true, Bound: true,
			XSKRegistered: true, Ready: true, RXPackets: 5,
		}},
	})

	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}
	if !m.linkCycleInFlight() {
		t.Fatal("PrepareLinkCycle must take the lease, otherwise nothing below is tested")
	}
	if err := m.NotifyLinkCycle(); err != nil {
		t.Fatalf("NotifyLinkCycle: %v", err)
	}

	if m.linkCycleInFlight() {
		t.Fatal("NotifyLinkCycle must release the lease")
	}
	if got := lookupUserspaceCtrl(t, ctrlMap); got.Enabled != 1 {
		t.Errorf("ctrl.Enabled = %d after a COMPLETED link cycle, want 1. The rebind "+
			"recreated the workers and every readiness gate passes, so the only thing "+
			"that can be holding ctrl down is the lease — which means the release was "+
			"placed after the status apply instead of at the TOP of NotifyLinkCycle's "+
			"critical section. That costs a full extra reconcile tick of fail-closed "+
			"transit on every RETH MAC link cycle", got.Enabled)
	}
}

// TestPrepareLinkCycleTakesNoLeaseWithoutAHelper_6871 is the over-reach guard for
// the acquire. No helper means no workers to join and nothing for a cycle to
// race, so suppressing the reconcile there is pure cost.
func TestPrepareLinkCycleTakesNoLeaseWithoutAHelper_6871(t *testing.T) {
	m := New()
	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle with no helper: %v", err)
	}
	if m.linkCycleInFlight() {
		t.Error("no helper is running, so there are no workers to protect; taking the " +
			"lease here suppresses the reconcile loop for nothing")
	}
}

// TestPrepareLinkCycleHoldsTheLeaseWhenTheJoinFails_6871 pins the acquire point.
// The lease must open at the ctrl disable, not at a successful join:
// disableCtrlBeforeTeardownLocked can clear every binding row fail-closed and
// stop_workers can still fail afterwards, and a tick landing in THAT state
// repopulates the rows that were just cleared. The daemon's rollback
// (NotifyLinkCycle) is what ends it.
func TestPrepareLinkCycleHoldsTheLeaseWhenTheJoinFails_6871(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, sock)
	// No listener on the control socket: the stop_workers dial fails.
	err := m.PrepareLinkCycle()
	if err == nil {
		t.Fatal("PrepareLinkCycle must fail when stop_workers cannot be delivered")
	}
	if !strings.Contains(err.Error(), "stop_workers") {
		t.Errorf("error should name stop_workers; got %v", err)
	}
	if !m.linkCycleInFlight() {
		t.Error("the lease must be held after a FAILED join too: ctrl is already off and " +
			"the binding rows may already be cleared, so the tick must stay out until the " +
			"daemon's rollback rebind runs")
	}
}
