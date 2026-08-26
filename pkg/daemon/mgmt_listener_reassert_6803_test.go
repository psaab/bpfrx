// mgmt_listener_reassert_6803_test.go — #6803.
//
// An unexpected management-listener serve exit was OBSERVABLE and never
// RECONCILED at the same endpoint. Three things had to be true for that, and
// each needs its own cell, because fixing any one alone leaves the endpoint down:
//
//  1. api.Server.ReconcileHTTP short-circuited on a same-address leg WITHOUT
//     asking whether it was still serving, so even a forced re-drive returned nil
//     having done nothing. ReconcileHTTPS asks. (pkg/api cell.)
//  2. reconcileTo gated the HTTP rebind on the converged FINGERPRINT alone, which
//     records what the last SUCCESSFUL reconcile bound and is not evidence the
//     socket is up. #6827 round 6 gave the HTTPS arm this liveness question; the
//     HTTP arm never got it.
//  3. Nothing CALLED reconcile except applyConfigLocked, so recovery waited on an
//     operator committing — from a box whose management API had just died.
//
// Every cell here is PAIRED against the healthy case, because each fix is a
// widened trigger and the failure mode of over-widening is real: a rebind that
// fires on a healthy leg bounces the management socket on every commit / every
// 30s tick. The existing #6827 over-reach guards
// (management_recovery_6827_test.go) already pin the empty-bind direction.
package daemon

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/api"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/sysservices"
)

// killLeg6803 simulates an UNEXPECTED serve exit the way production produces
// one: the listening socket goes away underneath a live Serve loop, which
// returns a non-ErrServerClosed error and marks the leg dead. It does NOT reach
// into api's unexported state, so the cell exercises the same path the defect
// arrives on.
func killLeg6803(t *testing.T, m *managementReconciler, reg *fakeReg, addr string) {
	t.Helper()
	reg.mu.Lock()
	ln := reg.byAddr[addr]
	reg.mu.Unlock()
	if ln == nil {
		t.Fatalf("no listener was ever created at %s; the case starts wrong", addr)
	}
	ln.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !m.srv.HTTPServing() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the HTTP leg at %s was still reported serving after its socket died", addr)
}

// bootMgmt6803 boots a management reconciler on a live (fake) listener and
// returns it with the Daemon that OWNS it.
//
// The daemon's opts.APIAddr is the address, and d.mgmt holds the reconciler, so
// reconcileWebManagement's own derivation (desired -> resolveAPIBinds) lands on
// the same endpoint the boot bound. That matters: the owner cells must exercise
// the REAL production entry point, not reconcileTo with a hand-built config —
// a helper that fed the address in directly would keep passing if the owner
// derived a different (or empty) desired endpoint, which is exactly how the
// first cut of this fixture went green on a no-op.
//
// addr is loopback because resolveAPIBinds' #4047/#5127 clamp pulls an off-box
// bind back to loopback when no api-auth is configured; using an off-box address
// here would silently reconcile toward a DIFFERENT endpoint than the one booted.
func bootMgmt6803(t *testing.T, reg *fakeReg, addr string) (*Daemon, *managementReconciler) {
	t.Helper()
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.opts.APIAddr = addr
	m := newManagementReconciler(d, api.Config{ListenFunc: reg.listen})
	d.mgmt.Store(m)

	if got := m.desired(nil).Addr; got != addr {
		t.Fatalf("the reconciler's own derivation wants %q but the fixture booted "+
			"%q; the owner cells would reconcile toward a different endpoint and "+
			"pass vacuously", got, addr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := m.startTo(ctx, cfgFor(reg, addr, false, "", nil)); err != nil {
		t.Fatalf("startTo: %v", err)
	}
	if !m.srv.HTTPServing() {
		t.Fatal("the boot bind did not leave the HTTP leg serving; the case starts wrong")
	}
	return d, m
}

func listenerCount6803(reg *fakeReg, addr string) int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if _, ok := reg.byAddr[addr]; ok {
		return 1
	}
	return 0
}

// TestReconcileRebindsADeadLegAtTheSameAddress6803 is the cell the whole issue
// turns on, and it is PAIRED.
//
// The dead leg drives the SAME desired config that is already recorded as
// converged — the smallest shape where the fingerprint gate and the liveness
// gate disagree. A fixture that also changed the address could not see the
// defect at all: `next.Addr != m.cur.addr` would be true and the rebind would
// happen either way.
//
// FAIL-ON-REVERT: restore reconcileTo's arm to a bare `next.Addr != m.cur.addr`,
// or restore ReconcileHTTP's short circuit to a bare address compare, and the
// dead leg is never rebound.
func TestReconcileRebindsADeadLegAtTheSameAddress6803(t *testing.T) {
	const addr = "127.0.0.1:8080"

	t.Run("dead-leg-is-rebound", func(t *testing.T) {
		reg := newFakeReg()
		_, m := bootMgmt6803(t, reg, addr)
		killLeg6803(t, m, reg, addr)

		// Same config the reconciler already recorded as converged.
		if err := m.reconcileTo(cfgFor(reg, addr, false, "", nil)); err != nil {
			t.Fatalf("reconcileTo: %v", err)
		}
		if !m.srv.HTTPServing() {
			t.Fatal("an UNCHANGED reconcile did not rebind the dead HTTP leg — the " +
				"management API stays down until a daemon restart even though the " +
				"operator's configuration never changed (#6803)")
		}
		if got := m.effectiveHTTPListener(); got.State != sysservices.StateListening {
			t.Errorf("`show system services` still reports the HTTP listener as %v "+
				"after a successful re-bind", got.State)
		}
	})

	t.Run("live-leg-is-not-bounced", func(t *testing.T) {
		// The over-reach direction. Widening the trigger to fire on a HEALTHY leg
		// would tear the management socket down and rebuild it on every commit and
		// on every 30s re-assert tick — an availability defect traded for an
		// availability defect.
		reg := newFakeReg()
		_, m := bootMgmt6803(t, reg, addr)
		reg.mu.Lock()
		before := reg.byAddr[addr]
		reg.mu.Unlock()

		if err := m.reconcileTo(cfgFor(reg, addr, false, "", nil)); err != nil {
			t.Fatalf("reconcileTo: %v", err)
		}
		reg.mu.Lock()
		after := reg.byAddr[addr]
		reg.mu.Unlock()
		if after != before {
			t.Fatal("an unchanged reconcile REBOUND a healthy HTTP leg; the liveness " +
				"trigger must fire on a dead leg only")
		}
		if !before.isOpen() {
			t.Fatal("the healthy listener was closed by an unchanged reconcile")
		}
	})
}

// TestMgmtListenerDownTracksTheOperatorView6803 pins the retry gate to the SAME
// question `show system services` answers.
//
// If they can disagree, the box either reports a dead listener nothing retries,
// or retries one it reports healthy. Binding the gate to StateFailed rather than
// to a second private predicate is what makes that impossible.
func TestMgmtListenerDownTracksTheOperatorView6803(t *testing.T) {
	const addr = "127.0.0.1:8080"
	reg := newFakeReg()
	d, m := bootMgmt6803(t, reg, addr)

	if d.mgmtListenerDown() {
		t.Fatal("a healthy serving listener reported DOWN; the re-assert owner " +
			"would rebind a working socket every 30s")
	}
	killLeg6803(t, m, reg, addr)
	if !d.mgmtListenerDown() {
		t.Fatal("a listener whose serve loop exited reported UP; nothing would " +
			"ever re-drive it (#6803)")
	}
	if got := m.effectiveHTTPListener().State; got != sysservices.StateFailed {
		t.Errorf("the operator view says %v while the gate says down — the two "+
			"must be the same question", got)
	}

	// No reconciler at all (--api-addr empty) must read UP, not down: an absent
	// management plane is not a failed one, and reporting it down would make the
	// owner re-drive a reconcile forever on a node that never wanted one.
	if (&Daemon{}).mgmtListenerDown() {
		t.Error("a daemon with no management reconciler reported a DOWN listener")
	}
}

// TestReassertRebindsWithoutACommit6803 is the OWNER cell: the piece that makes
// the two gate fixes reachable without an operator commit.
//
// PAIRED, because "re-drives the reconcile" is satisfied by an owner that
// re-drives unconditionally — which is the healthy-leg bounce again, now on a
// 30s timer.
func TestReassertRebindsWithoutACommit6803(t *testing.T) {
	const addr = "127.0.0.1:8080"

	t.Run("down-leg-is-re-driven", func(t *testing.T) {
		reg := newFakeReg()
		d, m := bootMgmt6803(t, reg, addr)
		killLeg6803(t, m, reg, addr)

		d.reassertMgmtListenersOnce(context.Background())

		if !m.srv.HTTPServing() {
			t.Fatal("the re-assert owner did not bring the management listener back; " +
				"the ONLY caller of reconcileWebManagement is applyConfigLocked, so " +
				"without this the endpoint returns only when an operator commits — " +
				"from a box whose management API has just died (#6803)")
		}
	})

	t.Run("healthy-leg-is-left-alone", func(t *testing.T) {
		reg := newFakeReg()
		d, m := bootMgmt6803(t, reg, addr)
		if !m.srv.HTTPServing() {
			t.Fatal("the healthy-case fixture is not serving; the case starts wrong")
		}
		reg.mu.Lock()
		before := reg.byAddr[addr]
		reg.mu.Unlock()

		d.reassertMgmtListenersOnce(context.Background())

		reg.mu.Lock()
		after := reg.byAddr[addr]
		reg.mu.Unlock()
		if after != before || !before.isOpen() {
			t.Fatal("the re-assert owner rebound a HEALTHY management listener; on a " +
				"30s ticker that is a management socket bounce every 30s forever")
		}
	})
}

// TestReassertRechecksTheGateInsideTheSemaphore6803 pins the #4001 ordering.
//
// The outer check is an optimisation; the inner one is the correctness gate. A
// tick that blocked behind an in-flight commit may find that the commit's own
// reconcile already rebound the listener — re-driving then is a redundant bind
// on a healthy socket, which is precisely what the paired cells above forbid.
//
// Every other cell drives the re-assert single-threaded, where the semaphore is
// invisible by construction, so this is the only cell that can see it.
func TestReassertRechecksTheGateInsideTheSemaphore6803(t *testing.T) {
	const addr = "127.0.0.1:8080"
	reg := newFakeReg()
	d, m := bootMgmt6803(t, reg, addr)
	killLeg6803(t, m, reg, addr)

	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Count RECONCILE CALLS, not listener outcomes. The re-drive is idempotent —
	// a reconcile against an already-healthy leg rebinds nothing — so an
	// outcome-shaped assertion cannot tell a correctly-skipped reconcile from a
	// full one run for nothing, and deleting the inner re-check left exactly that
	// assertion GREEN. The call is the observable.
	var reconciles atomic.Int64
	prev := mgmtReassertApply
	mgmtReassertApply = func(dd *Daemon, cfg *config.Config) error {
		reconciles.Add(1)
		return prev(dd, cfg)
	}
	t.Cleanup(func() { mgmtReassertApply = prev })

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		d.reassertMgmtListenersOnce(context.Background())
		close(done)
	}()
	<-started

	// Simulate the commit this tick queued behind having rebound the listener.
	if err := m.reconcileTo(cfgFor(reg, addr, false, "", nil)); err != nil {
		t.Fatalf("simulated commit reconcile: %v", err)
	}
	reg.mu.Lock()
	afterCommit := reg.byAddr[addr]
	reg.mu.Unlock()

	d.applySem.Release(1)
	<-done

	if n := reconciles.Load(); n != 0 {
		t.Fatalf("the re-assert ran %d management reconcile(s) after the commit it "+
			"queued behind had already brought the listener back — re-checking the "+
			"gate INSIDE the semaphore is what prevents that (#6803/#4001)", n)
	}
	reg.mu.Lock()
	afterReassert := reg.byAddr[addr]
	reg.mu.Unlock()
	if afterReassert != afterCommit || !afterCommit.isOpen() {
		t.Fatal("the listener the commit rebound was disturbed by the re-assert")
	}

	// POSITIVE CONTROL. Without it "ran 0 reconciles" is satisfied by an owner
	// that never reconciles at all, and the whole cell would be vacuous — the
	// gate under test is a SKIP, so it has to be shown skipping something that
	// otherwise happens.
	killLeg6803(t, m, reg, addr)
	d.reassertMgmtListenersOnce(context.Background())
	if n := reconciles.Load(); n != 1 {
		t.Fatalf("with the listener genuinely down the owner ran %d reconcile(s), "+
			"want 1 — the skip above proves nothing if the owner never reconciles", n)
	}
}

// TestRunStartsMgmtListenerReassertLoop6803 is the LOOP-START cell.
//
// Every cell above drives reassertMgmtListenersOnce directly, so a Run that
// never launched the owner would pass all of them — and "no owner" is gap 3 of
// three. #6793 shipped with exactly this hole.
//
// Run() cannot be driven from a unit test (netlink, a dataplane, sockets), so
// the start is asserted at the source with comments stripped: a source-scanning
// gate that greps for a line its own doc comment quotes is satisfied by the
// comment.
func TestRunStartsMgmtListenerReassertLoop6803(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_run.go"))

	const call = "d.mgmtListenerReassertLoop(ctx)"
	if !strings.Contains(src, call) {
		t.Fatalf("Run does not start mgmtListenerReassertLoop; a management " +
			"listener whose serve loop exited has no owner, so it comes back only " +
			"when an operator commits — from a box whose management API just died " +
			"(#6803)")
	}
	idx := strings.Index(src, call)
	window := src[clampZero6791(idx-400):idx]
	for _, gate := range []string{
		"if d.cluster != nil",
		"if d.isCluster",
		"if d.opts.ClusterEnabled",
	} {
		if strings.Contains(window, gate) {
			t.Errorf("mgmtListenerReassertLoop is started behind %q; a standalone "+
				"node's management listener dies the same way", gate)
		}
	}
}

// TestReassertLoopTicks6803 binds the loop BODY. It and the START cell fail for
// different reasons: this reds if the ticker is wired to the wrong function,
// that one reds if Run never launches it.
func TestReassertLoopTicks6803(t *testing.T) {
	const addr = "127.0.0.1:8080"
	prev := mgmtListenerReassertInterval
	mgmtListenerReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { mgmtListenerReassertInterval = prev })

	reg := newFakeReg()
	d, m := bootMgmt6803(t, reg, addr)
	killLeg6803(t, m, reg, addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.mgmtListenerReassertLoop(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.srv.HTTPServing() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("mgmtListenerReassertLoop never re-drove the dead management listener")
}
