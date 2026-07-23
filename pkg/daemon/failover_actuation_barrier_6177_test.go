package daemon

import (
	"context"
	"testing"
	"time"
)

// #6177 — the daemon-side companion to the VRRP resign-completion barrier.
//
// The #5640 fence-completion barrier (armFailoverActuation / waitFailoverActuated
// / signalFailoverActuated) withholds the peer's remote-failover applied-ack until
// the local demotion is actuated. #6177 (a) gates the RETH release on the VRRP
// resign VIPs being PHYSICALLY removed (releaseFailoverActuationAfterResign waits
// on the resign barriers) and (b) hardens disarm to an identity check so an older
// timed-out waiter can never drop a newer waiter's entry. These tests exercise
// the daemon barrier directly — the coverage gap #5640's hostile review flagged
// (residual #3) — with no cluster or VRRP manager.

// TestReleaseFailoverActuationWaitsForResign_6177 is the primary fail-on-revert
// guard: the applied-ack must NOT release until the RETH resign barrier closes
// (VIPs physically removed), then it releases cleanly.
//
// RED on revert: making releaseFailoverActuationAfterResign call
// signalFailoverActuated without first waiting on the resign barriers (the
// pre-#6177 behavior, where watchClusterEvents signalled immediately after the
// non-blocking ResignRG) releases the ack inside the 150ms window below — the
// "released before the RETH resign completed" assertion then fires.
func TestReleaseFailoverActuationWaitsForResign_6177(t *testing.T) {
	d := &Daemon{failoverActuateTimeout: 5 * time.Second}
	const rg = 1
	d.armFailoverActuation(rg)

	ackErr := make(chan error, 1)
	go func() { ackErr <- d.waitFailoverActuated(rg) }()

	resign := make(chan struct{})
	go d.releaseFailoverActuationAfterResign(context.Background(), rg, []<-chan struct{}{resign})

	// The ack is held while the RETH VIP removal is still in flight.
	select {
	case err := <-ackErr:
		t.Fatalf("applied-ack released before the RETH resign completed (the #6177 window): err=%v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(resign) // VIPs physically removed
	select {
	case err := <-ackErr:
		if err != nil {
			t.Fatalf("ack should release cleanly once the resign completed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ack never released after the resign barrier closed")
	}
}

// TestReleaseFailoverActuation_TimeoutLeavesAckToPeerSide_6177 pins the safe-
// direction leak guard: if a resign barrier never closes (a persistent VIP-remove
// failure), releaseFailoverActuationAfterResign must NOT signal — it leaves the
// ack to the peer-side waitFailoverActuated timeout so the peer HOLDS rather than
// promotes over a stale VIP. The barrier entry therefore stays armed (the peer
// side, not this goroutine, disarms it on its own timeout).
func TestReleaseFailoverActuation_TimeoutLeavesAckToPeerSide_6177(t *testing.T) {
	// budget = 2 * failoverActuateTimeout = 40ms, so the release goroutine gives
	// up quickly for the test.
	d := &Daemon{failoverActuateTimeout: 20 * time.Millisecond}
	const rg = 2
	ch := d.armFailoverActuation(rg)

	stuck := make(chan struct{}) // never closes — removal never confirms
	done := make(chan struct{})
	go func() {
		d.releaseFailoverActuationAfterResign(context.Background(), rg, []<-chan struct{}{stuck})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("release goroutine did not give up on the stuck barrier")
	}

	// It must not have signalled: the entry the peer side waits on is intact.
	d.failoverActuateMu.Lock()
	cur, present := d.failoverActuateWait[rg]
	d.failoverActuateMu.Unlock()
	if !present || cur != ch {
		t.Fatal("release goroutine signalled/dropped the barrier on timeout; the peer-side " +
			"timeout must own the safe HOLD, not a premature release")
	}
}

// TestFailoverActuationBarrier_SignalReleasesAndCleansUp_6177 pins the arm →
// wait → signal → cleanup semantics (residual #3 coverage): the waiter releases
// with no error and the barrier entry is deleted (no stale-channel leak).
func TestFailoverActuationBarrier_SignalReleasesAndCleansUp_6177(t *testing.T) {
	d := &Daemon{failoverActuateTimeout: 2 * time.Second}
	const rg = 7
	d.armFailoverActuation(rg)

	ackErr := make(chan error, 1)
	go func() { ackErr <- d.waitFailoverActuated(rg) }()
	d.signalFailoverActuated(rg)

	select {
	case err := <-ackErr:
		if err != nil {
			t.Fatalf("signal path: want nil, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("signalFailoverActuated did not release the waiter")
	}

	d.failoverActuateMu.Lock()
	_, present := d.failoverActuateWait[rg]
	d.failoverActuateMu.Unlock()
	if present {
		t.Fatal("signalFailoverActuated must delete the barrier entry (no stale-channel leak)")
	}
}

// TestFailoverActuationBarrier_TimeoutDowngradesAndCleansUp_6177 pins the
// bounded-wait downgrade: with no actuation signal the waiter returns an error
// (the ack downgrades to failed instead of hanging) and the stranded barrier is
// disarmed.
func TestFailoverActuationBarrier_TimeoutDowngradesAndCleansUp_6177(t *testing.T) {
	d := &Daemon{failoverActuateTimeout: 40 * time.Millisecond}
	const rg = 8
	d.armFailoverActuation(rg)

	if err := d.waitFailoverActuated(rg); err == nil {
		t.Fatal("waitFailoverActuated must return an error when the demotion is never actuated")
	}

	d.failoverActuateMu.Lock()
	_, present := d.failoverActuateWait[rg]
	d.failoverActuateMu.Unlock()
	if present {
		t.Fatal("the timeout path must disarm the stranded barrier (no stale-channel leak)")
	}
}

// TestFailoverActuationDisarmIdentityChecked_6177 is the delete-by-key hardening
// fail-on-revert guard (residual #2): a disarm keyed on an OLDER waiter's channel
// must not delete a NEWER overlapping waiter's entry.
//
// RED on revert: dropping the identity check in disarmFailoverActuation (reverting
// to the key-only `delete(d.failoverActuateWait, rgID)`) deletes ch2 — the
// assertion that the newer entry survives then fails, and the newer ack would
// spuriously fail.
func TestFailoverActuationDisarmIdentityChecked_6177(t *testing.T) {
	d := &Daemon{}
	const rg = 5
	ch1 := d.armFailoverActuation(rg)
	ch2 := d.armFailoverActuation(rg) // a newer overlapping waiter replaced the entry
	if ch1 == ch2 {
		t.Fatal("each arm must create a distinct channel")
	}

	// The older waiter's timeout-disarm passes ITS channel (ch1); the entry now
	// holds ch2, so nothing must be deleted.
	d.disarmFailoverActuation(rg, ch1)

	d.failoverActuateMu.Lock()
	cur, present := d.failoverActuateWait[rg]
	d.failoverActuateMu.Unlock()
	if !present || cur != ch2 {
		t.Fatal("a disarm keyed on a stale channel deleted the newer waiter's entry " +
			"(#6177 delete-by-key hazard): the newer ack would spuriously fail")
	}

	// The newer waiter still releases normally through signal.
	ackErr := make(chan error, 1)
	go func() { ackErr <- d.waitFailoverActuated(rg) }()
	d.signalFailoverActuated(rg)
	select {
	case err := <-ackErr:
		if err != nil {
			t.Fatalf("newer waiter: want nil, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("newer waiter never released")
	}
}
