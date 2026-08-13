package userspace

import (
	"testing"
	"time"
)

// #6871 round 8 B2: the lease renews ITSELF, so the TTL bounds a constant.
//
// THE MEASUREMENT THAT FORCED THIS. Round 7's TTL comment claimed 60s was "3x
// the only bounded term" — true, and still not a bound, because the other terms
// in the same interval scale with things an operator sets:
//
//	finishRethMemberLinkTail   one pass per CHILD NETDEV of the member; a member
//	                           can carry one VLAN sub-interface per VLAN id, and
//	                           each pass is a sysctl write plus up to three
//	                           netlink round trips
//	reconcileAfterRethLinkCycle one pass per REDUNDANCY GROUP
//	the enclosing loop          up to reth-count, schema ceiling 128
//	any netlink syscall         no elapsed-time bound whatsoever
//
// The last of those is the one no amount of call-site renewal can reach: a
// single blocking syscall sits between two renewals by construction. A heartbeat
// does reach it, because it renews from a different goroutine.
//
// So the interval the TTL must cover is now linkCycleLeaseHeartbeat — a
// constant — and the cardinality above is irrelevant to it. These cells drive
// beats through the same seam production uses.

// fakeLinkCycleHeartbeat replaces the beat source with a channel the test
// drives, and returns a func that delivers ONE beat and waits for the heartbeat
// goroutine to have consumed it. Without that wait the assertions would race the
// goroutine rather than observe it.
func fakeLinkCycleHeartbeat(t *testing.T) func() {
	t.Helper()
	beats := make(chan time.Time)
	old := linkCycleHeartbeatTicker
	linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) {
		return beats, func() {}
	}
	t.Cleanup(func() { linkCycleHeartbeatTicker = old })
	return func() {
		t.Helper()
		select {
		case beats <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatal("the heartbeat goroutine never consumed a beat; it is not running")
		}
	}
}

// TestLinkCycleLeaseRenewsItself_6871 is the B2 discriminator.
//
// The fixture holds a lease across FOUR full TTLs with no daemon renewal
// anywhere — no programRethMemberMAC, no finishRethMemberLinkTail, no
// reconcileAfterRethLinkCycle. That models the case the call-site renewals
// structurally cannot cover: one step of step 2.6 that takes longer than the TTL
// on its own, whether because the member carries thousands of VLAN children or
// because a single netlink syscall blocked.
//
// RED-on-revert: delete `m.startLinkCycleHeartbeat()` from
// acquireLinkCycleLease and this fails at "expired while the cycle was still
// running".
func TestLinkCycleLeaseRenewsItself_6871(t *testing.T) {
	advance := fakeLinkCycleClock(t)
	beat := fakeLinkCycleHeartbeat(t)

	m := New()
	t.Cleanup(m.releaseLinkCycleLease)
	m.acquireLinkCycleLease()

	// Four TTLs of ONE uninterruptible step, beating on schedule throughout.
	for i := 0; i < 4*int(linkCycleLeaseTTL/linkCycleLeaseHeartbeat); i++ {
		advance(linkCycleLeaseHeartbeat)
		beat()
		if !m.linkCycleInFlight() {
			t.Fatalf("the lease expired while the cycle was still running, after %s of a "+
				"single step-2.6 operation with the heartbeat beating every %s. The "+
				"heartbeat is what makes the TTL bound a CONSTANT instead of an interval "+
				"that scales with VLAN-child count, redundancy-group count, reth-count and "+
				"netlink latency — none of which any constant bounds (#6871 round 8 B2)",
				time.Duration(i+1)*linkCycleLeaseHeartbeat, linkCycleLeaseHeartbeat)
		}
	}
}

// TestLinkCycleHeartbeatStopsOnRelease_6871 is the over-reach control, and the
// reason the deferred abandon in pkg/daemon is not optional.
//
// A heartbeat that outlived its lease would re-arm a deadline nobody is obliged
// to release — the 1 Hz reconcile suppressed permanently, which is strictly
// worse than the race the lease closes. Release must therefore JOIN the
// goroutine, not merely signal it.
//
// It stays GREEN under the revert above (no heartbeat, nothing to leak), so it
// is a control rather than a restatement of the discriminator.
func TestLinkCycleHeartbeatStopsOnRelease_6871(t *testing.T) {
	beats := make(chan time.Time)
	stopped := false
	old := linkCycleHeartbeatTicker
	linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) {
		return beats, func() { stopped = true }
	}
	t.Cleanup(func() { linkCycleHeartbeatTicker = old })

	m := New()
	m.acquireLinkCycleLease()
	m.releaseLinkCycleLease()

	if !stopped {
		t.Error("releasing the lease left the beat source running; the goroutine outlives " +
			"the cycle it was renewing")
	}
	// The goroutine is joined, so nothing is left to receive. A send that
	// succeeded here would mean a beat could still land after release.
	select {
	case beats <- time.Now():
		t.Error("a beat was consumed AFTER the lease was released: the heartbeat goroutine " +
			"is still live, so a lease NotifyLinkCycle ended could be re-armed by it")
	default:
	}
	if m.linkCycleInFlight() {
		t.Error("the lease survived its release")
	}
}

// TestLinkCycleHeartbeatCannotResurrectAReleasedLease_6871 pins the interaction
// between the round-8 heartbeat and the property Codex confirmed sound in round
// 7 — RenewLinkCycle never CASes from the 0 sentinel.
//
// The heartbeat is a renewal like any other, so if that property were weakened
// the heartbeat would be the loudest way to notice: it would re-open a lease
// that NotifyLinkCycle had already ended, with nothing obliged to release it.
// This cell drives a beat at a manager whose lease is gone and requires nothing
// to come back.
func TestLinkCycleHeartbeatCannotResurrectAReleasedLease_6871(t *testing.T) {
	fakeLinkCycleClock(t)
	beat := fakeLinkCycleHeartbeat(t)

	m := New()
	m.acquireLinkCycleLease()
	// Retire the lease WITHOUT stopping the heartbeat, which is the only way to
	// get a beat and an absent lease at the same instant. Production cannot
	// reach this state (release stops the goroutine first); the point is that
	// even if it could, the beat is inert.
	m.linkCycleLeaseUntil.Store(0)

	beat()

	if m.linkCycleInFlight() {
		t.Error("a heartbeat beat re-opened a lease that was already retired. RenewLinkCycle " +
			"must never CAS from the 0 sentinel — otherwise the heartbeat becomes a way to " +
			"suppress the 1 Hz reconcile with no cycle in flight and nothing to end it")
	}
	if until := m.linkCycleLeaseUntil.Load(); until != 0 {
		t.Errorf("linkCycleLeaseUntil = %d, want the 0 sentinel", until)
	}
	m.releaseLinkCycleLease()
}

// TestAbandonLinkCycleReportsAndDropsTheLease_6871 binds the Manager half of the
// daemon's guaranteed release.
//
// The bool is not decoration: it is the only signal that a code path took a
// lease and did not release it, which is a bug in that path. The daemon logs on
// it (abandonLinkCycleLease), so a method that always returned false would make
// a real leak silent while still fixing it.
//
// RED-on-revert: make Manager.AbandonLinkCycle `return false` (keeping the
// release) and the held arm fails at "reported that no lease was held".
func TestAbandonLinkCycleReportsAndDropsTheLease_6871(t *testing.T) {
	t.Run("lease_held", func(t *testing.T) {
		fakeLinkCycleClock(t)
		m := New()
		m.acquireLinkCycleLease()

		if !m.AbandonLinkCycle() {
			t.Error("reported that no lease was held while one was; the daemon logs on this " +
				"return, so a leak between PrepareLinkCycle and NotifyLinkCycle would be " +
				"repaired silently and never diagnosed")
		}
		if m.linkCycleInFlight() {
			t.Error("the lease survived AbandonLinkCycle")
		}
	})
	t.Run("no_lease", func(t *testing.T) {
		fakeLinkCycleClock(t)
		m := New()

		if m.AbandonLinkCycle() {
			t.Error("reported a held lease on a manager that never took one; every commit " +
				"runs this defer, so a true here would log a spurious dataplane error on " +
				"the overwhelmingly common apply that cycles nothing")
		}
	})
	t.Run("stops_the_heartbeat", func(t *testing.T) {
		beats := make(chan time.Time)
		stopped := false
		old := linkCycleHeartbeatTicker
		linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) {
			return beats, func() { stopped = true }
		}
		t.Cleanup(func() { linkCycleHeartbeatTicker = old })

		m := New()
		m.acquireLinkCycleLease()
		m.AbandonLinkCycle()

		if !stopped {
			t.Error("abandoning the lease left its heartbeat running: the leak this call " +
				"exists to repair would keep re-arming a deadline with nobody to release it")
		}
	})
}

// TestLinkCycleLeaseTTLIsAMultipleOfTheHeartbeat_6871 pins the relationship the
// TTL's guarantee now rests on.
//
// Since round 8 the TTL is not an estimate of how long a step of step 2.6 takes
// — it is a multiple of the self-renewal period, and that is the whole of what
// makes it a bound. A change that raised the heartbeat to meet or exceed the TTL
// would silently restore the round-7 situation (an expiry that can fire during a
// live cycle) while every other cell here stayed green, because the fixtures
// drive beats explicitly rather than waiting for them.
func TestLinkCycleLeaseTTLIsAMultipleOfTheHeartbeat_6871(t *testing.T) {
	if linkCycleLeaseHeartbeat <= 0 {
		t.Fatalf("linkCycleLeaseHeartbeat = %s; a non-positive period never renews",
			linkCycleLeaseHeartbeat)
	}
	if missed := linkCycleLeaseTTL / linkCycleLeaseHeartbeat; missed < 3 {
		t.Errorf("the TTL (%s) allows only %d missed beats at a %s period. It must tolerate "+
			"at least three — a saturated box, a GC pause and a descheduled goroutine are "+
			"all routine — or the backstop fires on a cycle that is still running, which is "+
			"the round-7 defect this replaced",
			linkCycleLeaseTTL, missed, linkCycleLeaseHeartbeat)
	}
}
