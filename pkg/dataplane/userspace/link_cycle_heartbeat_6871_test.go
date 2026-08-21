package userspace

import (
	"runtime"
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
// drives, and returns a func that delivers ONE beat and waits for its EFFECT.
//
// #6871 round 9 (F3): an earlier revision of this comment said the func "waits
// for the heartbeat goroutine to have consumed it", and that is not what an
// unbuffered send buys. The send returns at the RENDEZVOUS — the goroutine has
// received the value and nothing more; RenewLinkCycle has not run yet. Every
// assertion placed after a beat was therefore racing the renewal it was there to
// observe. What synchronises correctly is waiting for the OBSERVABLE: the lease
// deadline reaching what a renewal at the current clock would set. That is a
// property of production state rather than of goroutine scheduling, so it cannot
// go stale if the heartbeat body changes.
func fakeLinkCycleHeartbeat(t *testing.T, m *Manager) func() {
	t.Helper()
	beats := make(chan time.Time)
	old := linkCycleHeartbeatTicker
	linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) {
		return beats, func() {}
	}
	t.Cleanup(func() { linkCycleHeartbeatTicker = old })
	return func() {
		t.Helper()
		if !deliverLinkCycleBeat(t, m, beats) {
			t.Fatal("the heartbeat goroutine never consumed a beat; it is not running")
		}
	}
}

// deliverLinkCycleBeat sends one beat and waits for the renewal it should cause,
// reporting whether the beat was consumed at all. Split out from the helper
// above so a test can assert on a beat that is EXPECTED to go unconsumed
// (F1) without taking the helper's t.Fatal.
func deliverLinkCycleBeat(t *testing.T, m *Manager, beats chan time.Time) bool {
	t.Helper()
	select {
	case beats <- time.Now():
	case <-time.After(2 * time.Second):
		return false
	}
	// A renewal only moves the word when a lease is live; with none held there
	// is no observable to wait for and the rendezvous is all there is.
	want := linkCycleLeaseDeadline()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		until := m.linkCycleLeaseUntil.Load()
		if until == 0 || until >= want {
			return true
		}
		runtime.Gosched()
	}
	t.Fatalf("the beat was consumed but the lease deadline never reached %d (still %d): "+
		"the heartbeat goroutine received the tick and did not renew", want,
		m.linkCycleLeaseUntil.Load())
	return false
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
	m := New()
	beat := fakeLinkCycleHeartbeat(t, m)
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
	m := New()
	beats := make(chan time.Time)
	oldTicker := linkCycleHeartbeatTicker
	linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) { return beats, func() {} }
	t.Cleanup(func() { linkCycleHeartbeatTicker = oldTicker })
	beat := func() {
		t.Helper()
		if !deliverLinkCycleBeat(t, m, beats) {
			t.Fatal("the heartbeat goroutine never consumed a beat; it is not running")
		}
	}
	m.acquireLinkCycleLease()
	// Retire the lease WITHOUT stopping the heartbeat, which is the only way to
	// get a beat and an absent lease at the same instant. Production cannot
	// reach this state (release stops the goroutine first); the point is that
	// even if it could, the beat is inert.
	m.linkCycleLeaseUntil.Store(0)

	beat()
	// SIBLING OF THE F1 FIXTURE RACE, swept rather than left (#6871 round 9).
	// deliverLinkCycleBeat returns at the RENDEZVOUS when no lease is held —
	// there is no deadline for it to wait on — so an assertion placed straight
	// after it can run BEFORE RenewLinkCycle has executed, and "nothing came
	// back" would then be true only because nothing had happened yet. The
	// heartbeat loop is single-threaded, so a SECOND beat can only be received
	// once the first iteration is complete: that rendezvous is the
	// happens-before this cell needs.
	if !deliverLinkCycleBeat(t, m, beats) {
		t.Fatal("fixture: the heartbeat stopped after one beat, so the first beat's effect " +
			"was never established and the assertion below would be vacuous")
	}

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

// TestLinkCycleHeartbeatSurvivesTheTTLBackstop_6871 is the round-9 F1
// discriminator: the heartbeat must still be renewing AFTER the TTL backstop has
// retired a starved lease.
//
// THE DEFECT. The round-8 heartbeat loop self-reaped on `linkCycleLeaseUntil ==
// 0` and returned WITHOUT clearing linkCycleHB.stop/done, while
// startLinkCycleHeartbeat's idempotence guard tests that FIELD rather than
// goroutine liveness. So after one self-reap the field is non-nil with nothing
// running, and every later acquireLinkCycleLease in the same apply silently
// starts no heartbeat at all — leaving every RETH member cycled after that point
// on round-7 protection, which the TTL comment argues is not survivable at
// operator-controlled cardinality.
//
// THE TRIGGER IS THE ONE THIS ROUND IS BUILT AROUND, which is why a bare
// `Store(0)` is the wrong way to drive it. The word reaches 0 in production two
// ways: releaseLinkCycleLease (which stops the heartbeat properly, so no reap can
// follow) and linkCycleInFlight's backstop CAS after four missed beats — exactly
// the starvation the 4x margin exists to absorb. This cell therefore fires the
// REAL backstop, through the production reader, and never writes the word itself.
// TestLinkCycleHeartbeatCannotResurrectAReleasedLease_6871 above does write it
// directly, and that is why it drives the same reap while MASKING this defect:
// it releases afterwards, and release resets the fields.
//
// RED-on-revert: restore the `if m.linkCycleLeaseUntil.Load() == 0 { return }`
// arm in startLinkCycleHeartbeat's loop and this fails at "the second lease has
// no live heartbeat".
func TestLinkCycleHeartbeatSurvivesTheTTLBackstop_6871(t *testing.T) {
	advance := fakeLinkCycleClock(t)
	m := New()
	beats := make(chan time.Time)
	old := linkCycleHeartbeatTicker
	linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) { return beats, func() {} }
	t.Cleanup(func() { linkCycleHeartbeatTicker = old })
	t.Cleanup(m.releaseLinkCycleLease)

	// Member N cycles: a lease and its heartbeat.
	m.acquireLinkCycleLease()

	// Four missed beats. Nothing renews, so the lease is past its deadline.
	advance(linkCycleLeaseTTL + time.Second)

	// The PRODUCTION reader fires the backstop CAS and retires the lease. This
	// is the whole point of the fixture: the word goes to 0 the way it does on a
	// real box, not because a test wrote it.
	if m.linkCycleInFlight() {
		t.Fatal("fixture: the backstop did not expire a lease that is a full TTL overdue")
	}
	if until := m.linkCycleLeaseUntil.Load(); until != 0 {
		t.Fatalf("fixture: the backstop must retire the deadline to 0, got %d", until)
	}

	// The starved heartbeat now wakes on a lease that is already gone.
	if !deliverLinkCycleBeat(t, m, beats) {
		t.Fatal("fixture: the heartbeat was not running before the backstop fired")
	}

	// SYNCHRONISE ON THE REAP, or the fixture races the defect instead of
	// driving it. deliverLinkCycleBeat returns as soon as the beat is consumed,
	// which is BEFORE the loop re-reads the lease word — so a re-acquire that
	// lands first stores a non-zero deadline, the reap arm does not fire, and
	// the whole cell passes while the bug is fully present. (Measured: the
	// discriminator passed on the unfixed code until this wait was added.)
	//
	// Bounded both ways on purpose: under round 8 the goroutine closes `done`
	// promptly, and under either accepted fix it never exits at all, so the
	// timeout arm is the expected path for a correct implementation rather than
	// a failure.
	m.linkCycleHB.mu.Lock()
	done := m.linkCycleHB.done
	m.linkCycleHB.mu.Unlock()
	select {
	case <-done:
	case <-time.After(250 * time.Millisecond):
	}

	// Member N+1 of the SAME apply cycles: a second lease, which needs a
	// heartbeat just as much as the first.
	m.acquireLinkCycleLease()
	if !m.linkCycleInFlight() {
		t.Fatal("fixture: the second acquire did not open a lease")
	}

	// The observable: is anything still renewing? Advance most of a TTL, beat,
	// and require the lease to survive past its ORIGINAL deadline.
	advance(linkCycleLeaseTTL - time.Second)
	if !deliverLinkCycleBeat(t, m, beats) {
		t.Fatal("the second lease has no live heartbeat: nothing consumed a beat. The " +
			"heartbeat goroutine reaped itself when the TTL backstop retired the FIRST " +
			"lease, and left linkCycleHB.stop non-nil — so startLinkCycleHeartbeat's " +
			"field-based idempotence guard now short-circuits forever. Every RETH member " +
			"cycled later in this apply runs with round-7 protection only (#6871 round 9 F1)")
	}
	advance(2 * time.Second)
	if !m.linkCycleInFlight() {
		t.Error("the second lease expired on its original schedule despite a beat: the " +
			"heartbeat is running but not renewing")
	}
}

// TestLinkCycleHeartbeatIdempotenceTracksLiveness_6871 is the structural control
// for F1, and it is what stops the defect coming back in a different shape.
//
// The bug was not the self-reap as such — it was that ONE half of a pair moved.
// startLinkCycleHeartbeat's early return and stopLinkCycleHeartbeat's field clear
// are a matched pair, and any exit path that ends the goroutine without going
// through the second one desynchronises them. So rather than asserting "there is
// no self-reap", this asserts the invariant that made the self-reap unsafe:
// whenever linkCycleHB.stop is non-nil, a goroutine is actually there to receive.
//
// It stays GREEN under the F1 revert only if that revert also clears the fields,
// which is the other acceptable fix — so it is a genuine invariant rather than a
// restatement of one implementation.
func TestLinkCycleHeartbeatIdempotenceTracksLiveness_6871(t *testing.T) {
	advance := fakeLinkCycleClock(t)
	m := New()
	beats := make(chan time.Time)
	old := linkCycleHeartbeatTicker
	linkCycleHeartbeatTicker = func() (<-chan time.Time, func()) { return beats, func() {} }
	t.Cleanup(func() { linkCycleHeartbeatTicker = old })
	t.Cleanup(m.releaseLinkCycleLease)

	m.acquireLinkCycleLease()
	advance(linkCycleLeaseTTL + time.Second)
	m.linkCycleInFlight() // backstop retires the lease
	deliverLinkCycleBeat(t, m, beats)

	m.linkCycleHB.mu.Lock()
	armed := m.linkCycleHB.stop != nil
	m.linkCycleHB.mu.Unlock()
	if !armed {
		return // the fields were cleared: the pair is still matched, nothing to check
	}
	// The guard says a heartbeat is armed. Then one must be receiving.
	if !deliverLinkCycleBeat(t, m, beats) {
		t.Error("linkCycleHB.stop is non-nil but no goroutine is receiving beats. That " +
			"field IS startLinkCycleHeartbeat's idempotence guard, so a later acquire " +
			"will take the early return and start nothing: the lease it opens is never " +
			"renewed and only the TTL backstop bounds it")
	}
}

// TestStatusTickResumesAfterAbandon_6871 binds the half of AbandonLinkCycle's
// recovery claim that a test CAN reach (#6871 round 9, F6).
//
// Nothing exercised the abandon path before this: TestStatusTickResumesAfterLinkCycle_6871
// drives Prepare -> Notify, which is the clean cycle, and the leaked-lease path
// the daemon's deferred release exists for was reached by no cell at all.
//
// SCOPE, stated because the doc used to overclaim it. What is asserted here is
// that abandoning UN-SUPPRESSES the reconcile — the 1 Hz tick, which skips its
// whole body while a lease is held, starts polling again. What is NOT asserted
// is how long forwarding takes to come back: the busy-binding auto-rebind that
// recreates workers needs lastStatus.ForwardingArmed, a wedge observed for >= 5s
// and a 15s rate limit (shouldAutoRebindBusyBindingsLocked, maps_sync.go), so
// that is a multi-producer property against a live helper and is seconds rather
// than one tick. A map-free fixture cannot reach it, and a cell that pretended
// to would be worse than this one.
//
// RED-on-revert: make Manager.AbandonLinkCycle's body `return false` without the
// release and this fails at "the tick never resumed".
func TestStatusTickResumesAfterAbandon_6871(t *testing.T) {
	fastStatusLoop(t, 20*time.Millisecond)
	m, srv := newLeaseTestManager(t)

	runStatusLoop(t, m)
	waitForRequest(t, srv, "status", 2*time.Second)

	if err := m.PrepareLinkCycle(); err != nil {
		t.Fatalf("PrepareLinkCycle: %v", err)
	}

	// CONTROL: the suppression has to be real, or "it resumed" proves nothing.
	// The status request lives INSIDE the linkCycleInFlight gate at the top of
	// the tick body (process_status.go), so a held lease means no new ones.
	base := len(srv.requests())
	time.Sleep(150 * time.Millisecond)
	if grew := len(srv.requests()) - base; grew != 0 {
		t.Fatalf("fixture: %d requests arrived while the lease was held; the tick is not "+
			"suppressed, so the resume assertion below would pass either way", grew)
	}

	// The leak path: the apply is leaving with the lease still held.
	if !m.AbandonLinkCycle() {
		t.Fatal("AbandonLinkCycle reported no lease held while PrepareLinkCycle had just " +
			"taken one")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if len(srv.requests()) > base {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tick never resumed after the lease was abandoned (still %d "+
				"requests). A leaked lease now renews ITSELF, so nothing else will ever "+
				"expire it: the reconcile stays suppressed for the life of the process "+
				"and the workers a cycle joined are never re-armed", len(srv.requests()))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCtrlMustStayDisabledDuringLinkCycle_6871 gives the ctrl gate its first
// coverage that actually EXECUTES unprivileged (#6871 round 9, F4).
//
// The clause `|| m.linkCycleInFlight()` in applyHelperStatusLocked's ctrl branch
// is what stops UpdateRGActive — driven by VRRP events and by
// reconcileRGStateLoop's 2s pass, neither serialized on the daemon's applySem —
// from re-enabling ctrl in the middle of a link cycle, pointing the shim at XSK
// sockets whose queues are about to be destroyed. Deleting it left both packages
// fully green, because the three cells that cover it need real BPF maps and SKIP
// without root, and Go reports a parent as PASS when every subtest skipped.
//
// The truth table is exhaustive over the three inputs, so a mutation to ANY
// disjunct — dropping the link-cycle term, dropping the RG-transition term, or
// dropping the status.Enabled conjunct — changes at least one row.
//
// RED-on-revert: delete `|| m.linkCycleInFlight()` and the
// enabled/no_rg/link_cycle row fails.
func TestCtrlMustStayDisabledDuringLinkCycle_6871(t *testing.T) {
	for _, tc := range []struct {
		name         string
		statusOn     bool
		rgTransition bool
		linkCycle    bool
		want         bool
	}{
		{"disabled/no_rg/no_cycle", false, false, false, false},
		{"disabled/rg/no_cycle", false, true, false, false},
		{"disabled/no_rg/link_cycle", false, false, true, false},
		{"disabled/rg/link_cycle", false, true, true, false},
		{"enabled/no_rg/no_cycle", true, false, false, false},
		{"enabled/rg/no_cycle", true, true, false, true},
		{"enabled/no_rg/link_cycle", true, false, true, true},
		{"enabled/rg/link_cycle", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeLinkCycleClock(t)
			m := New()
			t.Cleanup(m.releaseLinkCycleLease)
			m.rgTransitionInFlight.Store(tc.rgTransition)
			if tc.linkCycle {
				m.acquireLinkCycleLease()
			}

			if got := m.ctrlMustStayDisabledLocked(tc.statusOn); got != tc.want {
				t.Errorf("ctrlMustStayDisabledLocked(%v) with rgTransition=%v linkCycle=%v "+
					"= %v, want %v. This is the gate that keeps ctrl at 0 while a RETH MAC "+
					"link cycle owns the dataplane; a false here re-enables the XDP shim's "+
					"redirect into XSK sockets whose queues the cycle is about to destroy, "+
					"and UpdateRGActive reaches it off the applySem so the tick's own lease "+
					"skip does not cover it",
					tc.statusOn, tc.rgTransition, tc.linkCycle, got, tc.want)
			}
		})
	}
}
