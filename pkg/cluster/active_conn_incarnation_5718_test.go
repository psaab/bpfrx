package cluster

import (
	"testing"
)

// TestActiveConnPrefersCurrentIncarnation_5718 is the #5718 fold r4 BLOCKER 1
// fail-on-revert for connection SELECTION.
//
// The r2 stamp taught the ACK path that an installed connection can belong to
// a dead peer incarnation. The SEND path was left on raw slot occupancy:
// activeConnLocked returned conn0 whenever it was non-nil. After a peer reboot
// whose replacement dials FABRIC 1, conn0 still holds the dead incarnation's
// socket — a hard reboot sends no FIN/RST, so it stays ESTABLISHED — while
// conn1 holds the live one. Preferring conn0 hands every sender reached through
// getActiveConn a socket connected to nothing: bulk sync (which pins it once
// and streams the whole session table), config sync, failover requests and
// acks, and the session writer.
//
// Both fabric orderings run: the preference is a two-armed decision and a
// single-direction fixture would leave one arm free.
//
// #5718 fold r4b: this is now a BELT test on a directly-constructed state. The
// eviction added in r4b removes a retired incarnation's connections when the
// incarnation advances, so `installConn` can no longer leave a stale-stamped
// connection in a slot and no behavioural fixture can produce one. The
// selection guard is kept because it governs a different failure than the
// eviction does — an install path added later that forgets to evict would hand
// the senders a dead socket — so the state is built by hand here rather than
// driven, and the test is labelled a belt: it proves the guard fires, not that
// production still reaches the state.
func TestActiveConnPrefersCurrentIncarnation_5718(t *testing.T) {
	for _, tc := range []struct{ superseded, survivor int }{{1, 0}, {0, 1}} {
		t.Run(fabricPairName(tc.superseded, tc.survivor), func(t *testing.T) {
			ss := newAckTestSync(t)

			// Hand-build the post-supersession registry as it would look if the
			// eviction had not run: the current incarnation's connection in one
			// slot, the retired incarnation's still installed in the other.
			aSurv, b := pipeConn(t), pipeConn(t)
			ss.mu.Lock()
			ss.peerIncarnation = 2
			if tc.superseded == 0 {
				ss.conn0, ss.conn0Gen = b, 2
				ss.conn1, ss.conn1Gen = aSurv, 1
			} else {
				ss.conn1, ss.conn1Gen = b, 2
				ss.conn0, ss.conn0Gen = aSurv, 1
			}
			ss.mu.Unlock()

			if got := ss.connInSlot(tc.survivor); got != aSurv {
				t.Fatalf("setup: the dead incarnation's fabric-%d connection must still be "+
					"installed — that survivor is what the selection must reject", tc.survivor)
			}

			if got := ss.getActiveConn(); got != b {
				which := "the previous incarnation's stale connection"
				if got == nil {
					which = "nothing"
				}
				t.Fatalf("getActiveConn returned %s, not the current incarnation's connection "+
					"on fabric %d. Selection by raw slot occupancy prefers conn0 whenever it "+
					"is non-nil, so a fabric-1 supersession leaves every sender — bulk sync, "+
					"config sync, failover requests and acks, the session writer — writing "+
					"into a socket connected to a peer process that no longer exists",
					which, tc.superseded)
			}
		})
	}
}

// TestActiveConnFallsBackWhenNothingIsCurrent_5718 is the scope control for the
// selection change: it must not start returning nil for registries it used to
// serve.
//
// Two shapes must behave exactly as before:
//   - no supersession has happened, so every installed connection is current
//     and the historical fab0-before-fab1 preference applies unchanged;
//   - the incarnation advanced and the connection that established it has since
//     dropped, leaving only a stale sibling. Writing to that socket fails and
//     drives handleDisconnect, which cleans it up — the pre-existing
//     self-correcting path. Returning nil here would be a new behaviour, not a
//     fix.
func TestActiveConnFallsBackWhenNothingIsCurrent_5718(t *testing.T) {
	t.Run("no supersession keeps the fab0 preference", func(t *testing.T) {
		ss := newAckTestSync(t)
		c0, c1 := pipeConn(t), pipeConn(t)
		ss.installConn(0, c0)
		ss.installConn(1, c1)
		if got := ss.getActiveConn(); got != c0 {
			t.Fatal("with both connections current, fabric 0 must still be preferred")
		}
	})

	t.Run("fab1 only, still current", func(t *testing.T) {
		ss := newAckTestSync(t)
		c1 := pipeConn(t)
		ss.installConn(1, c1)
		if got := ss.getActiveConn(); got != c1 {
			t.Fatal("a lone fabric-1 connection must be selected")
		}
	})

	// #5718 fold r4b: hand-built, for the same reason as the belt test above —
	// the eviction means installConn cannot leave a stale-stamped connection in
	// a slot, so this shape is unreachable by driving the production path. It
	// still pins that the fallback exists: a selection guard that returned nil
	// instead would be a behaviour change on a registry the old code served.
	t.Run("only a stale connection remains", func(t *testing.T) {
		ss := newAckTestSync(t)
		a1 := pipeConn(t)
		ss.mu.Lock()
		ss.peerIncarnation = 2
		ss.conn1, ss.conn1Gen = a1, 1
		ss.mu.Unlock()

		if got := ss.connInSlot(1); got != a1 {
			t.Fatal("setup: the stale fabric-1 connection must still be installed")
		}
		if got := ss.getActiveConn(); got != a1 {
			t.Fatal("with no current-incarnation connection installed, selection must fall " +
				"back to the surviving connection rather than returning nil: writing to it " +
				"fails and drives handleDisconnect, which is the pre-existing " +
				"self-correcting path. Returning nil is a behaviour change, not a fix")
		}
	})
}

// TestSupersessionReArmsColdPrime_5718 is the #5718 fold r4 BLOCKER 1
// fail-on-revert for the cold-prime obligation.
//
// needColdPrime was armed only on the full-disconnect -> connect edge. A
// supersession of a CURRENT connection is positive evidence of a new peer
// process — precisely the signal #5480 records as unavailable ("the sync
// handshake carries no peer-cold / boot-incarnation / table-count signal"),
// which is why that path re-primes unconditionally. A rebooted peer has an
// EMPTY session table, so leaving the obligation unarmed means the standby
// receives no sessions and blackholes every established flow on the next
// failover to it: the #5480 blackhole through the supersession edge.
//
// shouldColdPrime is the decision handleNewConnection actually drives the bulk
// from, so that is what is asserted — arming the latch while the decision stays
// false would fix nothing.
func TestSupersessionReArmsColdPrime_5718(t *testing.T) {
	for _, fabric := range []int{0, 1} {
		t.Run(fabricPairName(fabric, 1-fabric), func(t *testing.T) {
			ss := newAckTestSync(t)

			// Incarnation A on both fabrics, with its cold prime already
			// discharged — the steady state a running cluster sits in.
			a0, a1 := pipeConn(t), pipeConn(t)
			ss.installConn(0, a0)
			ss.installConn(1, a1)
			ss.needColdPrime.Store(false)

			// A reboots; its replacement takes one fabric.
			b := pipeConn(t)
			d := ss.installConn(fabric, b)

			if !ss.needColdPrime.Load() {
				t.Fatal("superseding a CURRENT connection is evidence of a new peer process " +
					"with an empty session table, so the cold-prime obligation must be " +
					"re-armed. Leaving it disarmed strands the standby with no synced " +
					"sessions and blackholes every established flow on the next failover")
			}
			if !d.shouldColdPrime {
				t.Fatalf("the install decision must drive a cold-prime bulk (becameActive=%v, "+
					"activeAfter=%d, fabric=%d). Arming the latch is not enough: "+
					"handleNewConnection runs the bulk off shouldColdPrime, and computing "+
					"activeAfter from raw slot occupancy leaves the stale sibling looking "+
					"active, so becameActive stays false and the bulk is skipped",
					d.becameActive, d.activeAfter, fabric)
			}
		})
	}
}

// TestRoutineInstallDoesNotReArmColdPrime_5718 is the scope control for the
// cold-prime change: only a supersession of a CURRENT connection is evidence of
// a new peer. A fabric link coming up into an EMPTY slot beside a live one is
// the same peer process, and re-priming there would re-run a full bulk on every
// routine fabric flap — the #466 flap-suppression the existing code preserves.
//
// This pins the ROUTINE reading DELIBERATELY. A peer that REBOOTED and whose
// replacement enters through this same empty slot presents identically to a
// local observer, and it is the one reboot shape occupancy-based classification
// cannot see — tracked as #6910, blocked on #6669's peer-supplied boot epoch.
// Do not "fix" this test into failing to close that case: arming the cold prime
// on every empty-slot install re-bulks the whole session table on every link
// flap. See pkg/cluster/README.md, "ACCEPTED RESIDUAL".
func TestRoutineInstallDoesNotReArmColdPrime_5718(t *testing.T) {
	ss := newAckTestSync(t)

	c0 := pipeConn(t)
	ss.installConn(0, c0)
	ss.needColdPrime.Store(false)

	// Fabric 1 comes up into an empty slot beside the live fabric 0.
	c1 := pipeConn(t)
	d := ss.installConn(1, c1)

	if ss.needColdPrime.Load() {
		t.Fatal("a fabric link filling an EMPTY slot beside a live one is the same peer " +
			"process, not a new incarnation. Re-arming the cold prime there re-runs a full " +
			"bulk sync on every routine fabric flap")
	}
	if d.shouldColdPrime {
		t.Fatal("no cold-prime bulk may be driven for a routine second-fabric install")
	}
}
