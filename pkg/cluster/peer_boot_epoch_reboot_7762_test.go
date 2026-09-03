package cluster

import "testing"

// #7762: the EMPTY-alternate-slot peer reboot.
//
// A replacement that dials the empty alternate slot while the dead process's
// socket sits ESTABLISHED in the other one supersedes nothing and leaves the
// registry non-empty, so it satisfies neither `supersededCurrent` nor
// `wasDisconnected`. Pre-#7762 nothing advanced the incarnation, the corpse
// stayed "current", and `preferredFabricLocked` kept choosing dead fabric 0.
//
// These cells assert on the CHOSEN FABRIC, not on the incarnation stamp. The
// stamp is the mechanism; the choice is the property, and a future change that
// retires the incarnation differently must still land on the live connection.

// epochSource is a settable PeerBootEpochFn. Returning both values from one
// place keeps a test from constructing the incoherent (0, true) pair that the
// single-lock accessor exists to prevent.
type epochSource struct {
	epoch   uint64
	latched bool
}

func (e *epochSource) fn() (uint64, bool) { return e.epoch, e.latched }

// The headline property. RED on revert: drop `|| epochReboot` from installConn's
// advance condition and the corpse keeps fabric 0.
func TestEmptyAlternateSlotRebootPrefersTheReplacement_7762(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	// Incarnation A comes up on fabric 0 and establishes the baseline.
	corpse := pipeConn(t)
	ss.installConn(0, corpse)
	if got := ss.getActiveConn(); got != corpse {
		t.Fatalf("setup: fabric 0 must be active before the reboot, got %v", got)
	}

	// The peer reboots. Its heartbeat raises the floor; the replacement dials
	// the EMPTY alternate slot. Fabric 0 is never superseded and the registry
	// never empties — the two signals installConn could previously see.
	src.epoch = 101
	replacement := pipeConn(t)
	ss.installConn(1, replacement)

	if got := ss.getActiveConn(); got != replacement {
		t.Fatalf("after a peer reboot onto the empty alternate slot the ACTIVE fabric must be "+
			"the replacement, got the corpse (%v vs %v). With the corpse preferred, the "+
			"full-disconnect path never runs when it finally drops, cold prime is never "+
			"armed, and the replacement never receives the survivor's session table — the "+
			"next failover can blackhole established sessions", got, replacement)
	}
}

// THE MIDDLE STATE, and the reason the callback returns two values.
//
// On a peer reboot the heartbeat and the fabric connect RACE. If the connect
// wins, the floor is not yet latched and reads 0. Reporting no reboot is
// correct — but RECORDING that unlatched 0 is not: it overwrites the baseline,
// so a later latched observation compares against 0, takes the "first
// observation" arm, and the reboot is MISSED for good.
//
// This asserts the BASELINE FIELD rather than the chosen fabric, and the reason
// is worth recording because the first draft did the opposite and was WRONG.
//
// Driving it behaviourally needs a third install, and with both slots occupied
// any third install SUPERSEDES a live current connection — which retires the
// incarnation through `supersededCurrent` all by itself. The first version of
// this cell did exactly that, passed, and then survived the mutation that moves
// the record above the `!latched` return: it was measuring the supersession
// path, not the epoch baseline. The mutation is what exposed it.
//
// So the honest assertion is the state the arm actually protects. The headline
// cell above carries the fabric property on an uncontaminated path (an install
// into an EMPTY slot supersedes nothing), which is where a behavioural
// assertion belongs.
//
// RED on revert: move `s.peerEpochAtIncarnation = epoch` above the `!latched`
// return in peerEpochRebootLocked.
func TestUnlatchedEpochDoesNotPoisonTheBaseline_7762(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	ss.installConn(0, pipeConn(t))
	ss.mu.Lock()
	baseline := ss.peerEpochAtIncarnation
	ss.mu.Unlock()
	if baseline != 100 {
		t.Fatalf("setup: a latched install must record the floor, got %d want 100", baseline)
	}

	// The reboot's fabric connect arrives BEFORE its heartbeat: floor unlatched.
	src.epoch, src.latched = 0, false
	ss.installConn(1, pipeConn(t))

	ss.mu.Lock()
	after := ss.peerEpochAtIncarnation
	ss.mu.Unlock()
	if after != baseline {
		t.Fatalf("an install during the unlatched race window overwrote the epoch baseline "+
			"(%d -> %d). An unlatched floor is 0 and means nothing; recording it makes the "+
			"NEXT latched observation compare against 0, take the first-observation arm, and "+
			"miss the reboot permanently — the failure is silent and looks exactly like a "+
			"peer that never rebooted", baseline, after)
	}
}

// The nil arm: an embedder that wires no epoch source keeps exactly its
// pre-#7762 behaviour rather than reading a fabricated zero.
//
// This is also the control for the two cells above: it shows the fixture does
// NOT retire the corpse on its own, so their passes come from the epoch signal
// rather than from something incidental in installConn.
func TestNilEpochFnKeepsPreEpochBehaviour_7762(t *testing.T) {
	ss := newAckTestSync(t)
	if ss.PeerBootEpochFn != nil {
		t.Fatal("fixture must start unwired for this control to mean anything")
	}

	corpse := pipeConn(t)
	ss.installConn(0, corpse)
	replacement := pipeConn(t)
	ss.installConn(1, replacement)

	if got := ss.getActiveConn(); got != corpse {
		t.Fatalf("with no epoch source the classifier must behave exactly as before #7762 — "+
			"fabric 0 preferred, corpse and all. Got %v, want %v. If this ever changes, the "+
			"two cells above are no longer measuring the epoch signal", got, corpse)
	}
}

// THE INTERACTION with the #6910 boot-id path, which is the one I did not have
// until I reasoned about who else advances the incarnation.
//
// applyPeerIncarnationSwitchLocked (sync_conn_read.go, the prime path) retires
// an incarnation on boot-id evidence WITHOUT going through installConn. If it
// leaves peerEpochAtIncarnation holding the OLD floor, then the peer's SECOND
// fabric coming up afterwards reads a raise that has already been accounted
// for, advances the incarnation a SECOND time, and evicts the connection the
// prime path just established.
//
// That is the failure installConn's own comment warns about in the other
// direction: "a fabric link coming up into an EMPTY slot beside a surviving one
// is not a supersession and must NOT clear: same peer process". A double
// advance turns the healthy second fabric into an eviction of the first.
//
// RED on revert: remove the peerEpochAtIncarnation refresh from
// applyPeerIncarnationSwitchLocked.
func TestBootIdSwitchRebasesTheEpochBaseline_7762(t *testing.T) {
	ss := newAckTestSync(t)
	src := &epochSource{epoch: 100, latched: true}
	ss.PeerBootEpochFn = src.fn

	first := pipeConn(t)
	ss.installConn(0, first)

	// The peer reboots. Its heartbeat raises the floor, and its boot-id prime
	// lands on fabric 0 — so #6910's path retires the old incarnation here,
	// before any second-fabric install.
	src.epoch = 101
	ss.mu.Lock()
	ss.applyPeerIncarnationSwitchLocked(0)
	ss.mu.Unlock()

	// The SAME peer process now brings up its second fabric. This is not a
	// reboot; the raise it would observe was already consumed above.
	second := pipeConn(t)
	ss.installConn(1, second)

	ss.mu.Lock()
	stillInstalled := ss.conn0 == first
	ss.mu.Unlock()
	if !stillInstalled {
		t.Fatal("the peer's SECOND fabric coming up evicted its FIRST. The boot-id prime " +
			"path already retired the old incarnation for this reboot; if it does not also " +
			"rebase the epoch baseline, installConn reads the same raise again, advances a " +
			"second time, and evicts the connection the prime just established — the same " +
			"peer process losing a live fabric to a reboot that was already handled")
	}
}
