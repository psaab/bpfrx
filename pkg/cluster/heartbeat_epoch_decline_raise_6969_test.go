package cluster

import (
	"strings"
	"testing"
	"time"
)

// heartbeat_epoch_decline_raise_6969_test.go — #6969 F5.
//
// The forward bound gates a CLOCK-DEPENDENT judgement, and its own comment says
// it gates "ONLY the irreversible operation — raising the floor". The
// implementation was wider: when the bound fired it returned false, rejecting
// the frame. A rejected frame never reaches the monotonic lastSeen update, so a
// peer that RESTARTS while this receiver's clock is more than bootEpochMaxSkew
// slow is declared dead in ~500ms and the cluster goes dual-master — over a
// clock fault on one node.
//
// WHY A RESTART, and not "any healthy peer". The boot epoch is per-INCARNATION
// and fixed for its life, so a peer already latched keeps being admitted through
// the equality path however slow this node's clock is — that exemption is
// deliberate and predates this change (see the DO NOT HOIST paragraph in
// admitAuthed). The bound only meets a peer whose epoch is NEW to this receiver:
// first contact, or a restart. That is narrower than the finding as filed and it
// is what these cases drive.
//
// WHAT IS NOW ADMITTED THAT WAS NOT, which is the half that has to be argued
// rather than asserted, because this change LOOSENS a gate:
//
//   - the frame class is {authenticated, ring-fresh, inside the absolute
//     year-2200 band, epoch above the floor, beyond the clock's forward bound};
//   - it CANNOT raise the floor, so it cannot lock the live peer out — which is
//     the worst outcome in this area (#6711 poisoning) and is what a raise on an
//     unverifiable value would risk;
//   - it consumes one slot of the same bounded, non-refilling per-value session
//     budget an equality frame does, so it cannot churn the ring;
//   - its remaining power is forged liveness from a captured frame, which is
//     already reachable today through the equality path and the post-restart
//     archived-frame path documented at the arming comment, and which the same
//     PSK rotation retires.
//
// The one thing that genuinely widens: a capture from an incarnation whose epoch
// sits far ahead of this node's clock was previously unusable and is now usable
// for liveness and for one budget slot. It still cannot move the floor.

// admitAt drives one frame with the clock pinned, so the forward bound is
// exercised rather than raced.
func admitAt6969(t *testing.T, s *heartbeatAuthState, now int64, epoch, session, counter uint64) (bool, string) {
	t.Helper()
	restore := epochNowNanos
	epochNowNanos = func() int64 { return now }
	defer func() { epochNowNanos = restore }()
	return s.admitAuthed(true, epoch, session, counter)
}

// TestSlowReceiverAdmitsARestartedPeerWithoutRaising_6969 is the fix, and both
// halves are asserted because only the pair distinguishes it from "admit
// anything": the frame must be ADMITTED (liveness restored) and the floor must
// be UNCHANGED (the security object untouched).
func TestSlowReceiverAdmitsARestartedPeerWithoutRaising_6969(t *testing.T) {
	// This receiver's clock. The peer's is correct and two hours ahead of it.
	const receiverNow = int64(1_800_000_000_000_000_000)
	slowBy := int64(2 * bootEpochMaxSkew)

	s := &heartbeatAuthState{}

	// Incarnation A, latched normally: its epoch is inside the bound.
	epochA := uint64(receiverNow) - uint64(time.Minute)
	if ok, reason := admitAt6969(t, s, receiverNow, epochA, 0xA1, 1); !ok {
		t.Fatalf("the fixture could not latch incarnation A (%q); nothing below measures "+
			"what it claims", reason)
	}
	if s.highEpoch != epochA {
		t.Fatalf("floor = %d after latching A, want %d", s.highEpoch, epochA)
	}

	// The peer RESTARTS. Its clock is correct, so its new epoch is around the
	// peer's own now — which is beyond this receiver's forward bound.
	epochB := uint64(receiverNow + slowBy)
	// Premise: the fixture really does reach the bound, and is not out of band.
	if !epochUsableAsFloor(epochB) {
		t.Fatalf("fixture: %d is outside the absolute band, so this measures the out-of-band "+
			"arm instead of the forward bound", epochB)
	}
	if epochWithinForwardBound(epochB, receiverNow) {
		t.Fatalf("fixture: %d is INSIDE the forward bound at %d, so this case never reaches "+
			"the branch under test", epochB, receiverNow)
	}

	ok, reason := admitAt6969(t, s, receiverNow, epochB, 0xB1, 1)
	if !ok {
		t.Fatalf("the restarted peer was REFUSED (%q). The frame never reaches the monotonic "+
			"lastSeen update, so the peer is declared dead in ~500ms and the cluster goes "+
			"dual-master — over a clock fault on THIS node, not on the peer (#6969 F5)", reason)
	}
	if s.highEpoch != epochA {
		t.Fatalf("the floor moved from %d to %d on an epoch this node cannot verify against "+
			"its own clock. Declining the RAISE is what makes admitting the frame safe: a "+
			"floor raised to an unverifiable value locks out the live peer (#6711)",
			epochA, s.highEpoch)
	}
	if got := s.epochRaiseDeclinedAheadOfClock.Load(); got != 1 {
		t.Fatalf("epochRaiseDeclinedAheadOfClock = %d, want 1 — the decline must stay visible "+
			"to an operator, or a clock fault becomes silent", got)
	}
}

// TestDeclinedRaiseStillSpendsTheSessionBudget_6969 is the security half that
// the admit alone does not give.
//
// A frame that cannot be latched is admitted AT THE FLOOR, so it must be subject
// to the same bounded per-value session budget an equality frame is. Without
// that it would be an unbounded admission path for exactly the frames the clock
// cannot vouch for — the epochless bypass in miniature, which is what the floor
// exists to close.
func TestDeclinedRaiseStillSpendsTheSessionBudget_6969(t *testing.T) {
	const receiverNow = int64(1_800_000_000_000_000_000)
	ahead := uint64(receiverNow) + 3*bootEpochMaxSkew

	s := &heartbeatAuthState{}
	epochA := uint64(receiverNow) - uint64(time.Minute)
	if ok, _ := admitAt6969(t, s, receiverNow, epochA, 0xA1, 1); !ok {
		t.Fatal("fixture: incarnation A did not latch")
	}

	// The floor now holds one bound session (A). heartbeatEpochSessionsPerEpoch
	// slots exist in total, so exactly one more may be spent.
	admitted := 0
	for i := 0; i < heartbeatEpochSessionsPerEpoch+2; i++ {
		if ok, _ := admitAt6969(t, s, receiverNow, ahead+uint64(i), uint64(0xC000+i), 1); ok {
			admitted++
		}
	}
	if want := heartbeatEpochSessionsPerEpoch - 1; admitted != want {
		t.Fatalf("%d beyond-bound frames were admitted at the floor, want %d. A frame the "+
			"clock cannot vouch for is admitted AS IF at the floor, so it must spend the same "+
			"finite, non-refilling budget: an unbounded path for unverifiable frames is the "+
			"ring churn the floor exists to stop (#6969 F5)", admitted, want)
	}
	if s.highEpoch != epochA {
		t.Fatalf("the floor moved to %d while spending the budget; not one of these frames "+
			"may raise it", s.highEpoch)
	}
	if got := s.epochSessionCollision.Load(); got == 0 {
		t.Fatal("no session collision was counted, so the refusals above did not come from " +
			"the budget and this case is measuring something else")
	}
}

// TestCorrectedClockRaisesTheFloorAgain_6969 is the recovery half: declining is
// not a permanent state. Once the clocks agree the same incarnation's next frame
// raises the floor normally, so the decline costs nothing once the fault is
// fixed and needs no restart on either node.
func TestCorrectedClockRaisesTheFloorAgain_6969(t *testing.T) {
	const receiverNow = int64(1_800_000_000_000_000_000)
	slowBy := int64(2 * bootEpochMaxSkew)

	s := &heartbeatAuthState{}
	epochA := uint64(receiverNow) - uint64(time.Minute)
	if ok, _ := admitAt6969(t, s, receiverNow, epochA, 0xA1, 1); !ok {
		t.Fatal("fixture: incarnation A did not latch")
	}
	epochB := uint64(receiverNow + slowBy)
	if ok, _ := admitAt6969(t, s, receiverNow, epochB, 0xB1, 1); !ok {
		t.Fatal("fixture: the restarted peer was not admitted, so there is nothing to recover")
	}
	if s.highEpoch != epochA {
		t.Fatalf("fixture: the floor already moved to %d, so the recovery below proves nothing",
			s.highEpoch)
	}

	// NTP corrects this node's clock: it is no longer slow.
	correctedNow := receiverNow + slowBy
	if ok, reason := admitAt6969(t, s, correctedNow, epochB, 0xB1, 2); !ok {
		t.Fatalf("the peer's next frame was refused after the clock was corrected (%q)", reason)
	}
	if s.highEpoch != epochB {
		t.Fatalf("the floor is still %d after the clock was corrected, want %d. Declining a "+
			"raise must be a HOLD, not a permanent refusal — otherwise the fix trades a "+
			"dual-master for a floor that never tracks the peer again", s.highEpoch, epochB)
	}
}

// TestEpochRaiseDeclineIsNamedForTheOperator_6969 keeps the diagnosis the
// re-decided arm gave up.
//
// The rejection used to carry "check NTP on BOTH nodes — this is a clock fault,
// not a replay" in its reason string. There is no rejection any more, so that
// text has nowhere to travel except the counter's rendering. Losing it would
// leave an operator reading a bare number during exactly the incident where
// mistaking a clock fault for a replay costs the most.
func TestEpochRaiseDeclineIsNamedForTheOperator_6969(t *testing.T) {
	if note := epochRaiseDeclineNote(HeartbeatStats{}); note != "" {
		t.Fatalf("a zero decline count rendered a note (%q); the line must stay quiet when "+
			"there is nothing to say", note)
	}
	note := epochRaiseDeclineNote(HeartbeatStats{EpochRaiseDeclinedAheadOfClock: 1})
	if note == "" {
		t.Fatal("a non-zero decline count renders NO note. The reason string that carried " +
			"this guidance is gone with the rejection, so the counter is the only place it " +
			"can live (#6969 F5)")
	}
	if !strings.Contains(note, "NTP") {
		t.Fatalf("the note does not name the action (NTP): %q. An operator reading a bare "+
			"count opens a security incident for what is a clock fault", note)
	}
	if !strings.Contains(note, "admitted") {
		t.Fatalf("the note does not say the frames are still admitted: %q. Without that an "+
			"operator reads a rising count as lost heartbeats and starts looking for a "+
			"liveness problem that no longer exists", note)
	}
}
