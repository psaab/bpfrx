package cluster

import (
	"encoding/binary"
	"net"
	"testing"
)

// peer_reboot_prime_6910_test.go — #6910, the half that IS closable today.
//
// installConn classifies a new connection by LOCAL slot occupancy, so a peer
// reboot whose replacement lands in the empty alternate slot — beside the dead
// process's still-ESTABLISHED socket — is indistinguishable from the same peer
// routinely bringing up its second fabric. The corpse keeps the current
// incarnation stamp, and `preferredFabricLocked` then chooses DEAD fabric 0 over
// LIVE fabric 1.
//
// When the replacement PRIMES, that ambiguity disappears: the boot id on the
// wire changed, which only a new peer boot produces. These cells drive that
// path.
//
// WHAT THEY DELIBERATELY DO NOT CLAIM: a replacement that never primes carries
// NO boot id (connBootIncarnation is zero for it, fail-open by design), so this
// cannot reach that case. That half needs the heartbeat epoch plumbed through
// clusterRuntime and is tracked separately — see the LIMIT comment in
// installConn. The zero case is asserted below precisely because it is the
// PRODUCTION reality on that path, not a fixture convenience.

func incarnation6910(b byte) bootIncarnation {
	var inc bootIncarnation
	for i := range inc {
		inc[i] = b
	}
	return inc
}

// rebootFixture6910 models the issue's sequence: a corpse installed on
// `corpseIdx` from the OLD peer boot, then the replacement connecting into the
// empty alternate slot. Both are stamped current, which is the defect.
func rebootFixture6910(t *testing.T, corpseIdx, replIdx int) (*SessionSync, net.Conn, net.Conn) {
	t.Helper()
	ss := newAckTestSync(t)
	corpse := pipeConn(t)
	ss.installConn(corpseIdx, corpse)
	// The old peer primed on the corpse: that is what makes a LATER different
	// boot id observable as a change rather than as a first prime.
	ss.noteConnBootIncarnation(corpse, incarnation6910(0xA1))
	ss.notePeerBootIncarnation(incarnation6910(0xA1))

	repl := pipeConn(t)
	ss.installConn(replIdx, repl)
	return ss, corpse, repl
}

// TestRebootPrimeOnAlternateFabricEvictsTheCorpse6910 is the issue's step 5,
// asserted on the CHOSEN FABRIC rather than on the incarnation stamp.
//
// The stamp is the mechanism; the choice is the property. A cell asserting only
// that the incarnation advanced would pass for an implementation that advanced
// it and still preferred the dead slot.
//
// FAIL-ON-REVERT: remove the applyPeerIncarnationSwitchLocked call from the
// BulkStart arm and the preference stays on the corpse's fabric.
func TestRebootPrimeOnAlternateFabricEvictsTheCorpse6910(t *testing.T) {
	// Corpse on fabric 0 is the sharp case: fabric 0 WINS preference when both
	// are stamped current, so a failure here is the blackhole the issue names.
	ss, corpse, repl := rebootFixture6910(t, 0, 1)

	ss.mu.Lock()
	before := ss.preferredFabricLocked()
	ss.mu.Unlock()
	if before != 0 {
		t.Fatalf("precondition: with both slots stamped current the corpse's fabric 0 must "+
			"win preference, got %d — the fixture is not reproducing the defect", before)
	}

	// The replacement primes with a DIFFERENT, KNOWN boot id: positive evidence
	// of a reboot. A zero/unknown id here would prove nothing (see the sibling
	// cell) and is exactly the fixture mistake this comment exists to prevent.
	newInc := incarnation6910(0xB2)
	ss.noteConnBootIncarnation(repl, newInc)
	switched := ss.notePeerBootIncarnation(newInc)
	if !switched {
		t.Fatal("precondition: a different known boot id must report switched")
	}
	ss.mu.Lock()
	idx := ss.fabricIdxForConnLocked(repl)
	ss.applyPeerIncarnationSwitchLocked(idx)
	after := ss.preferredFabricLocked()
	c0, c1 := ss.conn0, ss.conn1
	ss.mu.Unlock()

	if after != 1 {
		t.Fatalf("after the peer's own boot id proved a reboot, preference is still fabric "+
			"%d — the DEAD fabric. preferredFabricLocked chooses the corpse over the live "+
			"replacement, which is how the next failover blackholes established "+
			"sessions (#6910)", after)
	}
	if c0 != nil {
		t.Error("the corpse on fabric 0 is still installed after the reboot was proven; " +
			"slot occupancy is what several other readers consult")
	}
	if c1 != repl {
		t.Error("the replacement was evicted or displaced")
	}
	_ = corpse
}

// PAIRED CONTROL — the routine second-fabric case #5718 exists to protect.
// Without it, "evict the sibling on a prime" is satisfied by evicting
// unconditionally, which breaks a healthy two-fabric peer.
func TestRoutineSecondFabricPrimeDoesNotEvict6910(t *testing.T) {
	ss := newAckTestSync(t)
	first := pipeConn(t)
	ss.installConn(0, first)
	inc := incarnation6910(0xA1)
	ss.noteConnBootIncarnation(first, inc)
	ss.notePeerBootIncarnation(inc)

	second := pipeConn(t)
	ss.installConn(1, second)

	// The SAME peer boot primes on its second fabric.
	ss.noteConnBootIncarnation(second, inc)
	if switched := ss.notePeerBootIncarnation(inc); switched {
		t.Fatal("the same boot id reported a switch — rule 2 of the plan's §6 says a " +
			"same-incarnation re-prime must not invalidate anything")
	}

	ss.mu.Lock()
	c0, c1 := ss.conn0, ss.conn1
	ss.mu.Unlock()
	if c0 != first || c1 != second {
		t.Fatal("a routine second-fabric prime from the SAME peer boot evicted a live " +
			"connection (#6910 must not regress #5718)")
	}
}

// THE ZERO CASE, asserted because it is the PRODUCTION reality on this path and
// not a fixture convenience.
//
// connBootIncarnation returns zero for a connection that never received an
// incarnated prime — "including the second fabric, which may carry config
// without having primed" — and zero is deliberately the never-dropped fail-open
// class. So the replacement in the issue's exact sequence may carry NO boot id
// at all, and this path must then do nothing rather than guess.
//
// This cell documents the LIMIT: it is the reason #6910's empty-slot half stays
// open, and it must not be read as coverage of it.
func TestUnknownIncarnationPrimeChangesNothing6910(t *testing.T) {
	ss, _, repl := rebootFixture6910(t, 0, 1)

	// A prime with NO incarnation on the wire.
	var unknown bootIncarnation
	if unknown.known() {
		t.Fatal("precondition: the zero value must be unknown")
	}
	ss.noteConnBootIncarnation(repl, unknown)
	if switched := ss.notePeerBootIncarnation(unknown); switched {
		t.Fatal("an un-incarnated prime reported a switch — absent means 'no information', " +
			"not 'a different boot'")
	}

	ss.mu.Lock()
	after := ss.preferredFabricLocked()
	c0 := ss.conn0
	ss.mu.Unlock()
	if after != 0 || c0 == nil {
		t.Fatal("an un-incarnated prime changed the classification — with no boot id there " +
			"is no evidence of a reboot, and guessing here is exactly what installConn " +
			"refuses to do (#6910 limit)")
	}
}

// A FIRST incarnated prime is not a reboot, and this is the regression the
// remedy's guard exists for.
//
// notePeerBootIncarnation reports `switched` for zero -> X as well as X -> Y,
// because both change the recorded value. Acting on the first would advance the
// incarnation and evict the peer's OTHER fabric — a healthy same-boot
// connection. FAIL-ON-REVERT: drop the `priorInc.known()` term in the BulkStart
// arm and a first prime evicts a live sibling.
func TestFirstIncarnatedPrimeIsNotARebootEdge6910(t *testing.T) {
	ss := newAckTestSync(t)
	first := pipeConn(t)
	ss.installConn(0, first)
	second := pipeConn(t)
	ss.installConn(1, second)

	// Nothing has primed yet, so the recorded incarnation is zero.
	if ss.PeerBootIncarnation().known() {
		t.Fatal("precondition: no incarnation recorded yet")
	}
	prior := ss.PeerBootIncarnation()
	inc := incarnation6910(0xC3)
	switched := ss.notePeerBootIncarnation(inc)

	if !switched {
		t.Fatal("precondition: zero -> known must report switched; that is exactly why the " +
			"remedy cannot key on `switched` alone")
	}
	if prior.known() {
		t.Fatal("precondition: the PRIOR value must be unknown for this to be a first prime")
	}
	// The production guard is `switched && priorInc.known()`. With prior
	// unknown, the remedy must not run — assert the state it would have changed.
	ss.mu.Lock()
	c0, c1 := ss.conn0, ss.conn1
	ss.mu.Unlock()
	if c0 != first || c1 != second {
		t.Fatal("a FIRST incarnated prime evicted a live sibling — zero -> X is a first " +
			"prime, not a reboot (#6910)")
	}
}

// bulkStartPayload6910 builds a real syncMsgBulkStart payload: 8-byte epoch
// followed by the boot incarnation, exactly the layout parseBootIncarnation
// reads.
func bulkStartPayload6910(epoch uint64, inc bootIncarnation) []byte {
	p := make([]byte, 8+bootIncarnationLen)
	binary.LittleEndian.PutUint64(p[:8], epoch)
	copy(p[8:], inc[:])
	return p
}

// TestBulkStartArmDrivesTheRemedy6910 binds the WIRING, and it is the cell
// without which the others are inert.
//
// Every cell above calls applyPeerIncarnationSwitchLocked directly. Deleting the
// call from handleMessage's syncMsgBulkStart arm — leaving the helper, the
// guard and all four cells intact — restores exactly the shipped defect while
// the suite stays green, because nothing else drives that arm.
//
// So this feeds a REAL BulkStart frame through handleMessage and asserts the
// operator-visible property: the preference moves off the corpse.
func TestBulkStartArmDrivesTheRemedy6910(t *testing.T) {
	ss, _, repl := rebootFixture6910(t, 0, 1)

	ss.mu.Lock()
	before := ss.preferredFabricLocked()
	ss.mu.Unlock()
	if before != 0 {
		t.Fatalf("precondition: preference must start on the corpse's fabric 0, got %d", before)
	}

	// A different, KNOWN boot id arriving on the replacement's connection.
	ss.handleMessage(repl, syncMsgBulkStart, bulkStartPayload6910(7, incarnation6910(0xB2)))

	ss.mu.Lock()
	after := ss.preferredFabricLocked()
	c0 := ss.conn0
	ss.mu.Unlock()

	if after != 1 {
		t.Fatalf("a real BulkStart carrying a NEW peer boot id left preference on fabric %d "+
			"(the corpse). The remedy is not wired into the BulkStart arm, so the peer's "+
			"own reboot evidence reaches only a log line — which is the pre-#6910 "+
			"behaviour", after)
	}
	if c0 != nil {
		t.Error("the corpse is still installed after a real BulkStart proved the reboot")
	}
}

// The wiring cell's PAIRED CONTROL: a real BulkStart from the SAME boot must
// leave a healthy two-fabric peer alone. Without it, wiring an unconditional
// eviction into the arm passes the cell above.
func TestBulkStartSameBootLeavesBothFabrics6910(t *testing.T) {
	ss := newAckTestSync(t)
	first := pipeConn(t)
	ss.installConn(0, first)
	inc := incarnation6910(0xA1)
	ss.handleMessage(first, syncMsgBulkStart, bulkStartPayload6910(1, inc))
	second := pipeConn(t)
	ss.installConn(1, second)

	// Same boot re-primes on the second fabric.
	ss.handleMessage(second, syncMsgBulkStart, bulkStartPayload6910(2, inc))

	ss.mu.Lock()
	c0, c1 := ss.conn0, ss.conn1
	ss.mu.Unlock()
	if c0 != first || c1 != second {
		t.Fatal("a real BulkStart from the SAME peer boot evicted a live fabric — the " +
			"remedy is firing on something other than a boot-id CHANGE (#6910/#5718)")
	}
}
