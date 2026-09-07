package daemon

import "testing"

// #9176: the exiting goroutine cleared the registered cancel unconditionally.
//
// The guard read `loopCancel != nil && loopCtx.Err() != nil`, and its own
// comment said it clears only "if this loop is still the registered one".
// `syncIPsecSAPeriodic` has exactly ONE return — `case <-ctx.Done()` — so the
// error is always non-nil at that line and the condition reduced to "always
// clear", the opposite of what the comment promised.
//
// Consequence: a stop-then-restart while the old goroutine is still in flight
// had A's exit clear B's cancel, leaving loop B UNREGISTERED — so a later
// knob-OFF silently did nothing and a later knob-ON started a SECOND publisher.
func TestOldGoroutineExitDoesNotClearTheNewLoop9176(t *testing.T) {
	d := &Daemon{}

	// Loop A registers.
	d.ipsecSASync.loopGen = 1
	genA := d.ipsecSASync.loopGen
	cancelledA := false
	d.ipsecSASync.loopCancel = func() { cancelledA = true }

	// Stop, then restart: loop B takes the registration while A is still
	// running. This is the OVERLAP the defect needs — a sequential stop/restart
	// passes even on the broken code.
	d.ipsecSASync.loopCancel()
	d.ipsecSASync.loopGen++
	cancelledB := false
	d.ipsecSASync.loopCancel = func() { cancelledB = true }

	// NOW loop A finally exits.
	d.clearIPsecSALoopIfCurrent(genA)

	if d.ipsecSASync.loopCancel == nil {
		t.Fatal("the OLD goroutine's exit cleared the NEW loop's cancel. Loop B is " +
			"now unregistered: a knob-OFF will silently do nothing (the publisher " +
			"keeps advertising after the operator disabled it) and a knob-ON will " +
			"start a SECOND publisher (#9176)")
	}

	// And the surviving handle must be B's, not a stale A.
	d.ipsecSASync.loopCancel()
	if !cancelledB {
		t.Error("the registered cancel is not loop B's")
	}
	if !cancelledA {
		t.Error("fixture: loop A was never cancelled, so the stop half did not happen")
	}
}

// NARROWNESS. The ordinary case must still clear: a loop that exits while it IS
// the registered one has to drop the handle, or `ensureIPsecSASyncLoop`'s
// already-running early return blocks every future launch and the publisher
// never restarts.
func TestTheCurrentLoopExitingStillClears9176(t *testing.T) {
	d := &Daemon{}
	d.ipsecSASync.loopGen = 7
	d.ipsecSASync.loopCancel = func() {}

	d.clearIPsecSALoopIfCurrent(7)

	if d.ipsecSASync.loopCancel != nil {
		t.Fatal("the CURRENT loop exited and its handle was not cleared — " +
			"ensureIPsecSASyncLoop takes its already-running early return forever " +
			"and the publisher can never be restarted")
	}
}

// #9176's sibling: stopClusterComms had a DHCP reset and no IPsec one, so a
// comms teardown left the handle set and the next ensure no-opped against a
// dead context. The reset must also bump the generation, or an in-flight
// goroutine's exit can still clear a handle installed after the teardown.
func TestResetClearsAndInvalidatesInFlightLoops9176(t *testing.T) {
	d := &Daemon{}
	d.ipsecSASync.loopGen = 3
	genOld := d.ipsecSASync.loopGen
	cancelled := false
	d.ipsecSASync.loopCancel = func() { cancelled = true }

	d.resetIPsecSASyncLoop()

	if !cancelled {
		t.Error("reset did not cancel the running loop")
	}
	if d.ipsecSASync.loopCancel != nil {
		t.Fatal("reset left the handle set; the next ensureIPsecSASyncLoop takes its " +
			"already-running early return against a cancelled context")
	}

	// A loop registered AFTER the teardown must survive the old goroutine's exit.
	//
	// NOTE: this deliberately does NOT bump the generation itself. My first
	// version did, and it masked the property under test — with the fixture
	// supplying the bump, removing it from resetIPsecSASyncLoop changed nothing
	// and the mutant SURVIVED. The generation must advance because the RESET
	// advanced it; a cell that advances it on the code's behalf is testing its
	// own arithmetic.
	d.ipsecSASync.loopCancel = func() {}
	d.clearIPsecSALoopIfCurrent(genOld)
	if d.ipsecSASync.loopCancel == nil {
		t.Error("an in-flight goroutine from before the reset cleared a handle " +
			"installed after it — the reset must invalidate the generation, not " +
			"only clear the pointer")
	}
}
