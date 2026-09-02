package daemon

import (
	"testing"
)

// #8326: `show chassis cluster` reported a redundancy group as FORWARDING
// whenever the state machine merely DESIRED it to be.
//
// THE FIXTURE MUST DIVERGE, and that is the whole design of this file. In the
// converged state `active` and `applied` hold the same value, so every
// assertion below passes on the broken code. A cell that only exercises a
// settled group proves nothing about a surface whose entire purpose is
// reporting the unsettled one. So each case sets desired WITHOUT recording an
// apply, which is exactly the blackhole an operator consults this surface to
// detect: the node wants to forward, the dataplane was never told, and the
// render said healthy.
//
// The defect was a comment. rg_forwarding_status_7367.go asserted "IsActive is
// the APPLIED value, not DesiredActive" — false, since both returned s.active
// — and named the failure it produced in its own next sentence.

func TestRGForwardingReportsAppliedNotDesired8326(t *testing.T) {
	s := newRGStateMachine()

	// Desired active, nothing applied: the divergent state.
	s.SetCluster(true)

	if !s.IsActive() {
		t.Fatal("setup: desired should be active after SetCluster(true)")
	}
	if s.AppliedActive() {
		t.Fatal("setup: nothing has been applied, so AppliedActive must be false; " +
			"if this fails the fixture is converged and the rest proves nothing")
	}

	d := &Daemon{rgStates: map[int]*rgStateMachine{1: s}}
	fwd, ok := d.rgForwardingStatus(1)
	if !ok {
		t.Fatal("rgForwardingStatus reported no state for a group that has one")
	}
	if fwd.Active {
		t.Error("show chassis cluster reports the group as FORWARDING while the apply " +
			"has not succeeded — the blackhole renders identical to healthy, which is " +
			"the case this surface exists to detect")
	}

	// Converged: once the apply lands, it must report forwarding. Without this
	// the assertion above is satisfied by a surface hardcoded to false.
	s.MarkApplied(true)
	fwd, ok = d.rgForwardingStatus(1)
	if !ok {
		t.Fatal("rgForwardingStatus lost the state after MarkApplied")
	}
	if !fwd.Active {
		t.Error("a group whose apply SUCCEEDED reports as not forwarding")
	}

	// And the other direction: desired goes inactive, apply not yet recorded.
	// Active must still report the applied truth (still forwarding), not the
	// new desire. A one-directional test passes on an implementation that
	// simply inverted the field it reads.
	s.SetCluster(false)
	if s.IsActive() {
		t.Fatal("setup: desired should be inactive")
	}
	fwd, _ = d.rgForwardingStatus(1)
	if !fwd.Active {
		t.Error("the group stopped reporting as forwarding the moment the DESIRE " +
			"changed, before any apply — the surface is reading desired again, " +
			"just with the sign flipped")
	}
}

// TestIsActiveAndAppliedActiveAreNotAliases8326 exists because the defect was
// two accessors returning one field, and a later change could silently
// recreate that. DesiredActive() was removed for the same reason: the sentence
// "IsActive is the APPLIED value, not DesiredActive" is only plausible while
// two names exist that could differ.
func TestIsActiveAndAppliedActiveAreNotAliases8326(t *testing.T) {
	s := newRGStateMachine()
	s.SetCluster(true)
	if s.IsActive() == s.AppliedActive() {
		t.Fatal("IsActive() and AppliedActive() agree in a state where desired and " +
			"applied MUST differ (desired set, nothing applied). They are reading the " +
			"same field again, which is the #8326 defect exactly")
	}
}
