package cluster

import "testing"

// TestElection_ArmFailedHold_IsolatedStaysSecondary is the #5275 cluster gate:
// a node whose dataplane failed to ARM at boot must never own the RGs, even
// ISOLATED (no peer) where a normal node auto-promotes to primary via the
// single-node election. It has no policy-enforcement forwarding, so the healthy
// peer must own the redundancy groups.
//
// FAIL-ON-REVERT: delete the `|| m.armFailedHold` clause from BOTH election
// gates (electRG + electSingleNode) in election.go and this goes RED — the
// isolated node wins the single-node election and IsLocalPrimary reports true.
func TestElection_ArmFailedHold_IsolatedStaysSecondary(t *testing.T) {
	m := NewManager(0, 1)
	m.SetArmFailedHold() // dataplane arm failed at boot
	if !m.ArmFailedHeld() {
		t.Fatal("SetArmFailedHold must make ArmFailedHeld report true")
	}
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)

	// An ordinary isolated node would win the single-node election and be
	// primary. The hold must keep it secondary even with no peer in sight.
	if m.IsLocalPrimary(0) {
		t.Fatal("arm-failed hold must keep an isolated node SECONDARY (it cannot forward)")
	}

	// A peer timeout re-runs election; the hold must still keep us secondary
	// (it is NOT auto-cleared the way ManualFailover is for an isolated node —
	// recovery from an arm failure is a daemon restart, not a runtime clear).
	m.handlePeerTimeout()
	if m.IsLocalPrimary(0) {
		t.Fatal("arm-failed hold must survive a re-election (no runtime auto-clear)")
	}
}

// TestElection_ArmFailedHold_DemotesAlreadyPrimary covers the call-ordering
// case the daemon actually hits: cluster.Start() runs an isolated single-node
// election and claims primary BEFORE the arm result is known (the arm happens
// after cluster.Start() in setupDataplaneAndInitialConfig). SetArmFailedHold
// must DEMOTE the already-primary group, not merely block future promotions.
//
// FAIL-ON-REVERT: delete the demotion loop in SetArmFailedHold and this goes
// RED — the group set primary before the hold stays primary.
func TestElection_ArmFailedHold_DemotesAlreadyPrimary(t *testing.T) {
	m := NewManager(0, 1)
	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200}))
	m.UpdateConfig(cfg)
	// Isolated node — wins the single-node election and is primary.
	if !m.IsLocalPrimary(0) {
		t.Fatal("precondition: isolated node should be primary before the hold")
	}
	drainEvents(m, 4)

	m.SetArmFailedHold()
	if m.IsLocalPrimary(0) {
		t.Fatal("SetArmFailedHold must DEMOTE an already-primary group")
	}
	// And it must stay secondary across a re-election.
	m.handlePeerTimeout()
	if m.IsLocalPrimary(0) {
		t.Fatal("held node must stay secondary after re-election")
	}
}
