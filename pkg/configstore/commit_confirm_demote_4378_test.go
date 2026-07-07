package configstore

import "testing"

// #4378: when a node running a `commit confirmed` window is DEMOTED from RG0
// primary (StateSecondary/StateSecondaryHold) before the operator confirms,
// the daemon calls ConfirmPendingOnDemotion. That MUST confirm the pending
// window — cancel the armed rollback timer and bump the confirm generation —
// so the timer does NOT later revert the demoted (now standby) node to its
// pre-confirm tree while the new primary keeps the committed config. Rolling
// back the standby while the primary keeps the commit is config divergence
// (the #4378 bug, surfacing at the next failover).
//
// CONFIRM (keep the commit), not roll back, is correct: the committing node
// pushed the committed config to the peer via config-sync at commit-confirmed
// time, so the peer — now primary — already runs it. Confirming keeps both
// nodes converged.
//
// RED-on-revert: without ConfirmPendingOnDemotion (or if it fails to clear the
// timer), the arm-time timer callback still matches confirmGen and reverts
// active to the baseline, so the host-name assertion fails.
func TestConfirmPendingOnDemotionConfirmsWindow_4378(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Baseline confirmed commit — this is the pre-confirm rollback target the
	// pending timer would otherwise revert to.
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// commit confirmed: arms the rollback timer, target = Base.
	if err := s.SetFromInput("system host-name Committed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("should have a pending confirm after CommitConfirmed")
	}
	// The confirm timer's real closure captures this generation at arm time.
	armGen := s.ConfirmGenForTesting()

	// The node is demoted from RG0 primary mid-window.
	if !s.ConfirmPendingOnDemotion() {
		t.Fatal("ConfirmPendingOnDemotion must report it confirmed a pending window")
	}

	// The demotion must have CONFIRMED the pending window.
	if s.IsConfirmPending() {
		t.Error("demotion must clear the pending commit-confirmed timer")
	}
	if got := s.ActiveConfig().System.HostName; got != "Committed" {
		t.Fatalf("active host-name after demotion = %q, want Committed", got)
	}

	// Simulate the armed timer firing with the arm-time generation (exactly
	// what time.AfterFunc's closure does; also models the Stop()-lost race
	// where the callback already started). The confirmGen bump must make it a
	// no-op — the committed config C must SURVIVE on the demoted standby.
	s.InvokeRollbackTimerForTesting(armGen)

	if got := s.ActiveConfig().System.HostName; got != "Committed" {
		t.Fatalf("confirm-timer fire reverted the committed config on the demoted standby: "+
			"active host-name = %q, want Committed (the standby rolled back while the "+
			"primary keeps the commit — #4378 config divergence)", got)
	}
}

// #4378: a node WITHOUT a pending commit-confirmed being demoted is a no-op —
// ConfirmPendingOnDemotion returns false and errors nothing (demotion fires on
// every clean weight-based failover; the common case is no pending window).
func TestConfirmPendingOnDemotionNoPendingIsNoop_4378(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	if s.IsConfirmPending() {
		t.Fatal("no commit confirmed was issued — nothing should be pending")
	}
	if s.ConfirmPendingOnDemotion() {
		t.Error("ConfirmPendingOnDemotion with no pending window must return false (no-op)")
	}
	if got := s.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("no-op demotion must not touch active config: host-name = %q, want Base", got)
	}
}
