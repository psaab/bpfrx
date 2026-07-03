package configstore

import "testing"

// #3861: while a `commit confirmed` window is pending, a PLAIN commit (the
// eventengine remediation path and every non-frontend committer) MUST
// confirm the pending window — cancel the armed rollback timer and bump the
// confirm generation — so the just-promoted config is not silently reverted
// to the pre-confirm T0 tree when the timer fires. Junos semantics: any
// subsequent explicit commit confirms a pending `commit confirmed`.
//
// RED-on-revert: without the fix, the arm-time timer callback (simulated via
// InvokeRollbackTimerForTesting with the generation captured at arm time)
// still matches confirmGen and reverts active to the baseline, so the
// host-name assertion fails.
func TestPlainCommitConfirmsPendingConfirmWindow_3861(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Baseline confirmed commit — this is the T0 rollback target the
	// pending timer would otherwise revert to.
	if err := s.SetFromInput("system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// commit confirmed C1: arms the rollback timer, target = Base.
	if err := s.SetFromInput("system host-name Confirmed"); err != nil {
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

	// Background/eventengine PLAIN commit C2 during the window.
	if err := s.SetFromInput("system host-name Remediated"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("plain Commit during confirm window: %v", err)
	}

	// The plain commit must have CONFIRMED the pending window.
	if s.IsConfirmPending() {
		t.Error("plain commit during a confirm window must clear the pending timer")
	}
	if got := s.ActiveConfig().System.HostName; got != "Remediated" {
		t.Fatalf("active host-name after plain commit = %q, want Remediated", got)
	}

	// Simulate the armed timer firing with the arm-time generation (exactly
	// what time.AfterFunc's closure does; also models the Stop()-lost race
	// where the callback already started). The confirmGen bump must make it
	// a no-op — the newer commit C2 must SURVIVE.
	s.InvokeRollbackTimerForTesting(armGen)

	if got := s.ActiveConfig().System.HostName; got != "Remediated" {
		t.Fatalf("confirm-timer fire reverted the background commit: active host-name = %q, "+
			"want Remediated (the plain commit was silently discarded — #3861 regression)", got)
	}
}

// #3861: the HA config-sync apply path (SyncApply) must likewise confirm a
// locally-pending commit-confirmed window. A node that armed `commit
// confirmed`, then received an authoritative config from the cluster primary,
// must not later revert that synced config to its stale local pre-confirm
// tree when the timer fires.
func TestSyncApplyConfirmsPendingConfirmWindow_3861(t *testing.T) {
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

	if err := s.SetFromInput("system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("should have a pending confirm after CommitConfirmed")
	}
	armGen := s.ConfirmGenForTesting()

	// Authoritative config synced from the cluster primary.
	synced := "system {\n    host-name Synced;\n}\n"
	if _, err := s.SyncApply(synced, nil); err != nil {
		t.Fatalf("SyncApply during confirm window: %v", err)
	}

	if s.IsConfirmPending() {
		t.Error("SyncApply during a confirm window must clear the pending timer")
	}
	if got := s.ActiveConfig().System.HostName; got != "Synced" {
		t.Fatalf("active host-name after SyncApply = %q, want Synced", got)
	}

	s.InvokeRollbackTimerForTesting(armGen)

	if got := s.ActiveConfig().System.HostName; got != "Synced" {
		t.Fatalf("confirm-timer fire reverted the synced config: active host-name = %q, "+
			"want Synced (HA sync silently reverted — #3861 regression)", got)
	}
}

// #3861 guardrail: a `commit confirmed` FOLLOWED BY another `commit
// confirmed` must still RE-ARM (Junos: it extends the window), NOT be
// treated as a plain-commit confirmation. The nested re-arm preserves the
// ORIGINAL rollback target (the last truly confirmed config), and the window
// stays pending. Only a PLAIN commit clears it.
func TestNestedCommitConfirmedStillReArms_3861(t *testing.T) {
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

	// First commit confirmed: target = Base.
	if err := s.SetFromInput("system host-name C1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	gen1 := s.ConfirmGenForTesting()

	// Nested commit confirmed: re-arms; still pending; target PRESERVED = Base.
	if err := s.SetFromInput("system host-name C2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(2); err != nil {
		t.Fatal(err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("a nested commit confirmed must STILL leave a pending window (re-arm, not clear)")
	}
	gen2 := s.ConfirmGenForTesting()
	if gen2 == gen1 {
		t.Fatalf("nested CommitConfirmed must advance confirmGen (re-arm): gen1=%d gen2=%d", gen1, gen2)
	}

	// The re-armed timer firing rolls back to the PRESERVED original target
	// (Base), proving the nested confirmed did not overwrite it and the
	// window was genuinely still armed.
	s.InvokeRollbackTimerForTesting(gen2)
	if got := s.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("re-armed confirm-timer rolled back to %q, want Base "+
			"(nested confirmed must preserve the original rollback target)", got)
	}
}

// #3861: the frontend explicit confirmation (ConfirmCommit) must still cancel
// the window so a subsequent timer fire is a no-op — the refactor to the
// shared clearPendingConfirmLocked helper must not regress it.
func TestConfirmCommitStillCancelsTimer_3861(t *testing.T) {
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

	if err := s.SetFromInput("system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatal(err)
	}
	armGen := s.ConfirmGenForTesting()

	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	if s.IsConfirmPending() {
		t.Error("ConfirmCommit must clear the pending window")
	}

	s.InvokeRollbackTimerForTesting(armGen)
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("post-ConfirmCommit timer fire reverted to %q, want Confirmed", got)
	}
}
