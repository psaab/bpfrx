package configstore

import "testing"

// #4000: ConfirmCommit only CANCELS the rollback timer — it does NOT apply any
// candidate edits staged during the confirm window. This is the store contract
// that makes a bare-commit-during-window intercept dangerous: if the frontend
// routes a DIRTY candidate through ConfirmCommit (the pre-#4000 behavior), the
// operator's new edits are silently dropped while the confirm succeeds.
//
// This test pins that fact (ConfirmCommit leaves the staged edit UNAPPLIED)
// AND the correct alternative the fix relies on: a plain Commit on the dirty
// candidate applies the edit AND confirms the window (#3861 timer-clear), so
// the arm-time timer fire is a no-op and the new commit survives.
func TestConfirmVsCommitDuringConfirmWindow_4000(t *testing.T) {
	// Half 1: ConfirmCommit on a dirty candidate does NOT apply the edit.
	t.Run("ConfirmCommitDropsStagedEdit", func(t *testing.T) {
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

		// Stage a new edit inside the window.
		if err := s.SetFromInput("system host-name Edited"); err != nil {
			t.Fatal(err)
		}
		if !s.IsDirty() {
			t.Fatal("candidate must be dirty after staging a new edit")
		}

		// ConfirmCommit clears the window but does NOT promote the candidate.
		if err := s.ConfirmCommit(); err != nil {
			t.Fatalf("ConfirmCommit: %v", err)
		}
		if s.IsConfirmPending() {
			t.Fatal("ConfirmCommit must clear the pending window")
		}
		if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
			t.Fatalf("ConfirmCommit unexpectedly changed active to %q; it must NOT apply "+
				"staged candidate edits (this is why the frontend must Commit a dirty "+
				"candidate instead of confirm-only)", got)
		}
	})

	// Half 2: the fix path — a plain Commit on the dirty candidate applies the
	// edit AND confirms the window; the arm-time timer fire is a no-op.
	t.Run("CommitAppliesEditAndConfirms", func(t *testing.T) {
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

		if err := s.SetFromInput("system host-name Edited"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatalf("plain Commit on dirty candidate during window: %v", err)
		}
		if s.IsConfirmPending() {
			t.Fatal("plain commit during a confirm window must clear the pending timer (#3861)")
		}
		if got := s.ActiveConfig().System.HostName; got != "Edited" {
			t.Fatalf("plain commit did not apply the staged edit: active = %q, want Edited", got)
		}

		s.InvokeRollbackTimerForTesting(armGen)
		if got := s.ActiveConfig().System.HostName; got != "Edited" {
			t.Fatalf("confirm-timer fire reverted the new commit: active = %q, want Edited", got)
		}
	})
}
