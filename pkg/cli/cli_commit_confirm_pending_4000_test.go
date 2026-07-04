package cli

import (
	"path/filepath"
	"testing"
)

// #4000: a bare `commit` issued while a `commit confirmed` window is pending
// must COMMIT any candidate edits staged after the confirmed commit — not just
// confirm the pending config and silently drop them. Before the fix the CLI
// commit handler intercepted ANY pending confirm and called ConfirmCommit
// (timer-clear only), returning success while discarding the new edits.
//
// RED-on-revert: with the `&& !c.store.IsDirty()` guard removed, the bare
// commit takes the confirm-only branch, so the staged "Edited" host-name is
// dropped (active still shows "Confirmed") while handleCommit returns nil —
// the silent edit loss this issue describes.
func TestBareCommitDuringConfirmWindowCommitsNewEdits_4000(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// commitFn / applyConfigFn are unwired: runCommit falls back to
	// store.Commit and commitApply is a no-op, so this drives the real
	// cli_config.go bare-commit intercept against a live store.
	c := &CLI{store: store}

	// Baseline commit.
	if _, err := store.LoadSet("set system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("baseline commit: %v", err)
	}

	// commit confirmed 5: arms the auto-rollback timer (target = Base).
	if _, err := store.LoadSet("set system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit([]string{"confirmed", "5"}); err != nil {
		t.Fatalf("commit confirmed: %v", err)
	}
	if !store.IsConfirmPending() {
		t.Fatal("expected a pending confirm after `commit confirmed`")
	}
	// The real timer closure captures this generation at arm time.
	armGen := store.ConfirmGenForTesting()

	// Stage a NEW candidate edit during the confirm window.
	if _, err := store.LoadSet("set system host-name Edited"); err != nil {
		t.Fatal(err)
	}
	if !store.IsDirty() {
		t.Fatal("candidate must be dirty after staging a new edit")
	}

	// Bare commit: must commit the new edit AND confirm the pending window.
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("bare commit during confirm window: %v", err)
	}

	if got := store.ActiveConfig().System.HostName; got != "Edited" {
		t.Fatalf("bare commit dropped the staged edit: active host-name = %q, "+
			"want Edited (#4000 silent edit loss)", got)
	}
	if store.IsConfirmPending() {
		t.Fatal("bare commit during a confirm window must clear the pending timer (#3861)")
	}

	// The armed timer firing must be a no-op — confirmGen was bumped by the
	// commit's clearPendingConfirmLocked, so the new commit must SURVIVE.
	store.InvokeRollbackTimerForTesting(armGen)
	if got := store.ActiveConfig().System.HostName; got != "Edited" {
		t.Fatalf("confirm-timer fire reverted the new commit: active host-name = %q, want Edited", got)
	}
}

// #4000 guardrail: a bare `commit` during a confirm window with an UNCHANGED
// candidate is a pure confirmation — it clears the timer without pushing a new
// commit. This preserves the pre-#4000 confirm-only behavior for the no-edit
// case (and the "no spurious rollback entry" property).
func TestBareCommitDuringConfirmWindowUnchangedJustConfirms_4000(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	c := &CLI{store: store}

	if _, err := store.LoadSet("set system host-name Base"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("baseline commit: %v", err)
	}

	if _, err := store.LoadSet("set system host-name Confirmed"); err != nil {
		t.Fatal(err)
	}
	if err := c.handleCommit([]string{"confirmed", "5"}); err != nil {
		t.Fatalf("commit confirmed: %v", err)
	}
	if !store.IsConfirmPending() {
		t.Fatal("expected a pending confirm after `commit confirmed`")
	}
	if store.IsDirty() {
		t.Fatal("candidate must be clean immediately after commit confirmed")
	}
	nHistBefore := len(store.ListHistory())

	// Bare commit with no new edits: confirm-only.
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("bare commit (unchanged) during confirm window: %v", err)
	}

	if store.IsConfirmPending() {
		t.Fatal("bare commit must clear the pending confirm window")
	}
	if got := store.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("active host-name = %q, want Confirmed", got)
	}
	// An unchanged-candidate confirm must NOT push a new commit history entry.
	if nHistAfter := len(store.ListHistory()); nHistAfter != nHistBefore {
		t.Fatalf("unchanged-candidate confirm pushed a spurious history entry: "+
			"before=%d after=%d", nHistBefore, nHistAfter)
	}
}
