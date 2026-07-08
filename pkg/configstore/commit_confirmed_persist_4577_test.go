package configstore

import (
	"path/filepath"
	"testing"
	"time"
)

// #4577: the commit-confirmed rollback deadline used to be an IN-MEMORY
// time.AfterFunc only — no confirm.json was persisted and Store.Load never
// re-armed it. A daemon crash/reboot INSIDE the confirm window therefore made
// the UNCONFIRMED config permanent, silently losing the auto-rollback safety
// hatch (the operator commits a management-stranding config relying on
// commit-confirmed to auto-revert, the daemon crashes, the box is stranded).
//
// These tests simulate a crash+restart by arming a commit-confirmed on one
// Store, then constructing a FRESH Store over the SAME .configdb and calling
// Load (the daemon boot path). The confirm state must survive.

// armed builds a Store at path, commits Base, then commit-confirmed Confirmed,
// leaving a pending window. Returns the store (its in-memory timer keeps
// running with `minutes`; harmless for the test).
func armedConfirmStore(t *testing.T, path string, minutes int) *Store {
	t.Helper()
	s := newTestStoreAt(t, path)
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
	if _, err := s.CommitConfirmed(minutes); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if !s.IsConfirmPending() {
		t.Fatal("should have a pending confirm after CommitConfirmed")
	}
	// The confirm.json must exist after arming.
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("CommitConfirmed must persist confirm.json: rec=%v err=%v", rec, err)
	}
	return s
}

// RED-on-revert (a): the confirm window expired during downtime. A fresh
// Store.Load MUST roll back to the pre-confirm config (Base) — the unconfirmed
// config (Confirmed) is NOT permanent. Before the fix Load ignored the
// (nonexistent) persisted state and left Confirmed active forever.
func TestConfirmRecovery_ExpiredRollsBackOnLoad_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10)

	// Force the persisted deadline into the past (simulate a downtime longer
	// than the window — the minutes granularity of the public API cannot go
	// sub-minute). In-package access to the DB is deliberate.
	s0 := newTestStoreAt(t, path)
	rec, err := s0.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("ReadConfirm: rec=%v err=%v", rec, err)
	}
	rec.Deadline = time.Now().Add(-2 * time.Minute)
	if err := s0.db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm (past deadline): %v", err)
	}

	// Crash+restart: a brand-new Store over the same .configdb.
	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if s.IsConfirmPending() {
		t.Error("an expired confirm window must NOT stay pending after Load")
	}
	got := s.ActiveConfig()
	if got == nil {
		t.Fatal("ActiveConfig is nil after recovery rollback")
	}
	if got.System.HostName != "Base" {
		t.Fatalf("expired confirm window: active host-name = %q, want Base "+
			"(the unconfirmed config was NOT rolled back — #4577 regression)",
			got.System.HostName)
	}
	// The persisted state must be cleared once resolved.
	if r, err := s.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed after recovery rollback: rec=%v err=%v", r, err)
	}
	// A second restart must be a clean, non-pending load of the rolled-back
	// config (idempotent recovery).
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if s2.IsConfirmPending() {
		t.Error("second restart must not resurrect the resolved window")
	}
	if s2.ActiveConfig().System.HostName != "Base" {
		t.Fatalf("second restart: active host-name = %q, want Base", s2.ActiveConfig().System.HostName)
	}
}

// RED-on-revert (b): still within the window. A fresh Store.Load MUST re-arm
// the timer (a pending confirm is still tracked) and keep the unconfirmed
// config active until the re-armed timer fires — at which point it rolls back
// to the ORIGINAL pre-confirm target (Base).
func TestConfirmRecovery_WithinWindowReArmsOnLoad_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10) // 10-minute window, still open

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !s.IsConfirmPending() {
		t.Fatal("a still-open confirm window must be re-armed (pending) after Load — #4577")
	}
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("within window: active host-name = %q, want Confirmed "+
			"(the unconfirmed config must stay active until the re-armed timer fires)", got)
	}
	// confirm.json is left in place while the window is open.
	if r, err := s.db.ReadConfirm(); err != nil || r == nil {
		t.Fatalf("confirm.json must remain while the window is open: rec=%v err=%v", r, err)
	}

	// Drive the re-armed timer deterministically: it must roll back to the
	// ORIGINAL rollback target (Base), proving the persisted target was
	// restored correctly.
	gen := s.ConfirmGenForTesting()
	s.InvokeRollbackTimerForTesting(gen)

	if got := s.ActiveConfig().System.HostName; got != "Base" {
		t.Fatalf("re-armed confirm timer rolled back to %q, want Base "+
			"(recovered rollback target wrong — #4577)", got)
	}
	if s.IsConfirmPending() {
		t.Error("after the re-armed timer fires the window must be resolved")
	}
	if r, err := s.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed after the re-armed timer fires: rec=%v err=%v", r, err)
	}
}

// A normal confirm-within-window (explicit ConfirmCommit) must make the config
// permanent: confirm.json is removed, and a subsequent restart loads the
// confirmed config with NO pending window and NO rollback.
func TestConfirmRecovery_ExplicitConfirmIsPermanent_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s0 := armedConfirmStore(t, path, 10)
	if err := s0.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	if r, err := s0.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("ConfirmCommit must remove confirm.json: rec=%v err=%v", r, err)
	}

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Error("a confirmed config must NOT be pending after restart")
	}
	if got := s.ActiveConfig().System.HostName; got != "Confirmed" {
		t.Fatalf("confirmed config after restart: active host-name = %q, want Confirmed", got)
	}
}

// A bare `commit` during the window confirms the pending config (Junos
// semantics). confirm.json is removed and a restart must NOT roll back — the
// bare-commit config is permanent.
func TestConfirmRecovery_BareCommitConfirms_4577(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s0 := armedConfirmStore(t, path, 10)

	// Background/eventengine PLAIN commit during the window (reaches
	// CommitWithDescription directly, which calls clearPendingConfirmLocked).
	if err := s0.SetFromInput("system host-name Remediated"); err != nil {
		t.Fatal(err)
	}
	if _, err := s0.Commit(); err != nil {
		t.Fatalf("plain Commit during confirm window: %v", err)
	}
	if s0.IsConfirmPending() {
		t.Error("a plain commit must confirm (clear) the pending window")
	}
	if r, err := s0.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("a plain commit must remove confirm.json: rec=%v err=%v", r, err)
	}

	s := newTestStoreAt(t, path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.IsConfirmPending() {
		t.Error("no pending window must survive a bare-commit confirmation")
	}
	if got := s.ActiveConfig().System.HostName; got != "Remediated" {
		t.Fatalf("bare-commit-confirmed config after restart: active host-name = %q, "+
			"want Remediated (the confirmed config must be permanent — not rolled back)", got)
	}
}
