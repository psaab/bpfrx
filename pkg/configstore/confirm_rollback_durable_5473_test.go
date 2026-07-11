package configstore

// #5473: a commit-confirmed recovery record (confirm.json) must NOT be removed
// until the rollback (or authoritative replacement) it guards is DURABLE on
// disk.
//
// The three resolution loci — the timeout auto-rollback (PromoteRollback), boot
// recovery (recoverPendingConfirmLocked), and an HA config-sync that supersedes
// a pending window (SyncApply) — used to promote the replacement in memory, run
// a degrade-not-fail active write, and then UNCONDITIONALLY delete confirm.json.
// On a write FAILURE the on-disk active config is still the PRE-rollback config
// (C) while the record that would re-drive the rollback to the target (A) is
// gone. A crash before the degraded retry heals then boots C — the exact config
// `commit confirmed` was supposed to revert — with no recovery record.
//
// These tests inject an active-write failure at each locus and assert the
// crash-recovery contract: on write FAILURE confirm.json is RETAINED and a
// subsequent boot re-drives the rollback to A; on write SUCCESS confirm.json is
// removed exactly as before.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// forceConfirmDeadlinePast rewrites the persisted confirm.json deadline into the
// past over the DB at path, so a fresh Store.Load hits the EXPIRED recovery
// branch deterministically (the public minutes API cannot express a sub-minute
// window). Mirrors the #4577 test's technique.
func forceConfirmDeadlinePast(t *testing.T, path string) {
	t.Helper()
	s := newTestStoreAt(t, path)
	rec, err := s.db.ReadConfirm()
	if err != nil || rec == nil {
		t.Fatalf("forceConfirmDeadlinePast: ReadConfirm rec=%v err=%v (record must be retained)", rec, err)
	}
	rec.Deadline = time.Now().Add(-2 * time.Minute)
	if err := s.db.WriteConfirm(rec); err != nil {
		t.Fatalf("forceConfirmDeadlinePast: WriteConfirm: %v", err)
	}
}

// TestAutoRollback_PersistFailureRetainsConfirmRecord_5473 pins the timeout
// auto-rollback locus (PromoteRollback). A failed rollback active write must
// KEEP confirm.json so a crash before the degraded retry heals boots into a
// state that RE-RUNS the rollback to the pre-confirm target (Base), not the
// unconfirmed committed config the failed write left on disk.
func TestAutoRollback_PersistFailureRetainsConfirmRecord_5473(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	s := newTestStoreAt(t, path)
	commitBaseline(t, s) // confirmed base A: trust only
	baseSet := s.ShowActiveSet()

	// Long backoff so the degraded retry does NOT heal during the crash
	// simulation below — we are proving the ON-DISK recovery record, not the
	// in-process heal.
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

	// Pending confirmed commit C (persists fine; disk now holds the unconfirmed
	// candidate + confirm.json whose rollback target is A).
	if err := s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("armed confirm.json must exist: rec=%v err=%v", rec, err)
	}
	gen := s.ConfirmGenForTesting()

	// Disk breaks before the timer fires.
	s.SetWriteActiveForTesting(failingWriteActive)

	// Fire the real auto-rollback timer dispatch (no executor -> performAutoRollback).
	s.InvokeRollbackTimerForTesting(gen)

	// In-memory rollback proceeded (the safety property is unconditional).
	if got := s.ShowActiveSet(); got != baseSet {
		t.Errorf("rollback did not revert active in memory:\nwant: %s\ngot: %s", baseSet, got)
	}
	if s.IsConfirmPending() {
		t.Error("in-memory confirm window must be resolved after auto-rollback")
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("degraded flag must be set after a failed rollback persist")
	}

	// #5473 core: the recovery record MUST survive a failed rollback write.
	// (RED-on-revert: the pre-#5473 unconditional removeConfirmState deletes it.)
	rec, err := s.db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
	if rec == nil {
		t.Fatal("confirm.json was DELETED despite the failed rollback write — a crash now " +
			"boots the unconfirmed config with NO recovery record (#5473 regression)")
	}
	// The retained record's target is A (Base), so recovery re-drives the
	// rollback to the pre-confirm config — not the unconfirmed committed config.
	if prevSet := rec.PrevTree.FormatSet(); strings.Contains(prevSet, "untrust") {
		t.Errorf("retained rollback target must be the pre-confirm config (A), got:\n%s", prevSet)
	}

	// Simulate a crash before the retry heals: a fresh Store over the same
	// .configdb (its writeActive works) must re-drive the rollback to A.
	forceConfirmDeadlinePast(t, path)
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load after crash: %v", err)
	}
	if got := s2.ShowActiveSet(); got != baseSet {
		t.Fatalf("boot recovery did not re-drive the rollback to A:\nwant: %s\ngot: %s\n"+
			"(the unconfirmed config became permanent — #5473)", baseSet, got)
	}
	if r, err := s2.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed once the boot rollback is durable: rec=%v err=%v", r, err)
	}
}

// TestAutoRollback_PersistSuccessRemovesConfirmRecord_5473 is the success
// control: when the rollback write SUCCEEDS, confirm.json is removed exactly as
// before the fix (the durable-transition success path is unchanged).
func TestAutoRollback_PersistSuccessRemovesConfirmRecord_5473(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)
	baseSet := s.ShowActiveSet()

	if err := s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	gen := s.ConfirmGenForTesting()

	s.InvokeRollbackTimerForTesting(gen) // writeActive succeeds (no seam)

	if got := s.ShowActiveSet(); got != baseSet {
		t.Errorf("rollback landed on the wrong config:\nwant: %s\ngot: %s", baseSet, got)
	}
	if s.ConfigPersistDegraded() {
		t.Error("a successful rollback persist must not flag degraded")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("a durable rollback must remove confirm.json: rec=%v err=%v", rec, err)
	}
}

// TestConfirmRecovery_PersistFailureRetainsConfirmRecord_5473 pins the boot
// recovery locus (recoverPendingConfirmLocked). When the confirm window expired
// during downtime and the recovery rollback's active write fails, confirm.json
// must be RETAINED so a second crash still re-drives the rollback to A.
func TestConfirmRecovery_PersistFailureRetainsConfirmRecord_5473(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	_ = armedConfirmStore(t, path, 10) // Base (A) confirmed, then Confirmed (C) unconfirmed
	forceConfirmDeadlinePast(t, path)  // expired during downtime

	// Boot with a broken disk AND a long retry backoff so the recovery
	// rollback's write fails and does not heal in-process.
	s := newTestStoreAt(t, path)
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)
	s.SetWriteActiveForTesting(failingWriteActive)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// In-memory recovery reverted to A even though the disk write failed.
	got := s.ActiveConfig()
	if got == nil {
		t.Fatal("ActiveConfig is nil after recovery rollback")
	}
	if got.System.HostName != "Base" {
		t.Fatalf("recovery must revert to A in memory: host-name=%q want Base", got.System.HostName)
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("degraded flag must be set after a failed recovery-rollback persist")
	}

	// #5473 core: the recovery record survives the failed recovery write.
	// (RED-on-revert: pre-#5473 deletes it, and disk active.json is still C.)
	rec, err := s.db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
	if rec == nil {
		t.Fatal("confirm.json was DELETED despite the failed recovery write — a second crash " +
			"would boot the unconfirmed config C permanently (#5473 regression)")
	}

	// Second crash: a fresh boot with a working disk finishes the rollback to A.
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("second boot Load: %v", err)
	}
	if hn := s2.ActiveConfig().System.HostName; hn != "Base" {
		t.Fatalf("second boot did not complete the rollback: host-name=%q want Base "+
			"(the unconfirmed config C survived — #5473)", hn)
	}
	if s2.IsConfirmPending() {
		t.Error("no pending window must survive the completed rollback")
	}
	if r, err := s2.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed once the rollback is durable: rec=%v err=%v", r, err)
	}
}

// TestSyncApply_PersistFailureRetainsConfirmRecord_5473 pins the HA config-sync
// locus (SyncApply). A sync that supersedes a pending commit-confirmed window
// must not delete confirm.json until the synced (replacement) config is durable:
// if the degrade-not-fail write fails, keep the record so a crash re-drives the
// ORIGINAL commit-confirmed rollback to A (the synced config never persisted).
func TestSyncApply_PersistFailureRetainsConfirmRecord_5473(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	s := newTestStoreAt(t, path)
	commitBaseline(t, s) // confirmed base A: trust only
	baseSet := s.ShowActiveSet()
	s.SetPersistRetryBackoffForTesting(time.Hour, time.Hour)

	// Pending confirmed commit C with rollback target A.
	if err := s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("armed confirm.json must exist: rec=%v err=%v", rec, err)
	}

	// Disk breaks, then the primary pushes a config sync that supersedes the
	// pending window. Option B: SyncApply must NOT fail.
	s.SetWriteActiveForTesting(failingWriteActive)
	compiled, err := s.SyncApply(syncContent, nil)
	if err != nil {
		t.Fatalf("SyncApply must not fail on persist failure (Option B): %v", err)
	}
	if _, ok := compiled.Security.Zones["synced"]; !ok {
		t.Fatal("synced zone missing from compiled config")
	}
	if s.IsConfirmPending() {
		t.Error("the sync must cancel the in-memory confirm timer")
	}
	if !s.ConfigPersistDegraded() {
		t.Fatal("degraded flag must be set after a failed sync persist")
	}

	// #5473 core: confirm.json survives the failed sync write. (RED-on-revert:
	// pre-#5473 clearPendingConfirmLocked removed it up front.)
	rec, err := s.db.ReadConfirm()
	if err != nil {
		t.Fatalf("ReadConfirm: %v", err)
	}
	if rec == nil {
		t.Fatal("confirm.json was DELETED despite the failed sync write — a crash would lose " +
			"the commit-confirmed rollback and strand the unconfirmed config (#5473 regression)")
	}
	if prevSet := rec.PrevTree.FormatSet(); strings.Contains(prevSet, "untrust") {
		t.Errorf("retained rollback target must be the pre-confirm config A, got:\n%s", prevSet)
	}

	// Crash: the synced config never reached disk, so a fresh boot re-drives the
	// ORIGINAL commit-confirmed rollback to A.
	forceConfirmDeadlinePast(t, path)
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("boot Load after crash: %v", err)
	}
	if got := s2.ShowActiveSet(); got != baseSet {
		t.Fatalf("boot recovery did not re-drive the commit-confirmed rollback to A:\n"+
			"want: %s\ngot: %s (the unconfirmed config C survived — #5473)", baseSet, got)
	}
	if r, err := s2.db.ReadConfirm(); err != nil || r != nil {
		t.Fatalf("confirm.json must be removed once the boot rollback is durable: rec=%v err=%v", r, err)
	}
}

// TestSyncApply_PersistSuccessRemovesConfirmRecord_5473 is the success control:
// a sync that supersedes a pending window and persists cleanly removes
// confirm.json, exactly as before the fix.
func TestSyncApply_PersistSuccessRemovesConfirmRecord_5473(t *testing.T) {
	s := newTestStore(t)
	commitBaseline(t, s)

	if err := s.SetFromInput("interfaces eth1 unit 0 family inet address 10.1.0.1/24"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone untrust interfaces eth1.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec == nil {
		t.Fatalf("armed confirm.json must exist: rec=%v err=%v", rec, err)
	}

	if _, err := s.SyncApply(syncContent, nil); err != nil { // writeActive succeeds (no seam)
		t.Fatalf("SyncApply: %v", err)
	}
	if s.ConfigPersistDegraded() {
		t.Error("a successful sync persist must not flag degraded")
	}
	if rec, err := s.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("a durable sync supersede must remove confirm.json: rec=%v err=%v", rec, err)
	}
}
