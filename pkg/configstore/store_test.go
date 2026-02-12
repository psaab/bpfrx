package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// newTestStore creates a Store backed by a temp file for testing.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	return New(path)
}

func TestEnterExitConfigure(t *testing.T) {
	s := newTestStore(t)

	if s.InConfigMode() {
		t.Error("should not be in config mode initially")
	}

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if !s.InConfigMode() {
		t.Error("should be in config mode after enter")
	}

	// Double enter should fail
	if err := s.EnterConfigure(); err == nil {
		t.Error("expected error on double EnterConfigure")
	}

	s.ExitConfigure()
	if s.InConfigMode() {
		t.Error("should not be in config mode after exit")
	}
}

func TestSetAndCommit(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}

	// Set outside config mode should fail after exit
	cmds := []string{
		"security zones security-zone trust interfaces eth0.0",
		"security zones security-zone untrust interfaces eth1.0",
	}
	for _, cmd := range cmds {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}

	if !s.IsDirty() {
		t.Error("should be dirty after set")
	}

	// CommitCheck should succeed
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("CommitCheck: %v", err)
	}
	if cfg == nil {
		t.Fatal("CommitCheck returned nil config")
	}
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("expected 2 zones, got %d", len(cfg.Security.Zones))
	}

	// Commit
	cfg, err = s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if s.IsDirty() {
		t.Error("should not be dirty after commit")
	}

	// Active should contain our config
	active := s.ShowActive()
	if !strings.Contains(active, "trust") {
		t.Error("active config missing 'trust'")
	}
	if !strings.Contains(active, "untrust") {
		t.Error("active config missing 'untrust'")
	}

	// Compiled active should be available
	if s.ActiveConfig() == nil {
		t.Error("ActiveConfig() returned nil after commit")
	}
	if len(s.ActiveConfig().Security.Zones) != 2 {
		t.Errorf("active config: expected 2 zones, got %d",
			len(s.ActiveConfig().Security.Zones))
	}
}

func TestSetOutsideConfigMode(t *testing.T) {
	s := newTestStore(t)

	// Set without entering config mode should fail
	err := s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if err == nil {
		t.Error("expected error when setting outside config mode")
	}
}

func TestDeletePath(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	cmds := []string{
		"security zones security-zone trust interfaces eth0.0",
		"security zones security-zone trust interfaces eth1.0",
		"security zones security-zone untrust interfaces eth2.0",
	}
	for _, cmd := range cmds {
		if err := s.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput: %v", err)
		}
	}

	// Delete one interface
	if err := s.DeleteFromInput("security zones security-zone trust interfaces eth1.0"); err != nil {
		t.Fatalf("DeleteFromInput: %v", err)
	}

	candidate := s.ShowCandidateSet()
	if strings.Contains(candidate, "eth1.0") {
		t.Error("eth1.0 should have been deleted")
	}
	if !strings.Contains(candidate, "eth0.0") {
		t.Error("eth0.0 should still exist")
	}

	// Commit and verify
	cfg, err := s.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	trustZone := cfg.Security.Zones["trust"]
	if trustZone == nil {
		t.Fatal("trust zone missing")
	}
	if len(trustZone.Interfaces) != 1 || trustZone.Interfaces[0] != "eth0.0" {
		t.Errorf("trust zone interfaces: %v", trustZone.Interfaces)
	}
}

func TestShowCompare(t *testing.T) {
	s := newTestStore(t)

	// First commit
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Modify candidate
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	diff := s.ShowCompare()
	if !strings.Contains(diff, "+") {
		t.Errorf("expected diff to contain additions, got:\n%s", diff)
	}
	if !strings.Contains(diff, "untrust") {
		t.Errorf("diff should mention untrust:\n%s", diff)
	}
}

func TestRollback(t *testing.T) {
	s := newTestStore(t)

	// Commit 1: trust zone
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	cfg1, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg1.Security.Zones) != 1 {
		t.Fatalf("commit 1: expected 1 zone, got %d", len(cfg1.Security.Zones))
	}

	// Commit 2: add untrust zone
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	cfg2, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg2.Security.Zones) != 2 {
		t.Fatalf("commit 2: expected 2 zones, got %d", len(cfg2.Security.Zones))
	}

	// Rollback to commit 1 (rollback 1)
	if err := s.Rollback(1); err != nil {
		t.Fatalf("Rollback(1): %v", err)
	}
	if !s.IsDirty() {
		t.Error("should be dirty after rollback")
	}

	// Commit the rollback
	cfg3, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg3.Security.Zones) != 1 {
		t.Errorf("after rollback: expected 1 zone, got %d", len(cfg3.Security.Zones))
	}
	if cfg3.Security.Zones["trust"] == nil {
		t.Error("after rollback: trust zone should exist")
	}
}

func TestRollbackZero(t *testing.T) {
	s := newTestStore(t)

	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Modify candidate
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if !s.IsDirty() {
		t.Error("should be dirty after modification")
	}

	// Rollback 0 = revert candidate to active
	if err := s.Rollback(0); err != nil {
		t.Fatalf("Rollback(0): %v", err)
	}
	if s.IsDirty() {
		t.Error("should not be dirty after rollback 0")
	}

	// Candidate should match active (no untrust)
	candidate := s.ShowCandidateSet()
	if strings.Contains(candidate, "untrust") {
		t.Error("candidate should not contain untrust after rollback 0")
	}
}

func TestDirtyFlag(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	if s.IsDirty() {
		t.Error("should not be dirty initially")
	}

	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if !s.IsDirty() {
		t.Error("should be dirty after set")
	}

	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.IsDirty() {
		t.Error("should not be dirty after commit")
	}
}

func TestCommitConfirmedAutoRollback(t *testing.T) {
	s := newTestStore(t)

	// Initial commit
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Track rollback callback
	rollbackCalled := make(chan struct{}, 1)
	s.SetAutoRollbackHandler(func(cfg *config.Config) {
		rollbackCalled <- struct{}{}
	})

	// Commit confirmed with very short timeout (use CommitConfirmed with 1 min)
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")

	// We can't easily test the real timer with minutes, so verify the state tracking
	if !s.IsConfirmPending() {
		// Before commit confirmed, no timer
	}

	_, err := s.CommitConfirmed(1)
	if err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}

	if !s.IsConfirmPending() {
		t.Error("should have pending confirm after CommitConfirmed")
	}

	// Confirm it
	if err := s.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}

	if s.IsConfirmPending() {
		t.Error("should not have pending confirm after ConfirmCommit")
	}
}

func TestConfirmWithoutPending(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	err := s.ConfirmCommit()
	if err == nil {
		t.Error("expected error when confirming without pending commit")
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	// Create and save config
	s1 := New(path)
	if err := s1.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	s1.SetFromInput("security zones security-zone trust interfaces eth0.0")
	s1.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s1.Commit(); err != nil {
		t.Fatal(err)
	}

	// Load in a new store
	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify loaded config
	cfg := s2.ActiveConfig()
	if cfg == nil {
		t.Fatal("loaded config is nil")
	}
	if len(cfg.Security.Zones) != 2 {
		t.Errorf("loaded config: expected 2 zones, got %d", len(cfg.Security.Zones))
	}
}

func TestLoadNonexistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent")

	s := New(path)
	if err := s.Load(); err != nil {
		t.Fatalf("Load should not error on non-existent file: %v", err)
	}
}

func TestRollbackFilesPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	s := New(path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Commit 1
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Check rollback file exists
	rollbackPath := filepath.Join(dir, "config.1")
	if _, err := os.Stat(rollbackPath); os.IsNotExist(err) {
		t.Error("rollback file config.1 should exist")
	}

	// Load in new store and check history
	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}

	entries := s2.ListHistory()
	if len(entries) < 1 {
		t.Errorf("expected at least 1 history entry, got %d", len(entries))
	}
}

func TestShowRollback(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	// Commit 1
	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Commit 2
	s.SetFromInput("security zones security-zone untrust interfaces eth1.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	// Show rollback 1 should show commit 1 state (without untrust)
	rb, err := s.ShowRollback(1)
	if err != nil {
		t.Fatalf("ShowRollback(1): %v", err)
	}
	if !strings.Contains(rb, "trust") {
		t.Error("rollback 1 should contain trust zone")
	}

	// Invalid rollback slot
	_, err = s.ShowRollback(100)
	if err == nil {
		t.Error("expected error for invalid rollback slot")
	}
}

func TestHistory(t *testing.T) {
	h := NewHistory(3) // small buffer

	if h.Len() != 0 {
		t.Errorf("empty history len: %d", h.Len())
	}

	for i := 0; i < 5; i++ {
		h.Push(&HistoryEntry{
			Timestamp: time.Now(),
			Comment:   "test",
		})
	}

	// Should only keep 3 most recent
	if h.Len() != 3 {
		t.Errorf("expected len 3, got %d", h.Len())
	}

	entries := h.List()
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}

	// Get valid entry
	_, err := h.Get(0)
	if err != nil {
		t.Errorf("Get(0): %v", err)
	}

	// Get out of bounds
	_, err = h.Get(10)
	if err == nil {
		t.Error("expected error for out-of-bounds Get")
	}
}

func TestExportJSON(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}

	s.SetFromInput("security zones security-zone trust interfaces eth0.0")
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}

	data, err := s.ExportJSON()
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported JSON should not be empty")
	}
	if !strings.Contains(string(data), "trust") {
		t.Error("exported JSON should contain zone name")
	}
}
