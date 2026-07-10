package configstore

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestStoreMutatorHolderEnforcement pins the #5059 atomic holder check in the
// session-scoped *As mutators: a non-holder session is rejected with
// ErrConfigLockedByOther, the holder is allowed, and the internal ("") caller
// bypasses. Reverting ensureHolderLocked to a no-op makes the non-holder cases
// return nil → RED.
func TestStoreMutatorHolderEnforcement(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnterConfigureSession("owner"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}

	// Every user mutator rejects a session that is not the lock holder.
	nonHolder := []struct {
		name string
		fn   func() error
	}{
		{"SetAs", func() error { return store.SetAs("intruder", []string{"system", "host-name", "x"}) }},
		{"SetFromInputAs", func() error { return store.SetFromInputAs("intruder", "system host-name x") }},
		{"DeleteAs", func() error { return store.DeleteAs("intruder", []string{"system", "host-name"}) }},
		{"DeleteFromInputAs", func() error { return store.DeleteFromInputAs("intruder", "system host-name") }},
		{"DeactivateFromInputAs", func() error { return store.DeactivateFromInputAs("intruder", "system host-name") }},
		{"ActivateFromInputAs", func() error { return store.ActivateFromInputAs("intruder", "system host-name") }},
		{"CopyAs", func() error {
			return store.CopyAs("intruder", []string{"system", "host-name"}, []string{"system", "domain-name"})
		}},
		{"RenameAs", func() error {
			return store.RenameAs("intruder", []string{"system", "host-name"}, []string{"system", "domain-name"})
		}},
		{"InsertAs", func() error {
			return store.InsertAs("intruder", []string{"a"}, []string{"b"}, true)
		}},
		{"LoadOverrideAs", func() error { return store.LoadOverrideAs("intruder", "system { host-name x; }") }},
		{"LoadMergeAs", func() error { return store.LoadMergeAs("intruder", "set system host-name x") }},
		{"LoadSetAs", func() error { _, e := store.LoadSetAs("intruder", "set system host-name x"); return e }},
		{"RollbackAs", func() error { return store.RollbackAs("intruder", 0) }},
		{"ConfirmCommitAs", func() error { return store.ConfirmCommitAs("intruder") }},
	}
	for _, tc := range nonHolder {
		if err := tc.fn(); !errors.Is(err, ErrConfigLockedByOther) {
			t.Errorf("%s(non-holder) = %v, want ErrConfigLockedByOther", tc.name, err)
		}
	}

	// The lock holder is allowed.
	if err := store.SetAs("owner", []string{"system", "host-name", "ok"}); err != nil {
		t.Errorf("SetAs(holder) = %v, want nil", err)
	}

	// The internal/system caller ("") bypasses ownership.
	if err := store.SetAs("", []string{"system", "host-name", "internal"}); err != nil {
		t.Errorf("SetAs(internal) = %v, want nil", err)
	}
}

// TestEnsureConfigHolder covers the exported gate the commit-family RPCs use.
func TestEnsureConfigHolder(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnterConfigureSession("owner"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	if err := store.EnsureConfigHolder("intruder"); !errors.Is(err, ErrConfigLockedByOther) {
		t.Errorf("EnsureConfigHolder(non-holder) = %v, want ErrConfigLockedByOther", err)
	}
	if err := store.EnsureConfigHolder("owner"); err != nil {
		t.Errorf("EnsureConfigHolder(holder) = %v, want nil", err)
	}
	if err := store.EnsureConfigHolder(""); err != nil {
		t.Errorf("EnsureConfigHolder(internal) = %v, want nil", err)
	}
}
