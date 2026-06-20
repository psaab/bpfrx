package configstore

import (
	"strings"
	"testing"
)

// #2051: the store DeactivateFromInput/ActivateFromInput wrappers must mark a
// candidate node actually inactive (not create a junk node literally named
// "deactivate"). ShowCandidateSet emits a `deactivate <path>` line ONLY for a
// node whose Inactive flag is set (via FormatSet), so asserting that line is a
// proxy for node.Inactive==true — a naive no-error test would also pass against
// the broken mangling path, so these assert the inactivation itself.

func seedActiveNameServer(t *testing.T, s *Store) {
	t.Helper()
	if err := s.SetFromInput("system host-name keep"); err != nil {
		t.Fatalf("SetFromInput host-name: %v", err)
	}
	if err := s.SetFromInput("system name-server 9.9.9.9"); err != nil {
		t.Fatalf("SetFromInput name-server: %v", err)
	}
}

func TestDeactivateFromInputMarksInactive(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	seedActiveNameServer(t, s)

	// Before: the node is active, so display-set has no deactivate line.
	if before := s.ShowCandidateSet(); strings.Contains(before, "deactivate ") {
		t.Fatalf("name-server unexpectedly inactive before deactivate:\n%s", before)
	}

	if err := s.DeactivateFromInput("system name-server 9.9.9.9"); err != nil {
		t.Fatalf("DeactivateFromInput: %v", err)
	}

	out := s.ShowCandidateSet()
	// The node must be ACTUALLY inactive, not a junk "set deactivate ..." path.
	if !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("DeactivateFromInput did not mark the node inactive:\n%s", out)
	}
	if strings.Contains(out, "set deactivate ") {
		t.Fatalf("input was mangled into a junk set path:\n%s", out)
	}
	// The node itself (its set line) and the active sibling survive.
	if !strings.Contains(out, "set system name-server 9.9.9.9") {
		t.Fatalf("deactivate removed the node's set line:\n%s", out)
	}
	if !strings.Contains(out, "set system host-name keep") {
		t.Fatalf("active sibling lost on deactivate:\n%s", out)
	}
}

func TestActivateFromInputClearsInactive(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	seedActiveNameServer(t, s)

	if err := s.DeactivateFromInput("system name-server 9.9.9.9"); err != nil {
		t.Fatalf("DeactivateFromInput: %v", err)
	}
	if out := s.ShowCandidateSet(); !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("setup deactivate did not take:\n%s", out)
	}

	if err := s.ActivateFromInput("system name-server 9.9.9.9"); err != nil {
		t.Fatalf("ActivateFromInput: %v", err)
	}

	out := s.ShowCandidateSet()
	if strings.Contains(out, "deactivate ") {
		t.Fatalf("ActivateFromInput did not clear the inactive marker:\n%s", out)
	}
	if !strings.Contains(out, "set system name-server 9.9.9.9") {
		t.Fatalf("activate dropped the node:\n%s", out)
	}
}

// Idempotency: double-deactivate and double-activate are no-ops, not errors
// (markMatchingNodeInactive just re-sets a bool).
func TestDeactivateActivateIdempotent(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)
	seedActiveNameServer(t, s)

	for i := 0; i < 2; i++ {
		if err := s.DeactivateFromInput("system name-server 9.9.9.9"); err != nil {
			t.Fatalf("DeactivateFromInput pass %d: %v", i, err)
		}
	}
	if out := s.ShowCandidateSet(); !strings.Contains(out, "deactivate system name-server 9.9.9.9") {
		t.Fatalf("double-deactivate lost the marker:\n%s", out)
	}
	for i := 0; i < 2; i++ {
		if err := s.ActivateFromInput("system name-server 9.9.9.9"); err != nil {
			t.Fatalf("ActivateFromInput pass %d: %v", i, err)
		}
	}
	if out := s.ShowCandidateSet(); strings.Contains(out, "deactivate ") {
		t.Fatalf("double-activate left a marker:\n%s", out)
	}
}

// Deactivate/activate of a path that does not exist must error (the verb
// toggles an existing statement; it never creates one).
func TestDeactivateMissingPathErrors(t *testing.T) {
	s := newTestStore(t)
	enterCfg(t, s)

	if err := s.DeactivateFromInput("system name-server 1.2.3.4"); err == nil {
		t.Fatal("DeactivateFromInput on a missing path must error")
	}
	if err := s.ActivateFromInput("system name-server 1.2.3.4"); err == nil {
		t.Fatal("ActivateFromInput on a missing path must error")
	}
}

// Outside config mode the wrappers must refuse (candidate is nil).
func TestDeactivateNotInConfigMode(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeactivateFromInput("system name-server 9.9.9.9"); err == nil {
		t.Fatal("DeactivateFromInput outside config mode must error")
	}
	if err := s.ActivateFromInput("system name-server 9.9.9.9"); err == nil {
		t.Fatal("ActivateFromInput outside config mode must error")
	}
}
