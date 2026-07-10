package configstore

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnnotateHolderEnforcement pins the #5379 fix: Store.Annotate and its new
// session-scoped AnnotateAs variant enforce config-lock ownership through the
// same ensureHolderLocked guard every sibling candidate mutator uses (#5059).
//
// Before the fix, Annotate consulted only ensureWritableLocked + candidate!=nil
// and never called ensureHolderLocked, so it was the one user mutator that let
// a caller who did NOT hold the config lock mutate another session's candidate
// (via AnnotatePath) and refresh — extend — the true holder's idle lease
// (touchConfigLockLocked) with no ownership check.
//
// RED-on-revert: remove the ensureHolderLocked call from AnnotateAs and the
// non-holder case returns nil instead of ErrConfigLockedByOther, failing this
// test.
func TestAnnotateHolderEnforcement(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnterConfigureSession("owner"); err != nil {
		t.Fatalf("EnterConfigureSession: %v", err)
	}
	// Seed the node the holder later annotates.
	if err := store.SetAs("owner", []string{"system", "host-name", "fw"}); err != nil {
		t.Fatalf("SetAs(owner) seed: %v", err)
	}

	// A non-holder session is rejected with the SAME sentinel the sibling
	// mutators return — no candidate mutation, no lease refresh.
	if err := store.AnnotateAs("intruder", []string{"system"}, "intruder-note"); !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("AnnotateAs(non-holder) = %v, want ErrConfigLockedByOther", err)
	}
	// The rejected annotate must not have touched the candidate.
	if strings.Contains(store.ShowCandidate(), "intruder-note") {
		t.Fatalf("non-holder annotation leaked into candidate:\n%s", store.ShowCandidate())
	}

	// The lock holder is allowed and the annotation is applied.
	if err := store.AnnotateAs("owner", []string{"system"}, "owned"); err != nil {
		t.Fatalf("AnnotateAs(holder) = %v, want nil", err)
	}
	if !strings.Contains(store.ShowCandidate(), "/* owned */") {
		t.Fatalf("holder annotation not applied:\n%s", store.ShowCandidate())
	}

	// The internal/system caller ("") bypasses ownership — this keeps the
	// stateless REST config-enter path and the in-process CLI (which call the
	// plain Annotate) bit-identical to before the fix.
	if err := store.Annotate([]string{"system"}, "internal"); err != nil {
		t.Fatalf("Annotate(internal) = %v, want nil", err)
	}
	if err := store.AnnotateAs("", []string{"system"}, "internal2"); err != nil {
		t.Fatalf("AnnotateAs(internal) = %v, want nil", err)
	}
}
