package configstore

import "testing"

// TestActiveApplied_TracksPromotionVsApply locks the #4957 store contract that
// handleConfigSync's converged shortcut relies on: SyncApply promotes s.active
// to the peer config, but ActiveApplied() stays FALSE until the daemon confirms
// the apply via MarkActiveApplied(). A promoted-but-unapplied config must never
// read as applied, and a subsequent promotion of a DIFFERENT config must reset
// the applied state (the marker is keyed on the active config text).
func TestActiveApplied_TracksPromotionVsApply(t *testing.T) {
	s := newTestStore(t)

	// A fresh store has never applied anything.
	if s.ActiveApplied() {
		t.Fatal("fresh store: ActiveApplied must be false before any apply")
	}

	// Promote config A via SyncApply (the HA config-sync ingress). This mirrors
	// the daemon flow: the store promotes active BEFORE the daemon runs the apply.
	confA := "system {\n    host-name node-a;\n}\n"
	if _, err := s.SyncApply(confA, nil); err != nil {
		t.Fatalf("SyncApply(A): %v", err)
	}
	if s.ActiveApplied() {
		t.Fatal("after SyncApply(A) but before MarkActiveApplied: must read NOT applied (#4957)")
	}

	// The daemon confirms the apply succeeded.
	s.MarkActiveApplied()
	if !s.ActiveApplied() {
		t.Fatal("after MarkActiveApplied: the active config must read applied")
	}

	// Promote a DIFFERENT config B: the applied marker (keyed on active text) must
	// no longer match, so B reads as not-yet-applied until its own apply lands.
	confB := "system {\n    host-name node-b;\n}\n"
	if _, err := s.SyncApply(confB, nil); err != nil {
		t.Fatalf("SyncApply(B): %v", err)
	}
	if s.ActiveApplied() {
		t.Fatal("after promoting B: the stale A marker must not read B as applied (#4957)")
	}

	// Re-promoting the SAME text A after B was applied+marked also reads
	// not-applied (the marker is for B now), proving the check is text-keyed.
	s.MarkActiveApplied() // mark B applied
	if _, err := s.SyncApply(confA, nil); err != nil {
		t.Fatalf("SyncApply(A again): %v", err)
	}
	if s.ActiveApplied() {
		t.Fatal("after re-promoting A over an applied B: must read NOT applied until A re-applies")
	}
}
