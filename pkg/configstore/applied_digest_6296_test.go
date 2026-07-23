package configstore

import "testing"

// TestMarkAppliedDigest_KeysCapturedNotCurrentActive locks the #6296 store
// contract: MarkAppliedDigest stamps a digest the caller CAPTURED earlier (via
// ActiveDigest, under its own apply serialization) rather than re-reading
// s.active. So when a concurrent promoter mutates s.active between the capture
// and the stamp, the marker still keys the config that was actually applied —
// not whatever active drifted to. This is the store-level property behind the
// daemon relocation of the config-sync stamp into syncAndApply.
//
// Contrast MarkActiveApplied (re-reads s.active at call time): TestActiveApplied
// (#4957) covers that path. Here we prove the capture/replay pair keys the
// captured tree even across an intervening promotion.
func TestMarkAppliedDigest_KeysCapturedNotCurrentActive(t *testing.T) {
	s := newTestStore(t)

	confA := "system {\n    host-name applied-a;\n}\n"
	confB := "system {\n    host-name promoter-b;\n}\n"

	// Promote + capture the digest of config A (what the caller "applied").
	if _, err := s.SyncApply(confA, nil); err != nil {
		t.Fatalf("SyncApply(A): %v", err)
	}
	if s.ActiveApplied() {
		t.Fatal("promoted-but-unstamped A must not read applied")
	}
	capturedA := s.ActiveDigest()
	if capturedA == "" {
		t.Fatal("ActiveDigest must be non-empty for a promoted config")
	}

	// A concurrent promoter lands and mutates active to a DIFFERENT config B
	// BEFORE the applied marker is stamped.
	if _, err := s.SyncApply(confB, nil); err != nil {
		t.Fatalf("SyncApply(B): %v", err)
	}

	// Stamp the digest captured for A. Because MarkAppliedDigest keys the CAPTURED
	// value (not a re-read of s.active == B), the current active B must NOT read
	// as applied — B's apply never happened.
	s.MarkAppliedDigest(capturedA)
	if s.ActiveApplied() {
		t.Fatal("#6296: MarkAppliedDigest(capturedA) must key A's digest, so the " +
			"concurrently-promoted active B must not read applied")
	}

	// Restore active to A (the config that WAS applied): now the captured marker
	// matches and ActiveApplied() reads true — proving the stamp keyed A, and that
	// ActiveDigest lives in the same space ActiveApplied compares against.
	if _, err := s.SyncApply(confA, nil); err != nil {
		t.Fatalf("SyncApply(A again): %v", err)
	}
	if !s.ActiveApplied() {
		t.Fatal("#6296: after restoring active to the applied config A, the marker " +
			"captured for A must read as applied")
	}
}

// TestMarkAppliedDigest_EmptyIsNoOp locks that an empty captured digest does not
// clear or overwrite an existing marker (the defensive nil-active path in
// syncAndApply must not disarm a previously-applied config).
func TestMarkAppliedDigest_EmptyIsNoOp(t *testing.T) {
	s := newTestStore(t)

	conf := "system {\n    host-name node-x;\n}\n"
	if _, err := s.SyncApply(conf, nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	s.MarkAppliedDigest(s.ActiveDigest())
	if !s.ActiveApplied() {
		t.Fatal("setup: config must read applied after stamping its captured digest")
	}

	// An empty stamp must leave the marker intact.
	s.MarkAppliedDigest("")
	if !s.ActiveApplied() {
		t.Fatal("#6296: MarkAppliedDigest(\"\") must be a no-op, not clear the marker")
	}
}
