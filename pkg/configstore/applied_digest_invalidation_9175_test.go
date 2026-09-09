package configstore

import "testing"

// #9175 — the store half of the applied-marker invalidation.
//
// The BEHAVIOURAL red-on-revert for this issue lives in `pkg/daemon`
// (`applied_digest_failed_apply_9175_test.go`), because the defect is that
// nothing CALLED an invalidator, and a cell that calls one directly is green on
// a build where no production path does. These cells pin the store contract that
// call site depends on: that a cleared marker really is cleared, that clearing is
// not a one-way latch, and that the #4957 shortcut still arms on a real success.

const (
	digestConfA9175 = "system {\n    host-name node-a;\n}\n"
	digestConfB9175 = "system {\n    host-name node-b;\n}\n"
)

func TestInvalidateAppliedDigestClearsTheMarker9175(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply(digestConfA9175, nil); err != nil {
		t.Fatalf("SyncApply(A): %v", err)
	}
	s.MarkActiveApplied()
	if !s.ActiveApplied() {
		t.Fatal("CONTROL FAILED: the marker was never armed, so clearing it proves nothing")
	}

	s.InvalidateAppliedDigest()

	if s.ActiveApplied() {
		t.Error("#9175: InvalidateAppliedDigest left the marker armed. Its whole job " +
			"is to unrecord a success that a later FAILED apply has contradicted")
	}
}

// LOAD-BEARING. Clearing must not be a one-way latch: a later successful apply
// has to re-arm the shortcut, or every standby degrades to a full re-apply on
// each peer re-push for the life of the process — the cost #4957 exists to
// avoid, paid permanently instead of once.
func TestAMarkerClearedByAFailureCanBeReArmed9175(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply(digestConfA9175, nil); err != nil {
		t.Fatalf("SyncApply(A): %v", err)
	}
	s.MarkActiveApplied()
	s.InvalidateAppliedDigest()
	if s.ActiveApplied() {
		t.Fatal("CONTROL FAILED: the marker did not clear")
	}

	s.MarkActiveApplied() // the retry succeeded

	if !s.ActiveApplied() {
		t.Error("#9175: after an invalidation the marker can never be re-armed. " +
			"A transient apply failure would then disable the #4957 convergence " +
			"shortcut permanently")
	}
}

// Clearing a marker that was never armed is a no-op, not a panic or a state
// change. The daemon's failure path runs on every failed apply, including on a
// store that has never applied anything (a boot apply that fails).
func TestInvalidateOnAFreshStoreIsANoOp9175(t *testing.T) {
	s := newTestStore(t)
	s.InvalidateAppliedDigest()
	if s.ActiveApplied() {
		t.Fatal("a fresh store must still read not-applied")
	}
	if _, err := s.SyncApply(digestConfA9175, nil); err != nil {
		t.Fatalf("SyncApply(A): %v", err)
	}
	s.MarkActiveApplied()
	if !s.ActiveApplied() {
		t.Error("a no-op invalidation on a fresh store must not poison a later stamp")
	}
}

// The #4957 forward-sequence invariant must survive: promoting a DIFFERENT
// config still reads not-applied on the text alone, with no invalidation
// involved. This is the property the field comment described correctly, and the
// one #9175 leaves untouched.
func TestForwardPromotionStillReadsUnappliedWithoutAnyInvalidation9175(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SyncApply(digestConfA9175, nil); err != nil {
		t.Fatalf("SyncApply(A): %v", err)
	}
	s.MarkActiveApplied()
	if _, err := s.SyncApply(digestConfB9175, nil); err != nil {
		t.Fatalf("SyncApply(B): %v", err)
	}
	if s.ActiveApplied() {
		t.Error("promoting a different text must read not-applied on the digest " +
			"comparison alone (#4957); #9175 adds an invalidation, it does not " +
			"replace the text keying")
	}
}
