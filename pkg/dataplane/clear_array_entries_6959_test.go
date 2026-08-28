package dataplane

import (
	"strings"
	"testing"
)

// #6959: the blind-write clear loops #6743 left behind now share one body,
// clearArrayEntriesIn, which PROPAGATES the first Update error instead of
// discarding it. These bind that body through the same counterMapUpdater
// seam #6743 introduced (a real *ebpf.Map cannot be created in the
// unprivileged unit lane — map creation returns EPERM — and a test that
// SKIPS leaves the mutation cell unknown rather than green).
//
// The fake is fakeCounterUpdater from counter_clear_error_2114_test.go:
// one fake, so it cannot drift into two shapes, and
// TestCounterMapUpdaterIsSatisfiedByEBPFMap there already pins that the
// seam is exactly what *ebpf.Map provides.

// TestClearArrayEntriesIn_PropagatesUpdateError is the binder.
//
// Fail-on-revert: drop the `if err := ...; err != nil { return ... }`
// wrapper in clearArrayEntriesIn (pkg/dataplane/maps_policy.go) back to a
// bare `zm.Update(i, zero, ebpf.UpdateAny)` and this reports a nil error
// for a map that rejected the write.
func TestClearArrayEntriesIn_PropagatesUpdateError(t *testing.T) {
	t.Parallel()

	up := &fakeCounterUpdater{failAt: 5, fail: true}
	err := clearArrayEntriesIn(up, "test_map", 64, uint32(0))
	if err == nil {
		t.Fatal("clearArrayEntriesIn reported SUCCESS after the map rejected the write at index 5; " +
			"the operator's clear silently did nothing")
	}
	if !strings.Contains(err.Error(), "test_map") {
		t.Errorf("error %q does not name the map", err)
	}
	if !strings.Contains(err.Error(), "entry 5") {
		t.Errorf("error %q does not name the rejected index", err)
	}
	// It must STOP at the rejection rather than blind-writing the rest:
	// indices 0..5 inclusive, and nothing after.
	if up.calls != 6 {
		t.Errorf("clearArrayEntriesIn made %d writes after the index-5 rejection, want 6 (0..5); "+
			"it kept blind-writing past a map that had already refused", up.calls)
	}
}

// TestClearArrayEntriesIn_HealthyMapWritesEveryEntry is the OVER-REACH
// guard: propagating an error must not change what a HEALTHY clear does.
// A healthy map must still succeed AND still be swept end to end, so the
// change cannot have narrowed the sweep, stopped it early, or turned a
// working clear into an error. GREEN under the revert above.
func TestClearArrayEntriesIn_HealthyMapWritesEveryEntry(t *testing.T) {
	t.Parallel()

	const entries = 4096
	up := &fakeCounterUpdater{}
	if err := clearArrayEntriesIn(up, "test_map", entries, uint32(0)); err != nil {
		t.Fatalf("healthy clear returned %v, want nil", err)
	}
	if up.calls != entries || up.maxKey != entries-1 {
		t.Fatalf("healthy clear wrote %d entries up to index %d, want %d up to %d",
			up.calls, up.maxKey, entries, entries-1)
	}
}

// TestClearArrayEntriesIn_ZeroEntriesIsNotAnError pins the degenerate
// bound: an empty range is a completed clear, not a failure. Without this
// a "fix" that returned an error on an empty sweep would look correct.
func TestClearArrayEntriesIn_ZeroEntriesIsNotAnError(t *testing.T) {
	t.Parallel()

	up := &fakeCounterUpdater{failAt: 0, fail: true}
	if err := clearArrayEntriesIn(up, "test_map", 0, uint32(0)); err != nil {
		t.Fatalf("empty clear returned %v, want nil", err)
	}
	if up.calls != 0 {
		t.Fatalf("empty clear made %d writes, want 0", up.calls)
	}
}
