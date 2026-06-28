package logging

import "testing"

// TestLatestNegativeN guards #3342: Latest(n) with a non-positive n must
// return an empty slice and never reach make([]EventRecord, n), which panics
// with "makeslice: len out of range" for a negative len.
//
// FAIL-ON-REVERT: removing the `if n <= 0 { return nil }` guard in Latest
// makes Latest(-1) panic, failing this test.
func TestLatestNegativeN(t *testing.T) {
	eb := NewEventBuffer(8)
	eb.Add(EventRecord{Type: "SESSION_OPEN"})
	eb.Add(EventRecord{Type: "SESSION_CLOSE"})

	for _, n := range []int{-1, -1000, 0} {
		got := eb.Latest(n)
		if len(got) != 0 {
			t.Errorf("Latest(%d) = %d records, want 0", n, len(got))
		}
	}
}

// TestLatestFilteredNegativeN locks the contract symmetry with Latest: a
// non-positive count returns empty rather than panicking or over-returning.
func TestLatestFilteredNegativeN(t *testing.T) {
	eb := NewEventBuffer(8)
	eb.Add(EventRecord{Type: "SESSION_OPEN", Protocol: "TCP"})

	for _, n := range []int{-1, -1000, 0} {
		got := eb.LatestFiltered(n, EventFilter{})
		if len(got) != 0 {
			t.Errorf("LatestFiltered(%d) = %d records, want 0", n, len(got))
		}
	}
}

// TestNewEventBufferZeroSize guards the #3342 secondary footgun: a
// non-positive size must be clamped so Add does not index an empty buffer
// or divide by zero (head % size).
//
// FAIL-ON-REVERT: removing the `if size < 1` clamp in NewEventBuffer makes
// the first Add panic (index out of range / integer divide by zero).
func TestNewEventBufferZeroSize(t *testing.T) {
	for _, size := range []int{0, -1, -100} {
		eb := NewEventBuffer(size)
		if eb.size < 1 {
			t.Fatalf("NewEventBuffer(%d) left size=%d (<1)", size, eb.size)
		}
		// Must not panic on the first event.
		eb.Add(EventRecord{Type: "SESSION_OPEN"})
		if got := eb.Latest(1); len(got) != 1 {
			t.Errorf("NewEventBuffer(%d): Latest(1) = %d, want 1", size, len(got))
		}
	}
}
