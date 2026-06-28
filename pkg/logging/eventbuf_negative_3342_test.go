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
// the first Add PANIC at the real footgun path — eb.buf[eb.head] is an
// index-out-of-range on a zero-length slice and eb.head % eb.size is an
// integer divide-by-zero. The test exercises Add (and reads back via
// Latest) FIRST so the revert fails AT the Add/modulo path, not at a size
// assertion that would short-circuit before Add ever runs.
func TestNewEventBufferZeroSize(t *testing.T) {
	for _, size := range []int{0, -1, -100} {
		eb := NewEventBuffer(size)

		// Drive the genuine Add/modulo path. A recover-based assertion
		// turns the revert panic into a clear test failure attributed to
		// the Add call (rather than a bare panic stack), and proves the
		// fixed buffer accepts an event without panicking.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("NewEventBuffer(%d): Add panicked (size not clamped): %v", size, r)
				}
			}()
			eb.Add(EventRecord{Type: "SESSION_OPEN"})
		}()

		if got := eb.Latest(1); len(got) != 1 {
			t.Errorf("NewEventBuffer(%d): Latest(1) = %d, want 1", size, len(got))
		}
		// Sanity: the clamp left a usable capacity. Checked last so it
		// never short-circuits the Add/modulo exercise above.
		if eb.size < 1 {
			t.Errorf("NewEventBuffer(%d) left size=%d (<1)", size, eb.size)
		}
	}
}
