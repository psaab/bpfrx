package daemon

import (
	"errors"
	"testing"
)

// TestCompileHealth_RecordFailure pins the #758 state transitions:
// - recordCompileFailure increments the counter and captures the error
// - recordCompileSuccess flips EverSucceeded and clears LastError, but
//   preserves the failure count so operators can see past transience
// - counter-factual: before recording any failure, the snapshot shows
//   EverSucceeded=false with FailureCount=0 — /health treats this as
//   healthy (the "never tried" case matches the "succeeded once" path
//   rather than the "persistent failure" path).
func TestCompileHealth_RecordFailure(t *testing.T) {
	d := &Daemon{}

	// Initial: zero state. /health must treat this as healthy (not
	// degraded) — the gate fires only on FailureCount > 0.
	s := d.CompileHealthSnapshot()
	if s.EverSucceeded || s.FailureCount != 0 || s.LastError != "" {
		t.Errorf("initial snapshot = %+v, want zero value", s)
	}

	// Record a failure. The counter increments; LastError carries
	// through verbatim; EverSucceeded stays false.
	d.recordCompileFailure(errors.New("compile zones: add tx port fab0: key too big for map"))
	s = d.CompileHealthSnapshot()
	if s.EverSucceeded {
		t.Error("EverSucceeded must stay false before any success")
	}
	if s.FailureCount != 1 {
		t.Errorf("FailureCount = %d, want 1", s.FailureCount)
	}
	if s.LastError == "" {
		t.Error("LastError must be populated on failure")
	}

	// Second failure with a different error: counter advances,
	// LastError rewrites to the latest message.
	d.recordCompileFailure(errors.New("different compile failure"))
	s = d.CompileHealthSnapshot()
	if s.FailureCount != 2 {
		t.Errorf("FailureCount after second failure = %d, want 2", s.FailureCount)
	}
	if s.LastError != "different compile failure" {
		t.Errorf("LastError = %q, want the most recent error text", s.LastError)
	}

	// Success flips EverSucceeded and clears LastError but preserves
	// the failure count (monotonic observability counter).
	d.recordCompileSuccess()
	s = d.CompileHealthSnapshot()
	if !s.EverSucceeded {
		t.Error("EverSucceeded must be true after a success")
	}
	if s.LastError != "" {
		t.Errorf("LastError = %q, want empty after success", s.LastError)
	}
	if s.FailureCount != 2 {
		t.Errorf("FailureCount after success = %d, want 2 (preserved)", s.FailureCount)
	}
}
