package userspace

import (
	"errors"
	"strings"
	"testing"
)

// #7919: the Go half of the session_counters contract. The property under test
// is the one the whole verb turns on — an UNSUPPORTED helper is an ERROR, never
// an empty result.
//
// In a rolling HA upgrade the two nodes run different binaries on one wire, so
// an older helper answering `unknown request type session_counters` is normal
// operation, not a test-only path. A caller that read that as `nil, nil` would
// record "no worker holds this session" — which is one of the two states this
// query exists to distinguish, so the failure would look exactly like a
// finding.

// The helper's real wording, from `server/handlers/mod.rs`'s catch-all arm.
// Pinned on the Rust side too, so a reword there breaks a test rather than
// silently downgrading "unsupported" to a generic error here.
const helperUnknownVerbWording = "unknown request type session_counters"

func TestUnsupportedVerbIsAnErrorNotAnEmptyResult7919(t *testing.T) {
	rows, err := sessionCountersFromResponse(ControlResponse{}, errors.New(helperUnknownVerbWording))
	if !errors.Is(err, ErrSessionCountersUnsupported) {
		t.Fatalf("an old helper's refusal must map to ErrSessionCountersUnsupported, got %v", err)
	}
	if rows != nil {
		t.Errorf("an unsupported verb must yield NO rows alongside the error; got %d — "+
			"a caller that ignored the error would read this as a measurement", len(rows))
	}
}

// POSITIVE CONTROL on the other side of the same predicate. A helper that
// UNDERSTOOD the verb and failed while executing it must NOT be reported as
// unsupported: "ask a newer helper" and "the answer is unavailable" are
// different remedies. Without this, a classifier that returned Unsupported for
// every error would pass the test above.
func TestAnExecutionFailureIsNotReportedAsUnsupported7919(t *testing.T) {
	real := errors.New("session_counters: unparseable src_ip \"not-an-ip\"")
	rows, err := sessionCountersFromResponse(ControlResponse{}, real)
	if errors.Is(err, ErrSessionCountersUnsupported) {
		t.Fatalf("an execution failure must not be classified as an unsupported verb: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "unparseable src_ip") {
		t.Fatalf("the helper's own error must survive verbatim, got %v", err)
	}
	if rows != nil {
		t.Errorf("a failed query must yield no rows, got %d", len(rows))
	}
}

// A SUCCESSFUL query passes its rows through untouched, including the three
// distinct states a row can carry. If this collapsed them the verb would answer
// neither of the questions it exists to separate.
func TestSuccessfulQueryPreservesEveryRowState7919(t *testing.T) {
	resp := ControlResponse{SessionCounters: []SessionCounterRow{
		{WorkerID: 0, Answered: false},                                 // never replied
		{WorkerID: 1, Answered: true, Found: false},                    // replied: not held
		{WorkerID: 2, Answered: true, Found: true, FwdPackets: 117280}, // held, with volume
		{WorkerID: 3, Answered: true, Found: true, Replica: true},      // held, replica, zero
	}}
	rows, err := sessionCountersFromResponse(resp, nil)
	if err != nil {
		t.Fatalf("a successful query must not error: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	if rows[0].Answered {
		t.Error("a worker that never replied must stay Answered=false — that is not an answer")
	}
	if !rows[1].Answered || rows[1].Found {
		t.Error("'replied: does not hold it' must survive as Answered && !Found")
	}
	if rows[2].FwdPackets != 117280 || !rows[2].Found {
		t.Error("a held session's volume must pass through unchanged")
	}
	if !rows[3].Replica {
		t.Error("the replica flag must survive; a replica reporting volume would " +
			"falsify the premise the investigation rests on")
	}
}

// An EMPTY successful answer is a real answer — no worker holds the session —
// and must be reported as success, not as unsupported. Pinned because the two
// are the same shape at the call site (no rows) and only the error separates
// them.
func TestEmptySuccessIsNotUnsupported7919(t *testing.T) {
	rows, err := sessionCountersFromResponse(ControlResponse{}, nil)
	if err != nil {
		t.Fatalf("an empty but successful answer must not error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(rows))
	}
}
