package userspace

import (
	"strings"
	"testing"
)

func TestCoSFairnessRSSSummariesBoundsSparseWorkerID(t *testing.T) {
	status := ProcessStatus{
		Workers: 2,
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: ^uint32(0), ActiveFlowCount: 2},
		},
	}

	rows := CoSFairnessRSSSummaries(status)
	if len(rows) != 1 {
		t.Fatalf("CoSFairnessRSSSummaries returned %d rows, want 1", len(rows))
	}
	if got, max := len(rows[0].WorkerFlowCounts), maxFairnessRSSWorkerSlots+1; got > max {
		t.Fatalf("worker distribution length = %d, want <= %d", got, max)
	}
	if got := rows[0].ActiveFlows; got != 3 {
		t.Fatalf("ActiveFlows = %d, want 3", got)
	}
	if got := rows[0].ActiveWorkers; got != 2 {
		t.Fatalf("ActiveWorkers = %d, want 2", got)
	}
}

func TestCoSFairnessRSSSummariesMultipleOverflowWorkers(t *testing.T) {
	status := ProcessStatus{
		Workers: 2,
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 1},
			{Ifindex: 80, QueueID: 4, WorkerID: 4096, ActiveFlowCount: 2},
			{Ifindex: 80, QueueID: 4, WorkerID: ^uint32(0), ActiveFlowCount: 3},
		},
	}

	rows := CoSFairnessRSSSummaries(status)
	if len(rows) != 1 {
		t.Fatalf("CoSFairnessRSSSummaries returned %d rows, want 1", len(rows))
	}
	if got := rows[0].ActiveFlows; got != 6 {
		t.Fatalf("ActiveFlows = %d, want 6", got)
	}
	if got := rows[0].ActiveWorkers; got != 3 {
		t.Fatalf("ActiveWorkers = %d, want 3", got)
	}
	if got := len(rows[0].WorkerFlowCounts); got != 4 {
		t.Fatalf("worker distribution length = %d, want 4", got)
	}
}

func TestBoundedFairnessRSSWorkerSlots(t *testing.T) {
	tests := []struct {
		name     string
		workers  int
		fallback int
		want     int
	}{
		{name: "negative workers and fallback", workers: -1, fallback: -1, want: 0},
		{name: "zero workers uses fallback", workers: 0, fallback: 8, want: 8},
		{name: "positive workers ignore fallback", workers: 4, fallback: 8, want: 4},
		{name: "workers capped", workers: maxFairnessRSSWorkerSlots + 1, fallback: 1, want: maxFairnessRSSWorkerSlots},
		{name: "fallback capped", workers: 0, fallback: maxFairnessRSSWorkerSlots + 1, want: maxFairnessRSSWorkerSlots},
		{name: "worker cap boundary", workers: maxFairnessRSSWorkerSlots, fallback: 1, want: maxFairnessRSSWorkerSlots},
		{name: "fallback cap boundary", workers: 0, fallback: maxFairnessRSSWorkerSlots, want: maxFairnessRSSWorkerSlots},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := boundedFairnessRSSWorkerSlots(tt.workers, tt.fallback); got != tt.want {
				t.Fatalf("boundedFairnessRSSWorkerSlots(%d, %d) = %d, want %d", tt.workers, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestEvaluateFairnessRSSExpectationsFailsMissingQueue(t *testing.T) {
	// The interface resolves (present in the snapshot) but has no active
	// flows on the queue → "no active flows observed".
	status := ProcessStatus{
		Workers:  4,
		Bindings: []BindingStatus{{Interface: "ge-0-0-2", Ifindex: 80}},
	}
	results := EvaluateFairnessRSSExpectations(status, []FairnessRSSExpectation{
		{Interface: "ge-0-0-2", QueueID: 4, RSSExpectation: "max-worker-flow-share:0.5"},
	})
	if len(results) != 1 {
		t.Fatalf("EvaluateFairnessRSSExpectations returned %d rows, want 1", len(results))
	}
	if results[0].Pass {
		t.Fatalf("missing queue expectation passed: %+v", results[0])
	}
	if results[0].Ifindex != 80 {
		t.Fatalf("resolved ifindex = %d, want 80", results[0].Ifindex)
	}
	if !strings.Contains(results[0].Reason, "no active flows observed") {
		t.Fatalf("missing queue reason = %q, want no active flows observed", results[0].Reason)
	}
}

// #hb166 G-9: an rss-expectation keyed by a STABLE interface name must
// track the named interface across NIC re-enumeration. When the kernel
// ifindex of "ge-0-0-2" changes from 80 to 91 between snapshots, the
// expectation must resolve to the CURRENT ifindex (91) and evaluate the
// distribution reported under 91 — not the stale 80. RED on revert: the
// pre-fix ifindex-keyed config baked in the ifindex and would judge
// whichever interface now holds 80 (here, none), or the wrong port.
func TestEvaluateFairnessRSSExpectationsNameKeyedSurvivesReenumeration(t *testing.T) {
	// After re-enumeration ge-0-0-2 is ifindex 91 and carries a balanced
	// 2-worker distribution; ifindex 80 now belongs to a different port
	// (ge-0-0-1) with a single-worker (skewed) distribution.
	status := ProcessStatus{
		Workers: 2,
		Bindings: []BindingStatus{
			{Interface: "ge-0-0-2", Ifindex: 91},
			{Interface: "ge-0-0-1", Ifindex: 80},
		},
		CoSActiveFlowCounts: []CoSActiveFlowCountStatus{
			// ge-0-0-2 (ifindex 91): balanced across two workers, 10 flows.
			{Ifindex: 91, QueueID: 4, WorkerID: 0, ActiveFlowCount: 5},
			{Ifindex: 91, QueueID: 4, WorkerID: 1, ActiveFlowCount: 5},
			// ge-0-0-1 (ifindex 80): all 7 flows on one worker (skewed).
			{Ifindex: 80, QueueID: 4, WorkerID: 0, ActiveFlowCount: 7},
		},
	}
	results := EvaluateFairnessRSSExpectations(status, []FairnessRSSExpectation{
		{Interface: "ge-0-0-2", QueueID: 4, RSSExpectation: "balanced"},
	})
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1: %+v", len(results), results)
	}
	if results[0].Ifindex != 91 {
		t.Fatalf("resolved ifindex = %d, want 91 (re-enumerated ge-0-0-2)", results[0].Ifindex)
	}
	if !results[0].Pass {
		t.Fatalf("balanced expectation on ge-0-0-2 (ifindex 91) failed: %+v", results[0])
	}
	if results[0].ActiveFlows != 10 {
		t.Fatalf("evaluated the wrong interface: active flows = %d, want 10 (ge-0-0-2)", results[0].ActiveFlows)
	}
}

// #hb166 G-9: a name that is not present in the current dataplane
// snapshot is reported explicitly instead of silently judging ifindex 0.
func TestEvaluateFairnessRSSExpectationsUnresolvedInterface(t *testing.T) {
	results := EvaluateFairnessRSSExpectations(ProcessStatus{Workers: 4}, []FairnessRSSExpectation{
		{Interface: "ge-9-9-9", QueueID: 4, RSSExpectation: "balanced"},
	})
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].Pass {
		t.Fatalf("unresolved interface passed: %+v", results[0])
	}
	if !strings.Contains(results[0].Reason, "not present in dataplane status") {
		t.Fatalf("unresolved reason = %q, want not present in dataplane status", results[0].Reason)
	}
}
