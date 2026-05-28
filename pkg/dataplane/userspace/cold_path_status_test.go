package userspace

import (
	"encoding/json"
	"strings"
	"testing"
)

// #1621 plan v2 + Copilot code-r1 C3: round-trip tests for the cold-
// path fields on WorkerRuntimeStatus. Pin two contracts:
//
//   1. Default (uncalibrated) worker emits ZERO cold_path_* fields on
//      the wire (wire-invariant preserved vs pre-#1621 daemons).
//   2. Populated cold_path_* fields survive JSON round-trip both
//      directions (Go-encode → JSON → Go-decode and Go-decode of a
//      hand-crafted JSON payload).
//
// Rust-side mirror tests live in
// userspace-dp/src/protocol/tests.rs:worker_runtime_status_cold_path_*.

func TestWorkerRuntimeStatus_DefaultOmitsAllColdPathFields(t *testing.T) {
	w := WorkerRuntimeStatus{WorkerID: 0}
	payload, err := json.Marshal(&w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(payload)
	coldKeys := []string{
		"cold_path_hist",
		"cold_path_sum_ns",
		"cold_path_samples",
		"cold_path_first_key",
		"cold_path_alias_seen",
		"cold_path_sample_phase",
		"cold_path_wrapper_underflow_count",
		"cold_path_ns_per_tsc_q32",
		"cold_path_wrapper_ns_baseline",
		"cold_path_clock_source",
		"cold_path_snapshot_failed",
	}
	for _, k := range coldKeys {
		if strings.Contains(body, k) {
			t.Errorf("default WorkerRuntimeStatus must omit %q on wire; got %s", k, body)
		}
	}
}

func TestWorkerRuntimeStatus_ColdPathFieldsRoundTrip(t *testing.T) {
	hist := make([][]uint64, 16)
	for i := range hist {
		hist[i] = make([]uint64, 24)
	}
	hist[3][5] = 42
	hist[3][6] = 100
	sumNS := make([]uint64, 16)
	sumNS[3] = 12345
	samples := make([]uint64, 16)
	samples[3] = 142
	firstKey := make([]uint64, 16)
	firstKey[3] = 0x1234
	aliasSeen := make([]bool, 16)
	aliasSeen[7] = true

	w := WorkerRuntimeStatus{
		WorkerID:                      2,
		ColdPathHist:                  hist,
		ColdPathSumNS:                 sumNS,
		ColdPathSamples:               samples,
		ColdPathFirstKey:              firstKey,
		ColdPathAliasSeen:             aliasSeen,
		ColdPathSamplePhase:           50000,
		ColdPathWrapperUnderflowCount: 3,
		ColdPathNSPerTSCQ32:           1871674289,
		ColdPathWrapperNSBaseline:     45,
		ColdPathClockSource:           "tsc",
		ColdPathSnapshotFailed:        2,
	}
	payload, err := json.Marshal(&w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Spot-check: wire contains the values.
	body := string(payload)
	for _, want := range []string{
		`"cold_path_sample_phase":50000`,
		`"cold_path_clock_source":"tsc"`,
		`"cold_path_snapshot_failed":2`,
		`"cold_path_ns_per_tsc_q32":1871674289`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("wire missing %q; got %s", want, body)
		}
	}

	var got WorkerRuntimeStatus
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ColdPathSamplePhase != 50000 {
		t.Errorf("sample_phase: want 50000 got %d", got.ColdPathSamplePhase)
	}
	if got.ColdPathClockSource != "tsc" {
		t.Errorf("clock_source: want tsc got %q", got.ColdPathClockSource)
	}
	if got.ColdPathSnapshotFailed != 2 {
		t.Errorf("snapshot_failed: want 2 got %d", got.ColdPathSnapshotFailed)
	}
	if len(got.ColdPathHist) != 16 {
		t.Fatalf("hist row count: want 16 got %d", len(got.ColdPathHist))
	}
	if got.ColdPathHist[3][5] != 42 {
		t.Errorf("hist[3][5]: want 42 got %d", got.ColdPathHist[3][5])
	}
	if got.ColdPathHist[3][6] != 100 {
		t.Errorf("hist[3][6]: want 100 got %d", got.ColdPathHist[3][6])
	}
	if !got.ColdPathAliasSeen[7] {
		t.Errorf("alias_seen[7]: want true got %v", got.ColdPathAliasSeen[7])
	}
	if got.ColdPathSamples[3] != 142 {
		t.Errorf("samples[3]: want 142 got %d", got.ColdPathSamples[3])
	}
}

func TestWorkerRuntimeStatus_RustEmittedJSONDecodes(t *testing.T) {
	// Cross-language compat: a JSON payload emitted by the Rust side
	// (as produced by the protocol_wire_v1.json fixture conventions)
	// must decode into the Go struct without loss.
	rustJSON := `{
		"worker_id": 1,
		"cold_path_hist": [[0,0,0,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
		                   [],[],[],[],[],[],[],[],[],[],[],[],[],[],[]],
		"cold_path_samples": [0,0,0,5,0,0,0,0,0,0,0,0,0,0,0,0],
		"cold_path_alias_seen": [false,false,false,false,false,false,false,true,
		                          false,false,false,false,false,false,false,false],
		"cold_path_sample_phase": 1280,
		"cold_path_clock_source": "tsc",
		"cold_path_ns_per_tsc_q32": 1871674289
	}`
	var got WorkerRuntimeStatus
	if err := json.Unmarshal([]byte(rustJSON), &got); err != nil {
		t.Fatalf("decode Rust-emitted JSON: %v", err)
	}
	if got.WorkerID != 1 {
		t.Errorf("worker_id: want 1 got %d", got.WorkerID)
	}
	if got.ColdPathSamplePhase != 1280 {
		t.Errorf("sample_phase: want 1280 got %d", got.ColdPathSamplePhase)
	}
	if got.ColdPathClockSource != "tsc" {
		t.Errorf("clock_source: want tsc got %q", got.ColdPathClockSource)
	}
	if got.ColdPathNSPerTSCQ32 != 1871674289 {
		t.Errorf("ns_per_tsc_q32: want 1871674289 got %d", got.ColdPathNSPerTSCQ32)
	}
	if !got.ColdPathAliasSeen[7] {
		t.Errorf("alias_seen[7]: want true got false")
	}
	if len(got.ColdPathHist) != 16 {
		t.Fatalf("hist row count: want 16 got %d", len(got.ColdPathHist))
	}
	if got.ColdPathHist[0][3] != 5 {
		t.Errorf("hist[0][3]: want 5 got %d", got.ColdPathHist[0][3])
	}
}
