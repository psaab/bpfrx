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
		// legacy dense v1 (retained read-only).
		"cold_path_hist",
		"cold_path_sum_ns",
		"cold_path_samples",
		"cold_path_first_key",
		"cold_path_alias_seen",
		// #1635 sparse v3.
		"cold_path_layout_version",
		"cold_path_active_slot_ids",
		"cold_path_active_zone_from",
		"cold_path_active_zone_to",
		"cold_path_active_samples",
		"cold_path_active_sum_ns",
		"cold_path_active_buckets",
		"cold_path_active_builder_collision",
		"cold_path_overflow_active",
		// shared scalars.
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

// #1635 (Copilot code-r3 finding 4): pin the sparse v3 wire contract on
// the Go side. Decodes a hand-crafted JSON payload using the exact
// field names the Rust serializer emits (userspace-dp/src/protocol/
// binding.rs cold_path_active_* + cold_path_layout_version +
// cold_path_overflow_active), then re-encodes and re-decodes to confirm
// the Go struct tags round-trip. A wrong/missing tag here would silently
// drop sparse cold-path data from the v3 Prometheus emitter.
func TestWorkerRuntimeStatus_SparseV3FieldsDecodeFromRustWire(t *testing.T) {
	// Field names MUST match the Rust serde renames exactly.
	rustJSON := `{
		"worker_id": 4,
		"cold_path_layout_version": 3,
		"cold_path_active_slot_ids": [0, 5],
		"cold_path_active_zone_from": [1, 2],
		"cold_path_active_zone_to": [3, 4],
		"cold_path_active_samples": [142, 7],
		"cold_path_active_sum_ns": [12345, 700],
		"cold_path_active_buckets": [[0,0,0,0,0,1], [9]],
		"cold_path_active_builder_collision": [false, true],
		"cold_path_overflow_active": true,
		"cold_path_clock_source": "tsc"
	}`
	var got WorkerRuntimeStatus
	if err := json.Unmarshal([]byte(rustJSON), &got); err != nil {
		t.Fatalf("decode Rust-shaped sparse v3 JSON: %v", err)
	}
	if got.ColdPathLayoutVersion != 3 {
		t.Errorf("layout_version: want 3 got %d", got.ColdPathLayoutVersion)
	}
	if len(got.ColdPathActiveSlotIDs) != 2 || got.ColdPathActiveSlotIDs[1] != 5 {
		t.Errorf("active_slot_ids decode mismatch: %v", got.ColdPathActiveSlotIDs)
	}
	if len(got.ColdPathActiveZoneFrom) != 2 || got.ColdPathActiveZoneFrom[0] != 1 {
		t.Errorf("active_zone_from decode mismatch: %v", got.ColdPathActiveZoneFrom)
	}
	if got.ColdPathActiveZoneTo[1] != 4 {
		t.Errorf("active_zone_to decode mismatch: %v", got.ColdPathActiveZoneTo)
	}
	if got.ColdPathActiveSamples[0] != 142 || got.ColdPathActiveSumNS[1] != 700 {
		t.Errorf("active samples/sum_ns decode mismatch: %v / %v",
			got.ColdPathActiveSamples, got.ColdPathActiveSumNS)
	}
	if len(got.ColdPathActiveBuckets) != 2 || got.ColdPathActiveBuckets[0][5] != 1 {
		t.Errorf("active_buckets decode mismatch: %v", got.ColdPathActiveBuckets)
	}
	if !got.ColdPathActiveBuilderCollision[1] {
		t.Errorf("active_builder_collision decode mismatch: %v", got.ColdPathActiveBuilderCollision)
	}
	if !got.ColdPathOverflowActive {
		t.Errorf("overflow_active: want true")
	}

	// Re-encode and re-decode to confirm Go's own tags round-trip and
	// keep the same wire names.
	payload, err := json.Marshal(&got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	for _, k := range []string{
		"cold_path_layout_version", "cold_path_active_slot_ids",
		"cold_path_active_zone_from", "cold_path_active_zone_to",
		"cold_path_active_samples", "cold_path_active_sum_ns",
		"cold_path_active_buckets", "cold_path_active_builder_collision",
		"cold_path_overflow_active",
	} {
		if !strings.Contains(string(payload), k) {
			t.Errorf("re-encoded payload missing wire key %q: %s", k, payload)
		}
	}
	var back WorkerRuntimeStatus
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if back.ColdPathActiveZoneTo[1] != 4 || !back.ColdPathOverflowActive {
		t.Errorf("round-trip lost data: %+v", back)
	}
}
