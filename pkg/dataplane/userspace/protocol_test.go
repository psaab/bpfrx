// #825 plan §3.9 test #5 / §3.8 Go mirror: round-trip pin for the
// four TX kick-latency fields added to BindingStatus and
// BindingCountersSnapshot. The JSON tag contract between Rust and
// Go is wire-critical — a rename on either side silently breaks
// the P3 capture consumer.

package userspace

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The wire JSON keys the Rust helper emits (serde rename strings
// verified in userspace-dp/src/protocol.rs). A rename on the Rust
// side without a matching Go update lands in the field as zero
// rather than erroring, so a static pin at CI time is the only
// line of defense.
var tx_kick_latency_wire_keys = []string{
	"tx_kick_latency_hist",
	"tx_kick_latency_count",
	"tx_kick_latency_sum_ns",
	"tx_kick_retry_count",
}

func TestBindingStatusTxKickLatencyRoundTrip(t *testing.T) {
	// Encode a Go BindingStatus with non-trivial values on the
	// four kick-latency fields; decode the JSON back; assert
	// field equality across the boundary.
	in := BindingStatus{
		WorkerID:           3,
		Slot:               7,
		Ifindex:            11,
		QueueID:            2,
		TxKickLatencyHist:  []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		TxKickLatencyCount: 136,
		TxKickLatencySumNs: 1_234_567,
		TxKickRetryCount:   42,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Wire-key presence: the Rust helper's consumer rejects a
	// BindingStatus that renamed one of the four keys. Pin the
	// names so a Go rename is caught here, not in the field.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range tx_kick_latency_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingStatus JSON: %s", key, string(raw))
		}
	}

	var back BindingStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingStatus: %v", err)
	}
	if !reflect.DeepEqual(back.TxKickLatencyHist, in.TxKickLatencyHist) {
		t.Fatalf("TxKickLatencyHist: got %v, want %v",
			back.TxKickLatencyHist, in.TxKickLatencyHist)
	}
	if back.TxKickLatencyCount != in.TxKickLatencyCount {
		t.Fatalf("TxKickLatencyCount: got %d, want %d",
			back.TxKickLatencyCount, in.TxKickLatencyCount)
	}
	if back.TxKickLatencySumNs != in.TxKickLatencySumNs {
		t.Fatalf("TxKickLatencySumNs: got %d, want %d",
			back.TxKickLatencySumNs, in.TxKickLatencySumNs)
	}
	if back.TxKickRetryCount != in.TxKickRetryCount {
		t.Fatalf("TxKickRetryCount: got %d, want %d",
			back.TxKickRetryCount, in.TxKickRetryCount)
	}
}

func TestBindingCountersSnapshotTxKickLatencyRoundTrip(t *testing.T) {
	in := BindingCountersSnapshot{
		WorkerID:           5,
		QueueID:            3,
		TxKickLatencyHist:  []uint64{100, 200, 300},
		TxKickLatencyCount: 600,
		TxKickLatencySumNs: 987_654,
		TxKickRetryCount:   7,
	}
	raw, err := json.Marshal(&in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal obj: %v", err)
	}
	for _, key := range tx_kick_latency_wire_keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("wire key %q missing from BindingCountersSnapshot JSON: %s",
				key, string(raw))
		}
	}

	var back BindingCountersSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal BindingCountersSnapshot: %v", err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", back, in)
	}
}

// Pre-#825 payload — four kick-latency keys absent. omitempty on
// the Go side means empty/zero values on the producing side are
// also absent on the wire, so backward-compat is symmetric: a
// pre-#825 Rust helper decodes into empty slice / zero uint64
// without failing.
func TestBindingCountersSnapshotTxKickLatencyBackwardCompat(t *testing.T) {
	legacyJSON := []byte(`{
		"worker_id": 5,
		"ifindex": 7,
		"queue_id": 2,
		"dbg_tx_ring_full": 0,
		"dbg_sendto_enobufs": 0,
		"dbg_bound_pending_overflow": 0,
		"dbg_cos_queue_overflow": 0,
		"rx_fill_ring_empty_descs": 0,
		"outstanding_tx": 0,
		"tx_errors": 0,
		"tx_submit_error_drops": 0,
		"pending_tx_local_overflow_drops": 0
	}`)
	var back BindingCountersSnapshot
	if err := json.Unmarshal(legacyJSON, &back); err != nil {
		t.Fatalf("pre-#825 payload must decode: %v", err)
	}
	if len(back.TxKickLatencyHist) != 0 {
		t.Fatalf("pre-#825 TxKickLatencyHist must decode as empty, got %v",
			back.TxKickLatencyHist)
	}
	if back.TxKickLatencyCount != 0 {
		t.Fatalf("pre-#825 TxKickLatencyCount must be 0, got %d",
			back.TxKickLatencyCount)
	}
	if back.TxKickLatencySumNs != 0 {
		t.Fatalf("pre-#825 TxKickLatencySumNs must be 0, got %d",
			back.TxKickLatencySumNs)
	}
	if back.TxKickRetryCount != 0 {
		t.Fatalf("pre-#825 TxKickRetryCount must be 0, got %d",
			back.TxKickRetryCount)
	}
}
