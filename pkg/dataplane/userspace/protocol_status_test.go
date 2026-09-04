package userspace

import (
	"encoding/json"
	"testing"
)

// #7919: the Go half of the session-volume high-water wire contract.
//
// The whole value of this field is that it distinguishes "this worker has never
// held a session carrying traffic" from "this helper cannot tell me". An older
// helper omits the key, and if that decoded to 0 the reader would attribute a
// measurement to a binary that never made one — manufacturing exactly the
// evidence the field exists to gather. So it decodes to a POINTER and absence
// stays nil.
func TestSessionVolumeHighWaterAbsentDecodesToNil7919(t *testing.T) {
	// An OLD helper's per-worker status: no such key.
	var old WorkerRuntimeStatus
	if err := json.Unmarshal([]byte(`{"worker_id":3,"work_loops":7}`), &old); err != nil {
		t.Fatalf("decode old payload: %v", err)
	}
	// POSITIVE CONTROL: the payload really did decode, so the nil below is
	// about the missing key and not about a failed unmarshal.
	if old.WorkerID != 3 || old.WorkLoops != 7 {
		t.Fatalf("control: old payload did not decode (worker_id=%d work_loops=%d); "+
			"the nil assertion below would prove nothing", old.WorkerID, old.WorkLoops)
	}
	if old.SessionVolumeHighWater != nil {
		t.Errorf("an absent session_volume_high_water must decode to nil (unknown), "+
			"got %d — a helper that cannot answer must not be recorded as having "+
			"measured zero", *old.SessionVolumeHighWater)
	}

	// A NEW helper that reports it.
	var cur WorkerRuntimeStatus
	if err := json.Unmarshal(
		[]byte(`{"worker_id":2,"session_volume_high_water":117280}`), &cur); err != nil {
		t.Fatalf("decode current payload: %v", err)
	}
	if cur.SessionVolumeHighWater == nil {
		t.Fatalf("a reported session_volume_high_water must decode non-nil")
	}
	if *cur.SessionVolumeHighWater != 117280 {
		t.Errorf("session_volume_high_water = %d, want 117280",
			*cur.SessionVolumeHighWater)
	}
}
