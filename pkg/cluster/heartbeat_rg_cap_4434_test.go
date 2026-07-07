package cluster

import "testing"

// #4434 (codex-172 C172-H02): the heartbeat group-count byte and each
// per-group id byte are uint8, and the frame is a fixed maxHeartbeatSize
// buffer written as heartbeatHeaderSize + N*heartbeatGroupSize. Before the
// defensive cap, marshaling 256 groups overflowed the count byte to 0 (wire
// desync against the records written) and ~293 groups indexed past the buffer
// and panicked. marshalHeartbeatBody now bounds the group section to
// maxHeartbeatGroups.
//
// FAIL-ON-REVERT: drop the maxHeartbeatGroups cap in marshalHeartbeatBody and
// TestMarshalHeartbeatDoesNotPanicOnOversizeGroups panics (index out of range)
// and TestMarshalHeartbeatCountMatchesBodyOnOversizeGroups sees a count byte
// of 0 that disagrees with the body.

func oversizeGroups(n int) []HeartbeatGroup {
	g := make([]HeartbeatGroup, n)
	for i := range g {
		g[i] = HeartbeatGroup{GroupID: uint8(i), Priority: 100, Weight: 1, State: 1}
	}
	return g
}

func TestMarshalHeartbeatDoesNotPanicOnOversizeGroups(t *testing.T) {
	// 400 groups would index past the 1472-byte buffer without the cap.
	pkt := &HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: oversizeGroups(400)}
	data := MarshalHeartbeat(pkt) // must not panic
	if len(data) == 0 {
		t.Fatalf("MarshalHeartbeat returned empty output")
	}
	if data[8] != maxHeartbeatGroups {
		t.Fatalf("group-count byte = %d, want capped %d", data[8], maxHeartbeatGroups)
	}
	// Re-parse: the group section must be self-consistent (count == records),
	// so the peer decodes exactly maxHeartbeatGroups groups.
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat of a capped frame failed: %v", err)
	}
	if len(got.Groups) != maxHeartbeatGroups {
		t.Fatalf("decoded %d groups, want %d", len(got.Groups), maxHeartbeatGroups)
	}
}

func TestMarshalHeartbeatCountMatchesBodyOnOversizeGroups(t *testing.T) {
	// Exactly 256 groups is the count-byte overflow boundary: uint8(256) == 0.
	pkt := &HeartbeatPacket{NodeID: 0, ClusterID: 1, Groups: oversizeGroups(256)}
	data := MarshalHeartbeat(pkt)
	if data[8] == 0 {
		t.Fatalf("group-count byte wrapped to 0 on 256 groups (wire desync)")
	}
	if data[8] != maxHeartbeatGroups {
		t.Fatalf("group-count byte = %d, want capped %d", data[8], maxHeartbeatGroups)
	}
}

func TestMarshalHeartbeatInRangeGroupsUnchanged(t *testing.T) {
	// A normal group set (well under the wire limit) is encoded verbatim.
	pkt := &HeartbeatPacket{
		NodeID:    1,
		ClusterID: 42,
		Groups: []HeartbeatGroup{
			{GroupID: 0, Priority: 200, Weight: 255, State: 1},
			{GroupID: 1, Priority: 100, Weight: 200, State: 2},
		},
	}
	data := MarshalHeartbeat(pkt)
	if data[8] != 2 {
		t.Fatalf("group-count byte = %d, want 2", data[8])
	}
	got, err := UnmarshalHeartbeat(data)
	if err != nil {
		t.Fatalf("UnmarshalHeartbeat failed: %v", err)
	}
	if len(got.Groups) != 2 || got.Groups[1].GroupID != 1 {
		t.Fatalf("round-trip mismatch: %+v", got.Groups)
	}
}
