package userspace

import (
	"strings"
	"testing"
	"time"
)

func TestFormatStatusSummary(t *testing.T) {
	now := time.Now().UTC()
	status := ProcessStatus{
		PID:                    1234,
		HelperMode:             "rust-bootstrap",
		Workers:                2,
		RingEntries:            2048,
		LastSnapshotGeneration: 7,
		LastSnapshotAt:         now.Add(-2 * time.Second),
		WorkerHeartbeats:       []time.Time{now.Add(-500 * time.Millisecond), now.Add(-700 * time.Millisecond)},
		Queues: []QueueStatus{
			{QueueID: 0, Ready: true},
			{QueueID: 1, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, Ready: true, Bound: true, XSKRegistered: true, RXPackets: 10},
			{Slot: 1, Ready: false, Bound: true, XSKRegistered: false, RXPackets: 5},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"Userspace dataplane helper:",
		"PID:",
		"Bound bindings:            2/2",
		"XSK-registered bindings:   1/2",
		"Ready queues:              1/2",
		"Ready bindings:            1/2",
		"RX packets:                15",
		"Worker 0 heartbeat age:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestFormatBindings(t *testing.T) {
	status := ProcessStatus{
		Queues: []QueueStatus{
			{QueueID: 0, WorkerID: 0, Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Registered: true, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Registered: true, Ready: false, Bound: true, XSKRegistered: true, Ifindex: 5, Interface: "ge-0-0-1", RXPackets: 99},
			{Slot: 1, QueueID: 0, WorkerID: 0, Registered: true, Ready: false, Bound: true, XSKRegistered: false, Ifindex: 6, Interface: "ge-0-0-2", LastError: "xsk map update failed"},
		},
	}

	out := FormatBindings(status)
	for _, want := range []string{
		"Userspace queues:",
		"Userspace bindings:",
		"ge-0-0-1,ge-0-0-2",
		"ge-0-0-1",
		"ge-0-0-2",
		"xsk map update failed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bindings output missing %q:\n%s", want, out)
		}
	}
}
