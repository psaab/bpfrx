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
		LastFIBGeneration:      3,
		LastSnapshotAt:         now.Add(-2 * time.Second),
		InterfaceAddresses:     6,
		NeighborEntries:        9,
		RouteEntries:           4,
		LastResolution: &PacketResolution{
			Disposition:   "forward_candidate",
			EgressIfindex: 11,
			NextHop:       "172.16.50.1",
			NeighborMAC:   "00:10:db:ff:10:01",
		},
		WorkerHeartbeats: []time.Time{now.Add(-500 * time.Millisecond), now.Add(-700 * time.Millisecond)},
		Queues: []QueueStatus{
			{QueueID: 0, Ready: true},
			{QueueID: 1, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, Ready: true, Bound: true, XSKRegistered: true, RXPackets: 10, ValidatedPackets: 8, ExceptionPackets: 1},
			{Slot: 1, Ready: false, Bound: true, XSKRegistered: false, RXPackets: 5, ValidatedPackets: 4, ExceptionPackets: 2},
		},
		RecentExceptions: []ExceptionStatus{
			{Timestamp: now, Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "metadata_parse", PacketLength: 128},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"Userspace dataplane helper:",
		"PID:",
		"Last FIB generation:       3",
		"Interface addresses:       6",
		"Neighbor entries:          9",
		"Route entries:             4",
		"Last resolution:           forward_candidate egress-ifindex=11 next-hop=172.16.50.1 mac=00:10:db:ff:10:01",
		"Bound bindings:            2/2",
		"XSK-registered bindings:   1/2",
		"Ready queues:              1/2",
		"Ready bindings:            1/2",
		"RX packets:                15",
		"Validated packets:         12",
		"Exception packets:         3",
		"Recent exceptions:         1",
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
			{Slot: 0, QueueID: 0, WorkerID: 0, Registered: true, Ready: false, Bound: true, XSKRegistered: true, Ifindex: 5, Interface: "ge-0-0-1", RXPackets: 99, ExceptionPackets: 3},
			{Slot: 1, QueueID: 0, WorkerID: 0, Registered: true, Ready: false, Bound: true, XSKRegistered: false, Ifindex: 6, Interface: "ge-0-0-2", ExceptionPackets: 1, LastError: "xsk map update failed"},
		},
		RecentExceptions: []ExceptionStatus{
			{Timestamp: time.Unix(0, 0).UTC(), Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "fib_generation_mismatch", PacketLength: 512, AddrFamily: 10, Protocol: 6, ConfigGeneration: 11, FIBGeneration: 9},
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
		"Recent userspace exceptions:",
		"fib_generation_mismatch",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bindings output missing %q:\n%s", want, out)
		}
	}
}
