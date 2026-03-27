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
		ForwardingArmed:        false,
		Workers:                2,
		RingEntries:            2048,
		LastSnapshotGeneration: 7,
		LastFIBGeneration:      3,
		LastSnapshotAt:         now.Add(-2 * time.Second),
		InterfaceAddresses:     6,
		NeighborEntries:        9,
		RouteEntries:           4,
		Fabrics: []FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		LastResolution: &PacketResolution{
			Disposition:   "forward_candidate",
			EgressIfindex: 11,
			NextHop:       "172.16.50.1",
			NeighborMAC:   "00:10:db:ff:10:01",
		},
		WorkerHeartbeats: []time.Time{now.Add(-500 * time.Millisecond), now.Add(-700 * time.Millisecond)},
		Queues: []QueueStatus{
			{QueueID: 0, Armed: false, Ready: true},
			{QueueID: 1, Armed: false, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, Armed: false, Ready: true, Bound: true, XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, RXPackets: 10, ValidatedPackets: 8, ExceptionPackets: 1, TXPackets: 3, TXBytes: 420, TXCompletions: 2, KernelRXDropped: 9, KernelRXInvalidDescs: 1, DirectTXPackets: 2, InPlaceTXPackets: 1, DirectTXNoFrameFallbackPackets: 5, DirectTXBuildFallbackPackets: 6, DebugPendingFillFrames: 10, DebugSpareFillFrames: 11, DebugFreeTXFrames: 12, DebugPendingTXPrepared: 13, DebugPendingTXLocal: 14, DebugOutstandingTX: 15, DebugInFlightRecycles: 16},
			{Slot: 1, Armed: false, Ready: false, Bound: true, XSKRegistered: false, RXPackets: 5, ValidatedPackets: 4, ExceptionPackets: 2, TXErrors: 1, TXCompletions: 3, KernelRXDropped: 4, KernelRXInvalidDescs: 2, CopyTXPackets: 4, DirectTXDisallowedFallbackPackets: 7, DebugPendingFillFrames: 20, DebugSpareFillFrames: 21, DebugFreeTXFrames: 22, DebugPendingTXPrepared: 23, DebugPendingTXLocal: 24, DebugOutstandingTX: 25, DebugInFlightRecycles: 26},
		},
		RecentExceptions: []ExceptionStatus{
			{Timestamp: now, Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "metadata_parse", PacketLength: 128},
		},
	}

	out := FormatStatusSummary(status)
	for _, want := range []string{
		"Userspace dataplane helper:",
		"PID:",
		"Forwarding armed:          false",
		"Last FIB generation:       3",
		"Interface addresses:       6",
		"Neighbor entries:          9",
		"Route entries:             4",
		"Fabric links:              fab0 parent=ge-0-0-0 peer=10.99.1.2",
		"Last resolution:           forward_candidate egress-ifindex=11 next-hop=172.16.50.1 mac=00:10:db:ff:10:01",
		"Bound bindings:            2/2",
		"XSK-registered bindings:   1/2",
		"Zerocopy bindings:         1/2",
		"Armed queues:              0/2",
		"Ready queues:              1/2",
		"Armed bindings:            0/2",
		"Ready bindings:            1/2",
		"RX packets:                15",
		"Validated packets:         12",
		"Exception packets:         3",
		"TX packets:                3",
		"TX bytes:                  420",
		"TX errors:                 1",
		"TX completions:            5",
		"Kernel RX dropped:         13",
		"Kernel RX invalid descs:   3",
		"Direct TX packets:         2",
		"Copy-path TX packets:      4",
		"In-place TX packets:       1",
		"Direct TX no-frame fb:     5",
		"Direct TX build-none fb:   6",
		"Direct TX disallowed fb:   7",
		"Pending fill frames:       30",
		"Spare fill frames:         32",
		"Free TX frames:            34",
		"Pending TX prepared:       36",
		"Pending TX local:          38",
		"Outstanding TX:            40",
		"In-flight recycles:        42",
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
		Fabrics: []FabricSnapshot{
			{Name: "fab0", ParentLinuxName: "ge-0-0-0", ParentIfindex: 7, OverlayLinux: "fab0", OverlayIfindex: 17, RXQueues: 4, PeerAddress: "10.99.1.2"},
		},
		Queues: []QueueStatus{
			{QueueID: 0, WorkerID: 0, Interfaces: []string{"ge-0-0-1", "ge-0-0-2"}, Registered: true, Armed: false, Ready: false},
		},
		Bindings: []BindingStatus{
			{Slot: 0, QueueID: 0, WorkerID: 0, Registered: true, Armed: false, Ready: false, Bound: true, XSKRegistered: true, XSKBindMode: "zerocopy", ZeroCopy: true, Ifindex: 5, Interface: "ge-0-0-1", RXPackets: 99, TXPackets: 7, DirectTXPackets: 5, CopyTXPackets: 1, InPlaceTXPackets: 1, ExceptionPackets: 3},
			{Slot: 1, QueueID: 0, WorkerID: 0, Registered: true, Armed: false, Ready: false, Bound: true, XSKRegistered: false, Ifindex: 6, Interface: "ge-0-0-2", ExceptionPackets: 1, LastError: "xsk map update failed"},
		},
		RecentExceptions: []ExceptionStatus{
			{Timestamp: time.Unix(0, 0).UTC(), Slot: 1, QueueID: 0, Interface: "ge-0-0-2", Reason: "fib_generation_mismatch", PacketLength: 512, AddrFamily: 10, Protocol: 6, ConfigGeneration: 11, FIBGeneration: 9},
		},
	}

	out := FormatBindings(status)
	for _, want := range []string{
		"Userspace queues:",
		"Userspace fabric links:",
		"fab0",
		"Userspace bindings:",
		"ge-0-0-1,ge-0-0-2",
		"ge-0-0-1",
		"ge-0-0-2",
		"zerocopy",
		"TXPkts",
		"DirTx",
		"CopyTx",
		"InPlTx",
		"xsk map update failed",
		"Recent userspace exceptions:",
		"fib_generation_mismatch",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("bindings output missing %q:\n%s", want, out)
		}
	}
}
