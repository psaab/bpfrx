package vrrp

import (
	"net"
	"testing"
	"time"
)

// TestAcceptArrivalIfindexCrossVLAN is the #2886 fail-on-revert guard for the
// raw-socket fallback receiver's arrival-interface filter.
//
// Background: when AF_PACKET is unavailable (afPacketFD < 0, e.g. an
// unprivileged namespace), VRRP falls back to per-instance raw IP sockets. On a
// VLAN sub-interface maybeBindToDevice is a deliberate no-op (manager.go), so
// two VLAN sockets on the same parent both bind to the wildcard address with NO
// device isolation. The kernel then delivers a proto-112 frame to ALL such
// sockets. Before this fix the only accept gates were TTL, self-IP, and VRID —
// so two VLAN sub-interfaces (reth0.50 / reth0.80) running instances with the
// SAME VRID cross-processed each other's adverts → state corruption, false
// BACKUP transitions, split-brain flapping.
//
// The receiver now enables the per-packet interface control message
// (ipv4.FlagInterface / ipv6.FlagInterface) and routes the reported arrival
// ifindex through acceptArrivalIfindex. A frame from a sibling VLAN
// (arrival ifindex != bound ifindex) MUST be rejected.
//
// Fail-on-revert: deleting the acceptArrivalIfindex calls in receiver() /
// receiverIPv6() (or making the helper always return true) restores the
// cross-VLAN cross-talk and flips the "sibling VLAN, same VRID" assertion below.
func TestAcceptArrivalIfindexCrossVLAN(t *testing.T) {
	const (
		reth050Index = 11 // VLAN sub-interface reth0.50
		reth080Index = 12 // sibling VLAN sub-interface reth0.80 (same parent)
	)

	cases := []struct {
		name       string
		arrival    int
		expected   int
		wantAccept bool
	}{
		{
			// Core defect: an advert that physically arrived on reth0.80 must
			// NOT be processed by the reth0.50 instance even though they share
			// a VRID and the wildcard-bound socket received it.
			name:       "sibling VLAN same VRID rejected",
			arrival:    reth080Index,
			expected:   reth050Index,
			wantAccept: false,
		},
		{
			name:       "matching interface accepted",
			arrival:    reth050Index,
			expected:   reth050Index,
			wantAccept: true,
		},
		{
			// Fail-open: a platform that did not report an arrival interface
			// (ifindex 0) keeps delivering — the VRID/TTL/self gates still run.
			name:       "no control message fails open",
			arrival:    0,
			expected:   reth050Index,
			wantAccept: true,
		},
		{
			// An instance with no resolved interface (test/edge construction)
			// must not start dropping everything.
			name:       "unresolved expected ifindex fails open",
			arrival:    reth080Index,
			expected:   0,
			wantAccept: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptArrivalIfindex(tc.arrival, tc.expected); got != tc.wantAccept {
				t.Fatalf("acceptArrivalIfindex(arrival=%d, expected=%d) = %v, want %v",
					tc.arrival, tc.expected, got, tc.wantAccept)
			}
		})
	}
}

// TestReceiverIPv6_DropsCrossInterfaceAdvert drives the full receiverIPv6 read
// path through the ipv6Recv seam and proves a valid same-VRID advert that
// arrived on a SIBLING VLAN (arrival ifindex != bound ifindex) is dropped, while
// the same advert arriving on the bound interface is delivered to rxCh. This is
// the receiver-level #2886 fail-on-revert guard: deleting the
// acceptArrivalIfindex check in receiverIPv6 makes the cross-interface frame
// reach rxCh and fails this test.
func TestReceiverIPv6_DropsCrossInterfaceAdvert(t *testing.T) {
	const boundIndex = 11 // reth0.50
	const siblingIndex = 12

	build := func(arrivalIfindex int) *vrrpInstance {
		eventCh := make(chan VRRPEvent, 4)
		vi := newInstance(Instance{Interface: "reth0.50", GroupID: 42, Priority: 100},
			&net.Interface{Name: "reth0.50", Index: boundIndex}, eventCh, nil)
		vi.setLocalIPv6(net.ParseIP("fe80::1"))

		srcIP := net.ParseIP("fe80::2")
		pkt := &VRRPPacket{VRID: 42, Priority: 200, MaxAdvertInt: 100,
			IPAddresses: []net.IP{net.ParseIP("2001:db8::1")}}
		data, err := pkt.Marshal(true, srcIP, net.ParseIP("ff02::12"))
		if err != nil {
			t.Fatal(err)
		}

		readOnce := make(chan struct{}, 1)
		readOnce <- struct{}{}
		vi.ipv6Recv = func(b []byte) (int, int, net.Addr, error) {
			select {
			case <-readOnce:
				return copy(b, data), arrivalIfindex, &net.IPAddr{IP: srcIP}, nil
			case <-vi.stopCh:
				return 0, 0, nil, net.ErrClosed
			}
		}
		return vi
	}

	// Sibling-VLAN arrival → must be dropped (NOT delivered to rxCh).
	viCross := build(siblingIndex)
	go viCross.receiverIPv6()
	defer close(viCross.stopCh)
	select {
	case rx := <-viCross.rxCh:
		t.Fatalf("cross-interface advert (arrival ifindex %d, bound %d) was processed: %+v",
			siblingIndex, boundIndex, rx)
	case <-time.After(300 * time.Millisecond):
		// Correct: dropped.
	}

	// Same advert on the bound interface → must be delivered.
	viOK := build(boundIndex)
	go viOK.receiverIPv6()
	defer close(viOK.stopCh)
	select {
	case rx := <-viOK.rxCh:
		if rx.VRID != 42 || rx.Priority != 200 {
			t.Fatalf("delivered packet mismatched: %+v", rx)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("matching-interface advert was not delivered to rxCh")
	}
}

// TestExpectedIfindexResolvesFromIface asserts the instance reports its bound
// kernel ifindex (the value compared against the per-packet arrival ifindex),
// and degrades to 0 (fail-open) when no interface is resolved.
func TestExpectedIfindexResolvesFromIface(t *testing.T) {
	vi := newInstance(Instance{Interface: "reth0.50", GroupID: 7, Priority: 200},
		&net.Interface{Index: 42, Name: "reth0.50"}, make(chan VRRPEvent, 1), nil)
	if got := vi.expectedIfindex(); got != 42 {
		t.Fatalf("expectedIfindex() = %d, want 42", got)
	}

	viNil := newInstance(Instance{Interface: "reth0.80", GroupID: 7, Priority: 200},
		nil, make(chan VRRPEvent, 1), nil)
	if got := viNil.expectedIfindex(); got != 0 {
		t.Fatalf("expectedIfindex() with nil iface = %d, want 0", got)
	}
}
