package vrrp

import (
	"net"
	"testing"
	"time"
)

// TestReceiverIPv6_RejectsNon255HopLimit is the #4549 F8 fail-on-revert guard
// for the raw-IPv6 fallback receiver's GTSM hop-limit check.
//
// RFC 5798 §5.1.2.3 requires VRRPv3 advertisements to carry an IPv6 hop limit
// of 255, so a receiver can reject any advert that was routed (hop limit
// decremented off-link). The AF_PACKET path (parseAfPacketIPv6) and the
// IPv4-raw path already enforce their TTL/hop-limit equivalents. The raw
// ip6:112 fallback socket strips the IPv6 header, so receiverIPv6 reads the
// hop limit from the IPV6_RECVHOPLIMIT control message returned by the
// ipv6Recv seam and drops anything != 255.
//
// This test drives the full receiverIPv6 read path through the seam: a
// hop-limit 200 advert must be dropped (never reaches rxCh); the identical
// advert at hop limit 255 must be delivered. Deleting the `hopLimit != 255`
// gate in receiverIPv6 makes the routed advert reach rxCh and fails this test.
func TestReceiverIPv6_RejectsNon255HopLimit(t *testing.T) {
	const boundIndex = 11 // reth0.50

	build := func(hopLimit int) *vrrpInstance {
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
		// arrival ifindex == boundIndex so the #2886 filter accepts; the
		// only variable under test is the hop limit.
		vi.ipv6Recv = func(b []byte) (int, int, int, net.Addr, error) {
			select {
			case <-readOnce:
				return copy(b, data), boundIndex, hopLimit, &net.IPAddr{IP: srcIP}, nil
			case <-vi.stopCh:
				return 0, 0, 0, nil, net.ErrClosed
			}
		}
		return vi
	}

	// Routed advert (hop limit 200) → must be dropped.
	viLow := build(200)
	go viLow.receiverIPv6()
	defer close(viLow.stopCh)
	select {
	case rx := <-viLow.rxCh:
		t.Fatalf("advert with hop limit 200 was processed (RFC 5798 requires 255): %+v", rx)
	case <-time.After(300 * time.Millisecond):
		// Correct: dropped.
	}

	// Identical advert at hop limit 255 → must be delivered.
	viOK := build(255)
	go viOK.receiverIPv6()
	defer close(viOK.stopCh)
	select {
	case rx := <-viOK.rxCh:
		if rx.VRID != 42 || rx.Priority != 200 {
			t.Fatalf("delivered packet mismatched: %+v", rx)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("hop-limit-255 advert was not delivered to rxCh")
	}
}
