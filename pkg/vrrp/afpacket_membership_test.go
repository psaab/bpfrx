package vrrp

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestAfPacketMembershipUsesAllmultiNotPromisc asserts that the VRRP AF_PACKET
// receiver requests PACKET_MR_ALLMULTI (receive all multicast) rather than
// PACKET_MR_PROMISC (receive everything). PROMISC disabled the NIC's unicast
// hardware filter, copying every tenant frame on the segment to the host CPU
// and leaking other tenants' unicast traffic to the raw capture socket (#2870).
// ALLMULTI still delivers VRRP's multicast adverts while preserving unicast
// filtering.
//
// Fail-on-revert: changing buildAfPacketMembership back to PACKET_MR_PROMISC
// makes this test fail.
func TestAfPacketMembershipUsesAllmultiNotPromisc(t *testing.T) {
	const ifIndex = 7
	mreq := buildAfPacketMembership(ifIndex)

	if mreq.Type == unix.PACKET_MR_PROMISC {
		t.Fatalf("VRRP receiver membership uses PACKET_MR_PROMISC; want ALLMULTI/MULTICAST (#2870)")
	}
	if mreq.Type != unix.PACKET_MR_ALLMULTI {
		t.Fatalf("VRRP receiver membership type = %#x; want PACKET_MR_ALLMULTI (%#x)",
			mreq.Type, unix.PACKET_MR_ALLMULTI)
	}
	if mreq.Ifindex != int32(ifIndex) {
		t.Fatalf("VRRP receiver membership ifindex = %d; want %d", mreq.Ifindex, ifIndex)
	}
}

// TestVRRPGroupMACsAreCorrect pins the VRRP advertisement multicast destination
// MACs. IPv4 224.0.0.18 maps to 01:00:5e:00:00:12 and IPv6 ff02::12 maps to
// 33:33:00:00:00:12. These are the groups ALLMULTI must deliver (and the MACs a
// future PACKET_MR_MULTICAST membership would join), so guard the constants
// against typos.
func TestVRRPGroupMACsAreCorrect(t *testing.T) {
	wantV4 := [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x12}
	wantV6 := [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x12}
	if vrrpGroupMACv4 != wantV4 {
		t.Fatalf("vrrpGroupMACv4 = %x; want %x", vrrpGroupMACv4, wantV4)
	}
	if vrrpGroupMACv6 != wantV6 {
		t.Fatalf("vrrpGroupMACv6 = %x; want %x", vrrpGroupMACv6, wantV6)
	}
}
