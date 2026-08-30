package vrrp

import (
	"net"
	"testing"
)

// #7334: the self-frame check compared against ONE selected address, not the
// interface's address set.
//
// `resolveLocalIPv4` selects the LOWEST non-VIP IPv4 and stores it as the
// snapshot; `resolveIPv6LinkLocal` does the same for link-local. The four
// receive-path self-checks then compared a frame's source against that single
// value.
//
// So the self-check failed with a NON-NIL snapshot too: a self-advert sent from
// address A bypassed the comparison once the selection had moved to B.
// `resolveEqualPriorityMaster` then compared `peerCmp` (our own OLD source A)
// against `localCmp` (our own NEW source B) and stepped down whenever A > B —
// a coin flip, and a self-inflicted master-down.
//
// #6560 fixed the two DELIVERY paths and named this residual explicitly; the
// comparison is the last line of defence if a delivery path is ever re-opened
// (a new socket, or a kernel without PACKET_IGNORE_OUTGOING plus a path that
// bypasses the pkttype check).
//
// THE SELECTION AND THE SET ARE DIFFERENT THINGS, deliberately. The send source
// must stay ONE deterministic address so it does not flip on unrelated
// secondary-address churn (#2528). The self-check must recognise EVERY address
// we might have sent from, including one the selection has since moved off.

func instWithAddrSet7334(v4, v6 []string) *vrrpInstance {
	vi := &vrrpInstance{cfg: Instance{Interface: "ge-0-0-2", GroupID: 1}}
	vi.setLocalAddrSet(false, v4)
	vi.setLocalAddrSet(true, v6)
	return vi
}

// THE DEFECT. The selection has moved to .20; a self-advert still in flight
// from .10 must be recognised.
func TestSelfFrameFromAPreviouslySelectedSource7334(t *testing.T) {
	// Sorted, as resolveLocalAddrSets stores them.
	vi := instWithAddrSet7334([]string{"10.0.0.10", "10.0.0.20"}, nil)
	vi.setLocalIP(net.ParseIP("10.0.0.20").To4()) // the CURRENT selection

	if !vi.isLocalAddr(net.ParseIP("10.0.0.10")) {
		t.Error("a self-advert from a PREVIOUSLY selected source was not recognised " +
			"as ours. resolveEqualPriorityMaster then compares our own old source " +
			"against our own new one and steps down whenever old > new — a coin " +
			"flip and a self-inflicted master-down (#7334)")
	}
	if !vi.isLocalAddr(net.ParseIP("10.0.0.20")) {
		t.Error("the currently selected source is not recognised as ours")
	}
}

func TestSelfFrameFromAPreviouslySelectedLinkLocal7334(t *testing.T) {
	vi := instWithAddrSet7334(nil, []string{"fe80::1", "fe80::2"})
	vi.setLocalIPv6(net.ParseIP("fe80::2"))

	if !vi.isLocalAddr(net.ParseIP("fe80::1")) {
		t.Error("a self-advert from a previously selected link-local was not " +
			"recognised as ours (#7334). The v6 side has the same shape, and a new " +
			"link-local after the RETH MAC change is one of the named triggers")
	}
}

// A GENUINE PEER must never be dropped. This is the assertion that bounds the
// risk: the fix's failure direction is dropping a peer's advert, which is a
// self-inflicted master-down — strictly worse than the bug.
func TestPeerAdvertIsNeverOurs7334(t *testing.T) {
	vi := instWithAddrSet7334([]string{"10.0.0.10", "10.0.0.20"}, []string{"fe80::1"})
	for _, peer := range []string{"10.0.0.30", "10.0.0.1", "192.168.1.1", "fe80::99"} {
		if vi.isLocalAddr(net.ParseIP(peer)) {
			t.Errorf("a peer address %s was classified as OURS; its advert would be "+
				"dropped and the peer's mastership ignored", peer)
		}
	}
}

// FAIL OPEN on an unresolved set — the #2528 RETH-MAC flush window, when
// programRethMAC's link DOWN has removed every kernel address.
//
// #6560 established this posture and the issue requires it: a frame we cannot
// classify must still be able to be a peer's advert. Dropping it would be the
// self-inflicted master-down the whole change exists to prevent.
func TestUnresolvedSetFailsOpen7334(t *testing.T) {
	vi := instWithAddrSet7334(nil, nil)
	for _, addr := range []string{"10.0.0.10", "fe80::1"} {
		if vi.isLocalAddr(net.ParseIP(addr)) {
			t.Errorf("%s was classified as ours with an UNRESOLVED address set. The "+
				"check must fail OPEN: dropping an unclassifiable frame is a "+
				"self-inflicted master-down, strictly worse than the bug (#7334)", addr)
		}
	}
	// And a nil source is never ours.
	if vi.isLocalAddr(nil) {
		t.Error("a nil source was classified as ours")
	}
}

// FAMILY SEPARATION. A v4 address must not match against the v6 set and vice
// versa — otherwise a link-local set could shadow a v4 peer, or the v4-in-v6
// representation could cross families.
func TestFamiliesDoNotCross7334(t *testing.T) {
	v4Only := instWithAddrSet7334([]string{"10.0.0.10"}, nil)
	if v4Only.isLocalAddr(net.ParseIP("fe80::1")) {
		t.Error("a v6 address matched against a v4-only set")
	}
	v6Only := instWithAddrSet7334(nil, []string{"fe80::1"})
	if v6Only.isLocalAddr(net.ParseIP("10.0.0.10")) {
		t.Error("a v4 address matched against a v6-only set")
	}
	// A v4 address parsed into 16-byte form must still match a 4-byte snapshot:
	// net.ParseIP returns 16 bytes for a dotted quad, and the receive path may
	// hand either representation.
	v4in6 := net.ParseIP("10.0.0.10")
	if len(v4in6) != net.IPv6len {
		t.Fatalf("fixture premise wrong: ParseIP returned %d bytes", len(v4in6))
	}
	if !v4Only.isLocalAddr(v4in6) {
		t.Error("a v4 address in 16-byte form did not match the 4-byte snapshot; " +
			"the receive path can hand either representation")
	}
}

// The SET must be recomputed in lockstep with the selection, or it lags across
// exactly the window this fixes. Both come from one re-resolve.
func TestSetAndSelectionComeFromOneResolve7334(t *testing.T) {
	vi := instWithAddrSet7334([]string{"10.0.0.10"}, nil)
	// Simulate the flush: reresolveLocalAddrs on an interface with no addresses
	// stores nil for both. Here the interface does not exist, so
	// interfaceAddrs errors and both must be cleared together.
	vi.cfg.Interface = "xpf-nonexistent-7334"
	vi.reresolveLocalAddrs()
	if vi.getLocalIP() != nil {
		t.Error("the selection survived a failed re-resolve")
	}
	if len(vi.getLocalAddrSet(false)) != 0 {
		t.Error("the address SET survived a failed re-resolve while the selection " +
			"was cleared; the two must move together or the set can name an address " +
			"the interface no longer has")
	}
}

// THE WIRING. Every cell above calls `isLocalAddr` directly, so all of them
// stay green if a receive-path call site is deleted — which is the shape of the
// defect being fixed (the check exists; it consults the wrong thing). The
// mutation matrix found exactly that: unwiring one site escaped every cell.
//
// These drive the real parse path with a frame whose source is one of OUR
// addresses and assert nothing reaches `rxCh`. `rxCh` is the observable: an
// admitted advert is queued there for the run loop, so a self-frame that
// bypasses the check becomes an equal-priority "peer" and can force a step-down.
func TestParsePathDropsAFrameFromOurOwnAddress7334(t *testing.T) {
	// The source is .10 while the SELECTION is .20 — the case that bypassed the
	// old single-address comparison.
	frame := buildEthFrame(t, 0, net.IPv4(10, 0, 0, 10), net.IPv4(224, 0, 0, 18), &VRRPPacket{
		VRID: 5, Priority: 100, MaxAdvertInt: 100,
		IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)},
	})
	vi := newInstance(Instance{Interface: "ge-0-0-0", GroupID: 5},
		&net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
	vi.setLocalAddrSet(false, []string{"10.0.0.10", "10.0.0.20"})
	vi.setLocalIP(net.ParseIP("10.0.0.20").To4())

	vi.parseAfPacketIPv4(frame, len(frame), 14)
	if got := len(vi.rxCh); got != 0 {
		t.Errorf("a frame from OUR OWN address 10.0.0.10 was queued for the run loop "+
			"(rxCh len=%d). The selection had moved to .20, so the old single-address "+
			"comparison let it through; it then carries our own priority and "+
			"resolveEqualPriorityMaster steps down on a coin flip (#7334)", got)
	}
}

// The PEER control on the same path — without it, the cell above is satisfied
// by a parse path that drops everything.
func TestParsePathStillAcceptsAPeerFrame7334(t *testing.T) {
	frame := buildEthFrame(t, 0, net.IPv4(10, 0, 0, 30), net.IPv4(224, 0, 0, 18), &VRRPPacket{
		VRID: 5, Priority: 100, MaxAdvertInt: 100,
		IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)},
	})
	vi := newInstance(Instance{Interface: "ge-0-0-0", GroupID: 5},
		&net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
	vi.setLocalAddrSet(false, []string{"10.0.0.10", "10.0.0.20"})

	vi.parseAfPacketIPv4(frame, len(frame), 14)
	if got := len(vi.rxCh); got != 1 {
		t.Errorf("a genuine PEER advert from 10.0.0.30 was dropped (rxCh len=%d). "+
			"Dropping a peer's advert is a self-inflicted master-down, strictly "+
			"worse than the bug this fixes", got)
	}
}

// And the fail-open control on the real path: an unresolved set must not turn
// the parse path into a black hole during the #2528 flush window.
func TestParsePathFailsOpenWithNoAddressSet7334(t *testing.T) {
	frame := buildEthFrame(t, 0, net.IPv4(10, 0, 0, 10), net.IPv4(224, 0, 0, 18), &VRRPPacket{
		VRID: 5, Priority: 100, MaxAdvertInt: 100,
		IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)},
	})
	vi := newInstance(Instance{Interface: "ge-0-0-0", GroupID: 5},
		&net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
	// No address set at all — the RETH-MAC flush window.

	vi.parseAfPacketIPv4(frame, len(frame), 14)
	if got := len(vi.rxCh); got != 1 {
		t.Errorf("a frame was dropped with an UNRESOLVED address set (rxCh len=%d). "+
			"The check must fail OPEN — during the #2528 flush window every advert, "+
			"including a real peer's, would otherwise be discarded", got)
	}
}

// The v6 parse path carries the same check and needs its own binding: the two
// sites are separate, so fixing one and not the other is a live possibility.
func TestParsePathV6DropsOurOwnLinkLocal7334(t *testing.T) {
	frame := buildEthIPv6Frame(t, 0, net.ParseIP("fe80::1"), net.ParseIP("ff02::12"), &VRRPPacket{
		VRID: 5, Priority: 100, MaxAdvertInt: 100,
		IPAddresses: []net.IP{net.ParseIP("2001:db8::1")},
	})
	vi := newInstance(Instance{Interface: "ge-0-0-0", GroupID: 5},
		&net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
	vi.setLocalAddrSet(true, []string{"fe80::1", "fe80::2"})
	vi.setLocalIPv6(net.ParseIP("fe80::2"))

	vi.parseAfPacketIPv6(frame, len(frame), 14)
	if got := len(vi.rxCh); got != 0 {
		t.Errorf("a v6 frame from our own previously-selected link-local was queued "+
			"(rxCh len=%d) (#7334)", got)
	}
}
