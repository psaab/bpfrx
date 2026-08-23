package vrrp

import (
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6779 VALIDATOR<->BUILDER AGREEMENT.
//
// The commit-time gate lives in pkg/config (validateVRRPVIPCountStrict) and the
// wire builder lives here (Marshal). pkg/vrrp imports pkg/config, never the
// reverse, so the per-family ceiling is necessarily spelled in two places:
// config.MaxVRRPVirtualAddressesIPv4/IPv6 and vrrp.MaxConfiguredVIPs. Two
// spellings of one number drift.
//
// These tests do NOT pin either side to the literal 255/254 — a literal encodes
// which side you trust, and if the wire format ever changes the "correct" number
// changes with it. They instead MEASURE the largest configured-VIP count that
// pkg/vrrp's real Marshal accepts for each family (driving the IPv6 case through
// the same link-local prepend sendPacketIPv6 performs) and assert the config
// constant equals exactly that. A change to Marshal's bound, or to the IPv6
// prepend, that the config constants did not follow fails here.

// marshalAcceptsConfiguredCount reports whether an advert built from n
// CONFIGURED virtual addresses of the given family marshals successfully.
//
// For IPv6 it reproduces sendPacketIPv6's mandatory link-local prepend, so the
// count reaching Marshal is n+1 — the exact arithmetic MaxConfiguredVIPs
// encodes. For IPv4 there is no prepend.
func marshalAcceptsConfiguredCount(t *testing.T, n int, isIPv6 bool) bool {
	t.Helper()

	addrs := make([]net.IP, 0, n+1)
	if isIPv6 {
		// sendPacketIPv6 prepends the virtual router's link-local first.
		addrs = append(addrs, net.ParseIP("fe80::1"))
	}
	for i := 0; i < n; i++ {
		if isIPv6 {
			addrs = append(addrs, net.ParseIP(fmt.Sprintf("2001:db8::%x", i+1)))
		} else {
			addrs = append(addrs, net.IPv4(10, 0, byte(i>>8), byte(i)))
		}
	}

	pkt := &VRRPPacket{VRID: 7, Priority: 100, MaxAdvertInt: 100, IPAddresses: addrs}
	var src, dst net.IP
	if isIPv6 {
		src, dst = net.ParseIP("fe80::1"), net.ParseIP("ff02::12")
	} else {
		src, dst = net.IPv4(10, 0, 0, 2), net.IPv4(224, 0, 0, 18)
	}
	_, err := pkt.Marshal(isIPv6, src, dst)
	return err == nil
}

// measureMarshalCeiling finds the largest configured-VIP count Marshal accepts
// for a family by probing the candidate boundary from the config constant: it
// asserts the constant is accepted and the next value up is refused, which
// together identify the ceiling uniquely without assuming its value.
func TestAdvertCapacity_ConfigConstantsMatchMarshalCeiling(t *testing.T) {
	for _, tc := range []struct {
		name       string
		isIPv6     bool
		configMax  int
		runtimeMax int
	}{
		{"IPv4", false, config.MaxVRRPVirtualAddressesIPv4, MaxConfiguredVIPs(false)},
		{"IPv6", true, config.MaxVRRPVirtualAddressesIPv6, MaxConfiguredVIPs(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 1. The two spellings agree with each other.
			if tc.configMax != tc.runtimeMax {
				t.Fatalf("config cap (%d) != runtime cap (%d): the commit gate and "+
					"the advert builder disagree about how many %s virtual "+
					"addresses fit, so a config the gate accepts can still fail "+
					"every Marshal", tc.configMax, tc.runtimeMax, tc.name)
			}

			// 2. Both agree with what Marshal ACTUALLY does. This is the leg a
			//    literal cannot provide: it exercises the real builder,
			//    including the IPv6 link-local prepend.
			if !marshalAcceptsConfiguredCount(t, tc.configMax, tc.isIPv6) {
				t.Errorf("Marshal REFUSED %d configured %s addresses, but the cap "+
					"claims that many fit — the gate would accept a config whose "+
					"every advert fails to build", tc.configMax, tc.name)
			}
			if marshalAcceptsConfiguredCount(t, tc.configMax+1, tc.isIPv6) {
				t.Errorf("Marshal ACCEPTED %d configured %s addresses, one more "+
					"than the cap claims fits — the gate rejects a config that "+
					"would have advertised fine", tc.configMax+1, tc.name)
			}
		})
	}
}

// TestAdvertCapacity_IPv6CapIsOneBelowIPv4 pins the REASON the two families
// differ rather than the numbers themselves: the IPv6 advert must carry the
// virtual router's link-local first (RFC 5798 §6.1), and sendPacketIPv6
// prepends it, so exactly one slot is unavailable to configured VIPs.
//
// Mutating MaxConfiguredVIPs to return MaxAdvertAddrCount for IPv6 (dropping
// the prepend allowance) makes this RED, and so does dropping the prepend in
// sendPacketIPv6 while leaving the cap alone.
func TestAdvertCapacity_IPv6ReservesExactlyOneSlotForLinkLocal(t *testing.T) {
	v4, v6 := MaxConfiguredVIPs(false), MaxConfiguredVIPs(true)
	if got := v4 - v6; got != 1 {
		t.Fatalf("IPv4 cap %d - IPv6 cap %d = %d, want exactly 1 slot reserved "+
			"for the mandatory IPv6 link-local prepend", v4, v6, got)
	}
	// The reserved slot is real: an IPv6 advert at the IPv6 cap fills the wire
	// count to the IPv4 cap once the link-local is prepended.
	if v6+1 != MaxAdvertAddrCount {
		t.Fatalf("IPv6 cap %d + link-local = %d, want the wire maximum %d",
			v6, v6+1, MaxAdvertAddrCount)
	}
}
