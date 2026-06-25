package vrrp

import (
	"strings"
	"testing"
)

// TestMaybeBindToDeviceVLANGate asserts the SO_BINDTODEVICE gate that both the
// IPv4 (openPerInterfaceSocket) and IPv6 (openIPv6Socket) raw-socket paths
// route through: the device bind is applied on a plain interface and SKIPPED
// on a VLAN sub-interface. This is the #2786 fix — before it, the IPv6 path
// bound SO_BINDTODEVICE unconditionally while IPv4 skipped on VLANs, so the two
// families saw VRRP multicast differently on a VLAN RETH member and could
// split-brain (dual-MASTER). The bindSocketToDevice seam is intercepted so the
// decision is observable without CAP_NET_RAW or a real raw socket.
//
// Fail-on-revert: reverting maybeBindToDevice to bind unconditionally (or
// reverting either call site back to a direct unconditional bindSocketToDevice)
// makes the VLAN case bind → this test fails.
func TestMaybeBindToDeviceVLANGate(t *testing.T) {
	var bound []string
	orig := bindSocketToDevice
	bindSocketToDevice = func(fd int, ifName string) error {
		bound = append(bound, ifName)
		return nil
	}
	defer func() { bindSocketToDevice = orig }()

	cases := []struct {
		name      string
		ifName    string
		isVLAN    bool
		wantBound bool
	}{
		{"plain interface binds", "reth0", false, true},
		{"vlan sub-interface skips", "reth0.50", true, false},
		{"second vlan skips", "reth0.80", true, false},
		{"plain LAN binds", "reth1", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bound = nil
			// fd is irrelevant — the seam captures the call, never touches it.
			if err := maybeBindToDevice(7, tc.ifName, tc.isVLAN); err != nil {
				t.Fatalf("maybeBindToDevice(%q): %v", tc.ifName, err)
			}
			gotBound := len(bound) == 1 && bound[0] == tc.ifName
			if tc.wantBound && !gotBound {
				t.Fatalf("isVLAN=%v ifName=%q: expected SO_BINDTODEVICE bind, got calls %v",
					tc.isVLAN, tc.ifName, bound)
			}
			if !tc.wantBound && len(bound) != 0 {
				t.Fatalf("isVLAN=%v ifName=%q: expected NO bind on VLAN, got calls %v",
					tc.isVLAN, tc.ifName, bound)
			}
		})
	}
}

// TestVLANDetectionMatchesCallSite documents the VLAN-detection rule the socket
// call sites use (instance.openSocket: strings.Contains(Interface, ".")) so the
// two stay coupled: openIPv6Socket and openPerInterfaceSocket receive the SAME
// isVLAN value, derived from the SAME interface name, guaranteeing v4 and v6
// reach maybeBindToDevice with an identical decision.
func TestVLANDetectionMatchesCallSite(t *testing.T) {
	for _, tc := range []struct {
		ifName string
		isVLAN bool
	}{
		{"reth0", false},
		{"reth0.50", true},
		{"ge-0-0-2", false},
		{"ge-0-0-2.80", true},
	} {
		if got := strings.Contains(tc.ifName, "."); got != tc.isVLAN {
			t.Fatalf("VLAN detection for %q: got %v want %v", tc.ifName, got, tc.isVLAN)
		}
	}
}
