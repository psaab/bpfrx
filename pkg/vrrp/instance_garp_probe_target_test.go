package vrrp

import (
	"net"
	"testing"
)

// #2377: the supplementary gateway-probe target must be computed as the first
// usable host (network address + 1), not by forcing the network address's last
// octet to .1. On /25-or-longer subnets whose network address does not end in
// .0, the legacy gwIP[3] = 1 computation landed OUTSIDE the subnet, sending the
// directed probe to a foreign address.
//
// These tests pin gatewayProbeTarget directly. They are fail-on-revert: the
// /28 case (VIP 10.0.61.18/28, network 10.0.61.16) wants 10.0.61.17; the
// pre-#2377 code computed 10.0.61.1, which is OUTSIDE the .16-.31 subnet — so
// asserting the target is in-subnet fails against master.

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return ipNet
}

func TestGatewayProbeTargetInSubnet(t *testing.T) {
	cases := []struct {
		cidr     string
		wantGW   string
		wantOK   bool
		inSubnet bool // assert the target is inside the parsed subnet when ok
	}{
		// /24 — unchanged behavior: network .0 + 1 = .1.
		{"10.0.0.100/24", "10.0.0.1", true, true},
		// /28 — the #2377 regression: network 10.0.61.16 + 1 = .17, INSIDE
		// .16-.31. Master computes .1 (out of subnet).
		{"10.0.61.18/28", "10.0.61.17", true, true},
		// /25 with a non-.0 network: network 192.168.1.128 + 1 = .129.
		{"192.168.1.130/25", "192.168.1.129", true, true},
		// /26: network 10.5.5.64 + 1 = .65.
		{"10.5.5.70/26", "10.5.5.65", true, true},
		// /30: network 10.0.0.4 + 1 = .5 (a usable host, here == VIP — the
		// caller's equals-VIP guard skips it, but the target is in-subnet).
		{"10.0.0.5/30", "10.0.0.5", true, true},
		// /31 RFC 3021 — no usable network+1 host; skip the directed probe.
		{"10.0.0.4/31", "", false, false},
		// /32 host route — the VIP is the only address; skip.
		{"10.1.2.3/32", "", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.cidr, func(t *testing.T) {
			ipNet := mustCIDR(t, tc.cidr)
			gw, ok := gatewayProbeTarget(ipNet)
			if ok != tc.wantOK {
				t.Fatalf("gatewayProbeTarget(%s) ok = %v, want %v", tc.cidr, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if gw.String() != tc.wantGW {
				t.Errorf("gatewayProbeTarget(%s) = %s, want %s", tc.cidr, gw, tc.wantGW)
			}
			if tc.inSubnet && !ipNet.Contains(gw) {
				t.Errorf("gatewayProbeTarget(%s) = %s is OUTSIDE the subnet %s — #2377 regression",
					tc.cidr, gw, ipNet)
			}
		})
	}
}

// TestSendGARPProbeTargetOnLongPrefix exercises the full sendGARP path through
// the arpProbeFn seam on a /28 VIP and asserts the directed probe target is the
// in-subnet first host (10.0.61.17), not the out-of-subnet .1 master computed.
func TestSendGARPProbeTargetOnLongPrefix(t *testing.T) {
	var gotTarget net.IP
	var calls int

	orig := arpProbeFn
	arpProbeFn = func(_ string, _, targetIP net.IP) error {
		calls++
		gotTarget = append(net.IP(nil), targetIP...)
		return nil
	}
	defer func() { arpProbeFn = orig }()

	vi := masterInstanceWithVIP(t, "10.0.61.18/28")
	vi.sendGARP(true)

	if calls != 1 {
		t.Fatalf("expected exactly 1 gateway ARP probe, got %d", calls)
	}
	_, ipNet := mustParseVIP(t, "10.0.61.18/28")
	if gotTarget.String() != "10.0.61.17" {
		t.Errorf("probe target = %s, want 10.0.61.17 (network .16 + 1)", gotTarget)
	}
	if !ipNet.Contains(gotTarget) {
		t.Errorf("probe target %s is OUTSIDE the /28 subnet %s — #2377 regression", gotTarget, ipNet)
	}
}

// TestSendGARPProbeSkippedOnHostRoute confirms no directed probe fires for a
// /32 VIP (only the broadcast GARP burst, which is not observable via the
// arpProbeFn seam).
func TestSendGARPProbeSkippedOnHostRoute(t *testing.T) {
	var calls int
	orig := arpProbeFn
	arpProbeFn = func(string, net.IP, net.IP) error {
		calls++
		return nil
	}
	defer func() { arpProbeFn = orig }()

	vi := masterInstanceWithVIP(t, "10.1.2.3/32")
	vi.sendGARP(true)

	if calls != 0 {
		t.Fatalf("expected no directed ARP probe on a /32 VIP, got %d", calls)
	}
}

func mustParseVIP(t *testing.T, s string) (net.IP, *net.IPNet) {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return ip, ipNet
}
