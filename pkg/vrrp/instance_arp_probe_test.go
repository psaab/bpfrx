package vrrp

import (
	"net"
	"testing"
	"time"
)

// #2152: the post-failover gateway ARP probe must carry the VIP as the ARP
// sender protocol address so a gateway that ignores gratuitous ARP re-binds
// VIP -> our (new) MAC. Pre-fix, sendGARP passed only the gateway target to
// SendARPProbe, which self-resolved the sender to the interface PRIMARY IP —
// so the gateway refreshed the primary binding and the VIP entry stayed
// stale (blackhole until it aged out).
//
// These tests capture the (sender, target) sendGARP passes via the arpProbeFn
// seam — no AF_PACKET I/O — and assert the sender is the VIP. They are
// non-tautological: against pre-fix wiring (no sender argument) they would
// not compile/pass, and a regression that reverts to passing the primary
// would fail the sender assertion.

// masterInstanceWithVIP builds a MASTER vrrpInstance carrying a single IPv4
// VIP so sendGARP's IPv4 probe branch executes. The interface name is
// nonexistent so SendGratuitousARPBurst's netlink work is a harmless no-op;
// the ARP probe itself is intercepted by the arpProbeFn seam.
func masterInstanceWithVIP(t *testing.T, vipCIDR string) *vrrpInstance {
	t.Helper()
	vi := newInstance(Instance{
		Interface:        "xpf-test-nonexistent0",
		GroupID:          102,
		Priority:         200,
		VirtualAddresses: []string{vipCIDR},
	}, &net.Interface{Name: "xpf-test-nonexistent0"}, make(chan VRRPEvent, 8), nil)
	vi.setState(StateMaster)
	return vi
}

func TestSendGARPProbeUsesVIPAsSender(t *testing.T) {
	const vip = "10.0.0.100"
	const wantGW = "10.0.0.1"

	var gotIface string
	var gotSender, gotTarget net.IP
	var calls int

	orig := arpProbeFn
	arpProbeFn = func(iface string, senderIP, targetIP net.IP) error {
		calls++
		gotIface = iface
		gotSender = append(net.IP(nil), senderIP...)
		gotTarget = append(net.IP(nil), targetIP...)
		return nil
	}
	defer func() { arpProbeFn = orig }()

	vi := masterInstanceWithVIP(t, vip+"/24")
	// Force so the time dampener never suppresses the burst in this test.
	vi.sendGARP(true)

	if calls != 1 {
		t.Fatalf("expected exactly 1 gateway ARP probe, got %d", calls)
	}
	if gotIface != "xpf-test-nonexistent0" {
		t.Errorf("probe iface = %q, want the VRRP interface", gotIface)
	}
	if s := gotSender.String(); s != vip {
		t.Errorf("ARP probe sender = %s, want the VIP %s — #2152 regression: "+
			"the probe is using the primary IP, not the VIP", s, vip)
	}
	if tg := gotTarget.String(); tg != wantGW {
		t.Errorf("ARP probe target = %s, want gateway %s", tg, wantGW)
	}
}

// TestSendGARPProbeSkippedWhenVIPIsGateway confirms the existing skip-if-.1
// guard survives the #2152 change: if the VIP is itself the subnet .1, no
// probe is sent (we would otherwise probe ourselves).
func TestSendGARPProbeSkippedWhenVIPIsGateway(t *testing.T) {
	var calls int
	orig := arpProbeFn
	arpProbeFn = func(string, net.IP, net.IP) error {
		calls++
		return nil
	}
	defer func() { arpProbeFn = orig }()

	vi := masterInstanceWithVIP(t, "10.0.0.1/24") // VIP == gateway .1
	vi.sendGARP(true)

	if calls != 0 {
		t.Fatalf("expected no ARP probe when the VIP is the gateway .1, got %d", calls)
	}
}

// TestSendGARPProbeSenderMatchesEachVIP proves the sender tracks the VIP per
// VIP (not a single self-resolved address), exercising the wiring across
// multiple VIPs in distinct subnets.
func TestSendGARPProbeSenderMatchesEachVIP(t *testing.T) {
	type probe struct{ sender, target string }
	var got []probe

	orig := arpProbeFn
	arpProbeFn = func(_ string, senderIP, targetIP net.IP) error {
		got = append(got, probe{senderIP.String(), targetIP.String()})
		return nil
	}
	defer func() { arpProbeFn = orig }()

	vi := newInstance(Instance{
		Interface:        "xpf-test-nonexistent0",
		GroupID:          103,
		Priority:         200,
		VirtualAddresses: []string{"10.0.5.100/24", "10.0.6.50/24"},
	}, &net.Interface{Name: "xpf-test-nonexistent0"}, make(chan VRRPEvent, 8), nil)
	vi.setState(StateMaster)
	vi.lastGARPTime.Store(time.Now().Add(-time.Second).UnixNano())

	vi.sendGARP(true)

	want := []probe{
		{"10.0.5.100", "10.0.5.1"},
		{"10.0.6.50", "10.0.6.1"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d probes, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("probe %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
