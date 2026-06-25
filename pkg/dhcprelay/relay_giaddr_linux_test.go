package dhcprelay

import (
	"errors"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func mustIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	ipnet.IP = ip
	return ipnet
}

// TestSelectPrimaryIPv4_SecondaryBeforePrimary is the #2849 fail-on-revert
// guard. The kernel returns interface addresses in maintenance order, NOT
// guaranteed primary-first, so a secondary subnet alias can appear BEFORE the
// primary. The relay must stamp the PRIMARY address as giaddr. If the resolver
// is reverted to "return the first kernel IPv4", this test goes RED because the
// first list element here is a secondary alias from a different subnet.
func TestSelectPrimaryIPv4_SecondaryBeforePrimary(t *testing.T) {
	const iface = "ge-0-0-0"
	primary := net.IPv4(10, 0, 1, 1).To4()
	secondary := net.IPv4(192, 168, 50, 1).To4()

	orig := netlinkAddrLister
	t.Cleanup(func() { netlinkAddrLister = orig })
	netlinkAddrLister = func(name string) ([]netlink.Addr, error) {
		if name != iface {
			t.Errorf("unexpected iface %q", name)
		}
		// Secondary alias FIRST, primary SECOND — the ordering hazard.
		return []netlink.Addr{
			{IPNet: mustIPNet(t, "192.168.50.1/24"), Flags: unix.IFA_F_SECONDARY},
			{IPNet: mustIPNet(t, "10.0.1.1/24"), Flags: 0},
		}, nil
	}

	got, err := defaultIfaceResolver(iface)
	if err != nil {
		t.Fatalf("defaultIfaceResolver: %v", err)
	}
	if !got.Equal(primary) {
		t.Fatalf("giaddr = %s, want PRIMARY %s (secondary %s must be skipped)",
			got, primary, secondary)
	}
}

// TestNetlinkIPv4Lister_FlagsAndOrder verifies the netlink lister records the
// secondary flag per-address and preserves kernel ordering.
func TestNetlinkIPv4Lister_FlagsAndOrder(t *testing.T) {
	orig := netlinkAddrLister
	t.Cleanup(func() { netlinkAddrLister = orig })
	netlinkAddrLister = func(string) ([]netlink.Addr, error) {
		return []netlink.Addr{
			{IPNet: mustIPNet(t, "127.0.0.1/8"), Flags: 0}, // loopback skipped
			{IPNet: mustIPNet(t, "172.16.5.2/24"), Flags: unix.IFA_F_SECONDARY},
			{IPNet: mustIPNet(t, "172.16.5.1/24"), Flags: 0},
		}, nil
	}
	cands, err := netlinkIPv4Lister("eth0")
	if err != nil {
		t.Fatalf("netlinkIPv4Lister: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("got %d candidates, want 2 (loopback dropped)", len(cands))
	}
	if !cands[0].secondary {
		t.Errorf("cands[0] should be secondary")
	}
	if cands[1].secondary {
		t.Errorf("cands[1] should be primary")
	}
}

// TestNetlinkIPv4Lister_FallsBackOnError asserts a netlink failure does not
// fail closed: the lister falls back to the portable path. We cannot guarantee
// the portable path finds an address in the test env, so we only assert the
// fallback is attempted (no netlink error is surfaced as-is).
func TestNetlinkIPv4Lister_FallsBackOnError(t *testing.T) {
	orig := netlinkAddrLister
	t.Cleanup(func() { netlinkAddrLister = orig })
	netlinkAddrLister = func(string) ([]netlink.Addr, error) {
		return nil, errors.New("netlink boom")
	}
	// "lo" exists in essentially every test env; portable lister will return no
	// usable (non-loopback) IPv4, i.e. an empty slice with nil error. The point
	// is that the netlink error is swallowed, not returned.
	_, err := netlinkIPv4Lister("lo")
	if err != nil {
		t.Fatalf("expected fallback (nil error), got netlink error surfaced: %v", err)
	}
}

// TestSelectPrimaryIPv4_AllSecondaryFallback covers the defensive branch: if
// every candidate is somehow secondary, the first is returned rather than
// failing closed.
func TestSelectPrimaryIPv4_AllSecondaryFallback(t *testing.T) {
	cands := []ipv4Candidate{
		{ip: net.IPv4(10, 0, 0, 2).To4(), secondary: true},
		{ip: net.IPv4(10, 0, 0, 3).To4(), secondary: true},
	}
	got, err := selectPrimaryIPv4("x", cands)
	if err != nil {
		t.Fatalf("selectPrimaryIPv4: %v", err)
	}
	if !got.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("got %s, want first secondary 10.0.0.2", got)
	}
}

// TestSelectPrimaryIPv4_Empty asserts an empty candidate list is an error.
func TestSelectPrimaryIPv4_Empty(t *testing.T) {
	if _, err := selectPrimaryIPv4("x", nil); err == nil {
		t.Fatal("expected error for empty candidate list")
	}
}
