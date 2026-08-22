package userspace

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

// #6598: buildFabricPeerMAC is the LIVE fabric peer-MAC resolver — its result
// becomes FabricSnapshot.PeerMAC and reaches the dataplane as the cross-chassis
// redirect destination. It used to accept the first address-matched entry with
// any non-nil HardwareAddr, checking neither the NUD state nor the address
// length, which made it laxer than refreshFabricFwd, the path whose result is
// NOT consulted.

func mustMAC6598(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return mac
}

const (
	peerIP6598   = "10.99.0.2"
	staleMAC6598 = "02:bf:72:cc:00:01" // the MAC the peer used to own
	freshMAC6598 = "02:bf:72:cc:00:02" // the MAC it owns now
)

func TestFabricPeerMACRejectsStaleAndMalformed_6598(t *testing.T) {
	ip := net.ParseIP(peerIP6598)
	other := net.ParseIP("10.99.0.3")

	cases := []struct {
		name   string
		neighs []netlink.Neigh
		want   string
	}{{
		// The realistic trigger: the peer's fabric NIC MAC changed (RETH
		// virtual-MAC reprogramming does link DOWN -> set MAC -> link UP), the
		// entry went FAILED, and it still carries the old lladdr.
		name: "NUD_FAILED with a stale lladdr is not selected",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, staleMAC6598), State: netlink.NUD_FAILED},
		},
		want: "",
	}, {
		name: "NUD_INCOMPLETE is not selected",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, staleMAC6598), State: netlink.NUD_INCOMPLETE},
		},
		want: "",
	}, {
		name: "NUD_NONE (state 0) is not selected",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, staleMAC6598), State: 0},
		},
		want: "",
	}, {
		name: "a non-6-byte hardware address is not selected",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: net.HardwareAddr{0x02, 0xbf, 0x72}, State: netlink.NUD_REACHABLE},
		},
		want: "",
	}, {
		name: "an over-long hardware address is not selected",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, "02:00:00:00:00:00:00:01"), State: netlink.NUD_REACHABLE},
		},
		want: "",
	}, {
		// The whole point: a stale entry must not shadow a usable one, whatever
		// order netlink returns them in.
		name: "a stale entry ahead of a usable one does not win",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, staleMAC6598), State: netlink.NUD_FAILED},
			{IP: ip, HardwareAddr: mustMAC6598(t, freshMAC6598), State: netlink.NUD_REACHABLE},
		},
		want: freshMAC6598,
	}, {
		name: "a different address never answers for the peer",
		neighs: []netlink.Neigh{
			{IP: other, HardwareAddr: mustMAC6598(t, freshMAC6598), State: netlink.NUD_REACHABLE},
		},
		want: "",
	}, {
		name: "NUD_STALE is usable — the kernel still believes the address",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, freshMAC6598), State: netlink.NUD_STALE},
		},
		want: freshMAC6598,
	}, {
		name: "NUD_PERMANENT is usable",
		neighs: []netlink.Neigh{
			{IP: ip, HardwareAddr: mustMAC6598(t, freshMAC6598), State: netlink.NUD_PERMANENT},
		},
		want: freshMAC6598,
	}, {
		name:   "no entries at all resolves to nothing",
		neighs: nil,
		want:   "",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			if mac := selectFabricPeerMAC(tc.neighs, ip); mac != nil {
				got = mac.String()
			}
			if got != tc.want {
				t.Errorf("selectFabricPeerMAC = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFabricNeighUsableStatePartition_6598 pins the two halves of the predicate
// independently, so a change that drops either check is caught even if the
// other still rejects the case.
func TestFabricNeighUsableStatePartition_6598(t *testing.T) {
	good := mustMAC6598(t, freshMAC6598)

	usable := []struct {
		name  string
		state uint16
	}{
		{"REACHABLE", netlink.NUD_REACHABLE},
		{"STALE", netlink.NUD_STALE},
		{"PERMANENT", netlink.NUD_PERMANENT},
		{"DELAY", netlink.NUD_DELAY},
		{"PROBE", netlink.NUD_PROBE},
	}
	unusable := []struct {
		name  string
		state uint16
	}{
		{"NONE", 0},
		{"INCOMPLETE", netlink.NUD_INCOMPLETE},
		{"FAILED", netlink.NUD_FAILED},
		{"NOARP", netlink.NUD_NOARP},
	}
	if len(usable) == 0 || len(unusable) == 0 {
		t.Fatal("state partition is empty; the assertions below would be vacuous")
	}

	for _, s := range usable {
		if !FabricNeighUsable(netlink.Neigh{HardwareAddr: good, State: int(s.state)}) {
			t.Errorf("NUD_%s with a 6-byte MAC should be usable for forwarding", s.name)
		}
		// Same state, bad length: the length check must reject on its own.
		short := netlink.Neigh{HardwareAddr: net.HardwareAddr{1, 2, 3}, State: int(s.state)}
		if FabricNeighUsable(short) {
			t.Errorf("NUD_%s with a 3-byte MAC must be rejected on length", s.name)
		}
	}
	for _, s := range unusable {
		// Same length, bad state: the state check must reject on its own.
		if FabricNeighUsable(netlink.Neigh{HardwareAddr: good, State: int(s.state)}) {
			t.Errorf("NUD_%s must be rejected on state even with a valid 6-byte MAC", s.name)
		}
	}
}
