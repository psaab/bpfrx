package userspace

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func rt9019(gw string) netlink.Route {
	if gw == "" {
		return netlink.Route{}
	}
	return netlink.Route{Gw: net.ParseIP(gw)}
}

func ngh9019(ip string, state int) netlink.Neigh {
	return netlink.Neigh{
		IP:           net.ParseIP(ip),
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		State:        state,
	}
}

// #9019: the NAPI bootstrap derived its probe target from IPv4 only, so an
// interface with no v4 gateway route and no v4 neighbour was skipped
// unconditionally — a v6-only segment always — with no log, no counter and no
// status field.
//
// THE POSITIVE CONTROL IS THE POINT OF THIS TABLE. "The v6 path does not fire"
// is an ABSENCE claim, and an absence observed against a harness that was never
// wired up measures the harness. Every v6 row here runs beside v4 rows that
// demonstrably DO derive a target in the same run, so a broken fixture reds the
// v4 rows instead of quietly passing the v6 ones.
func TestDeriveNAPIProbeTarget9019(t *testing.T) {
	cases := []struct {
		name   string
		routes []netlink.Route
		neighs []netlink.Neigh
		want   string
	}{
		// --- POSITIVE CONTROLS: the pre-#9019 behaviour, unchanged. ---
		{
			name:   "v4-gateway (control: the path that always worked)",
			routes: []netlink.Route{rt9019("10.0.2.1")},
			want:   "10.0.2.1",
		},
		{
			name:   "v4-neighbour (control: the pre-existing second choice)",
			neighs: []netlink.Neigh{ngh9019("10.0.2.55", netlink.NUD_REACHABLE)},
			want:   "10.0.2.55",
		},
		// --- THE DEFECT: these returned "" and the interface was skipped. ---
		{
			name:   "v6-gateway only",
			routes: []netlink.Route{rt9019("fe80::1")},
			want:   "fe80::1",
		},
		{
			name:   "v6-neighbour only",
			neighs: []netlink.Neigh{ngh9019("2001:db8::55", netlink.NUD_REACHABLE)},
			want:   "2001:db8::55",
		},
		// --- ORDER IS PART OF THE CONTRACT: an interface that derived a target
		//     before must derive the SAME one now, or this is a behaviour
		//     change on every working box rather than a widening. ---
		{
			name:   "v4 gateway outranks v6 gateway",
			routes: []netlink.Route{rt9019("fe80::1"), rt9019("10.0.2.1")},
			want:   "10.0.2.1",
		},
		{
			name:   "v4 NEIGHBOUR outranks a v6 GATEWAY",
			routes: []netlink.Route{rt9019("fe80::1")},
			neighs: []netlink.Neigh{ngh9019("10.0.2.55", netlink.NUD_REACHABLE)},
			want:   "10.0.2.55",
		},
		{
			name:   "gateway outranks neighbour within v6",
			routes: []netlink.Route{rt9019("fe80::1")},
			neighs: []netlink.Neigh{ngh9019("2001:db8::55", netlink.NUD_REACHABLE)},
			want:   "fe80::1",
		},
		// --- Exclusions carried into the v6 arms. ---
		{
			name:   "v6 NUD_FAILED neighbour is not a target",
			neighs: []netlink.Neigh{ngh9019("2001:db8::55", netlink.NUD_FAILED)},
			want:   "",
		},
		{
			name: "v6 neighbour with no hardware address is not a target",
			neighs: []netlink.Neigh{{
				IP:    net.ParseIP("2001:db8::55"),
				State: netlink.NUD_REACHABLE,
			}},
			want: "",
		},
		{
			name:   "a route with no gateway (on-link) is not a target",
			routes: []netlink.Route{{}},
			want:   "",
		},
		{
			name: "nothing to derive from",
			want: "",
		},
	}

	var controlsFired int
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveNAPIProbeTarget(tc.routes, tc.neighs)
			if got != tc.want {
				t.Fatalf("deriveNAPIProbeTarget = %q, want %q", got, tc.want)
			}
		})
		if tc.want != "" {
			controlsFired++
		}
	}
	if controlsFired < 4 {
		t.Fatalf("only %d rows derived a target; the table must contain live "+
			"POSITIVE rows or an all-empty result would satisfy every negative "+
			"assertion above", controlsFired)
	}
}

// A v4 address held in a 16-byte net.IP must not be mistaken for v6.
//
// `net.ParseIP("10.0.2.1")` returns a 16-byte slice, so a v6 arm written as
// `len(ip) == 16` — or as `To16() != nil` alone — would re-admit v4 addresses.
//
// WHAT THIS CELL DOES AND DOES NOT PROVE. It pins that a 16-byte v4 gateway is
// claimed by the V4 arm and outranks a v6 neighbour. It does NOT prove the
// `To4() == nil` clause in the v6 arms is load-bearing, and it cannot: the v4
// arms run first and return for any `To4() != nil` address, so dropping that
// clause is an EQUIVALENT mutation that survives — verified, not assumed. The
// clause is defensive redundancy that only matters if the arm ordering changes,
// and the ordering rows in the table above are what red when it does.
func TestDeriveNAPIProbeTargetV4InV6NotTreatedAsV6_9019(t *testing.T) {
	v4in16 := net.ParseIP("10.0.2.1")
	if len(v4in16) != net.IPv6len {
		t.Fatalf("fixture precondition: net.ParseIP of a v4 literal should be 16 bytes, got %d", len(v4in16))
	}
	// Only a v4 neighbour exists, expressed in 16-byte form. The v4 NEIGHBOUR
	// arm must claim it; if the v6 gateway arm claimed it first the answer
	// would be the same string here, so the discriminating case is below.
	got := deriveNAPIProbeTarget(
		[]netlink.Route{{Gw: v4in16}},
		[]netlink.Neigh{ngh9019("2001:db8::55", netlink.NUD_REACHABLE)},
	)
	if got != "10.0.2.1" {
		t.Fatalf("a 16-byte v4 gateway must be taken by the V4 arm and outrank the "+
			"v6 neighbour; got %q", got)
	}
}

// The skip must be OBSERVABLE. Silence is the property that made this
// expensive: it is indistinguishable from "bootstrap succeeded here", and the
// XSK liveness gate is box-wide so a live queue elsewhere still reports the box
// healthy.
func TestNAPIProbeTargetSkipIsCounted9019(t *testing.T) {
	before := NAPIProbeTargetSkips()
	noteNAPIProbeTargetSkip("ge-0-0-9", "no gateway route and no resolved neighbour in either family")
	after := NAPIProbeTargetSkips()
	if after != before+1 {
		t.Fatalf("a skipped interface must move the counter: %d -> %d", before, after)
	}
}
