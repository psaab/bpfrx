package routing

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestRouteToEntryRejectDiscard proves the kernel-FIB reader distinguishes
// a `route <p> reject` (installed as RTN_UNREACHABLE by FRR, #5298) from a
// `discard` (RTN_BLACKHOLE) and from a directly-connected route. Before
// #5410 only RTN_BLACKHOLE mapped to "discard"; an RTN_UNREACHABLE reject
// route fell through to the else branch and rendered as "direct" — the
// bug. Reverting the routes.go RTN_UNREACHABLE mapping makes the reject
// case render "direct" — RED on revert. The discard and connected cases
// pin the existing behavior is unchanged.
func TestRouteToEntryRejectDiscard(t *testing.T) {
	rr := &routeReader{ops: &fakeRouteLister{byIndex: map[int]string{}}}

	cases := []struct {
		name     string
		rtType   int
		wantNext string
	}{
		{"reject", unix.RTN_UNREACHABLE, "reject"},
		{"discard", unix.RTN_BLACKHOLE, "discard"},
		{"connected", unix.RTN_UNICAST, "direct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dst, _ := net.ParseCIDR("10.7.0.0/24")
			route := netlink.Route{
				Dst:      dst,
				Type:     tc.rtType,
				Protocol: netlink.RouteProtocol(unix.RTPROT_STATIC),
				Priority: 5,
			}
			entry := rr.routeToEntry(route, netlink.FAMILY_V4)
			if entry.NextHop != tc.wantNext {
				t.Errorf("%s route: NextHop = %q, want %q", tc.name, entry.NextHop, tc.wantNext)
			}
			if len(entry.NextHops) != 0 {
				t.Errorf("%s route: NextHops = %+v, want empty", tc.name, entry.NextHops)
			}
		})
	}
}
