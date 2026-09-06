package vrrp

import (
	"net"
	"testing"
)

// advertInstance9039 builds an instance advertising every advertiseMS.
func advertInstance9039(t *testing.T, advertiseMS int) *vrrpInstance {
	t.Helper()
	return newInstance(Instance{
		Interface:         "xpf-9039",
		GroupID:           42,
		Priority:          200,
		AdvertiseInterval: advertiseMS,
		GARPCount:         3,
		VirtualAddresses:  []string{"10.0.0.254/24"},
	}, &net.Interface{Name: "xpf-9039"}, nil, nil)
}

// wireMaxAdvert9039 returns the MaxAdvertInt a single sendAdvert put on the
// wire, observed through the production send seam.
func wireMaxAdvert9039(t *testing.T, advertiseMS int) uint16 {
	t.Helper()
	vi := advertInstance9039(t, advertiseMS)
	var seen uint16
	var sawIt bool
	prev := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
		seen, sawIt = pkt.MaxAdvertInt, true
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })
	vi.sendAdvert(200)
	if !sawIt {
		t.Fatal("sendAdvert emitted no packet; the fixture measures nothing")
	}
	return seen
}

// #9039: the Max Advert Int field is 12 bits of centiseconds and packet.go
// masks it with 0x0FFF. An over-range interval therefore did not lose
// precision, it WRAPPED — and a small Max Advert Int tells the peer to expect
// adverts far more often than this instance sends them, so the peer's
// master-down window expires while a healthy master is simply between adverts.
//
// The conversion now saturates. Saturating is the safe direction: too large a
// value on the wire makes a peer notice a real failure late, recovered by the
// next advert; too small a value makes it declare a LIVE master dead.
func TestOverRangeAdvertIntervalSaturatesOnTheWire9039(t *testing.T) {
	for _, tc := range []struct {
		name string
		ms   int
		want uint16
	}{
		// REFERENCE ARM: ordinary values must be untouched. Without these, a
		// clamp hardwired to 0x0FFF would satisfy every row below.
		{"default 30ms", 30, 3},
		{"1 second", 1000, 100},
		{"largest encodable", 40950, 0x0FFF},
		// THE DEFECT. 700000 ms is 70000 cs; uint16 truncation gives 4464 and
		// the 0x0FFF mask gives 368 cs = 3.68 s, while the local timer really
		// does advertise every 700 s.
		{"aliased to 3.68s before the fix", 700000, 0x0FFF},
		// The first value past the encodable range: without the clamp this is
		// 4096 & 0x0FFF = 0, i.e. "expect an advert immediately".
		{"first value past the range", 40960, 0x0FFF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wireMaxAdvert9039(t, tc.ms); got != tc.want {
				t.Errorf("%d ms advertised MaxAdvertInt %d cs, want %d cs", tc.ms, got, tc.want)
			}
		})
	}
}

// The mask must never see a value it would change. This is the invariant the
// clamp exists to hold, stated independently of any particular input: whatever
// reaches packet.go must already fit in 12 bits, so masking is a no-op rather
// than a silent rewrite.
func TestWireValueNeverNeedsTheMask9039(t *testing.T) {
	for _, ms := range []int{30, 1000, 40950, 40960, 700000, 1 << 30} {
		got := wireMaxAdvert9039(t, ms)
		if got&0x0FFF != got {
			t.Errorf("%d ms produced MaxAdvertInt %d, which the 0x0FFF mask in "+
				"packet.go would rewrite to %d — the clamp is meant to make that "+
				"mask a no-op", ms, got, got&0x0FFF)
		}
	}
}
