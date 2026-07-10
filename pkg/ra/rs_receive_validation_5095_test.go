// rs_receive_validation_5095_test.go — #5095.
//
// RFC 4861 §6.1.1 requires a router to silently discard a received Router
// Solicitation whose IP Hop Limit is not 255 (a value forwarding would have
// decremented, so 255 proves the RS originated on-link) or whose source is
// off-link. Before #5095 the RS receiver discarded the ICMPv6 control message
// and validated only the decoded message TYPE, so an off-link or spoofed RS
// (wrong hop limit / global source) was accepted and triggered a multicast RA
// (RA-injection / DoS surface). These tests pin the receive validation both at
// the predicate level and end-to-end through the sender's RS pipeline.
package ra

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

func TestValidRSReceiveRFC4861(t *testing.T) {
	hop := func(n int) *ipv6.ControlMessage { return &ipv6.ControlMessage{HopLimit: n} }
	cases := []struct {
		name string
		cm   *ipv6.ControlMessage
		src  string
		want bool
	}{
		{"hop255 link-local", hop(255), "fe80::2", true},
		{"hop255 unspecified", hop(255), "::", true},
		{"hop255 global source", hop(255), "2001:db8::1", false},
		{"hop255 ULA source", hop(255), "fc00::1", false},
		{"hop255 multicast source", hop(255), "ff02::1", false},
		{"hop254 link-local (off-link)", hop(254), "fe80::2", false},
		{"hop64 link-local (forwarded)", hop(64), "fe80::2", false},
		{"nil control message", nil, "fe80::2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validRSReceive(tc.cm, netip.MustParseAddr(tc.src))
			if got != tc.want {
				t.Fatalf("validRSReceive(%v, %s) = %v, want %v", tc.cm, tc.src, got, tc.want)
			}
		})
	}
}

// TestRSReceiveValidationEndToEnd drives the sender's real RS pipeline: an
// invalid RS (off-link hop limit) must NOT trigger an RA reply, while a valid RS
// (hop 255, link-local) does. fail-on-revert: reverting rsReceiver to skip
// validRSReceive makes the invalid RS reach the owner and trigger a reply within
// maxRSDelay, so the "no reply" assertion goes red.
func TestRSReceiveValidationEndToEnd(t *testing.T) {
	getConn, _ := installFakeListen(t)
	iface := &net.Interface{Name: "rs5095", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1}}
	s := newSender(testCfg("rs5095"), iface)
	if err := s.start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.stop()

	fc := waitConn(t, getConn, "rs5095")
	waitWrites(t, fc, startupBurstCount)

	// Push lastRA into the past so the RS rate-limit (minRAMulticastDelay) does
	// not itself suppress a reply — isolating the receive validation.
	s.setLastRA(time.Now().Add(-2 * minRAMulticastDelay))

	// An off-link RS (hop limit 254) from a link-local source: RFC 4861 §6.1.1
	// requires it be silently discarded. It must produce no RA reply.
	fc.injectRSRaw(&ipv6.ControlMessage{HopLimit: 254}, netip.MustParseAddr("fe80::2"))

	// Wait comfortably past maxRSDelay so a reply (if the RS were wrongly
	// accepted) would already have been written.
	time.Sleep(maxRSDelay + 300*time.Millisecond)
	if n := len(fc.snapshot()); n != startupBurstCount {
		t.Fatalf("off-link RS (hop-limit 254) triggered %d RA reply(ies); RFC 4861 §6.1.1 "+
			"requires it be silently discarded (#5095)", n-startupBurstCount)
	}

	// Contrast: a valid RS (hop 255, link-local) DOES trigger a reply — proving
	// the pipeline is live and it was the validation, not a dead receiver, that
	// dropped the off-link RS.
	fc.injectRS(netip.MustParseAddr("fe80::2"))
	waitWrites(t, fc, startupBurstCount+1)
}
