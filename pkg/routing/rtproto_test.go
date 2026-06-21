package routing

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestRtProtoName asserts that each kernel rtnetlink rtm_protocol value
// maps to the xpf protocol name shown by "show route" (#2127). The
// inputs use the named unix.RTPROT_* constants so the test stays correct
// if the constant numbers ever change. The cases are non-tautological:
// against pre-#2127 code, RTPROT_ISIS yielded the literal "187",
// RTPROT_ZEBRA yielded "ospf", and RTPROT_BIRD yielded "isis".
func TestRtProtoName(t *testing.T) {
	tests := []struct {
		name  string
		proto int
		want  string
	}{
		// Correct mappings (must not regress).
		{"redirect", unix.RTPROT_REDIRECT, "redirect"},
		{"kernel->connected", unix.RTPROT_KERNEL, "connected"},
		{"boot->dhcp", unix.RTPROT_BOOT, "dhcp"},
		{"static", unix.RTPROT_STATIC, "static"},
		{"dhcp", unix.RTPROT_DHCP, "dhcp"},
		{"bgp", unix.RTPROT_BGP, "bgp"},
		{"ospf", unix.RTPROT_OSPF, "ospf"},
		{"rip", unix.RTPROT_RIP, "rip"},

		// FRR staticd installs routes as RTPROT_ZSTATIC=196, mapped to
		// "static". This arm pre-dates #2127 and must be preserved (the
		// kernel UAPI RTPROT_STATIC=4 above is a different value).
		{"frr-zstatic-196", rtprotZStatic, "static"},

		// The #2127 fixes.
		{"isis-187", unix.RTPROT_ISIS, "isis"}, // was the literal "187"

		// RTPROT_ZEBRA(11) is FRR's ZEBRA_ROUTE_TABLE/NHG marker, not a
		// named xpf protocol, so it falls through to the numeric string.
		// Pre-#2127 it was wrongly mapped to "ospf".
		{"zebra-11-falls-through", unix.RTPROT_ZEBRA, "11"},

		// BIRD(12) is not emitted by FRR; fall through to numeric.
		// Pre-#2127 it was wrongly mapped to "isis".
		{"bird-12-falls-through", unix.RTPROT_BIRD, "12"},

		// Genuinely unknown protocol byte.
		{"unknown-250", 250, "250"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rtProtoName(netlink.RouteProtocol(tc.proto))
			if got != tc.want {
				t.Errorf("rtProtoName(%d) = %q, want %q", tc.proto, got, tc.want)
			}
		})
	}
}

// TestRtProtoNameFeedsFormatters proves the end-to-end #2127 fix: the
// name rtProtoName produces for IS-IS routes drives the Junos display
// helpers to "I" (terse) and "IS-IS" (detail/summary), instead of the
// pre-fix "?" / "187".
func TestRtProtoNameFeedsFormatters(t *testing.T) {
	name := rtProtoName(netlink.RouteProtocol(unix.RTPROT_ISIS))
	if got := protoTag(name); got != "I" {
		t.Errorf("protoTag(rtProtoName(RTPROT_ISIS)) = %q, want %q", got, "I")
	}
	if got := junosProtoName(name); got != "IS-IS" {
		t.Errorf("junosProtoName(rtProtoName(RTPROT_ISIS)) = %q, want %q", got, "IS-IS")
	}
}
