package logging

import "testing"

// TestProtoNameSSOT pins the security event-log (RT_FLOW / ring buffer)
// protocol rendering to the appid.ProtocolName SSOT (#3040). Before #3040 the
// helper carried a local tcp/udp/icmp/icmpv6 map, so GRE(47)/ESP(50)/IPIP(4)/
// IPv6(41) sessions rendered NUMERIC while REST and gRPC (already on the SSOT
// via #2949/#3037) rendered them named. Reverting protoName to the 4-protocol
// set turns the gre/esp/ipip/ipv6 rows RED.
//
// Casing contract: this surface has always rendered upper-case (TCP/UDP/ICMP)
// with ICMPv6 keeping its mixed-case spelling, and unknown protocols fall back
// to the numeric form. The new named protocols follow the same upper-case rule.
func TestProtoNameSSOT(t *testing.T) {
	cases := []struct {
		proto uint8
		want  string
	}{
		{6, "TCP"},
		{17, "UDP"},
		{1, "ICMP"},
		{58, "ICMPv6"}, // historical mixed-case preserved (trace contract)
		{47, "GRE"},    // #3040: was "47" before SSOT routing
		{50, "ESP"},    // #3040: was "50"
		{4, "IPIP"},    // #3040: was "4"
		{41, "IPV6"},   // #3040: was "41"
		{99, "99"},     // unknown -> numeric fallback preserved
		{0, "0"},
	}
	for _, c := range cases {
		if got := protoName(c.proto); got != c.want {
			t.Errorf("protoName(%d) = %q, want %q", c.proto, got, c.want)
		}
	}
}
