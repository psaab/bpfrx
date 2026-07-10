package cli

import "testing"

// TestPeerEndpointBracketsIPv6 pins #4909: the peer fabric dial target must
// bracket IPv6 literals. The pre-fix fmt.Sprintf("%s:%d") built
// "2001:db8::2:50051" (no brackets), an unparseable gRPC/TCP target that broke
// cluster CLI reachability on an IPv6 fabric.
//
// RED on revert: restore fmt.Sprintf("%s:%d") and the IPv6 case yields
// "2001:db8::2:50051", failing the expected bracketed form.
func TestPeerEndpointBracketsIPv6(t *testing.T) {
	cases := []struct {
		ip   string
		port int
		want string
	}{
		{"2001:db8::2", 50051, "[2001:db8::2]:50051"},
		{"fe80::1", 50051, "[fe80::1]:50051"},
		{"10.0.0.2", 50051, "10.0.0.2:50051"},
		{"192.168.1.1", 8080, "192.168.1.1:8080"},
	}
	for _, tc := range cases {
		if got := peerEndpoint(tc.ip, tc.port); got != tc.want {
			t.Errorf("peerEndpoint(%q, %d) = %q, want %q", tc.ip, tc.port, got, tc.want)
		}
	}
}
