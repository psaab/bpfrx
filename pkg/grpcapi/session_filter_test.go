// #1827 PR-3: server-side session-filter tests — source-nat-pool
// predicate and operator-input validation (unknown pool must fail the
// RPC instead of matching nothing / clearing everything).
package grpcapi

import (
	"encoding/binary"
	"net"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/dataplane"
)

func grpcPoolNets(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%s): %v", c, err)
		}
		nets = append(nets, n)
	}
	return nets
}

func TestServerSessionFilterSourceNATPool(t *testing.T) {
	f := &sessionFilter{
		snatPool:     "isp-a",
		snatPoolNets: grpcPoolNets(t, "203.0.113.0/29"),
		snatPoolOK:   true,
	}
	key := dataplane.SessionKey{Protocol: 6}

	in := dataplane.SessionValue{
		Flags:    dataplane.SessFlagSNAT,
		NATSrcIP: binary.NativeEndian.Uint32(net.ParseIP("203.0.113.4").To4()),
	}
	if !f.matchV4(key, in) {
		t.Errorf("SNAT session translated into the pool should match")
	}

	out := dataplane.SessionValue{
		Flags:    dataplane.SessFlagSNAT,
		NATSrcIP: binary.NativeEndian.Uint32(net.ParseIP("198.51.100.4").To4()),
	}
	if f.matchV4(key, out) {
		t.Errorf("SNAT session translated outside the pool must not match")
	}

	noNAT := dataplane.SessionValue{
		NATSrcIP: binary.NativeEndian.Uint32(net.ParseIP("203.0.113.4").To4()),
	}
	if f.matchV4(key, noNAT) {
		t.Errorf("non-SNAT session must not match source-nat-pool")
	}

	var v6val dataplane.SessionValueV6
	v6val.Flags = dataplane.SessFlagSNAT
	copy(v6val.NATSrcIP[:], net.ParseIP("2001:db8:b::1").To16())
	f6 := &sessionFilter{
		snatPool:     "isp-b-v6",
		snatPoolNets: grpcPoolNets(t, "2001:db8:b::/64"),
		snatPoolOK:   true,
	}
	if !f6.matchV6(dataplane.SessionKeyV6{Protocol: 6}, v6val) {
		t.Errorf("v6 SNAT session translated into the pool should match")
	}
}

// Numeric protocol filters must match (protoName(47) renders "gre",
// so a pure name comparison fails numeric operator input — AGY r1
// Finding 4).
func TestProtoFilterMatches(t *testing.T) {
	for _, tc := range []struct {
		p      uint8
		filter string
		want   bool
	}{
		{6, "tcp", true},
		{6, "TCP", true},
		{6, "udp", false},
		{58, "icmpv6", true},
		{47, "gre", true},
		{47, "47", true},
		{89, "89", true},
		{89, "88", false},
		{6, "6", true},
	} {
		if got := protoFilterMatches(tc.p, tc.filter); got != tc.want {
			t.Errorf("protoFilterMatches(%d, %q) = %v, want %v", tc.p, tc.filter, got, tc.want)
		}
	}
}

// Invalid prefix/port inputs must fail validate() — they bypass the
// no-filter clear-all guard (the request LOOKS filtered) while a
// silently-zeroed predicate would match every session, turning a
// filtered ClearSessions into clear-all (Codex r2 Critical).
func TestServerSessionFilterInvalidInput(t *testing.T) {
	if _, err := parseSessionPrefix("10.0.0.300"); err == nil {
		t.Errorf("parseSessionPrefix(10.0.0.300) should fail")
	}
	if _, err := parseSessionPrefix("not-a-prefix"); err == nil {
		t.Errorf("parseSessionPrefix(not-a-prefix) should fail")
	}
	if n, err := parseSessionPrefix("10.0.0.1"); err != nil || n == nil {
		t.Errorf("parseSessionPrefix(10.0.0.1) = %v, %v; want host net", n, err)
	}
	if n, err := parseSessionPrefix("2001:db8::1"); err != nil || n == nil {
		t.Errorf("parseSessionPrefix(2001:db8::1) = %v, %v; want host net", n, err)
	}

	f := &sessionFilter{}
	f.setInputErr(status.Errorf(codes.InvalidArgument, "invalid source prefix"))
	if err := f.validate(); err == nil {
		t.Errorf("validate() must surface inputErr")
	}
}

func TestServerSessionFilterValidate(t *testing.T) {
	ok := &sessionFilter{snatPool: "isp-a", snatPoolOK: true}
	if err := ok.validate(); err != nil {
		t.Errorf("resolved pool: unexpected error %v", err)
	}
	bad := &sessionFilter{snatPool: "ghost"}
	if err := bad.validate(); err == nil {
		t.Errorf("unknown pool must fail validation — an inert filter on the clear path is dangerous")
	}
	none := &sessionFilter{}
	if err := none.validate(); err != nil {
		t.Errorf("empty filter: unexpected error %v", err)
	}
}
