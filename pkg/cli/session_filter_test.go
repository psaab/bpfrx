// #1827 PR-3: session-filter regression tests — source-nat-pool
// matching, network-order port comparison, and peer-forwarded clear
// requests that must never degrade to a peer clear-all.
package cli

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// natSrcU32 encodes an IPv4 translated source the way session dumps
// carry it (decoded for display via uint32ToIP).
func natSrcU32(s string) uint32 {
	return binary.NativeEndian.Uint32(net.ParseIP(s).To4())
}

func poolNets(t *testing.T, cidrs ...string) []*net.IPNet {
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

func TestSessionFilterSourceNATPoolV4(t *testing.T) {
	f := sessionFilter{
		snatPool:     "isp-a",
		snatPoolNets: poolNets(t, "203.0.113.10/32", "203.0.113.11/32"),
		snatPoolOK:   true,
	}
	key := dataplane.SessionKey{Protocol: 6}

	inPool := dataplane.SessionValue{
		Flags:    dataplane.SessFlagSNAT,
		NATSrcIP: natSrcU32("203.0.113.10"),
	}
	if !f.matchesV4(key, inPool) {
		t.Errorf("SNAT session translated to pool address should match")
	}

	otherPool := dataplane.SessionValue{
		Flags:    dataplane.SessFlagSNAT,
		NATSrcIP: natSrcU32("198.51.100.1"),
	}
	if f.matchesV4(key, otherPool) {
		t.Errorf("SNAT session translated outside the pool must not match")
	}

	// Non-SNAT session whose ORIGINAL source happens to sit inside the
	// pool range must not match — the filter is about the translated
	// source binding, not the wire tuple.
	noNAT := dataplane.SessionValue{NATSrcIP: natSrcU32("203.0.113.10")}
	if f.matchesV4(key, noNAT) {
		t.Errorf("session without SessFlagSNAT must not match source-nat-pool")
	}
}

func TestSessionFilterSourceNATPoolV6(t *testing.T) {
	f := sessionFilter{
		snatPool:     "isp-b-v6",
		snatPoolNets: poolNets(t, "2001:db8:b::/64"),
		snatPoolOK:   true,
	}
	key := dataplane.SessionKeyV6{Protocol: 6}

	var in dataplane.SessionValueV6
	in.Flags = dataplane.SessFlagSNAT
	copy(in.NATSrcIP[:], net.ParseIP("2001:db8:b::42").To16())
	if !f.matchesV6(key, in) {
		t.Errorf("v6 SNAT session translated to pool address should match")
	}

	var out dataplane.SessionValueV6
	out.Flags = dataplane.SessFlagSNAT
	copy(out.NATSrcIP[:], net.ParseIP("2001:db8:c::1").To16())
	if f.matchesV6(key, out) {
		t.Errorf("v6 SNAT session translated outside the pool must not match")
	}
}

// Session keys carry ports in network byte order; the filter holds
// host order. The comparison must byte-swap — before #1827 PR-3 it did
// not, so port-filtered show/clear matched only byte-palindromic ports.
func TestSessionFilterPortByteOrder(t *testing.T) {
	f := sessionFilter{dstPort: 5201} // 5201 = 0x1451; htons = 0x5114
	key := dataplane.SessionKey{
		Protocol: 6,
		DstPort:  ntohs(5201), // network byte order, as dumps store it
	}
	if !f.matchesV4(key, dataplane.SessionValue{}) {
		t.Errorf("destination-port 5201 should match a key holding htons(5201)")
	}
	f2 := sessionFilter{dstPort: 5202}
	if f2.matchesV4(key, dataplane.SessionValue{}) {
		t.Errorf("destination-port 5202 must not match htons(5201)")
	}

	keyV6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: ntohs(33000)}
	f3 := sessionFilter{srcPort: 33000}
	if !f3.matchesV6(keyV6, dataplane.SessionValueV6{}) {
		t.Errorf("v6 source-port 33000 should match a key holding htons(33000)")
	}
}

func TestSessionFilterValidate(t *testing.T) {
	ok := sessionFilter{snatPool: "isp-a", snatPoolOK: true}
	if err := ok.validate(); err != nil {
		t.Errorf("resolved pool: unexpected error %v", err)
	}
	bad := sessionFilter{snatPool: "nope"}
	if err := bad.validate(); err == nil {
		t.Errorf("unknown pool must be an error, not an inert filter")
	}
	badZone := sessionFilter{zoneName: "ghost"}
	if err := badZone.validate(); err == nil {
		t.Errorf("unresolvable zone must be an error, not an inert filter")
	}
}

// A filter expressed ONLY through interface/zone/nat-only/pool used to
// forward an EMPTY ClearSessionsRequest to the peer — which the peer
// interprets as clear-all. Every dimension must be carried.
func TestBuildPeerClearRequestCarriesAllFilters(t *testing.T) {
	f := &sessionFilter{
		zoneName: "untrust-a",
		iface:    "ge-0-0-2",
		natOnly:  true,
		snatPool: "isp-a",
	}
	req := buildPeerClearRequest(f)
	if req.Zone != "untrust-a" {
		t.Errorf("Zone not forwarded: %q", req.Zone)
	}
	if req.Interface != "ge-0-0-2" {
		t.Errorf("Interface not forwarded: %q", req.Interface)
	}
	if !req.NatOnly {
		t.Errorf("NatOnly not forwarded")
	}
	if req.SourceNatPool != "isp-a" {
		t.Errorf("SourceNatPool not forwarded: %q", req.SourceNatPool)
	}

	// hasFilter must also see each of these dimensions, or the local
	// node itself falls through to ClearAllSessions.
	for _, fl := range []sessionFilter{
		{zoneName: "untrust-a"},
		{iface: "ge-0-0-2"},
		{natOnly: true},
		{snatPool: "isp-a"},
	} {
		if !fl.hasFilter() {
			t.Errorf("hasFilter() = false for %+v — would clear-all", fl)
		}
	}
}
