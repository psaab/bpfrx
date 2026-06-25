package vrrp

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

// TestSendPacketIPv6PinsSourceViaPktInfo asserts that sendPacketIPv6 attaches
// an IPV6_PKTINFO control message whose Src equals the link-local address the
// pseudo-header checksum was computed over (getLocalIPv6()), and whose IfIndex
// is the VRRP interface index (#2644).
//
// fail-on-revert: if the cmsg is removed and the source is left to the kernel
// (RFC 6724 selection on the wildcard `::` socket), there is no pinned cm.Src
// to assert against — the captured control message would be nil and the
// "outer source matches checksum source" re-parse would have nothing to verify
// against. The equality + successful ParseVRRPPacket below is the gate.
func TestSendPacketIPv6PinsSourceViaPktInfo(t *testing.T) {
	const ifIndex = 7
	src := net.ParseIP("fe80::1")
	if src == nil {
		t.Fatal("bad test src")
	}

	vi := newInstance(
		Instance{Interface: "reth0", GroupID: 1, Priority: 200,
			AdvertiseInterval: 1000,
			VirtualAddresses:  []string{"2001:db8::1/64"}},
		&net.Interface{Name: "reth0", Index: ifIndex},
		make(chan VRRPEvent, 1), nil,
	)

	// Make sendPacketIPv6 believe the IPv6 socket is open without actually
	// opening a raw socket (requires CAP_NET_RAW). The send seam captures
	// the marshaled data and the control message.
	vi.ipv6Conn = stubPacketConn{}
	vi.setLocalIPv6(src)

	var gotData []byte
	var gotCM *ipv6.ControlMessage
	var gotDst net.Addr
	vi.ipv6Send = func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error {
		gotData = append([]byte(nil), data...)
		gotCM = cm
		gotDst = dst
		return nil
	}

	pkt := &VRRPPacket{
		VRID:         1,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.ParseIP("2001:db8::1")},
	}
	if err := vi.sendPacketIPv6(pkt); err != nil {
		t.Fatalf("sendPacketIPv6: %v", err)
	}

	if gotCM == nil {
		t.Fatal("no IPV6_PKTINFO control message attached: outer source left " +
			"to kernel selection -> checksum may mismatch (#2644)")
	}
	if gotCM.Src == nil || !gotCM.Src.Equal(src) {
		t.Fatalf("cmsg Src = %v, want checksum source %v", gotCM.Src, src)
	}
	if gotCM.IfIndex != ifIndex {
		t.Fatalf("cmsg IfIndex = %d, want %d", gotCM.IfIndex, ifIndex)
	}

	// The cmsg Src must equal the address sendPacketIPv6 fed to Marshal for
	// the pseudo-header checksum. Re-parse the captured advert using the
	// cmsg Src as the outer source — the receiver does exactly this and
	// would drop the advert on any mismatch. A successful parse proves the
	// outer source the kernel will stamp (cmsg.Src) matches the checksum.
	dstIP := net.ParseIP("ff02::12")
	if _, err := ParseVRRPPacket(gotData, true, gotCM.Src, dstIP); err != nil {
		t.Fatalf("checksum does not validate against cmsg Src %v: %v "+
			"(outer source != checksum source -> split-brain #2644)",
			gotCM.Src, err)
	}

	// Sanity: a DIFFERENT outer source must fail the checksum, proving the
	// checksum really is source-bound (otherwise the test is vacuous).
	other := net.ParseIP("fe80::2")
	if _, err := ParseVRRPPacket(gotData, true, other, dstIP); err == nil {
		t.Fatal("checksum validated against a different source — checksum is " +
			"not source-bound, test would not catch a mismatch")
	}

	if ipd, ok := gotDst.(*net.IPAddr); !ok || !ipd.IP.Equal(dstIP) {
		t.Fatalf("dst = %v, want %v", gotDst, dstIP)
	}
}

// stubPacketConn is a no-op net.PacketConn used only to make ipv6Conn non-nil
// in tests (sendPacketIPv6 early-returns when ipv6Conn == nil). All sends route
// through the vi.ipv6Send seam, never through this conn.
type stubPacketConn struct{}

func (stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (stubPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (stubPacketConn) Close() error                           { return nil }
func (stubPacketConn) LocalAddr() net.Addr                    { return nil }
func (stubPacketConn) SetDeadline(time.Time) error            { return nil }
func (stubPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (stubPacketConn) SetWriteDeadline(time.Time) error       { return nil }
