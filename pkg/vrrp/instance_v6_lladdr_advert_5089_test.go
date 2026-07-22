package vrrp

import (
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

// TestSendPacketIPv6PrependsVirtualRouterLinkLocal asserts that an IPv6 VRRP
// advertisement carries the virtual router's link-local as the FIRST IPvX
// address in its payload, ahead of the configured global VIPs, and that the
// header "Count IPvX Addr" field includes it (#5089).
//
// RFC 5798 §5.2.9 defines the advertisement address list as "one or more IPvX
// address(es) that are associated with the virtual router" and §6.1 documents
// that for IPv6 the virtual router owns a link-local address; §5.1.1.2 further
// requires the source of an IPv6 advert to be that link-local. RFC 5798 §8.1.2
// (Backup send/receive) and the reference vSRX/keepalived-v3 wire format place
// the virtual router's link-local as address[0], followed by the remaining
// (global) addresses. Serializing only the global VIPs — as xpf did before
// #5089 — produced a payload whose address[0] was a global VIP, non-conformant
// and rejectable by strict peers.
//
// fail-on-revert: remove the srcIP prepend in sendPacketIPv6 and the serialized
// payload collapses to [VIP] — address[0] becomes the global VIP (not the
// link-local), the Count byte drops from 2 to 1, and the "address[0] == outer
// source" check fails. Every assertion below then goes RED.
func TestSendPacketIPv6PrependsVirtualRouterLinkLocal(t *testing.T) {
	const ifIndex = 9
	ll := net.ParseIP("fe80::abcd") // virtual-router link-local (getLocalIPv6)
	vip := net.ParseIP("2001:db8::1")
	if ll == nil || vip == nil {
		t.Fatal("bad test fixtures")
	}

	vi := newInstance(
		Instance{Interface: "reth0", GroupID: 3, Priority: 200,
			AdvertiseInterval: 1000,
			VirtualAddresses:  []string{"2001:db8::1/64"}},
		&net.Interface{Name: "reth0", Index: ifIndex},
		make(chan VRRPEvent, 1), nil,
	)

	// Make sendPacketIPv6 believe the IPv6 socket is open without a raw socket
	// (needs CAP_NET_RAW). The send seam captures the marshaled advert and the
	// control message the kernel would use to pin the outer source.
	vi.ipv6Conn = stubPacketConn{}
	vi.setLocalIPv6(ll)

	var gotData []byte
	var gotCM *ipv6.ControlMessage
	vi.ipv6Send = func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error {
		gotData = append([]byte(nil), data...)
		gotCM = cm
		return nil
	}

	// The caller (sendAdvert) builds pkt.IPAddresses from the configured global
	// VIPs only; the link-local prepend happens inside sendPacketIPv6.
	pkt := &VRRPPacket{
		VRID:         3,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{vip},
	}
	if err := vi.sendPacketIPv6(pkt); err != nil {
		t.Fatalf("sendPacketIPv6: %v", err)
	}
	if gotCM == nil || gotCM.Src == nil {
		t.Fatal("no pinned outer source captured")
	}

	// Count IPvX Addr wire byte (buf[3]) must include the prepended link-local:
	// 1 VIP + 1 link-local = 2.
	if len(gotData) < vrrpHeaderLen {
		t.Fatalf("advert too short: %d bytes", len(gotData))
	}
	if gotData[3] != 2 {
		t.Fatalf("Count IPvX Addr = %d, want 2 (link-local + 1 VIP) — "+
			"link-local not prepended (#5089)", gotData[3])
	}

	// Re-parse the advert exactly as a receiver would: outer source = the
	// pinned cmsg Src (also the checksum source). Payload length + count must
	// be self-consistent or ParseVRRPPacket errors.
	parsed, err := ParseVRRPPacket(gotData, true, gotCM.Src, net.ParseIP("ff02::12"))
	if err != nil {
		t.Fatalf("re-parse failed (count/length inconsistent?): %v", err)
	}
	if len(parsed.IPAddresses) != 2 {
		t.Fatalf("payload carries %d addresses, want 2 (link-local + VIP)",
			len(parsed.IPAddresses))
	}

	// RFC 5798: address[0] MUST be the virtual router's link-local, and it must
	// be the SAME address used as the outer/checksum source (getLocalIPv6).
	if !parsed.IPAddresses[0].Equal(ll) {
		t.Fatalf("payload address[0] = %v, want virtual-router link-local %v "+
			"(#5089: link-local must be FIRST)", parsed.IPAddresses[0], ll)
	}
	if !parsed.IPAddresses[0].Equal(gotCM.Src) {
		t.Fatalf("payload address[0] = %v != outer source %v — the first "+
			"advert address must equal the checksum/link-local source",
			parsed.IPAddresses[0], gotCM.Src)
	}
	// The configured global VIP follows the link-local.
	if !parsed.IPAddresses[1].Equal(vip) {
		t.Fatalf("payload address[1] = %v, want configured VIP %v",
			parsed.IPAddresses[1], vip)
	}
}

// TestSendPacketIPv6LinkLocalFirstWithMultipleVIPs confirms the prepend keeps
// the link-local at index 0 and preserves the configured VIP order behind it,
// with the Count field covering all of them (#5089).
func TestSendPacketIPv6LinkLocalFirstWithMultipleVIPs(t *testing.T) {
	const ifIndex = 9
	ll := net.ParseIP("fe80::5")
	vip1 := net.ParseIP("2001:db8::10")
	vip2 := net.ParseIP("2001:db8::20")

	vi := newInstance(
		Instance{Interface: "reth1", GroupID: 4, Priority: 150,
			AdvertiseInterval: 1000,
			VirtualAddresses:  []string{"2001:db8::10/64", "2001:db8::20/64"}},
		&net.Interface{Name: "reth1", Index: ifIndex},
		make(chan VRRPEvent, 1), nil,
	)
	vi.ipv6Conn = stubPacketConn{}
	vi.setLocalIPv6(ll)

	var gotData []byte
	var gotSrc net.IP
	vi.ipv6Send = func(data []byte, cm *ipv6.ControlMessage, dst net.Addr) error {
		gotData = append([]byte(nil), data...)
		if cm != nil {
			gotSrc = cm.Src
		}
		return nil
	}

	pkt := &VRRPPacket{
		VRID:         4,
		Priority:     150,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{vip1, vip2},
	}
	if err := vi.sendPacketIPv6(pkt); err != nil {
		t.Fatalf("sendPacketIPv6: %v", err)
	}

	if gotData[3] != 3 {
		t.Fatalf("Count IPvX Addr = %d, want 3 (link-local + 2 VIPs)", gotData[3])
	}
	parsed, err := ParseVRRPPacket(gotData, true, gotSrc, net.ParseIP("ff02::12"))
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	want := []net.IP{ll, vip1, vip2}
	if len(parsed.IPAddresses) != len(want) {
		t.Fatalf("payload carries %d addresses, want %d", len(parsed.IPAddresses), len(want))
	}
	for i, w := range want {
		if !parsed.IPAddresses[i].Equal(w) {
			t.Fatalf("payload address[%d] = %v, want %v (link-local first, then "+
				"configured VIP order)", i, parsed.IPAddresses[i], w)
		}
	}
}
