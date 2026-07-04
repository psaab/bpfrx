package vrrp

import (
	"encoding/binary"
	"net"
	"testing"
)

// refIPv4PseudoChecksum is an independent reference implementation of the RFC
// 5798 §5.2.8 IPv4 VRRP checksum. It is deliberately NOT the production
// vrrpIPv4Checksum so that a revert of the production pseudo-header code makes
// the assertions below go RED. The pseudo-header is: src(4) dst(4) zero(1)
// protocol(1)=112 vrrp-length(2), followed by the VRRP message (with the
// checksum field zeroed).
func refIPv4PseudoChecksum(src, dst net.IP, msg []byte) uint16 {
	src4, dst4 := src.To4(), dst.To4()
	ph := make([]byte, 12+len(msg))
	copy(ph[0:4], src4)
	copy(ph[4:8], dst4)
	ph[8] = 0
	ph[9] = 112
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(msg)))
	copy(ph[12:], msg)
	// Ensure the checksum field inside the copied message is zero.
	ph[12+6] = 0
	ph[12+7] = 0

	var sum uint32
	for i := 0; i+1 < len(ph); i += 2 {
		sum += uint32(ph[i])<<8 | uint32(ph[i+1])
	}
	if len(ph)%2 == 1 {
		sum += uint32(ph[len(ph)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// legacyIPv4Checksum is the VRRPv2-style checksum: ones-complement over the
// VRRP message only, with no pseudo-header. It reproduces the pre-#4100 xpf
// wire behavior so the dual-accept migration path can be exercised.
func legacyIPv4Checksum(msg []byte) uint16 {
	buf := make([]byte, len(msg))
	copy(buf, msg)
	buf[6] = 0
	buf[7] = 0
	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(buf[i])<<8 | uint32(buf[i+1])
	}
	if len(buf)%2 == 1 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// canonicalIPv4Advert builds a hand-constructed VRRPv3 IPv4 advertisement with
// the checksum field left zero. Callers fill in the checksum.
func canonicalIPv4Advert() []byte {
	msg := make([]byte, vrrpHeaderLen+4)
	msg[0] = (vrrpVersion << 4) | vrrpTypeAdvert // 0x31
	msg[1] = 1                                   // VRID
	msg[2] = 100                                 // priority
	msg[3] = 1                                   // address count
	binary.BigEndian.PutUint16(msg[4:6], 100)    // MaxAdvertInt = 100cs
	// checksum msg[6:8] left zero
	copy(msg[8:12], net.IPv4(10, 0, 0, 1).To4())
	return msg
}

// TestVRRPIPv4ChecksumRFC5798Vector confirms a canonical RFC 5798 IPv4 advert
// checksummed WITH the pseudo-header is accepted by ParseVRRPPacket. Goes RED
// on revert of the pseudo-header ADD to the parse path (which then only
// verifies the legacy no-pseudo-header checksum and rejects this packet).
func TestVRRPIPv4ChecksumRFC5798Vector(t *testing.T) {
	src := net.IPv4(192, 0, 2, 1)
	dst := net.IPv4(224, 0, 0, 18)

	msg := canonicalIPv4Advert()
	csum := refIPv4PseudoChecksum(src, dst, msg)
	binary.BigEndian.PutUint16(msg[6:8], csum)

	// Sanity: the pseudo-header checksum differs from the legacy one, so this
	// vector genuinely exercises the pseudo-header path (not an accidental
	// collision).
	if csum == legacyIPv4Checksum(msg) {
		t.Fatalf("pseudo-header and legacy checksums collide (0x%04x) — vector is not discriminating", csum)
	}

	parsed, err := ParseVRRPPacket(msg, false, src, dst)
	if err != nil {
		t.Fatalf("conformant RFC-5798 IPv4 advert rejected: %v", err)
	}
	if parsed.VRID != 1 || parsed.Priority != 100 {
		t.Fatalf("parsed fields wrong: vrid=%d prio=%d", parsed.VRID, parsed.Priority)
	}
	if len(parsed.IPAddresses) != 1 || !parsed.IPAddresses[0].Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("parsed addresses wrong: %v", parsed.IPAddresses)
	}
}

// TestVRRPIPv4MarshalUsesPseudoHeader confirms xpf's own marshalled IPv4 advert
// carries the RFC 5798 pseudo-header checksum (matches the independent
// reference) and round-trips through parse. Goes RED on revert of the
// pseudo-header ADD to Marshal (which then stores the legacy checksum).
func TestVRRPIPv4MarshalUsesPseudoHeader(t *testing.T) {
	src := net.IPv4(192, 0, 2, 1)
	dst := net.IPv4(224, 0, 0, 18)

	pkt := &VRRPPacket{
		VRID:         1,
		Priority:     100,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	data, err := pkt.Marshal(false, src, dst)
	if err != nil {
		t.Fatal(err)
	}

	got := binary.BigEndian.Uint16(data[6:8])
	want := refIPv4PseudoChecksum(src, dst, data)
	if got != want {
		t.Fatalf("marshalled IPv4 checksum = 0x%04x, want pseudo-header 0x%04x", got, want)
	}
	// It must NOT be the legacy no-pseudo-header value.
	if got == legacyIPv4Checksum(data) {
		t.Fatalf("marshalled IPv4 checksum is the legacy no-pseudo-header value 0x%04x", got)
	}

	if _, err := ParseVRRPPacket(data, false, src, dst); err != nil {
		t.Fatalf("round-trip parse of marshalled advert failed: %v", err)
	}
}

// TestVRRPIPv4ChecksumLegacyAccepted confirms the dual-accept migration path:
// a legacy (VRRPv2-style, no pseudo-header) IPv4 advert is still accepted so a
// rolling upgrade of a pure-xpf cluster does not split-brain. Goes RED on
// revert of the legacy fallback (parse becomes pseudo-header-only).
func TestVRRPIPv4ChecksumLegacyAccepted(t *testing.T) {
	src := net.IPv4(192, 0, 2, 1)
	dst := net.IPv4(224, 0, 0, 18)

	msg := canonicalIPv4Advert()
	binary.BigEndian.PutUint16(msg[6:8], legacyIPv4Checksum(msg))

	// Guard: this legacy advert would FAIL the pseudo-header check, so
	// acceptance can only come from the legacy fallback.
	if refIPv4PseudoChecksum(src, dst, msg) == binary.BigEndian.Uint16(msg[6:8]) {
		t.Fatal("legacy and pseudo-header checksums collide — not testing the fallback")
	}

	if _, err := ParseVRRPPacket(msg, false, src, dst); err != nil {
		t.Fatalf("legacy no-pseudo-header advert rejected (dual-accept broken): %v", err)
	}
}

// TestVRRPIPv4ChecksumRejectsCorrupt confirms a corrupt checksum still fails
// BOTH the pseudo-header and legacy checks.
func TestVRRPIPv4ChecksumRejectsCorrupt(t *testing.T) {
	src := net.IPv4(192, 0, 2, 1)
	dst := net.IPv4(224, 0, 0, 18)

	pkt := &VRRPPacket{
		VRID:         1,
		Priority:     100,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	data, err := pkt.Marshal(false, src, dst)
	if err != nil {
		t.Fatal(err)
	}
	data[6] ^= 0xFF // corrupt the checksum

	if _, err := ParseVRRPPacket(data, false, src, dst); err == nil {
		t.Fatal("corrupt IPv4 checksum was accepted")
	}
}

// TestVRRPIPv4MarshalRequiresAddresses confirms IPv4 marshal now requires
// src/dst (needed for the pseudo-header), mirroring the IPv6 leg.
func TestVRRPIPv4MarshalRequiresAddresses(t *testing.T) {
	pkt := &VRRPPacket{
		VRID:         1,
		Priority:     100,
		MaxAdvertInt: 100,
		IPAddresses:  []net.IP{net.IPv4(10, 0, 0, 1)},
	}
	if _, err := pkt.Marshal(false, nil, net.IPv4(224, 0, 0, 18)); err == nil {
		t.Fatal("expected error marshalling IPv4 advert without a source address")
	}
	if _, err := pkt.Marshal(false, net.IPv4(192, 0, 2, 1), nil); err == nil {
		t.Fatal("expected error marshalling IPv4 advert without a destination address")
	}
}
