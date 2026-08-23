package vrrp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// VRRPv3 constants.
const (
	vrrpVersion    = 3
	vrrpTypeAdvert = 1
	vrrpProto      = 112

	// VRRPv3 header is 8 bytes (before IP addresses).
	vrrpHeaderLen = 8
)

// MinAdvertAddrCount / MaxAdvertAddrCount bound the number of virtual IP
// addresses a single VRRPv3 advertisement may carry. RFC 5798 §5.2.4 defines
// the "Count IPvX Addr" field as 8 bits, so at most 255 addresses fit and a
// valid advert carries at least one. Marshal writes this count straight onto
// the single wire byte (`buf[3] = uint8(count)`), so an unbounded address
// slice would truncate: 256 addresses wrap to Count 0, producing a
// fully-serialized 8+N-byte payload whose header claims zero addresses — every
// receiver then rejects (or misparses) the advert. Marshal range-checks the
// slice length against these bounds BEFORE serializing and refuses to build
// such a packet, mirroring the VRID guard (vrrp.go MinVRID/MaxVRID, #4573).
const (
	MinAdvertAddrCount = 1
	MaxAdvertAddrCount = 255
)

// VRRPPacket represents a VRRPv3 advertisement packet (RFC 5798).
type VRRPPacket struct {
	VRID         uint8
	Priority     uint8
	MaxAdvertInt uint16 // centiseconds (default 100 = 1s)
	IPAddresses  []net.IP
	SrcIP        net.IP // source IP of the sender (for RFC 5798 §6.4.3 tie-breaking)
}

// Marshal serializes a VRRPv3 advertisement packet.
// For IPv4, addresses are 4 bytes each; for IPv6, 16 bytes each.
// Per RFC 5798 §5.2.8 the checksum is computed over an upper-layer
// pseudo-header (source, destination, protocol 112, VRRP length) plus
// the VRRP message for BOTH families. This is a change from VRRPv2,
// which for IPv4 checksummed the VRRP message only (no pseudo-header).
// Both srcIP and dstIP are therefore required for IPv4 as well as IPv6.
func (p *VRRPPacket) Marshal(isIPv6 bool, srcIP, dstIP net.IP) ([]byte, error) {
	addrSize := 4
	if isIPv6 {
		addrSize = 16
	}

	count := len(p.IPAddresses)
	// Reject before serializing: the count is written to a single u8 wire byte
	// (buf[3]), so >255 addresses would narrow lossily (256→Count 0) and a
	// 0-address advert is meaningless per RFC 5798 §5.2.4. Surface the
	// misconfiguration instead of emitting an advert with a wrong Count.
	if count < MinAdvertAddrCount || count > MaxAdvertAddrCount {
		return nil, fmt.Errorf("VRRP advert address count %d out of range %d..%d",
			count, MinAdvertAddrCount, MaxAdvertAddrCount)
	}
	pktLen := vrrpHeaderLen + count*addrSize
	buf := make([]byte, pktLen)

	// Byte 0: version(4 bits) | type(4 bits)
	buf[0] = (vrrpVersion << 4) | vrrpTypeAdvert
	buf[1] = p.VRID
	buf[2] = p.Priority
	buf[3] = uint8(count)

	// MaxAdvertInt: top 4 bits reserved (0), bottom 12 bits = interval
	binary.BigEndian.PutUint16(buf[4:6], p.MaxAdvertInt&0x0FFF)

	// Checksum placeholder
	buf[6] = 0
	buf[7] = 0

	// IP addresses
	off := vrrpHeaderLen
	for _, ip := range p.IPAddresses {
		if isIPv6 {
			ip16 := ip.To16()
			if ip16 == nil {
				return nil, fmt.Errorf("invalid IPv6 address: %s", ip)
			}
			copy(buf[off:off+16], ip16)
		} else {
			ip4 := ip.To4()
			if ip4 == nil {
				return nil, fmt.Errorf("invalid IPv4 address: %s", ip)
			}
			copy(buf[off:off+4], ip4)
		}
		off += addrSize
	}

	// Compute checksum over the RFC 5798 §5.2.8 pseudo-header + VRRP message.
	if isIPv6 {
		src16, dst16 := srcIP.To16(), dstIP.To16()
		if src16 == nil || dst16 == nil {
			return nil, fmt.Errorf("IPv6 src/dst required for checksum")
		}
		csum := vrrpIPv6Checksum(src16, dst16, buf)
		binary.BigEndian.PutUint16(buf[6:8], csum)
	} else {
		src4, dst4 := srcIP.To4(), dstIP.To4()
		if src4 == nil || dst4 == nil {
			return nil, fmt.Errorf("IPv4 src/dst required for checksum")
		}
		csum := vrrpIPv4Checksum(src4, dst4, buf)
		binary.BigEndian.PutUint16(buf[6:8], csum)
	}

	return buf, nil
}

// ParseVRRPPacket parses and validates a VRRPv3 advertisement packet.
func ParseVRRPPacket(data []byte, isIPv6 bool, srcIP, dstIP net.IP) (*VRRPPacket, error) {
	if len(data) < vrrpHeaderLen {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	version := data[0] >> 4
	pktType := data[0] & 0x0F

	if version != vrrpVersion {
		return nil, fmt.Errorf("unsupported VRRP version: %d", version)
	}
	if pktType != vrrpTypeAdvert {
		return nil, fmt.Errorf("unsupported VRRP type: %d", pktType)
	}

	vrid := data[1]
	priority := data[2]
	count := int(data[3])
	maxAdvertInt := binary.BigEndian.Uint16(data[4:6]) & 0x0FFF

	addrSize := 4
	if isIPv6 {
		addrSize = 16
	}

	expectedLen := vrrpHeaderLen + count*addrSize
	if len(data) < expectedLen {
		return nil, fmt.Errorf("packet too short for %d addresses: have %d, need %d",
			count, len(data), expectedLen)
	}

	// Verify checksum
	if isIPv6 {
		if srcIP == nil || dstIP == nil {
			return nil, fmt.Errorf("IPv6 src/dst required for checksum")
		}
		// Zero out checksum field, compute, compare
		saved := binary.BigEndian.Uint16(data[6:8])
		data[6] = 0
		data[7] = 0
		expected := vrrpIPv6Checksum(srcIP.To16(), dstIP.To16(), data[:expectedLen])
		data[6] = byte(saved >> 8)
		data[7] = byte(saved)
		if saved != expected {
			return nil, fmt.Errorf("IPv6 checksum mismatch: got 0x%04x, want 0x%04x", saved, expected)
		}
	} else {
		// RFC 5798 §5.2.8 checksums IPv4 adverts over a pseudo-header +
		// the VRRP message (a change from VRRPv2, which had no
		// pseudo-header). Accept the conformant pseudo-header checksum
		// OR the legacy no-pseudo-header checksum: this lets a new node
		// interoperate with a conformant vSRX/Cisco/keepalived-v3 peer
		// AND with an old xpf node during a rolling upgrade. Emit only
		// the conformant form (Marshal). The legacy accept is a
		// migration aid that can be tightened to pseudo-header-only in a
		// future release once all peers are upgraded.
		saved := binary.BigEndian.Uint16(data[6:8])

		// Legacy check needs the stored checksum field in place: over the
		// VRRP message only, a correct checksum makes the sum fold to 0.
		legacyOK := onesComplementChecksum(data[:expectedLen]) == 0

		// Pseudo-header check: zero the field, recompute over the
		// pseudo-header + message, compare against the stored value.
		data[6] = 0
		data[7] = 0
		pseudoOK := false
		if src4, dst4 := srcIP.To4(), dstIP.To4(); src4 != nil && dst4 != nil {
			pseudoOK = vrrpIPv4Checksum(src4, dst4, data[:expectedLen]) == saved
		}
		data[6] = byte(saved >> 8)
		data[7] = byte(saved)

		if !pseudoOK && !legacyOK {
			return nil, fmt.Errorf("IPv4 checksum verification failed")
		}
	}

	// Parse addresses
	addrs := make([]net.IP, count)
	off := vrrpHeaderLen
	for i := 0; i < count; i++ {
		ip := make(net.IP, addrSize)
		copy(ip, data[off:off+addrSize])
		addrs[i] = ip
		off += addrSize
	}

	return &VRRPPacket{
		VRID:         vrid,
		Priority:     priority,
		MaxAdvertInt: maxAdvertInt,
		IPAddresses:  addrs,
		SrcIP:        srcIP,
	}, nil
}

// onesComplementChecksum computes the ones-complement checksum over data.
// Used to verify the legacy (VRRPv2-style, no pseudo-header) IPv4 checksum
// during a rolling-upgrade migration window — the conformant path uses
// vrrpIPv4Checksum.
func onesComplementChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// vrrpIPv4Checksum computes the VRRPv3 checksum for IPv4 with the RFC 5798
// §5.2.8 pseudo-header. VRRPv3 (unlike VRRPv2) covers a pseudo-header of the
// upper-layer source (4B) and destination (4B) addresses, a zero byte, the
// protocol number (112), and the 2-byte VRRP message length, followed by the
// VRRP message itself. src and dst must be 4-byte IPv4 slices.
func vrrpIPv4Checksum(src, dst net.IP, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header: source address (4 bytes)
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	// Pseudo-header: destination address (4 bytes)
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	// Pseudo-header: zero byte (high) + protocol 112 (low) = one 16-bit word.
	sum += vrrpProto
	// Pseudo-header: VRRP message length (2 bytes)
	sum += uint32(len(payload))

	// Payload (the VRRP message)
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// vrrpIPv6Checksum computes the VRRPv3 checksum for IPv6 with pseudo-header.
// Same algorithm as ICMPv6: pseudo-header (src, dst, length, next-header=112) + payload.
func vrrpIPv6Checksum(src, dst net.IP, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header: source address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
	}
	// Pseudo-header: destination address (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	// Pseudo-header: upper-layer packet length (4 bytes)
	plen := uint32(len(payload))
	sum += plen
	// Pseudo-header: next header = 112 (VRRP)
	sum += vrrpProto

	// Payload
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// MaxConfiguredVIPs returns the largest number of CONFIGURED virtual addresses
// of a single family that one VRRP instance can carry in a legal advertisement.
//
// It is DERIVED from MaxAdvertAddrCount rather than restated, because the two
// families do not have the same budget: RFC 5798 §5.2.9 / §6.1 require an IPv6
// advertisement to list the virtual router's link-local address FIRST, and
// sendPacketIPv6 (instance_send.go) prepends that link-local to the configured
// VIP slice immediately before Marshal. That prepended address occupies one of
// the 255 slots the u8 "Count IPvX Addr" field can express, so the IPv6 budget
// for CONFIGURED addresses is one less than the wire maximum. IPv4 has no
// prepend and spends the full budget on configured VIPs.
//
// Callers that need the wire-format limit itself (Marshal's own range check)
// use MaxAdvertAddrCount; callers that need "how many VIPs may an operator
// configure" use this. Keeping the subtraction in one place is what stops the
// validator and the builder from disagreeing by exactly the link-local.
func MaxConfiguredVIPs(isIPv6 bool) int {
	if isIPv6 {
		// One slot is reserved for the mandatory link-local prepend.
		return MaxAdvertAddrCount - 1
	}
	return MaxAdvertAddrCount
}
