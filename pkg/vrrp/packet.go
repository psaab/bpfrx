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

// VRRPPacket represents a VRRPv3 advertisement packet (RFC 5798).
type VRRPPacket struct {
	VRID         uint8
	Priority     uint8
	MaxAdvertInt uint16 // centiseconds (default 100 = 1s)
	IPAddresses  []net.IP
}

// Marshal serializes a VRRPv3 advertisement packet.
// For IPv4, addresses are 4 bytes each; for IPv6, 16 bytes each.
// Checksum is computed over the VRRP data only (IPv4) or with
// a pseudo-header (IPv6).
func (p *VRRPPacket) Marshal(isIPv6 bool, srcIP, dstIP net.IP) ([]byte, error) {
	addrSize := 4
	if isIPv6 {
		addrSize = 16
	}

	count := len(p.IPAddresses)
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

	// Compute checksum
	if isIPv6 {
		csum := vrrpIPv6Checksum(srcIP.To16(), dstIP.To16(), buf)
		binary.BigEndian.PutUint16(buf[6:8], csum)
	} else {
		csum := onesComplementChecksum(buf)
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
		if onesComplementChecksum(data[:expectedLen]) != 0 {
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
	}, nil
}

// onesComplementChecksum computes the ones-complement checksum over data.
// Used for IPv4 VRRP (checksum over VRRP data only, no pseudo-header).
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
