package cluster

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// SendGratuitousARP sends gratuitous ARP replies on the specified interface
// for the given IP address. Count specifies how many to send (with 100ms gaps).
func SendGratuitousARP(iface string, ip net.IP, count int) error {
	if count <= 0 {
		count = 1
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	pkt := buildGratuitousARP(ifi.HardwareAddr, ip4)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	for i := 0; i < count; i++ {
		if err := unix.Sendto(fd, pkt, 0, &addr); err != nil {
			return fmt.Errorf("sendto: %w", err)
		}
		if i < count-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	slog.Info("cluster: sent gratuitous ARP",
		"interface", iface, "ip", ip4.String(), "count", count)
	return nil
}

// buildGratuitousARP constructs a raw Ethernet+ARP gratuitous reply packet.
func buildGratuitousARP(mac net.HardwareAddr, ip net.IP) []byte {
	pkt := make([]byte, 42) // 14 ethernet + 28 ARP

	// Ethernet header
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst: broadcast
	copy(pkt[6:12], mac)                                         // src: our MAC
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_ARP)       // ethertype

	// ARP header
	binary.BigEndian.PutUint16(pkt[14:16], 1)    // hardware type: Ethernet
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // protocol type: IPv4
	pkt[18] = 6                                     // hardware addr len
	pkt[19] = 4                                     // protocol addr len
	binary.BigEndian.PutUint16(pkt[20:22], 2)      // opcode: ARP reply

	// Sender hardware + protocol address
	copy(pkt[22:28], mac)
	copy(pkt[28:32], ip.To4())

	// Target hardware + protocol address (broadcast + our IP for GARP)
	copy(pkt[32:38], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[38:42], ip.To4())

	return pkt
}

// SendGratuitousIPv6 sends unsolicited ICMPv6 Neighbor Advertisements on the
// specified interface for the given IPv6 address. This is the IPv6 equivalent
// of gratuitous ARP — it updates neighbor caches on the LAN after failover.
func SendGratuitousIPv6(iface string, ip net.IP, count int) error {
	if count <= 0 {
		count = 1
	}

	ip6 := ip.To16()
	if ip6 == nil || ip6.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %s", ip)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	pkt := buildUnsolicitedNA(ifi.HardwareAddr, ip6)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_IPV6)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer unix.Close(fd)

	addr := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IPV6),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	// IPv6 all-nodes multicast MAC: 33:33:00:00:00:01
	copy(addr.Addr[:], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})

	for i := 0; i < count; i++ {
		if err := unix.Sendto(fd, pkt, 0, &addr); err != nil {
			return fmt.Errorf("sendto: %w", err)
		}
		if i < count-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	slog.Info("cluster: sent unsolicited IPv6 NA",
		"interface", iface, "ip", ip6.String(), "count", count)
	return nil
}

// buildUnsolicitedNA constructs a raw Ethernet + IPv6 + ICMPv6 Neighbor
// Advertisement packet. The NA is sent to the all-nodes multicast address
// (ff02::1) with Override and Solicited flags cleared per RFC 4861 §7.2.6
// (unsolicited NA). Includes Target Link-Layer Address option.
func buildUnsolicitedNA(mac net.HardwareAddr, ip net.IP) []byte {
	// 14 Ethernet + 40 IPv6 + 24 ICMPv6 NA (8 hdr + 16 target) + 8 TLLA option = 86
	pkt := make([]byte, 86)

	// --- Ethernet header (14 bytes) ---
	// Dst: IPv6 all-nodes multicast MAC 33:33:00:00:00:01
	copy(pkt[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(pkt[6:12], mac)
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_IPV6)

	// --- IPv6 header (40 bytes) ---
	pkt[14] = 0x60 // Version 6, TC=0
	// pkt[15:18] = 0 (TC low + Flow Label)
	binary.BigEndian.PutUint16(pkt[18:20], 32) // Payload Length: ICMPv6 NA(24) + TLLA option(8)
	pkt[20] = 58                                // Next Header: ICMPv6
	pkt[21] = 255                               // Hop Limit
	// Source: our IP
	copy(pkt[22:38], ip.To16())
	// Destination: ff02::1 (all-nodes multicast)
	pkt[38] = 0xff
	pkt[39] = 0x02
	// pkt[40:52] = 0
	pkt[53] = 0x01

	// --- ICMPv6 Neighbor Advertisement (32 bytes) ---
	pkt[54] = 136  // Type: Neighbor Advertisement
	pkt[55] = 0    // Code: 0
	// pkt[56:58] = checksum (filled below)
	// Flags: Override=1, Router=0, Solicited=0
	pkt[58] = 0x20 // Override flag (bit 29, byte offset 0 bit 5)
	// pkt[59:62] = 0 (reserved)
	// Target address
	copy(pkt[62:78], ip.To16())

	// --- Target Link-Layer Address option (8 bytes) ---
	pkt[78] = 2 // Type: Target Link-Layer Address
	pkt[79] = 1 // Length: 1 (in units of 8 bytes)
	copy(pkt[80:86], mac)

	// Compute ICMPv6 checksum over pseudo-header + ICMPv6 body.
	csum := icmpv6Checksum(pkt[22:38], pkt[38:54], pkt[54:86])
	binary.BigEndian.PutUint16(pkt[56:58], csum)

	return pkt
}

// icmpv6Checksum computes the ICMPv6 checksum per RFC 4443 §2.3.
// It includes the IPv6 pseudo-header (src, dst, length, next-header=58).
func icmpv6Checksum(src, dst, payload []byte) uint16 {
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
	// Pseudo-header: next header = 58 (ICMPv6)
	sum += 58

	// Payload
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}
