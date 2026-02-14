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

func htons(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}
