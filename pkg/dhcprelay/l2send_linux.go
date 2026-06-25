package dhcprelay

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/psaab/xpf/pkg/linuxsock"
	"golang.org/x/sys/unix"
)

// Frame layout constants for the hand-rolled Ethernet+IPv4+UDP frame.
const (
	ethHeaderLen  = 14
	ipv4HeaderLen = 20 // no options
	udpHeaderLen  = 8

	etherTypeIPv4 = 0x0800
	ipProtoUDP    = 17
	ipv4TTL       = 64
)

// l2Sender owns an AF_PACKET TX socket used to deliver DHCP server replies
// directly to a client's hardware address when the client cleared the
// broadcast flag (RFC 2131 §4.1). A normal UDP WriteTo(yiaddr) would force the
// kernel to ARP-resolve the offered address, but a client in SELECTING/
// REQUESTING has not yet configured that address and will not answer ARP, so
// the reply would be undeliverable (#2076).
//
// The socket is TX-only — it never blocks on a read — so it is deliberately
// NOT registered with the relay's close-on-cancel watcher (that watcher exists
// only to unblock a stuck ReadFrom; see runRelay). It is closed by Close(),
// which is idempotent (sync.Once) and invoked from a defer that runs only after
// wg.Wait() returns, i.e. after every sendReply caller has joined. This mirrors
// the pkg/lldp closeOnce lifecycle and preserves the #1915 socket invariants.
type l2Sender struct {
	fd        int
	ifaceName string // re-resolved per send for index + MAC (link-flap safe)
	// openMAC is the interface MAC captured at open time. It is the fallback
	// source MAC when a per-send re-resolution returns no MAC (e.g. mid-flap).
	openMAC   net.HardwareAddr
	closeOnce sync.Once
}

// newL2Sender opens an AF_PACKET/SOCK_RAW TX socket bound to the relay
// interface. Open is fail-soft for the caller: any error (including EPERM when
// CAP_NET_RAW is absent) is returned so the caller records a nil sender and
// every flag-clear reply takes the broadcast fallback instead of failing the
// relay. The socket protocol is ETH_P_IP because we send fully-formed IPv4
// frames; the bound interface scopes egress.
func newL2Sender(ifaceName string) (*l2Sender, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}
	fd, err := linuxsock.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsLocal(unix.ETH_P_IP)))
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w", err)
	}
	// Bind to the interface so the kernel scopes the socket to this netdev.
	// Binding is not strictly required for Sendto (which carries the ifindex),
	// but it matches the lldp.go precedent and rejects an obviously wrong fd
	// early.
	ll := unix.SockaddrLinklayer{
		Protocol: htonsLocal(unix.ETH_P_IP),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &ll); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	return &l2Sender{
		fd:        fd,
		ifaceName: ifaceName,
		openMAC:   append(net.HardwareAddr(nil), iface.HardwareAddr...),
	}, nil
}

// Close closes the underlying fd. It is idempotent (safe to call from multiple
// defers) and must be called only after every sendReply caller has joined.
func (s *l2Sender) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() {
		err = unix.Close(s.fd)
	})
	return err
}

// sendReply builds an Ethernet+IPv4+UDP frame carrying the BOOTP reply payload
// and transmits it on the AF_PACKET socket to dstMAC. The interface index and
// source MAC are re-resolved at send time (garp.go precedent) so a link flap,
// dynamic recreate, or VRRP programMAC change does not leave a stale ifindex or
// source MAC. The source IP is the saved giaddr the caller passes (never the
// per-send address list) so the L2 frame's IPv4 source matches what the server
// saw in the relayed request (#2076 §7.2).
//
// On any guard failure or syscall error it returns an error so the caller falls
// back to broadcast (which always works) — the relay never regresses to
// undeliverable.
func (s *l2Sender) sendReply(dstMAC net.HardwareAddr,
	srcIP, dstIP net.IP, payload []byte) error {
	if len(dstMAC) != 6 {
		return fmt.Errorf("dst MAC not 6 bytes: %v", dstMAC)
	}
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil {
		return fmt.Errorf("src IP not IPv4: %v", srcIP)
	}
	if dst4 == nil {
		return fmt.Errorf("dst IP not IPv4: %v", dstIP)
	}

	// Re-resolve the interface for a current ifindex + source MAC.
	iface, err := net.InterfaceByName(s.ifaceName)
	if err != nil {
		return fmt.Errorf("interface re-resolve: %w", err)
	}
	srcMAC := iface.HardwareAddr
	if len(srcMAC) != 6 {
		// Fall back to the MAC captured at open time if the live one is
		// missing (e.g. mid-flap). Still require a 6-byte Ethernet MAC.
		srcMAC = s.openMAC
	}
	if len(srcMAC) != 6 {
		return fmt.Errorf("src MAC not 6 bytes: %v", srcMAC)
	}

	// MTU guard: the raw path cannot fragment. The L3 size (IPv4 + UDP +
	// payload) must fit the interface MTU (which excludes the 14-byte
	// Ethernet header). Over-MTU → error so the caller broadcasts/UDP-falls-
	// back and lets the kernel fragment.
	l3Size := ipv4HeaderLen + udpHeaderLen + len(payload)
	if iface.MTU > 0 && l3Size > iface.MTU {
		return fmt.Errorf("reply L3 size %d exceeds MTU %d on %s",
			l3Size, iface.MTU, s.ifaceName)
	}

	frame := buildL2Reply(dstMAC, srcMAC, src4, dst4, payload)

	addr := unix.SockaddrLinklayer{
		Protocol: htonsLocal(unix.ETH_P_IP),
		Ifindex:  iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], dstMAC)

	if err := unix.Sendto(s.fd, frame, 0, &addr); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	return nil
}

// buildL2Reply hand-rolls an Ethernet(0x0800)+IPv4(proto 17, header checksum
// computed)+UDP(67->68, checksum=0)+payload frame. UDP checksum 0 is legal for
// IPv4 (RFC 768) and removes the hand-rolled pseudo-header checksum bug class
// (#2076 §7.2 / Q2). The IPv4 header checksum is mandatory and is computed.
//
// Exposed (unexported) for exhaustive per-byte unit tests.
func buildL2Reply(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP,
	payload []byte) []byte {
	udpLen := udpHeaderLen + len(payload)
	totalLen := ipv4HeaderLen + udpLen
	frame := make([]byte, ethHeaderLen+totalLen)

	// --- Ethernet header (14 bytes) ---
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	// --- IPv4 header (20 bytes), starts at offset 14 ---
	ip := frame[ethHeaderLen : ethHeaderLen+ipv4HeaderLen]
	ip[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	ip[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)      // Identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // Flags=DF, Fragment offset 0
	ip[8] = ipv4TTL
	ip[9] = ipProtoUDP
	// ip[10:12] checksum filled below.
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	// --- UDP header (8 bytes), starts at offset 14+20 = 34 ---
	udp := frame[ethHeaderLen+ipv4HeaderLen : ethHeaderLen+ipv4HeaderLen+udpHeaderLen]
	binary.BigEndian.PutUint16(udp[0:2], relayPort)  // src port 67
	binary.BigEndian.PutUint16(udp[2:4], clientPort) // dst port 68
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0) // checksum 0 (legal for IPv4)

	// --- Payload (BOOTP reply bytes) ---
	copy(frame[ethHeaderLen+ipv4HeaderLen+udpHeaderLen:], payload)

	return frame
}

// ipv4Checksum computes the standard IPv4 header checksum (RFC 791) over the
// given 20-byte header. The checksum field (bytes 10:12) must be zero on input.
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	if len(hdr)%2 != 0 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// htonsLocal converts a uint16 from host to network byte order. Co-located here
// (rather than importing pkg/cluster) to keep pkg/dhcprelay dependency-free
// (README "Dependencies: pkg/config only").
func htonsLocal(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}
